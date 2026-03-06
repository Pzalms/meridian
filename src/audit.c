#include <stdlib.h>
#include <string.h>
#include "audit.h"

/* ------------------------------------------------------------------ */
/* Internal helpers                                                     */
/* ------------------------------------------------------------------ */

static uint16_t rd16(const uint8_t *p) {
    uint16_t v;
    memcpy(&v, p, 2);
    return v;
}

static uint32_t rd32(const uint8_t *p) {
    uint32_t v;
    memcpy(&v, p, 4);
    return v;
}

/* ------------------------------------------------------------------ */
/* audit_window_load                                                    */
/* ------------------------------------------------------------------ */

int audit_window_load(mdn_ctx_t *ctx, const uint8_t *data, uint32_t len, uint16_t id)
{
    (void)id;

    /* minimum: win_id(2) + flags(2) + heap_len(4) + dir_count(4) = 12 bytes */
    if (len < 12) return -1;

    uint32_t pos = 0;
    uint16_t win_id  = rd16(data + pos); pos += 2;
    uint16_t flags   = rd16(data + pos); pos += 2;
    uint32_t heap_len = rd32(data + pos); pos += 4;

    if (len - pos < heap_len) return -1;
    const uint8_t *heap_data = data + pos;
    pos += heap_len;

    if (len - pos < 4) return -1;
    uint32_t dir_count = rd32(data + pos); pos += 4;

    /* guard against unreasonably large dir_count before allocation */
    if (dir_count > 65535u) return -1;

    /* each dir entry: off(4) + len(2) + kind(2) = 8 bytes */
    if (len - pos < dir_count * 8u) return -1;

    mdn_audit_window_t *win = calloc(1, sizeof(mdn_audit_window_t));
    if (!win) return -1;

    win->win_id    = win_id;
    win->flags     = flags;
    win->heap_len  = heap_len;
    win->dir_count = dir_count;

    if (heap_len > 0) {
        win->heap = malloc(heap_len);
        if (!win->heap) { free(win); return -1; }
        memcpy(win->heap, heap_data, heap_len);
    }

    if (dir_count > 0) {
        win->dir = malloc(dir_count * sizeof(mdn_audit_dirent_t));
        if (!win->dir) { free(win->heap); free(win); return -1; }
        for (uint32_t i = 0; i < dir_count; i++) {
            win->dir[i].off  = rd32(data + pos); pos += 4;
            win->dir[i].len  = rd16(data + pos); pos += 2;
            win->dir[i].kind = rd16(data + pos); pos += 2;
        }
    }

    /* grow audit_windows array */
    mdn_audit_window_t *arr = realloc(ctx->audit_windows,
                                       (ctx->audit_count + 1) * sizeof(mdn_audit_window_t));
    if (!arr) {
        free(win->dir);
        free(win->heap);
        free(win);
        return -1;
    }
    ctx->audit_windows = arr;
    ctx->audit_windows[ctx->audit_count] = *win;
    ctx->audit_count++;
    free(win);
    return 0;
}

/* ------------------------------------------------------------------ */
/* audit_compact_window                                                 */
/* ------------------------------------------------------------------ */

void audit_compact_window(mdn_audit_window_t *win)
{
    if (win->heap_len < 2) return;
    /* pre-pass: compute compacted size to right-size the allocation */
    uint32_t new_len = 0;
    uint16_t prev_kind = 0xFFFF;
    for (uint32_t i = 0; i < win->dir_count; i++) {
        mdn_audit_dirent_t *de = &win->dir[i];
        if (de->off + de->len > win->heap_len) continue;
        if (de->kind == prev_kind) continue;
        new_len += de->len;
        prev_kind = de->kind;
    }

    uint8_t *new_heap = malloc(new_len ? new_len : 1);
    if (!new_heap) return;
    uint32_t fill_len = 0;

    prev_kind = 0xFFFF;
    for (uint32_t i = 0; i < win->dir_count; i++) {
        mdn_audit_dirent_t *de = &win->dir[i];
        if (de->off + de->len > win->heap_len) continue;
        if (de->kind == prev_kind) continue;   /* coalesce: skip duplicate-kind */
        memcpy(new_heap + fill_len, win->heap + de->off, de->len);
        fill_len += de->len;
        prev_kind = de->kind;
        /* de->off and de->len in dir[] are NOT updated to reflect new_heap positions */
    }
    free(win->heap);
    win->heap     = new_heap;
    win->heap_len = fill_len;
    /* dir[] retains prior offsets into the pre-compaction layout */
}

/* ------------------------------------------------------------------ */
/* audit_expand_record                                                  */
/* ------------------------------------------------------------------ */

int audit_expand_record(mdn_audit_window_t *win, uint32_t idx,
                         uint8_t *out, uint32_t out_cap)
{
    if (idx >= win->dir_count) return -1;
    mdn_audit_dirent_t *de = &win->dir[idx];
    if (de->off >= win->heap_len) return -1;    /* passes for in-range entries */
    uint32_t read_len = de->len;
    if (read_len > out_cap) read_len = out_cap; /* clamps to out_cap, not heap_len */
    memcpy(out, win->heap + de->off, read_len); /* reads past end of compact heap */
    return (int)read_len;
}

/* ------------------------------------------------------------------ */
/* audit_free_all                                                       */
/* ------------------------------------------------------------------ */

void audit_free_all(mdn_ctx_t *ctx)
{
    for (uint32_t i = 0; i < ctx->audit_count; i++) {
        free(ctx->audit_windows[i].heap);
        free(ctx->audit_windows[i].dir);
    }
    free(ctx->audit_windows);
    ctx->audit_windows = NULL;
    ctx->audit_count   = 0;
}

/* ------------------------------------------------------------------ */
/* audit_record_count                                                   */
/* ------------------------------------------------------------------ */

/*
 * Returns the number of directory entries (logical records) in the
 * given audit window.  Returns -1 when win is NULL.
 */
int audit_record_count(mdn_audit_window_t *win)
{
    if (!win)
        return -1;
    return (int)win->dir_count;
}

/* ------------------------------------------------------------------ */
/* audit_find_record                                                    */
/* ------------------------------------------------------------------ */

/*
 * Scan the directory of win for the first entry whose kind field equals
 * the requested kind value.  Returns the zero-based index of the first
 * matching entry, or -1 when no match is found or win is NULL.
 */
int audit_find_record(mdn_audit_window_t *win, uint16_t kind)
{
    if (!win || !win->dir)
        return -1;
    for (uint32_t i = 0; i < win->dir_count; i++) {
        if (win->dir[i].kind == kind)
            return (int)i;
    }
    return -1;
}

/* ------------------------------------------------------------------ */
/* audit_append_record                                                  */
/* ------------------------------------------------------------------ */

/*
 * Append a new record to the audit window.  The record bytes are
 * appended to the heap allocation and a new directory entry is added.
 * Both arrays are grown via realloc.  Returns 0 on success, -1 on
 * allocation failure.
 */
int audit_append_record(mdn_audit_window_t *win, const uint8_t *data,
                         uint16_t len, uint16_t kind)
{
    if (!win || !data)
        return -1;

    /* Grow heap */
    uint32_t new_heap_len = win->heap_len + (uint32_t)len;
    uint8_t *new_heap = realloc(win->heap, new_heap_len ? new_heap_len : 1);
    if (!new_heap)
        return -1;
    memcpy(new_heap + win->heap_len, data, len);
    win->heap     = new_heap;

    /* Grow directory */
    uint32_t new_dir_count = win->dir_count + 1u;
    mdn_audit_dirent_t *new_dir = realloc(win->dir,
                                            new_dir_count * sizeof(mdn_audit_dirent_t));
    if (!new_dir)
        return -1;

    new_dir[win->dir_count].off  = win->heap_len;
    new_dir[win->dir_count].len  = len;
    new_dir[win->dir_count].kind = kind;

    win->dir       = new_dir;
    win->heap_len  = new_heap_len;
    win->dir_count = new_dir_count;
    return 0;
}

/* ------------------------------------------------------------------ */
/* audit_remove_record                                                  */
/* ------------------------------------------------------------------ */

/*
 * Logically remove the directory entry at position idx by shifting
 * subsequent entries one place toward the front.  The heap bytes for
 * the removed record are not reclaimed (the heap remains valid for
 * surviving entries).  Returns 0 on success, -1 when idx is out of
 * range.
 */
int audit_remove_record(mdn_audit_window_t *win, uint32_t idx)
{
    if (!win || !win->dir)
        return -1;
    if (idx >= win->dir_count)
        return -1;

    uint32_t new_count = win->dir_count - 1u;
    for (uint32_t i = idx; i < new_count; i++)
        win->dir[i] = win->dir[i + 1];

    win->dir_count = new_count;

    if (new_count == 0) {
        free(win->dir);
        win->dir = NULL;
    } else {
        mdn_audit_dirent_t *arr = realloc(win->dir,
                                           new_count * sizeof(mdn_audit_dirent_t));
        if (arr)
            win->dir = arr;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* audit_window_serialize                                               */
/* ------------------------------------------------------------------ */

/*
 * Serialize the audit window to the flat wire format that
 * audit_window_load() expects.  Layout (little-endian):
 *   win_id    u16
 *   flags     u16
 *   heap_len  u32
 *   [heap_len bytes of heap data]
 *   dir_count u32
 *   [dir_count × { off(u32) len(u16) kind(u16) }]
 *
 * Returns the total bytes written, or -1 when cap is too small.
 */
int audit_window_serialize(mdn_audit_window_t *win, uint8_t *out, uint32_t cap)
{
    if (!win || !out)
        return -1;

    uint32_t need = 2u + 2u + 4u + win->heap_len + 4u +
                    win->dir_count * 8u;
    if (cap < need)
        return -1;

    uint32_t pos = 0;

    /* win_id */
    out[pos++] = (uint8_t)(win->win_id & 0xFF);
    out[pos++] = (uint8_t)(win->win_id >> 8);
    /* flags */
    out[pos++] = (uint8_t)(win->flags & 0xFF);
    out[pos++] = (uint8_t)(win->flags >> 8);
    /* heap_len */
    out[pos++] = (uint8_t)( win->heap_len        & 0xFF);
    out[pos++] = (uint8_t)((win->heap_len >>  8) & 0xFF);
    out[pos++] = (uint8_t)((win->heap_len >> 16) & 0xFF);
    out[pos++] = (uint8_t)((win->heap_len >> 24) & 0xFF);
    /* heap bytes */
    if (win->heap_len > 0 && win->heap)
        memcpy(out + pos, win->heap, win->heap_len);
    pos += win->heap_len;
    /* dir_count */
    out[pos++] = (uint8_t)( win->dir_count        & 0xFF);
    out[pos++] = (uint8_t)((win->dir_count >>  8) & 0xFF);
    out[pos++] = (uint8_t)((win->dir_count >> 16) & 0xFF);
    out[pos++] = (uint8_t)((win->dir_count >> 24) & 0xFF);
    /* directory entries */
    for (uint32_t i = 0; i < win->dir_count; i++) {
        mdn_audit_dirent_t *de = &win->dir[i];
        out[pos++] = (uint8_t)( de->off        & 0xFF);
        out[pos++] = (uint8_t)((de->off >>  8) & 0xFF);
        out[pos++] = (uint8_t)((de->off >> 16) & 0xFF);
        out[pos++] = (uint8_t)((de->off >> 24) & 0xFF);
        out[pos++] = (uint8_t)(de->len & 0xFF);
        out[pos++] = (uint8_t)(de->len >> 8);
        out[pos++] = (uint8_t)(de->kind & 0xFF);
        out[pos++] = (uint8_t)(de->kind >> 8);
    }
    return (int)pos;
}

/* ------------------------------------------------------------------ */
/* audit_stats                                                          */
/* ------------------------------------------------------------------ */

/*
 * Aggregate counts across all audit windows in ctx.
 *   total_windows — set to ctx->audit_count
 *   total_records — set to the sum of dir_count across all windows
 */
void audit_stats(mdn_ctx_t *ctx, uint32_t *total_windows, uint32_t *total_records)
{
    if (!ctx) {
        if (total_windows) *total_windows = 0;
        if (total_records) *total_records = 0;
        return;
    }

    uint32_t recs = 0;
    for (uint32_t i = 0; i < ctx->audit_count; i++)
        recs += ctx->audit_windows[i].dir_count;

    if (total_windows) *total_windows = ctx->audit_count;
    if (total_records) *total_records = recs;
}

/* ------------------------------------------------------------------ */
/* audit_merge_windows                                                  */
/* ------------------------------------------------------------------ */

/*
 * Append every record from src into dst by iterating src->dir and
 * calling audit_append_record() for each valid entry.  Records whose
 * heap region extends past src->heap_len are skipped.
 * Returns 0 when all valid records were merged, -1 on the first
 * allocation failure.
 */
int audit_merge_windows(mdn_audit_window_t *dst, mdn_audit_window_t *src)
{
    if (!dst || !src)
        return -1;

    for (uint32_t i = 0; i < src->dir_count; i++) {
        mdn_audit_dirent_t *de = &src->dir[i];

        /* Skip entries whose region extends past the heap */
        if (!src->heap || de->off + de->len > src->heap_len)
            continue;

        if (audit_append_record(dst, src->heap + de->off, de->len, de->kind) != 0)
            return -1;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* audit_filter_by_kind                                                 */
/* ------------------------------------------------------------------ */

/*
 * Collect the data of every record in win whose kind equals the
 * requested kind and copy the bytes consecutively into out.  Returns
 * the total number of bytes written, or -1 when out is NULL.  If the
 * data to be copied would exceed cap, copying stops and the bytes
 * written so far are returned (no partial record is written mid-copy).
 */
int audit_filter_by_kind(mdn_audit_window_t *win, uint16_t kind,
                          uint8_t *out, uint32_t cap)
{
    if (!win || !out)
        return -1;

    uint32_t written = 0;
    for (uint32_t i = 0; i < win->dir_count; i++) {
        mdn_audit_dirent_t *de = &win->dir[i];
        if (de->kind != kind)
            continue;
        if (!win->heap || de->off + de->len > win->heap_len)
            continue;
        if (written + de->len > cap)
            break;
        memcpy(out + written, win->heap + de->off, de->len);
        written += de->len;
    }
    return (int)written;
}
