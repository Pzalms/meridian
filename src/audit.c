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
    /* dir[] retains stale offsets into the pre-compaction layout */
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
