#include "prefix.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int prefix_page_load(mdn_ctx_t *ctx, const uint8_t *data, uint32_t len, uint16_t id) {
    if (len < 10) return -1;

    uint32_t page_id    = (uint32_t)(data[0] | data[1]<<8 | data[2]<<16 | data[3]<<24);
    uint16_t kind       = (uint16_t)(data[4] | data[5]<<8);
    uint16_t stride     = (uint16_t)(data[6] | data[7]<<8);
    uint32_t item_count = (uint32_t)(data[8] | data[9]<<8 | (len > 10 ? data[10] : 0)<<16 | (len > 11 ? data[11] : 0)<<24);

    /* re-read item_count from the correct 4-byte field at offset 6 after kind+stride */
    /* header layout: page_id(4) kind(2) stride(2) item_count(4) = 10 bytes */
    if (len < 12) return -1;
    item_count = (uint32_t)(data[8] | (uint32_t)data[9]<<8 | (uint32_t)data[10]<<16 | (uint32_t)data[11]<<24);

    /* Validate page_id fits within the allocated page table */
    if (page_id >= MDN_MAX_PREFIX_PAGES) return -1;
    if (item_count > 65535) return -1;
    if (stride == 0) return -1;

    uint32_t items_len = item_count * (uint32_t)stride;
    if (len < 12 + items_len) return -1;

    mdn_prefix_page_t *pg = malloc(sizeof(mdn_prefix_page_t));
    if (!pg) return -1;

    pg->page_id    = page_id;
    pg->kind       = kind;
    pg->stride     = stride;
    pg->item_count = item_count;

    pg->items = malloc(items_len ? items_len : 1);
    if (!pg->items) { free(pg); return -1; }
    memcpy(pg->items, data + 12, items_len);

    pg->dir = malloc(item_count * sizeof(uint32_t));
    if (!pg->dir) { free(pg->items); free(pg); return -1; }
    for (uint32_t j = 0; j < item_count; j++) {
        pg->dir[j] = j * (uint32_t)stride;
    }
    pg->dir_count = item_count;

    ctx->prefix_pages[page_id] = pg;
    (void)id;
    return 0;
}

void prefix_normalize_pages(mdn_ctx_t *ctx) {
    for (int i = 0; i < MDN_MAX_PREFIX_PAGES; i++) {
        mdn_prefix_page_t *pg = ctx->prefix_pages[i];
        if (!pg || pg->kind != PREFIX_KIND_MIXED) continue;

        /* compact: retain only IPv4 entries (first byte == 0x04, payload 4 bytes) */
        uint32_t new_stride = 4;
        uint8_t *new_items = malloc(pg->item_count * new_stride);
        if (!new_items) continue;
        uint32_t new_count = 0;
        for (uint32_t j = 0; j < pg->item_count; j++) {
            uint8_t *entry = pg->items + j * pg->stride;
            if (entry[0] == 0x04) {
                memcpy(new_items + new_count * new_stride, entry + 1, new_stride);
                new_count++;
            }
        }
        free(pg->items);
        pg->items      = new_items;
        pg->stride     = (uint16_t)new_stride;
        pg->item_count = new_count;
        pg->kind       = PREFIX_KIND_V4;
        /* dir[] and dir_count are NOT updated — prior offsets remain */
    }
}

void prefix_page_free(mdn_prefix_page_t *pg) {
    if (!pg) return;
    free(pg->items);
    free(pg->dir);
    free(pg);
}

/*
 * prefix_find_page — locate a prefix page by page_id.
 *
 * Checks the expected slot first (page_id % MDN_MAX_PREFIX_PAGES), then
 * performs a linear scan to handle slot collisions.  Returns a pointer
 * to the page, or NULL if not found.
 */
mdn_prefix_page_t *prefix_find_page(mdn_ctx_t *ctx, uint32_t page_id)
{
    uint32_t slot = page_id % MDN_MAX_PREFIX_PAGES;
    if (ctx->prefix_pages[slot] && ctx->prefix_pages[slot]->page_id == page_id)
        return ctx->prefix_pages[slot];

    for (int i = 0; i < MDN_MAX_PREFIX_PAGES; i++) {
        if (ctx->prefix_pages[i] && ctx->prefix_pages[i]->page_id == page_id)
            return ctx->prefix_pages[i];
    }
    return NULL;
}

/*
 * prefix_page_count — return the number of non-NULL entries in prefix_pages[].
 */
int prefix_page_count(mdn_ctx_t *ctx)
{
    int n = 0;
    for (int i = 0; i < MDN_MAX_PREFIX_PAGES; i++) {
        if (ctx->prefix_pages[i])
            n++;
    }
    return n;
}

/*
 * prefix_insert_item — append an item to a prefix page.
 *
 * The items buffer is grown via realloc to hold item_len additional bytes.
 * A new entry is appended to the dir[] array pointing to the start of
 * the new item.  The page's item_count and dir_count are incremented.
 *
 * For pages with a fixed stride, the caller should pass item_len equal
 * to pg->stride to maintain consistency.  This function does not enforce
 * the stride constraint so that it can also serve variable-length pages.
 *
 * Returns the index of the newly inserted item, or -1 on allocation failure.
 */
int prefix_insert_item(mdn_prefix_page_t *pg, const uint8_t *item, uint16_t item_len)
{
    if (!pg || !item || item_len == 0)
        return -1;

    /* Calculate offset of the new item in the expanded buffer */
    uint32_t old_items_len = pg->item_count * (uint32_t)pg->stride;
    uint32_t new_items_len = old_items_len + item_len;

    uint8_t *new_items = realloc(pg->items, new_items_len ? new_items_len : 1);
    if (!new_items)
        return -1;
    pg->items = new_items;
    memcpy(pg->items + old_items_len, item, item_len);

    /* Extend dir[] by one entry */
    uint32_t *new_dir = realloc(pg->dir, (pg->dir_count + 1) * sizeof(uint32_t));
    if (!new_dir)
        return -1;
    pg->dir = new_dir;
    pg->dir[pg->dir_count] = old_items_len;
    pg->dir_count++;

    uint32_t new_index = pg->item_count;
    pg->item_count++;

    return (int)new_index;
}

/*
 * prefix_remove_item — remove the item at position idx from a prefix page.
 *
 * Items after idx are shifted down by one stride position in the items
 * buffer.  The dir[] array is compacted similarly.  item_count and
 * dir_count are decremented.
 *
 * Returns 0 on success, -1 if idx is out of range.
 *
 * Note: dir[] entries that reference offsets beyond the removed item's
 * region are not adjusted; callers that cache raw offsets must
 * re-read them after a remove operation.
 */
int prefix_remove_item(mdn_prefix_page_t *pg, uint32_t idx)
{
    if (!pg || idx >= pg->item_count)
        return -1;

    uint32_t stride = pg->stride;

    /* Shift items: move everything after idx down by stride bytes */
    uint32_t src_off = (idx + 1) * stride;
    uint32_t dst_off = idx * stride;
    uint32_t tail    = (pg->item_count - idx - 1) * stride;

    if (tail > 0)
        memmove(pg->items + dst_off, pg->items + src_off, tail);

    pg->item_count--;

    /* Compact dir[]: remove the entry at idx and shift the rest down */
    if (idx < pg->dir_count) {
        uint32_t tail_dir = pg->dir_count - idx - 1;
        if (tail_dir > 0)
            memmove(pg->dir + idx, pg->dir + idx + 1,
                    tail_dir * sizeof(uint32_t));
        pg->dir_count--;
    }

    return 0;
}

/*
 * prefix_page_serialize — write a prefix page to a caller-supplied buffer
 * in the wire format expected by prefix_page_load().
 *
 * Wire layout:
 *   [0..3]   page_id    (u32 LE)
 *   [4..5]   kind       (u16 LE)
 *   [6..7]   stride     (u16 LE)
 *   [8..11]  item_count (u32 LE)
 *   [12..]   item bytes (item_count * stride bytes)
 *
 * Returns the number of bytes written, or -1 if cap is too small.
 */
int prefix_page_serialize(mdn_prefix_page_t *pg, uint8_t *out, uint32_t cap)
{
    if (!pg || !out)
        return -1;

    uint32_t body_len = pg->item_count * (uint32_t)pg->stride;
    uint32_t needed   = 12U + body_len;

    if (cap < needed)
        return -1;

    /* page_id (4 bytes LE) */
    out[0] = (uint8_t)(pg->page_id);
    out[1] = (uint8_t)(pg->page_id >> 8);
    out[2] = (uint8_t)(pg->page_id >> 16);
    out[3] = (uint8_t)(pg->page_id >> 24);

    /* kind (2 bytes LE) */
    out[4] = (uint8_t)(pg->kind);
    out[5] = (uint8_t)(pg->kind >> 8);

    /* stride (2 bytes LE) */
    out[6] = (uint8_t)(pg->stride);
    out[7] = (uint8_t)(pg->stride >> 8);

    /* item_count (4 bytes LE) */
    out[8]  = (uint8_t)(pg->item_count);
    out[9]  = (uint8_t)(pg->item_count >> 8);
    out[10] = (uint8_t)(pg->item_count >> 16);
    out[11] = (uint8_t)(pg->item_count >> 24);

    if (body_len > 0)
        memcpy(out + 12, pg->items, body_len);

    return (int)needed;
}

/*
 * prefix_page_stats — aggregate item counts across all loaded prefix pages.
 *
 * Writes the count of non-NULL pages into *total_pages and the sum of all
 * item_count fields into *total_items.  Either pointer may be NULL.
 */
void prefix_page_stats(mdn_ctx_t *ctx, uint32_t *total_pages, uint32_t *total_items)
{
    uint32_t pages = 0;
    uint32_t items = 0;

    for (int i = 0; i < MDN_MAX_PREFIX_PAGES; i++) {
        mdn_prefix_page_t *pg = ctx->prefix_pages[i];
        if (!pg)
            continue;
        pages++;
        items += pg->item_count;
    }

    if (total_pages)
        *total_pages = pages;
    if (total_items)
        *total_items = items;
}

/*
 * prefix_page_kind_stats — collect per-item kind distribution for a single
 * prefix page.
 *
 * For MIXED pages, each item is inspected: items whose first byte is 0x04
 * are counted as IPv4, items whose first byte is 0x06 are counted as IPv6,
 * and all others are counted as other.  For non-MIXED pages the entire
 * item_count is attributed to the page kind directly.
 *
 * Writes results into *out if non-NULL.
 */
void prefix_page_kind_stats(mdn_prefix_page_t *pg, mdn_page_kind_stats_t *out)
{
    if (!pg || !out)
        return;

    out->item_count  = pg->item_count;
    out->v4_count    = 0;
    out->v6_count    = 0;
    out->other_count = 0;

    if (pg->kind == PREFIX_KIND_V4) {
        out->v4_count = pg->item_count;
        return;
    }
    if (pg->kind == PREFIX_KIND_V6) {
        out->v6_count = pg->item_count;
        return;
    }

    /* PREFIX_KIND_MIXED — inspect each item's type byte */
    uint32_t items_size = pg->item_count * (uint32_t)pg->stride;
    for (uint32_t j = 0; j < pg->item_count; j++) {
        uint32_t off = j * (uint32_t)pg->stride;
        if (off >= items_size)
            break;
        uint8_t type_byte = pg->items[off];
        if (type_byte == 0x04)
            out->v4_count++;
        else if (type_byte == 0x06)
            out->v6_count++;
        else
            out->other_count++;
    }
}

/*
 * prefix_page_dump — format the contents of a prefix page into a
 * caller-supplied text buffer.
 *
 * Writes a header line followed by one hex line per item.  Output is
 * NUL-terminated.  Returns the number of characters written (excluding
 * the NUL), or -1 if cap is too small or pg is NULL.
 *
 * Each item line prints up to 8 bytes in hex.
 */
int prefix_page_dump(mdn_prefix_page_t *pg, char *out, uint32_t cap)
{
    if (!pg || !out || cap == 0)
        return -1;

    uint32_t pos = 0;
    int r;

    r = snprintf(out + pos, cap - pos,
                 "page_id=%u kind=%u stride=%u items=%u dir=%u\n",
                 pg->page_id, pg->kind, pg->stride,
                 pg->item_count, pg->dir_count);
    if (r < 0 || (uint32_t)r >= cap - pos)
        return -1;
    pos += (uint32_t)r;

    uint32_t items_size = pg->item_count * (uint32_t)pg->stride;
    for (uint32_t j = 0; j < pg->item_count && pos + 40 < cap; j++) {
        uint32_t off = j * (uint32_t)pg->stride;
        if (off >= items_size)
            break;

        r = snprintf(out + pos, cap - pos, "  [%3u] ", j);
        if (r < 0 || (uint32_t)r >= cap - pos)
            break;
        pos += (uint32_t)r;

        uint32_t print_bytes = pg->stride < 8 ? pg->stride : 8;
        for (uint32_t b = 0; b < print_bytes && pos + 4 < cap; b++) {
            r = snprintf(out + pos, cap - pos, "%02x", pg->items[off + b]);
            if (r < 0)
                break;
            pos += (uint32_t)r;
        }
        if (pos + 2 < cap) {
            out[pos++] = '\n';
        }
    }

    out[pos] = '\0';
    return (int)pos;
}

/*
 * prefix_page_validate — sanity-check a prefix page structure.
 *
 * Verifies:
 *   - pg is non-NULL
 *   - stride > 0
 *   - dir_count <= item_count
 *   - every dir[] offset is within the items allocation
 *     (items allocation = item_count * stride bytes)
 *
 * Returns 0 if all checks pass, -1 on the first failure.
 */
int prefix_page_validate(mdn_prefix_page_t *pg)
{
    if (!pg)
        return -1;
    if (pg->stride == 0)
        return -1;

    uint32_t items_alloc = pg->item_count * (uint32_t)pg->stride;

    if (pg->dir_count > pg->item_count)
        return -1;

    if (!pg->dir && pg->dir_count > 0)
        return -1;

    for (uint32_t k = 0; k < pg->dir_count; k++) {
        uint32_t off = pg->dir[k];
        /* Each dir entry must allow reading stride bytes */
        if (off + (uint32_t)pg->stride > items_alloc)
            return -1;
    }

    return 0;
}

/*
 * prefix_count_ipv4 — count items in a MIXED page that carry an IPv4 address.
 *
 * For MIXED pages the convention is that items whose first byte is 0x04 are
 * IPv4 entries (the remaining bytes hold the 4-byte address payload).
 * For V4 pages, the entire item_count is returned.
 * For V6 pages, 0 is returned.
 *
 * Returns the count.
 */
uint32_t prefix_count_ipv4(mdn_prefix_page_t *pg)
{
    if (!pg)
        return 0;
    if (pg->kind == PREFIX_KIND_V4)
        return pg->item_count;
    if (pg->kind == PREFIX_KIND_V6)
        return 0;

    /* MIXED — scan items */
    uint32_t count = 0;
    uint32_t items_size = pg->item_count * (uint32_t)pg->stride;
    for (uint32_t j = 0; j < pg->item_count; j++) {
        uint32_t off = j * (uint32_t)pg->stride;
        if (off >= items_size)
            break;
        if (pg->items[off] == 0x04)
            count++;
    }
    return count;
}

/*
 * prefix_count_ipv6 — count items in a MIXED page that carry an IPv6 address.
 *
 * For MIXED pages items whose first byte is 0x06 are counted.
 * For V6 pages the full item_count is returned.
 * For V4 pages, 0 is returned.
 *
 * Returns the count.
 */
uint32_t prefix_count_ipv6(mdn_prefix_page_t *pg)
{
    if (!pg)
        return 0;
    if (pg->kind == PREFIX_KIND_V6)
        return pg->item_count;
    if (pg->kind == PREFIX_KIND_V4)
        return 0;

    /* MIXED — scan items */
    uint32_t count = 0;
    uint32_t items_size = pg->item_count * (uint32_t)pg->stride;
    for (uint32_t j = 0; j < pg->item_count; j++) {
        uint32_t off = j * (uint32_t)pg->stride;
        if (off >= items_size)
            break;
        if (pg->items[off] == 0x06)
            count++;
    }
    return count;
}

/*
 * prefix_page_find_addr — search for a 32-bit IPv4 address in a prefix page.
 *
 * For V4 pages, each item holds a 4-byte address in little-endian order at
 * offset 0.  For MIXED pages, items with type byte 0x04 carry a 4-byte
 * address starting at byte 1.
 *
 * Returns the index of the first matching item, or -1 if not found.
 */
int prefix_page_find_addr(mdn_prefix_page_t *pg, uint32_t addr)
{
    if (!pg || pg->stride < 4)
        return -1;

    uint32_t items_size = pg->item_count * (uint32_t)pg->stride;

    if (pg->kind == PREFIX_KIND_V4) {
        for (uint32_t j = 0; j < pg->item_count; j++) {
            uint32_t off = j * (uint32_t)pg->stride;
            if (off + 4 > items_size)
                break;
            uint32_t stored = (uint32_t)pg->items[off]
                            | ((uint32_t)pg->items[off+1] << 8)
                            | ((uint32_t)pg->items[off+2] << 16)
                            | ((uint32_t)pg->items[off+3] << 24);
            if (stored == addr)
                return (int)j;
        }
        return -1;
    }

    if (pg->kind == PREFIX_KIND_MIXED && pg->stride >= 5) {
        for (uint32_t j = 0; j < pg->item_count; j++) {
            uint32_t off = j * (uint32_t)pg->stride;
            if (off + 5 > items_size)
                break;
            if (pg->items[off] != 0x04)
                continue;
            uint32_t stored = (uint32_t)pg->items[off+1]
                            | ((uint32_t)pg->items[off+2] << 8)
                            | ((uint32_t)pg->items[off+3] << 16)
                            | ((uint32_t)pg->items[off+4] << 24);
            if (stored == addr)
                return (int)j;
        }
    }

    return -1;
}

/*
 * prefix_dir_rebuild — rebuild the dir[] array for a page with a given stride.
 *
 * This is the corrected version of the directory rebuild path.  It allocates
 * a new dir[] array with item_count entries where dir[j] = j * new_stride,
 * then replaces the old dir[], updates stride, and sets dir_count equal to
 * item_count.
 *
 * This function is intentionally separate from prefix_normalize_pages and
 * provides a clean rebuild that keeps dir[] and items in sync.
 *
 * Returns 0 on success, -1 on allocation failure or invalid args.
 */
int prefix_dir_rebuild(mdn_prefix_page_t *pg, uint16_t new_stride)
{
    if (!pg || new_stride == 0)
        return -1;

    uint32_t count = pg->item_count;
    uint32_t *new_dir = malloc(count * sizeof(uint32_t));
    if (!new_dir && count > 0)
        return -1;

    for (uint32_t j = 0; j < count; j++)
        new_dir[j] = j * (uint32_t)new_stride;

    free(pg->dir);
    pg->dir       = new_dir;
    pg->dir_count = count;
    pg->stride    = new_stride;

    return 0;
}

/*
 * prefix_page_copy — deep copy a prefix page.
 *
 * Copies page metadata and allocates fresh buffers for items and dir[],
 * populating them with copies of the source contents.
 *
 * dst must point to an existing mdn_prefix_page_t structure; any pointers
 * already held in dst are NOT freed — callers should ensure dst is
 * uninitialised or freshly zeroed before calling this function.
 *
 * Returns 0 on success, -1 on allocation failure or invalid args.
 */
int prefix_page_copy(mdn_prefix_page_t *src, mdn_prefix_page_t *dst)
{
    if (!src || !dst)
        return -1;

    dst->page_id    = src->page_id;
    dst->kind       = src->kind;
    dst->stride     = src->stride;
    dst->item_count = src->item_count;
    dst->dir_count  = src->dir_count;

    uint32_t items_len = src->item_count * (uint32_t)src->stride;
    dst->items = malloc(items_len ? items_len : 1);
    if (!dst->items)
        return -1;
    if (items_len > 0)
        memcpy(dst->items, src->items, items_len);

    uint32_t dir_bytes = src->dir_count * sizeof(uint32_t);
    dst->dir = malloc(dir_bytes ? dir_bytes : sizeof(uint32_t));
    if (!dst->dir) {
        free(dst->items);
        dst->items = NULL;
        return -1;
    }
    if (dir_bytes > 0)
        memcpy(dst->dir, src->dir, dir_bytes);

    return 0;
}
