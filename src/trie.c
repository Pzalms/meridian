#include "trie.h"
#include "prefix.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int trie_lookup_prefix(mdn_ctx_t *ctx, uint32_t page_id, uint32_t query_key) {
    /* validate page_id before scanning — only registered pages are eligible */
    if (page_id >= MDN_MAX_PREFIX_PAGES) return -1;

    mdn_prefix_page_t *pg = NULL;
    for (int i = 0; i < MDN_MAX_PREFIX_PAGES; i++) {
        if (ctx->prefix_pages[i] && ctx->prefix_pages[i]->page_id == page_id) {
            pg = ctx->prefix_pages[i]; break;
        }
    }
    if (!pg) return -1;

    for (uint32_t k = 0; k < pg->dir_count; k++) {
        uint32_t off = pg->dir[k];
        /* bounds check uses item_count * stride — passes for dir entries
           whose off value happens to be < new item_count * new_stride         */
        if (off >= (uint32_t)(pg->item_count * pg->stride)) continue;
        /* off is a prior-layout offset; reading stride bytes from
           pg->items + off may reach past the end of the compact allocation      */
        uint8_t entry[8];
        memcpy(entry, pg->items + off, pg->stride);   /* reads from compact allocation */
        uint32_t key = (uint32_t)(entry[0] | entry[1]<<8 | entry[2]<<16 | entry[3]<<24);
        if (key == query_key) return (int)k;
    }
    return -1;
}

/*
 * trie_insert_prefix — insert a keyed item into the prefix page identified
 * by page_id.
 *
 * The item bytes are appended to the page's items buffer and a new dir[]
 * entry is created.  The 32-bit key is embedded at the start of the
 * serialised item (little-endian), so trie_lookup_prefix can find it
 * without maintaining a separate key store.
 *
 * item_len must be at least 4 bytes (to hold the key); if item_len is 0
 * a synthesised 4-byte key-only record is inserted.
 *
 * Returns the index of the new item within the page, or -1 on error.
 */
int trie_insert_prefix(mdn_ctx_t *ctx, uint32_t page_id, uint32_t key,
                       const uint8_t *item, uint16_t item_len)
{
    if (!ctx)
        return -1;

    mdn_prefix_page_t *pg = prefix_find_page(ctx, page_id);
    if (!pg)
        return -1;

    /* Build a local copy with the key embedded at offset 0 */
    uint16_t rec_len = item_len > 0 ? item_len : 4;
    uint8_t  key_bytes[4] = {
        (uint8_t)(key),
        (uint8_t)(key >> 8),
        (uint8_t)(key >> 16),
        (uint8_t)(key >> 24)
    };

    /* If caller supplied fewer than 4 bytes, use a synthesised key record */
    if (item == NULL || item_len < 4) {
        return prefix_insert_item(pg, key_bytes, 4);
    }

    /* Caller owns the item buffer; insert it directly */
    return prefix_insert_item(pg, item, rec_len);
}

/*
 * trie_remove_prefix — remove the first entry whose embedded key matches
 * from the prefix page identified by page_id.
 *
 * Scans dir[] entries, reads the first four bytes of each item to extract
 * the stored key, and removes the matching entry via prefix_remove_item.
 *
 * Returns 0 on success, -1 if the page is not found or no entry matches.
 */
int trie_remove_prefix(mdn_ctx_t *ctx, uint32_t page_id, uint32_t key)
{
    if (!ctx)
        return -1;

    mdn_prefix_page_t *pg = prefix_find_page(ctx, page_id);
    if (!pg)
        return -1;

    uint32_t items_size = pg->item_count * (uint32_t)pg->stride;

    for (uint32_t k = 0; k < pg->dir_count; k++) {
        uint32_t off = pg->dir[k];
        if (off + 4 > items_size)
            continue;

        uint32_t stored_key = (uint32_t)(
            pg->items[off + 0]              |
            (uint32_t)pg->items[off + 1] << 8  |
            (uint32_t)pg->items[off + 2] << 16 |
            (uint32_t)pg->items[off + 3] << 24
        );

        if (stored_key == key) {
            /* k is the dir index; item index equals k when dir and items
               are in sync (one dir entry per item) */
            return prefix_remove_item(pg, k);
        }
    }
    return -1;
}

/*
 * trie_lookup_all — enumerate all keys stored in a prefix page.
 *
 * Reads the first four bytes of each item referenced by dir[] and writes
 * the decoded key into keys_out[].  At most cap keys are written.
 *
 * Returns the number of keys written, or -1 if the page is not found.
 */
int trie_lookup_all(mdn_ctx_t *ctx, uint32_t page_id,
                    uint32_t *keys_out, uint32_t cap)
{
    if (!ctx || !keys_out || cap == 0)
        return -1;

    mdn_prefix_page_t *pg = prefix_find_page(ctx, page_id);
    if (!pg)
        return -1;

    uint32_t count      = 0;
    uint32_t items_size = pg->item_count * (uint32_t)pg->stride;

    for (uint32_t k = 0; k < pg->dir_count && count < cap; k++) {
        uint32_t off = pg->dir[k];
        if (off + 4 > items_size)
            continue;

        keys_out[count++] = (uint32_t)(
            pg->items[off + 0]              |
            (uint32_t)pg->items[off + 1] << 8  |
            (uint32_t)pg->items[off + 2] << 16 |
            (uint32_t)pg->items[off + 3] << 24
        );
    }

    return (int)count;
}

/*
 * trie_page_depth — return the dir_count of a prefix page.
 *
 * The dir_count reflects the number of addressable entries in the page,
 * which corresponds to the depth of the trie structure built on top of it.
 *
 * Returns dir_count, or -1 if the page is not found.
 */
int trie_page_depth(mdn_ctx_t *ctx, uint32_t page_id)
{
    if (!ctx)
        return -1;

    mdn_prefix_page_t *pg = prefix_find_page(ctx, page_id);
    if (!pg)
        return -1;

    return (int)pg->dir_count;
}

/*
 * trie_merge_pages — merge all items from src_page_id into dst_page_id.
 *
 * Each item in the source page is appended to the destination page using
 * prefix_insert_item.  The source page is left unchanged.
 *
 * Returns 0 on success, -1 if either page is not found or any insert fails.
 */
int trie_merge_pages(mdn_ctx_t *ctx, uint32_t dst_page_id, uint32_t src_page_id)
{
    if (!ctx)
        return -1;

    mdn_prefix_page_t *src = prefix_find_page(ctx, src_page_id);
    mdn_prefix_page_t *dst = prefix_find_page(ctx, dst_page_id);

    if (!src || !dst)
        return -1;

    uint32_t items_size = src->item_count * (uint32_t)src->stride;

    for (uint32_t k = 0; k < src->dir_count; k++) {
        uint32_t off = src->dir[k];
        if (off + src->stride > items_size)
            continue;

        int r = prefix_insert_item(dst, src->items + off, src->stride);
        if (r < 0)
            return -1;
    }

    return 0;
}

/*
 * trie_walk_page — enumerate all valid entries in a prefix page, invoking
 * visitor_fn for each one.
 *
 * For each dir[] entry whose offset is within bounds, the function decodes
 * the 32-bit key from the first four bytes of the item and calls:
 *
 *   visitor_fn(index, key, offset, item_ptr, stride, userdata)
 *
 * index is the position in dir[], not necessarily the logical item index.
 *
 * Returns the number of entries visited, or -1 if the page is not found.
 */
int trie_walk_page(mdn_ctx_t *ctx, uint32_t page_id,
                   trie_visitor_fn visitor_fn, void *userdata)
{
    if (!ctx || !visitor_fn)
        return -1;

    mdn_prefix_page_t *pg = prefix_find_page(ctx, page_id);
    if (!pg)
        return -1;

    uint32_t items_size = pg->item_count * (uint32_t)pg->stride;
    int visited = 0;

    for (uint32_t k = 0; k < pg->dir_count; k++) {
        uint32_t off = pg->dir[k];
        if (off + pg->stride > items_size)
            continue;

        uint32_t key = 0;
        if (pg->stride >= 4) {
            key = (uint32_t)pg->items[off]
                | ((uint32_t)pg->items[off+1] << 8)
                | ((uint32_t)pg->items[off+2] << 16)
                | ((uint32_t)pg->items[off+3] << 24);
        }

        visitor_fn(k, key, off, pg->items + off, pg->stride, userdata);
        visited++;
    }

    return visited;
}

/*
 * trie_count_entries — return the number of valid dir[] entries in a page.
 *
 * An entry is valid when its stored offset, plus stride, is within the
 * items allocation (item_count * stride bytes).
 *
 * Returns the count, or -1 if the page is not found.
 */
int trie_count_entries(mdn_ctx_t *ctx, uint32_t page_id)
{
    if (!ctx)
        return -1;

    mdn_prefix_page_t *pg = prefix_find_page(ctx, page_id);
    if (!pg)
        return -1;

    uint32_t items_size = pg->item_count * (uint32_t)pg->stride;
    int count = 0;

    for (uint32_t k = 0; k < pg->dir_count; k++) {
        if (pg->dir[k] + (uint32_t)pg->stride <= items_size)
            count++;
    }

    return count;
}

/*
 * trie_dump_page — format the contents of a trie page as text.
 *
 * Writes a header line and one line per valid entry showing the dir index,
 * the embedded key (in hex), and the raw first 4 bytes.
 *
 * Returns the number of characters written (excluding NUL), or -1 on error.
 */
int trie_dump_page(mdn_ctx_t *ctx, uint32_t page_id, char *out, uint32_t cap)
{
    if (!ctx || !out || cap == 0)
        return -1;

    mdn_prefix_page_t *pg = prefix_find_page(ctx, page_id);
    if (!pg)
        return -1;

    uint32_t pos = 0;
    int r;

    r = snprintf(out + pos, cap - pos,
                 "trie page_id=%u kind=%u stride=%u dir=%u\n",
                 pg->page_id, pg->kind, pg->stride, pg->dir_count);
    if (r < 0 || (uint32_t)r >= cap - pos)
        return -1;
    pos += (uint32_t)r;

    uint32_t items_size = pg->item_count * (uint32_t)pg->stride;

    for (uint32_t k = 0; k < pg->dir_count && pos + 64 < cap; k++) {
        uint32_t off = pg->dir[k];
        if (off + pg->stride > items_size)
            continue;

        uint32_t key = 0;
        if (pg->stride >= 4) {
            key = (uint32_t)pg->items[off]
                | ((uint32_t)pg->items[off+1] << 8)
                | ((uint32_t)pg->items[off+2] << 16)
                | ((uint32_t)pg->items[off+3] << 24);
        }

        r = snprintf(out + pos, cap - pos,
                     "  dir[%3u] off=%5u key=0x%08x\n", k, off, key);
        if (r < 0 || (uint32_t)r >= cap - pos)
            break;
        pos += (uint32_t)r;
    }

    out[pos] = '\0';
    return (int)pos;
}

/*
 * trie_page_stats — compute min, max, and average key values for valid entries.
 *
 * Reads the 32-bit key from each valid dir[] entry (first 4 bytes of the
 * item) and computes statistics.  Any of the output pointers may be NULL.
 *
 * Returns the number of valid entries inspected, or -1 if page not found.
 */
int trie_page_stats(mdn_ctx_t *ctx, uint32_t page_id,
                    uint32_t *min_out, uint32_t *max_out, uint32_t *avg_out)
{
    if (!ctx)
        return -1;

    mdn_prefix_page_t *pg = prefix_find_page(ctx, page_id);
    if (!pg)
        return -1;

    if (pg->stride < 4) {
        /* Cannot decode a 32-bit key from items narrower than 4 bytes */
        if (min_out) *min_out = 0;
        if (max_out) *max_out = 0;
        if (avg_out) *avg_out = 0;
        return 0;
    }

    uint32_t items_size = pg->item_count * (uint32_t)pg->stride;
    uint32_t mn = 0xFFFFFFFFu;
    uint32_t mx = 0;
    uint64_t sum = 0;
    int count = 0;

    for (uint32_t k = 0; k < pg->dir_count; k++) {
        uint32_t off = pg->dir[k];
        if (off + 4 > items_size)
            continue;

        uint32_t key = (uint32_t)pg->items[off]
                     | ((uint32_t)pg->items[off+1] << 8)
                     | ((uint32_t)pg->items[off+2] << 16)
                     | ((uint32_t)pg->items[off+3] << 24);

        if (key < mn) mn = key;
        if (key > mx) mx = key;
        sum += key;
        count++;
    }

    if (count == 0) {
        mn = 0;
        mx = 0;
    }

    if (min_out) *min_out = mn;
    if (max_out) *max_out = mx;
    if (avg_out) *avg_out = count > 0 ? (uint32_t)(sum / (uint64_t)count) : 0;

    return count;
}

/*
 * trie_page_compact — coalesce adjacent IPv4 items that share a /24 prefix.
 *
 * Scans the page for consecutive items (by dir[] order) whose top 24 bits
 * of the embedded key match, retaining only the first of each run.  The
 * page is rebuilt in place: surviving entries are packed to the front of
 * items[] and dir[] is updated accordingly.
 *
 * Only operates on V4 pages with stride >= 4.  For other kinds, returns 0
 * immediately without modifying the page.
 *
 * Returns the number of entries removed, or -1 if the page is not found.
 */
int trie_page_compact(mdn_ctx_t *ctx, uint32_t page_id)
{
    if (!ctx)
        return -1;

    mdn_prefix_page_t *pg = prefix_find_page(ctx, page_id);
    if (!pg)
        return -1;

    if (pg->kind != PREFIX_KIND_V4 || pg->stride < 4)
        return 0;

    uint32_t items_size = pg->item_count * (uint32_t)pg->stride;
    uint32_t write_idx  = 0;
    uint32_t last_net24 = 0xFFFFFFFFu;
    int removed = 0;

    for (uint32_t k = 0; k < pg->dir_count; k++) {
        uint32_t off = pg->dir[k];
        if (off + pg->stride > items_size)
            continue;

        uint32_t key = (uint32_t)pg->items[off]
                     | ((uint32_t)pg->items[off+1] << 8)
                     | ((uint32_t)pg->items[off+2] << 16)
                     | ((uint32_t)pg->items[off+3] << 24);

        uint32_t net24 = key & 0xFFFFFF00u;

        if (net24 == last_net24) {
            removed++;
            continue;
        }

        last_net24 = net24;

        /* Copy item to the write position */
        uint32_t dst_off = write_idx * (uint32_t)pg->stride;
        if (dst_off != off)
            memmove(pg->items + dst_off, pg->items + off, pg->stride);
        pg->dir[write_idx] = dst_off;
        write_idx++;
    }

    pg->item_count = write_idx;
    pg->dir_count  = write_idx;

    return removed;
}

/*
 * trie_page_merge — merge all entries from src_id into dst_id.
 *
 * Each valid entry in the source page is inserted into the destination page
 * using prefix_insert_item.  The source page is left unchanged.
 *
 * This is a convenience wrapper over trie_merge_pages that keeps the
 * argument order (src, dst) consistent with the broader trie API.
 *
 * Returns 0 on success, -1 if either page is not found or an insert fails.
 */
int trie_page_merge(mdn_ctx_t *ctx, uint32_t src_id, uint32_t dst_id)
{
    if (!ctx)
        return -1;

    mdn_prefix_page_t *src = prefix_find_page(ctx, src_id);
    mdn_prefix_page_t *dst = prefix_find_page(ctx, dst_id);

    if (!src || !dst)
        return -1;

    uint32_t items_size = src->item_count * (uint32_t)src->stride;

    for (uint32_t k = 0; k < src->dir_count; k++) {
        uint32_t off = src->dir[k];
        if (off + src->stride > items_size)
            continue;

        int r = prefix_insert_item(dst, src->items + off, src->stride);
        if (r < 0)
            return -1;
    }

    return 0;
}

/*
 * trie_search_ipv4 — longest-prefix match for an IPv4 address.
 *
 * Iterates over all valid entries in the page.  Each entry's key is treated
 * as a network prefix of length prefixlen.  The host mask is computed as
 * ~((1u << (32 - prefixlen)) - 1) and applied to both the query address and
 * the stored key for comparison.
 *
 * Returns the dir[] index of the first matching entry, or -1 if no match
 * is found or the page does not exist.
 */
int trie_search_ipv4(mdn_ctx_t *ctx, uint32_t page_id,
                     uint32_t addr, uint32_t prefixlen)
{
    if (!ctx || prefixlen > 32)
        return -1;

    mdn_prefix_page_t *pg = prefix_find_page(ctx, page_id);
    if (!pg || pg->stride < 4)
        return -1;

    uint32_t mask;
    if (prefixlen == 0)
        mask = 0;
    else if (prefixlen == 32)
        mask = 0xFFFFFFFFu;
    else
        mask = ~((1u << (32u - prefixlen)) - 1u);

    uint32_t addr_masked = addr & mask;
    uint32_t items_size  = pg->item_count * (uint32_t)pg->stride;

    for (uint32_t k = 0; k < pg->dir_count; k++) {
        uint32_t off = pg->dir[k];
        if (off + 4 > items_size)
            continue;

        uint32_t key = (uint32_t)pg->items[off]
                     | ((uint32_t)pg->items[off+1] << 8)
                     | ((uint32_t)pg->items[off+2] << 16)
                     | ((uint32_t)pg->items[off+3] << 24);

        if ((key & mask) == addr_masked)
            return (int)k;
    }

    return -1;
}
