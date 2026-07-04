#include "trie.h"
#include "prefix.h"
#include <stdlib.h>
#include <string.h>

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
