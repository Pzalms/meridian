#include "prefix.h"
#include <stdlib.h>
#include <string.h>

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
