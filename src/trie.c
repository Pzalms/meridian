#include "trie.h"
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
