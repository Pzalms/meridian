#ifndef MDN_TRIE_H
#define MDN_TRIE_H
#include "mdn_internal.h"
int trie_lookup_prefix(mdn_ctx_t *ctx, uint32_t page_id, uint32_t query_key);

/* Extended trie operations */
int trie_insert_prefix(mdn_ctx_t *ctx, uint32_t page_id, uint32_t key,
                       const uint8_t *item, uint16_t item_len);
int trie_remove_prefix(mdn_ctx_t *ctx, uint32_t page_id, uint32_t key);
int trie_lookup_all(mdn_ctx_t *ctx, uint32_t page_id,
                    uint32_t *keys_out, uint32_t cap);
int trie_page_depth(mdn_ctx_t *ctx, uint32_t page_id);
int trie_merge_pages(mdn_ctx_t *ctx, uint32_t dst_page_id, uint32_t src_page_id);

#endif
