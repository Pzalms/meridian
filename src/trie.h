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

/* Visitor-based enumeration */
typedef void (*trie_visitor_fn)(uint32_t index, uint32_t key, uint32_t off,
                                const uint8_t *item, uint16_t stride,
                                void *userdata);

int trie_walk_page(mdn_ctx_t *ctx, uint32_t page_id,
                   trie_visitor_fn visitor_fn, void *userdata);
int trie_count_entries(mdn_ctx_t *ctx, uint32_t page_id);
int trie_dump_page(mdn_ctx_t *ctx, uint32_t page_id, char *out, uint32_t cap);
int trie_page_stats(mdn_ctx_t *ctx, uint32_t page_id,
                    uint32_t *min_out, uint32_t *max_out, uint32_t *avg_out);
int trie_page_compact(mdn_ctx_t *ctx, uint32_t page_id);
int trie_page_merge(mdn_ctx_t *ctx, uint32_t src_id, uint32_t dst_id);
int trie_search_ipv4(mdn_ctx_t *ctx, uint32_t page_id,
                     uint32_t addr, uint32_t prefixlen);

#endif
