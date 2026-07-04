#ifndef MDN_PREFIX_H
#define MDN_PREFIX_H
#include "mdn_internal.h"
int  prefix_page_load(mdn_ctx_t *ctx, const uint8_t *data, uint32_t len, uint16_t id);
void prefix_normalize_pages(mdn_ctx_t *ctx);   /* called from POLICY_PATCH handler */
void prefix_page_free(mdn_prefix_page_t *pg);

/* Extended prefix page management */
mdn_prefix_page_t *prefix_find_page(mdn_ctx_t *ctx, uint32_t page_id);
int                prefix_page_count(mdn_ctx_t *ctx);
int                prefix_insert_item(mdn_prefix_page_t *pg, const uint8_t *item,
                                      uint16_t item_len);
int                prefix_remove_item(mdn_prefix_page_t *pg, uint32_t idx);
int                prefix_page_serialize(mdn_prefix_page_t *pg, uint8_t *out, uint32_t cap);
void               prefix_page_stats(mdn_ctx_t *ctx, uint32_t *total_pages,
                                     uint32_t *total_items);

#endif
