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

/* Per-page inspection helpers */
typedef struct {
    uint32_t item_count;
    uint32_t v4_count;
    uint32_t v6_count;
    uint32_t other_count;
} mdn_page_kind_stats_t;

void prefix_page_kind_stats(mdn_prefix_page_t *pg, mdn_page_kind_stats_t *out);
int  prefix_page_dump(mdn_prefix_page_t *pg, char *out, uint32_t cap);
int  prefix_page_validate(mdn_prefix_page_t *pg);
uint32_t prefix_count_ipv4(mdn_prefix_page_t *pg);
uint32_t prefix_count_ipv6(mdn_prefix_page_t *pg);
int  prefix_page_find_addr(mdn_prefix_page_t *pg, uint32_t addr);
int  prefix_dir_rebuild(mdn_prefix_page_t *pg, uint16_t new_stride);
int  prefix_page_copy(mdn_prefix_page_t *src, mdn_prefix_page_t *dst);

#endif
