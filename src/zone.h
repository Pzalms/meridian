#ifndef MDN_ZONE_H
#define MDN_ZONE_H

#include "mdn_internal.h"

int         zone_load(mdn_ctx_t *ctx, const uint8_t *data, uint32_t len, uint16_t id);
mdn_zone_t *zone_lookup(mdn_ctx_t *ctx, uint16_t zone_id);
int         zone_merge(mdn_ctx_t *ctx, uint16_t a_id, uint16_t b_id);
void        zone_free_all(mdn_ctx_t *ctx);

/* Extended zone management */
int         zone_set_parent(mdn_ctx_t *ctx, uint16_t zone_id, uint16_t parent_id);
int         zone_increment_epoch(mdn_ctx_t *ctx, uint16_t zone_id);
mdn_zone_t *zone_find(mdn_ctx_t *ctx, uint16_t zone_id);
int         zone_count(mdn_ctx_t *ctx);
int         zone_walk(mdn_ctx_t *ctx, uint16_t root_id, uint16_t *out, uint32_t out_cap);
int         zone_copy(mdn_ctx_t *ctx, uint16_t src_id, uint16_t dst_id);
void        zone_stats(mdn_ctx_t *ctx, uint32_t *total_out, uint32_t *with_parent_out);

#endif /* MDN_ZONE_H */
