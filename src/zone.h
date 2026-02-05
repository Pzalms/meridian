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

/* Hierarchy traversal and analysis */
uint16_t    zone_find_root(mdn_ctx_t *ctx, uint16_t zone_id);
int         zone_depth(mdn_ctx_t *ctx, uint16_t zone_id);
int         zone_ancestors(mdn_ctx_t *ctx, uint16_t zone_id,
                            uint16_t *out, uint32_t max);
int         zone_children_count(mdn_ctx_t *ctx, uint16_t parent_id);
int         zone_dump(mdn_ctx_t *ctx, uint16_t zone_id, char *out, uint32_t cap);
int         zone_validate_hierarchy(mdn_ctx_t *ctx);
uint32_t    zone_epoch_max(mdn_ctx_t *ctx);
int         zone_flag_count(mdn_ctx_t *ctx, uint16_t flag_mask);
uint16_t    zone_max_if_count(mdn_ctx_t *ctx);
int         zone_collect_by_flag(mdn_ctx_t *ctx, uint16_t flag_mask,
                                  uint16_t *out, uint32_t max);
uint32_t    zone_total_if_count(mdn_ctx_t *ctx);
int         zone_sibling_count(mdn_ctx_t *ctx, uint16_t zone_id);
int         zone_subtree_count(mdn_ctx_t *ctx, uint16_t zone_id);
int         zone_format_flags(mdn_ctx_t *ctx, uint16_t zone_id,
                               char *out, uint32_t cap);
int         zone_leaf_count(mdn_ctx_t *ctx);
int         zone_summary_stats(mdn_ctx_t *ctx, char *out, uint32_t cap);

#endif /* MDN_ZONE_H */
