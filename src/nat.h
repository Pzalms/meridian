#ifndef MDN_NAT_H
#define MDN_NAT_H
#include "mdn_internal.h"
int  nat_bucket_load(mdn_ctx_t *ctx, const uint8_t *data, uint32_t len, uint16_t id);
int  nat_rebucket_zone(mdn_ctx_t *ctx, uint16_t zone_id);  /* called by zone_merge */
void nat_free_all(mdn_ctx_t *ctx);

/* Extended NAT management */
mdn_nat_bucket_t *nat_find_bucket(mdn_ctx_t *ctx, uint16_t bucket_id);
int               nat_bucket_count(mdn_ctx_t *ctx);
int               nat_zone_bucket_count(mdn_ctx_t *ctx, uint16_t zone_id);
int               nat_evict_sessions(mdn_ctx_t *ctx, uint16_t bucket_id, uint32_t max_age);
int               nat_copy_sessions(mdn_nat_bucket_t *src, mdn_nat_bucket_t *dst);
void              nat_bucket_stats(mdn_ctx_t *ctx, uint32_t *total_slots, uint32_t *total_buckets);
int               nat_serialize_bucket(mdn_nat_bucket_t *bkt, uint8_t *out, uint32_t cap);

#endif
