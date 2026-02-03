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

/* Additional NAT operations */
int      nat_bucket_age(mdn_ctx_t *ctx, uint16_t bucket_id, uint32_t cutoff_epoch);
int      nat_bucket_hits_misses(mdn_ctx_t *ctx, uint16_t bucket_id,
                                uint32_t *hits_out, uint32_t *misses_out);
int      nat_zone_summary(mdn_ctx_t *ctx, uint16_t zone_id,
                          char *out_buf, uint32_t cap);
uint32_t nat_session_count(mdn_ctx_t *ctx);
int      nat_evict_oldest(mdn_ctx_t *ctx, uint16_t zone_id, uint32_t max_evict);
uint32_t nat_tuple_hash(const uint8_t *tuple, uint32_t len);
int      nat_bucket_fill_ratio(mdn_ctx_t *ctx, uint16_t bucket_id);
int      nat_bucket_epoch_advance(mdn_ctx_t *ctx, uint16_t bucket_id);
uint32_t nat_zone_max_epoch(mdn_ctx_t *ctx, uint16_t zone_id);
uint16_t nat_session_flags_or(mdn_ctx_t *ctx, uint16_t zone_id);
int      nat_compact_buckets(mdn_ctx_t *ctx);
int      nat_bucket_zone_remap(mdn_ctx_t *ctx, uint16_t bucket_id, uint16_t new_zone_id);
uint32_t nat_session_max_last_seen(mdn_ctx_t *ctx, uint16_t zone_id);

#endif
