#ifndef MDN_NAT_H
#define MDN_NAT_H
#include "mdn_internal.h"
int  nat_bucket_load(mdn_ctx_t *ctx, const uint8_t *data, uint32_t len, uint16_t id);
int  nat_rebucket_zone(mdn_ctx_t *ctx, uint16_t zone_id);  /* called by zone_merge */
void nat_free_all(mdn_ctx_t *ctx);
#endif
