#ifndef MDN_ZONE_H
#define MDN_ZONE_H

#include "mdn_internal.h"

int         zone_load(mdn_ctx_t *ctx, const uint8_t *data, uint32_t len, uint16_t id);
mdn_zone_t *zone_lookup(mdn_ctx_t *ctx, uint16_t zone_id);
int         zone_merge(mdn_ctx_t *ctx, uint16_t a_id, uint16_t b_id);
void        zone_free_all(mdn_ctx_t *ctx);

#endif /* MDN_ZONE_H */
