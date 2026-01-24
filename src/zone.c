#include "zone.h"
#include "util.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* nat_rebucket_zone is implemented in a later module */
extern int nat_rebucket_zone(mdn_ctx_t *ctx, uint16_t zone_id);

/*
 * zone_load — parse a SECT_ZONE payload and store into ctx->zones[].
 *
 * Wire layout (12 bytes minimum):
 *   [0..1]  zone_id   (u16 LE)
 *   [2..3]  parent_id (u16 LE)
 *   [4..5]  if_count  (u16 LE)
 *   [6..7]  flags     (u16 LE)
 *   [8..11] epoch     (u32 LE)
 */
int zone_load(mdn_ctx_t *ctx, const uint8_t *data, uint32_t len, uint16_t id)
{
    (void)id; /* section-table id; authoritative id is inside the payload */

    if (len < 12)
        return -1;

    uint16_t zone_id   = mdn_u16le(data + 0);
    uint16_t parent_id = mdn_u16le(data + 2);
    uint16_t if_count  = mdn_u16le(data + 4);
    uint16_t flags     = mdn_u16le(data + 6);
    uint32_t epoch     = mdn_u32le(data + 8);

    mdn_zone_t *z = calloc(1, sizeof(mdn_zone_t));
    if (!z)
        return -1;

    z->zone_id   = zone_id;
    z->parent_id = parent_id;
    z->if_count  = if_count;
    z->flags     = flags;
    z->epoch     = epoch;

    ctx->zones[zone_id % MDN_MAX_ZONES] = z;

    return 0;
}

/*
 * zone_lookup — scan ctx->zones[] for an entry whose zone_id matches.
 */
mdn_zone_t *zone_lookup(mdn_ctx_t *ctx, uint16_t zone_id)
{
    for (uint32_t i = 0; i < MDN_MAX_ZONES; i++) {
        if (ctx->zones[i] && ctx->zones[i]->zone_id == zone_id)
            return ctx->zones[i];
    }
    return NULL;
}

/*
 * zone_merge — reassign all NAT buckets whose zone_id matches b_id to a_id,
 * then notify the NAT layer to rehash those entries.
 */
int zone_merge(mdn_ctx_t *ctx, uint16_t a_id, uint16_t b_id)
{
    for (uint32_t i = 0; i < MDN_MAX_NAT_BUCKETS; i++) {
        if (ctx->nat_buckets[i] && ctx->nat_buckets[i]->zone_id == b_id)
            ctx->nat_buckets[i]->zone_id = a_id;
    }
    nat_rebucket_zone(ctx, b_id);
    return 0;
}

/*
 * zone_free_all — free all allocated zone entries.
 */
void zone_free_all(mdn_ctx_t *ctx)
{
    for (uint32_t i = 0; i < MDN_MAX_ZONES; i++) {
        if (ctx->zones[i]) {
            free(ctx->zones[i]);
            ctx->zones[i] = NULL;
        }
    }
}
