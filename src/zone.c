#include "zone.h"
#include "util.h"
#include <stdint.h>
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

    uint16_t zone_id = mdn_u16le(data + 0);

    if (zone_id >= MDN_MAX_ZONES)
        return -1;

    uint16_t flags_wire = mdn_u16le(data + 6);

    mdn_zone_t *z = &ctx->zones[zone_id % MDN_MAX_ZONES];
    memset(z, 0, sizeof(*z));
    z->id    = (uint32_t)zone_id;
    z->flags = (uint32_t)flags_wire;

    if (zone_id >= ctx->zone_count)
        ctx->zone_count = (uint32_t)zone_id + 1u;

    return 0;
}

/*
 * zone_lookup — scan ctx->zones[] for an entry whose id matches zone_id.
 * Slots are keyed by zone_id % MDN_MAX_ZONES so the authoritative id field
 * is used to distinguish occupied entries from zero-initialised slots.
 */
mdn_zone_t *zone_lookup(mdn_ctx_t *ctx, uint16_t zone_id)
{
    for (uint32_t i = 0; i < MDN_MAX_ZONES; i++) {
        if (ctx->zones[i].id == (uint32_t)zone_id) {
            /* Confirm the slot was written by checking zone_count */
            if ((uint32_t)zone_id < ctx->zone_count)
                return &ctx->zones[i];
        }
    }
    return NULL;
}

/*
 * zone_merge — reassign all NAT buckets whose zone_id matches b_id to a_id,
 * then notify the NAT layer to rehash those entries.
 */
int zone_merge(mdn_ctx_t *ctx, uint16_t a_id, uint16_t b_id)
{
    for (uint32_t i = 0; i < ctx->nat_bucket_count; i++) {
        if (ctx->nat_buckets[i].zone_id == (uint32_t)b_id)
            ctx->nat_buckets[i].zone_id = (uint32_t)a_id;
    }
    nat_rebucket_zone(ctx, b_id);
    return 0;
}
