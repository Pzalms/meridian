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

/*
 * zone_find — locate a zone by zone_id using the slot index.
 * Returns a pointer to the zone if found, NULL otherwise.
 *
 * Unlike zone_lookup which performs a linear scan for zone_id equality,
 * zone_find indexes directly into the slot computed from zone_id and
 * confirms that the stored zone_id matches.
 */
mdn_zone_t *zone_find(mdn_ctx_t *ctx, uint16_t zone_id)
{
    uint32_t slot = (uint32_t)zone_id % MDN_MAX_ZONES;
    mdn_zone_t *z = ctx->zones[slot];
    if (z && z->zone_id == zone_id)
        return z;
    /* Slot collision: fall back to linear scan */
    for (uint32_t i = 0; i < MDN_MAX_ZONES; i++) {
        if (ctx->zones[i] && ctx->zones[i]->zone_id == zone_id)
            return ctx->zones[i];
    }
    return NULL;
}

/*
 * zone_set_parent — update the parent_id field of a loaded zone.
 * Returns 0 on success, -1 if the zone is not found.
 *
 * The parent relationship is used by zone_walk to traverse zone
 * hierarchies; this function allows the control plane to re-parent
 * a zone without reloading its full payload.
 */
int zone_set_parent(mdn_ctx_t *ctx, uint16_t zone_id, uint16_t parent_id)
{
    mdn_zone_t *z = zone_find(ctx, zone_id);
    if (!z)
        return -1;
    z->parent_id = parent_id;
    return 0;
}

/*
 * zone_increment_epoch — advance the epoch counter for a zone.
 * Returns the new epoch value, or -1 if the zone is not found.
 *
 * Epoch values are used by NAT cursors to detect when a zone's
 * bucket layout has changed.  Incrementing the epoch signals that
 * previously issued cursors for this zone should be treated as
 * potentially inconsistent.
 */
int zone_increment_epoch(mdn_ctx_t *ctx, uint16_t zone_id)
{
    mdn_zone_t *z = zone_find(ctx, zone_id);
    if (!z)
        return -1;
    z->epoch++;
    return (int)z->epoch;
}

/*
 * zone_count — return the number of non-NULL zone entries in ctx->zones[].
 */
int zone_count(mdn_ctx_t *ctx)
{
    int n = 0;
    for (uint32_t i = 0; i < MDN_MAX_ZONES; i++) {
        if (ctx->zones[i])
            n++;
    }
    return n;
}

/*
 * zone_walk — collect all zone_ids reachable from root_id by following
 * parent_id chains.  Writes up to out_cap zone_ids into out[].
 *
 * The walk ascends the parent chain starting at root_id.  A parent_id
 * of 0 (or a parent that resolves to a zone already in the output list)
 * terminates the walk.  Returns the number of zone_ids written.
 *
 * Notes:
 *   - root_id itself is always the first entry written (if out_cap >= 1).
 *   - Cycles are broken by bounding iterations at MDN_MAX_ZONES.
 *   - A zone whose parent_id equals its own zone_id is treated as a root.
 */
int zone_walk(mdn_ctx_t *ctx, uint16_t root_id, uint16_t *out, uint32_t out_cap)
{
    if (!out || out_cap == 0)
        return 0;

    uint32_t count = 0;
    uint16_t current = root_id;

    for (uint32_t step = 0; step < MDN_MAX_ZONES && count < out_cap; step++) {
        mdn_zone_t *z = zone_find(ctx, current);
        if (!z)
            break;

        /* Record this zone_id */
        out[count++] = z->zone_id;

        /* Stop if we have reached a root (parent_id == 0 or self-referential) */
        if (z->parent_id == 0 || z->parent_id == z->zone_id)
            break;

        /* Detect duplicates to avoid infinite loops */
        int already_seen = 0;
        for (uint32_t k = 0; k < count - 1; k++) {
            if (out[k] == z->parent_id) {
                already_seen = 1;
                break;
            }
        }
        if (already_seen)
            break;

        current = z->parent_id;
    }

    return (int)count;
}

/*
 * zone_copy — duplicate the zone data stored at src_id into the dst_id slot.
 *
 * The destination slot is allocated (or replaced if already occupied).
 * The copy retains all fields from the source but has its zone_id set
 * to dst_id so it occupies the correct identity in the table.
 *
 * Returns 0 on success, -1 if src zone is not found or allocation fails.
 */
int zone_copy(mdn_ctx_t *ctx, uint16_t src_id, uint16_t dst_id)
{
    mdn_zone_t *src = zone_find(ctx, src_id);
    if (!src)
        return -1;

    mdn_zone_t *dst = calloc(1, sizeof(mdn_zone_t));
    if (!dst)
        return -1;

    *dst = *src;           /* copy all fields */
    dst->zone_id = dst_id; /* override identity */

    uint32_t slot = (uint32_t)dst_id % MDN_MAX_ZONES;
    if (ctx->zones[slot]) {
        free(ctx->zones[slot]);
    }
    ctx->zones[slot] = dst;
    return 0;
}

/*
 * zone_stats — aggregate statistics across all loaded zones.
 *
 * Fills *total_out with the count of non-NULL zone entries.
 * Fills *with_parent_out with the count of zones whose parent_id != 0.
 * Either output pointer may be NULL if the caller does not need that stat.
 */
void zone_stats(mdn_ctx_t *ctx, uint32_t *total_out, uint32_t *with_parent_out)
{
    uint32_t total = 0;
    uint32_t with_parent = 0;

    for (uint32_t i = 0; i < MDN_MAX_ZONES; i++) {
        mdn_zone_t *z = ctx->zones[i];
        if (!z)
            continue;
        total++;
        if (z->parent_id != 0)
            with_parent++;
    }

    if (total_out)
        *total_out = total;
    if (with_parent_out)
        *with_parent_out = with_parent;
}
