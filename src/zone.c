#include "zone.h"
#include "util.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

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

/*
 * zone_find_root — follow the parent_id chain starting from zone_id until
 * a zone with parent_id == 0 or parent_id == its own zone_id is reached.
 *
 * Cycles are broken by bounding iteration at MDN_MAX_ZONES steps.
 * Returns the zone_id of the root, or 0 if the starting zone is not found.
 */
uint16_t zone_find_root(mdn_ctx_t *ctx, uint16_t zone_id)
{
    uint16_t current = zone_id;

    for (uint32_t step = 0; step < MDN_MAX_ZONES; step++) {
        mdn_zone_t *z = zone_find(ctx, current);
        if (!z)
            return 0;
        if (z->parent_id == 0 || z->parent_id == z->zone_id)
            return z->zone_id;
        current = z->parent_id;
    }

    return current;
}

/*
 * zone_depth — count the number of hops from zone_id to the root of its
 * parent chain.
 *
 * A zone with no parent (parent_id == 0) has depth 0.  Each additional
 * hop to a parent adds 1.  Cycles are bounded at MDN_MAX_ZONES.
 * Returns -1 if zone_id is not found.
 */
int zone_depth(mdn_ctx_t *ctx, uint16_t zone_id)
{
    mdn_zone_t *z = zone_find(ctx, zone_id);
    if (!z)
        return -1;

    int depth = 0;
    uint16_t current = zone_id;

    for (uint32_t step = 0; step < MDN_MAX_ZONES; step++) {
        mdn_zone_t *cur = zone_find(ctx, current);
        if (!cur)
            break;
        if (cur->parent_id == 0 || cur->parent_id == cur->zone_id)
            break;
        depth++;
        current = cur->parent_id;
    }

    return depth;
}

/*
 * zone_ancestors — collect the ancestor zone_ids of zone_id into out[].
 *
 * Follows parent_id links starting at zone_id's parent.  The starting
 * zone itself is not included.  Writes up to max entries.  Returns the
 * number written.  Cycles are bounded at MDN_MAX_ZONES iterations.
 */
int zone_ancestors(mdn_ctx_t *ctx, uint16_t zone_id,
                   uint16_t *out, uint32_t max)
{
    if (!out || max == 0)
        return 0;

    mdn_zone_t *start = zone_find(ctx, zone_id);
    if (!start || start->parent_id == 0 || start->parent_id == zone_id)
        return 0;

    uint32_t count   = 0;
    uint16_t current = start->parent_id;

    for (uint32_t step = 0; step < MDN_MAX_ZONES && count < max; step++) {
        mdn_zone_t *z = zone_find(ctx, current);
        if (!z)
            break;

        out[count++] = z->zone_id;

        if (z->parent_id == 0 || z->parent_id == z->zone_id)
            break;

        /* Cycle check against already-recorded ancestors */
        int seen = 0;
        for (uint32_t k = 0; k < count - 1; k++) {
            if (out[k] == z->parent_id) {
                seen = 1;
                break;
            }
        }
        if (seen)
            break;

        current = z->parent_id;
    }

    return (int)count;
}

/*
 * zone_children_count — count zones whose parent_id equals parent_id.
 *
 * Returns the number of loaded zones that are direct children of the
 * given parent zone.
 */
int zone_children_count(mdn_ctx_t *ctx, uint16_t parent_id)
{
    int count = 0;

    for (uint32_t i = 0; i < MDN_MAX_ZONES; i++) {
        mdn_zone_t *z = ctx->zones[i];
        if (z && z->parent_id == parent_id && z->zone_id != parent_id)
            count++;
    }

    return count;
}

/*
 * zone_dump — format a zone's fields as a text string.
 *
 * Writes a null-terminated description of the zone into out.
 * Returns the number of bytes written (excluding null terminator), or -1
 * if out is NULL, cap is 0, or the zone is not found.
 */
int zone_dump(mdn_ctx_t *ctx, uint16_t zone_id, char *out, uint32_t cap)
{
    if (!out || cap == 0)
        return -1;

    mdn_zone_t *z = zone_find(ctx, zone_id);
    if (!z) {
        int n = snprintf(out, cap, "zone=%u not_found", (unsigned)zone_id);
        return n < 0 ? -1 : n;
    }

    int n = snprintf(out, cap,
                     "zone_id=%u parent_id=%u if_count=%u flags=0x%04x epoch=%u",
                     (unsigned)z->zone_id,
                     (unsigned)z->parent_id,
                     (unsigned)z->if_count,
                     (unsigned)z->flags,
                     (unsigned)z->epoch);
    return n < 0 ? -1 : n;
}

/*
 * zone_validate_hierarchy — check that the parent_id graph contains no
 * cycles.
 *
 * For each zone, walks the parent chain and checks that no zone_id is
 * visited twice within MDN_MAX_ZONES steps.  Returns 0 if the hierarchy
 * is acyclic, or 1 if a cycle is detected.
 */
int zone_validate_hierarchy(mdn_ctx_t *ctx)
{
    for (uint32_t i = 0; i < MDN_MAX_ZONES; i++) {
        mdn_zone_t *start = ctx->zones[i];
        if (!start || start->parent_id == 0 || start->parent_id == start->zone_id)
            continue;

        /* Walk from this zone's parent upward; detect revisiting start->zone_id */
        uint16_t visited[MDN_MAX_ZONES];
        uint32_t visited_count = 0;
        uint16_t current = start->zone_id;

        for (uint32_t step = 0; step < MDN_MAX_ZONES; step++) {
            /* Check if current already appeared */
            for (uint32_t k = 0; k < visited_count; k++) {
                if (visited[k] == current)
                    return 1; /* cycle detected */
            }

            visited[visited_count++] = current;

            mdn_zone_t *z = zone_find(ctx, current);
            if (!z || z->parent_id == 0 || z->parent_id == z->zone_id)
                break;

            current = z->parent_id;
        }
    }

    return 0;
}

/*
 * zone_epoch_max — return the largest epoch value across all loaded zones.
 *
 * Returns 0 if no zones are loaded.
 */
uint32_t zone_epoch_max(mdn_ctx_t *ctx)
{
    uint32_t max_epoch = 0;

    for (uint32_t i = 0; i < MDN_MAX_ZONES; i++) {
        if (ctx->zones[i] && ctx->zones[i]->epoch > max_epoch)
            max_epoch = ctx->zones[i]->epoch;
    }

    return max_epoch;
}

/*
 * zone_flag_count — count zones that have a specific flag bit set.
 *
 * Returns the number of loaded zones for which (z->flags & flag_mask) != 0.
 */
int zone_flag_count(mdn_ctx_t *ctx, uint16_t flag_mask)
{
    int count = 0;

    for (uint32_t i = 0; i < MDN_MAX_ZONES; i++) {
        if (ctx->zones[i] && (ctx->zones[i]->flags & flag_mask))
            count++;
    }

    return count;
}

/*
 * zone_max_if_count — return the highest if_count value across all zones.
 *
 * Returns 0 if no zones are loaded.
 */
uint16_t zone_max_if_count(mdn_ctx_t *ctx)
{
    uint16_t max_ifc = 0;

    for (uint32_t i = 0; i < MDN_MAX_ZONES; i++) {
        if (ctx->zones[i] && ctx->zones[i]->if_count > max_ifc)
            max_ifc = ctx->zones[i]->if_count;
    }

    return max_ifc;
}

/*
 * zone_collect_by_flag — collect zone_ids whose flags match flag_mask.
 *
 * Writes up to max zone_ids into out[].  A zone is included when
 * (z->flags & flag_mask) != 0.  Returns the number written.
 */
int zone_collect_by_flag(mdn_ctx_t *ctx, uint16_t flag_mask,
                         uint16_t *out, uint32_t max)
{
    if (!out || max == 0)
        return 0;

    uint32_t count = 0;
    for (uint32_t i = 0; i < MDN_MAX_ZONES && count < max; i++) {
        mdn_zone_t *z = ctx->zones[i];
        if (z && (z->flags & flag_mask))
            out[count++] = z->zone_id;
    }
    return (int)count;
}

/*
 * zone_total_if_count — sum if_count across all loaded zones.
 */
uint32_t zone_total_if_count(mdn_ctx_t *ctx)
{
    uint32_t total = 0;
    for (uint32_t i = 0; i < MDN_MAX_ZONES; i++) {
        if (ctx->zones[i])
            total += ctx->zones[i]->if_count;
    }
    return total;
}

/*
 * zone_sibling_count — count zones that share the same parent_id as zone_id
 * (excluding zone_id itself).
 *
 * Returns -1 if zone_id is not found.
 */
int zone_sibling_count(mdn_ctx_t *ctx, uint16_t zone_id)
{
    mdn_zone_t *ref = zone_find(ctx, zone_id);
    if (!ref)
        return -1;

    if (ref->parent_id == 0)
        return 0; /* root zones have no siblings by definition */

    int count = 0;
    for (uint32_t i = 0; i < MDN_MAX_ZONES; i++) {
        mdn_zone_t *z = ctx->zones[i];
        if (z && z->zone_id != zone_id && z->parent_id == ref->parent_id)
            count++;
    }
    return count;
}

/*
 * zone_subtree_count — count the number of zones in the subtree rooted at
 * zone_id, including zone_id itself.
 *
 * The subtree is defined as all zones reachable by following child
 * relationships downward.  This implementation does a two-pass linear scan
 * bounded at MDN_MAX_ZONES levels to avoid recursion.
 *
 * Returns the total count, which is at least 1 if zone_id is found.
 * Returns 0 if zone_id is not found.
 */
int zone_subtree_count(mdn_ctx_t *ctx, uint16_t zone_id)
{
    mdn_zone_t *root = zone_find(ctx, zone_id);
    if (!root)
        return 0;

    /* Collect all zone_ids that are descendants of zone_id using BFS. */
    uint16_t queue[MDN_MAX_ZONES];
    uint32_t head = 0, tail = 0;
    queue[tail++] = zone_id;

    while (head < tail && tail < MDN_MAX_ZONES) {
        uint16_t current = queue[head++];

        /* Find all direct children of current */
        for (uint32_t i = 0; i < MDN_MAX_ZONES; i++) {
            mdn_zone_t *z = ctx->zones[i];
            if (!z || z->zone_id == current)
                continue;
            if (z->parent_id != current)
                continue;

            /* Check not already queued */
            int already = 0;
            for (uint32_t k = 0; k < tail; k++) {
                if (queue[k] == z->zone_id) {
                    already = 1;
                    break;
                }
            }
            if (!already && tail < MDN_MAX_ZONES)
                queue[tail++] = z->zone_id;
        }
    }

    return (int)tail;
}

/*
 * zone_format_flags — write the flags field of a zone as a hex string.
 *
 * Writes "flags=0xXXXX" into out.  Returns bytes written, or -1 on error.
 */
int zone_format_flags(mdn_ctx_t *ctx, uint16_t zone_id, char *out, uint32_t cap)
{
    if (!out || cap == 0)
        return -1;

    mdn_zone_t *z = zone_find(ctx, zone_id);
    if (!z) {
        int n = snprintf(out, cap, "zone=%u not_found", (unsigned)zone_id);
        return n < 0 ? -1 : n;
    }

    int n = snprintf(out, cap, "flags=0x%04x", (unsigned)z->flags);
    return n < 0 ? -1 : n;
}

/*
 * zone_leaf_count — count zones that have no children (leaf nodes).
 *
 * A zone is a leaf if no other loaded zone has its zone_id as a parent_id.
 * Returns the number of leaf zones.
 */
int zone_leaf_count(mdn_ctx_t *ctx)
{
    int leaves = 0;

    for (uint32_t i = 0; i < MDN_MAX_ZONES; i++) {
        mdn_zone_t *z = ctx->zones[i];
        if (!z)
            continue;

        int has_child = 0;
        for (uint32_t j = 0; j < MDN_MAX_ZONES; j++) {
            mdn_zone_t *c = ctx->zones[j];
            if (c && c->zone_id != z->zone_id && c->parent_id == z->zone_id) {
                has_child = 1;
                break;
            }
        }
        if (!has_child)
            leaves++;
    }

    return leaves;
}

/*
 * zone_summary_stats — write a summary line with all key stats to out.
 *
 * Writes: total zones, root count, leaf count, max depth, max epoch.
 * Returns bytes written, or -1 on error.
 */
int zone_summary_stats(mdn_ctx_t *ctx, char *out, uint32_t cap)
{
    if (!out || cap == 0)
        return -1;

    uint32_t total = 0;
    uint32_t roots = 0;
    uint32_t max_epoch = 0;

    for (uint32_t i = 0; i < MDN_MAX_ZONES; i++) {
        mdn_zone_t *z = ctx->zones[i];
        if (!z)
            continue;
        total++;
        if (z->parent_id == 0 || z->parent_id == z->zone_id)
            roots++;
        if (z->epoch > max_epoch)
            max_epoch = z->epoch;
    }

    int leaves = zone_leaf_count(ctx);

    int n = snprintf(out, cap,
                     "total=%u roots=%u leaves=%u max_epoch=%u",
                     total, roots, (unsigned)leaves, max_epoch);
    return n < 0 ? -1 : n;
}
