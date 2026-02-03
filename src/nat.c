#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "nat.h"
#include "cap.h"

/* Size of one serialised session record in a SECT_NAT payload */
#define SESSION_WIRE_SIZE   52U

int nat_bucket_load(mdn_ctx_t *ctx, const uint8_t *data, uint32_t len, uint16_t id) {
    (void)id;

    /* Require at least the 10-byte fixed header */
    if (len < 10U) return -1;

    uint16_t bucket_id, zone_id, slot_count;
    uint32_t epoch;

    memcpy(&bucket_id,  data + 0, 2);
    memcpy(&zone_id,    data + 2, 2);
    memcpy(&slot_count, data + 4, 2);
    memcpy(&epoch,      data + 6, 4);

    /* Reject payloads that are too small to hold the declared slot count.
     * This prevents integer-width issues when slot_count * SESSION_WIRE_SIZE
     * Arithmetic wraps at UINT32_MAX only when slot_count > 82M,
     * well beyond what fits in a 16-bit field (max 65535 slots). */
    if (len < 10U + (uint32_t)slot_count * SESSION_WIRE_SIZE) return -1;

    mdn_nat_bucket_t *bkt = calloc(1, sizeof(mdn_nat_bucket_t));
    if (!bkt) return -1;

    mdn_session_t *slots = NULL;
    if (slot_count > 0) {
        slots = calloc(slot_count, sizeof(mdn_session_t));
        if (!slots) { free(bkt); return -1; }
    }

    /* Parse each session record from wire format */
    const uint8_t *p = data + 10;
    for (uint16_t i = 0; i < slot_count; i++) {
        memcpy(&slots[i].sess_id,   p +  0, 4);
        memcpy(&slots[i].zone_id,   p +  4, 2);
        memcpy(&slots[i].flags,     p +  6, 2);
        memcpy(&slots[i].last_seen, p +  8, 4);
        memcpy(slots[i].tuple,      p + 12, 40);
        p += SESSION_WIRE_SIZE;
    }

    bkt->bucket_id  = bucket_id;
    bkt->zone_id    = zone_id;
    bkt->slot_count = slot_count;
    bkt->epoch      = epoch;
    bkt->slots      = slots;

    uint32_t idx = bucket_id % MDN_MAX_NAT_BUCKETS;
    if (ctx->nat_buckets[idx]) {
        free(ctx->nat_buckets[idx]->slots);
        free(ctx->nat_buckets[idx]);
    }
    ctx->nat_buckets[idx] = bkt;
    return 0;
}

int nat_rebucket_zone(mdn_ctx_t *ctx, uint16_t zone_id) {
    if (!mdn_cap_check(ctx, 0x51)) return 0;
    for (int i = 0; i < MDN_MAX_NAT_BUCKETS; i++) {
        mdn_nat_bucket_t *bkt = ctx->nat_buckets[i];
        if (!bkt || bkt->zone_id != zone_id) continue;

        uint16_t new_count = (uint16_t)(bkt->slot_count + 4);
        mdn_session_t *new_slots = calloc(new_count, sizeof(mdn_session_t));
        if (!new_slots) return -1;
        memcpy(new_slots, bkt->slots, bkt->slot_count * sizeof(mdn_session_t));

        free(bkt->slots);          /* releases storage that cursors may reference */
        bkt->slots      = new_slots;
        bkt->slot_count = new_count;
        bkt->epoch++;
        /* cursors referencing this bucket retain their slot_ptr into released storage */
    }
    return 0;
}

void nat_free_all(mdn_ctx_t *ctx) {
    for (int i = 0; i < MDN_MAX_NAT_BUCKETS; i++) {
        if (ctx->nat_buckets[i]) {
            free(ctx->nat_buckets[i]->slots);
            free(ctx->nat_buckets[i]);
            ctx->nat_buckets[i] = NULL;
        }
    }
}

/*
 * nat_find_bucket — locate a NAT bucket by bucket_id.
 *
 * Checks the expected slot first (bucket_id % MDN_MAX_NAT_BUCKETS), then
 * performs a linear scan to handle slot collisions.  Returns a pointer
 * to the bucket, or NULL if not found.
 */
mdn_nat_bucket_t *nat_find_bucket(mdn_ctx_t *ctx, uint16_t bucket_id)
{
    uint32_t slot = (uint32_t)bucket_id % MDN_MAX_NAT_BUCKETS;
    if (ctx->nat_buckets[slot] && ctx->nat_buckets[slot]->bucket_id == bucket_id)
        return ctx->nat_buckets[slot];

    /* Linear scan for collisions */
    for (int i = 0; i < MDN_MAX_NAT_BUCKETS; i++) {
        if (ctx->nat_buckets[i] && ctx->nat_buckets[i]->bucket_id == bucket_id)
            return ctx->nat_buckets[i];
    }
    return NULL;
}

/*
 * nat_bucket_count — return the number of non-NULL entries in ctx->nat_buckets[].
 */
int nat_bucket_count(mdn_ctx_t *ctx)
{
    int n = 0;
    for (int i = 0; i < MDN_MAX_NAT_BUCKETS; i++) {
        if (ctx->nat_buckets[i])
            n++;
    }
    return n;
}

/*
 * nat_zone_bucket_count — count how many NAT buckets belong to zone_id.
 *
 * Iterates all bucket slots; a bucket is counted when its zone_id field
 * matches the requested zone_id.
 */
int nat_zone_bucket_count(mdn_ctx_t *ctx, uint16_t zone_id)
{
    int n = 0;
    for (int i = 0; i < MDN_MAX_NAT_BUCKETS; i++) {
        if (ctx->nat_buckets[i] && ctx->nat_buckets[i]->zone_id == zone_id)
            n++;
    }
    return n;
}

/*
 * nat_evict_sessions — remove all sessions in a bucket whose last_seen
 * timestamp is strictly less than max_age.
 *
 * Remaining sessions are shifted down to fill gaps so that the slots
 * array stays contiguous.  The slot_count field is updated accordingly.
 * Returns the number of sessions evicted, or -1 if the bucket is not found.
 *
 * max_age is an inclusive lower bound: sessions with last_seen == max_age
 * are retained.
 */
int nat_evict_sessions(mdn_ctx_t *ctx, uint16_t bucket_id, uint32_t max_age)
{
    mdn_nat_bucket_t *bkt = nat_find_bucket(ctx, bucket_id);
    if (!bkt)
        return -1;

    uint16_t write = 0;
    int evicted = 0;

    for (uint16_t read = 0; read < bkt->slot_count; read++) {
        if (bkt->slots[read].last_seen < max_age) {
            evicted++;
        } else {
            if (write != read)
                bkt->slots[write] = bkt->slots[read];
            write++;
        }
    }

    bkt->slot_count = write;
    bkt->epoch++;
    return evicted;
}

/*
 * nat_copy_sessions — append all sessions from src into dst.
 *
 * The dst bucket's slots array is grown via realloc to accommodate the
 * additional sessions.  Sessions are appended after any existing entries
 * in dst.  Returns 0 on success, -1 on allocation failure.
 *
 * The dst bucket's epoch is incremented after a successful copy to
 * signal that its layout has changed.
 */
int nat_copy_sessions(mdn_nat_bucket_t *src, mdn_nat_bucket_t *dst)
{
    if (!src || !dst)
        return -1;
    if (src->slot_count == 0)
        return 0;

    uint32_t new_count = (uint32_t)dst->slot_count + (uint32_t)src->slot_count;
    if (new_count > 65535)
        return -1;

    mdn_session_t *grown = realloc(dst->slots, new_count * sizeof(mdn_session_t));
    if (!grown)
        return -1;

    memcpy(grown + dst->slot_count, src->slots,
           src->slot_count * sizeof(mdn_session_t));

    dst->slots      = grown;
    dst->slot_count = (uint16_t)new_count;
    dst->epoch++;
    return 0;
}

/*
 * nat_bucket_stats — aggregate slot and bucket counts across all entries.
 *
 * Writes the total number of sessions (sum of slot_count across all
 * non-NULL buckets) into *total_slots, and the number of non-NULL
 * buckets into *total_buckets.  Either pointer may be NULL.
 */
void nat_bucket_stats(mdn_ctx_t *ctx, uint32_t *total_slots, uint32_t *total_buckets)
{
    uint32_t slots   = 0;
    uint32_t buckets = 0;

    for (int i = 0; i < MDN_MAX_NAT_BUCKETS; i++) {
        mdn_nat_bucket_t *bkt = ctx->nat_buckets[i];
        if (!bkt)
            continue;
        buckets++;
        slots += bkt->slot_count;
    }

    if (total_slots)
        *total_slots = slots;
    if (total_buckets)
        *total_buckets = buckets;
}

/*
 * nat_serialize_bucket — write a NAT bucket to a caller-supplied buffer
 * in the same wire format that nat_bucket_load() expects.
 *
 * Wire layout:
 *   [0..1]   bucket_id  (u16 LE)
 *   [2..3]   zone_id    (u16 LE)
 *   [4..5]   slot_count (u16 LE)
 *   [6..9]   epoch      (u32 LE)
 *   [10..]   session records (SESSION_WIRE_SIZE bytes each)
 *
 * Returns the number of bytes written, or -1 if cap is too small.
 *
 * SESSION_WIRE_SIZE is 52: 4 (sess_id) + 2 (zone_id) + 2 (flags) +
 *                          4 (last_seen) + 40 (tuple).
 */
int nat_serialize_bucket(mdn_nat_bucket_t *bkt, uint8_t *out, uint32_t cap)
{
    if (!bkt || !out)
        return -1;

    uint32_t needed = 10U + (uint32_t)bkt->slot_count * SESSION_WIRE_SIZE;
    if (cap < needed)
        return -1;

    /* Fixed header */
    memcpy(out + 0, &bkt->bucket_id,  2);
    memcpy(out + 2, &bkt->zone_id,    2);
    memcpy(out + 4, &bkt->slot_count, 2);
    memcpy(out + 6, &bkt->epoch,      4);

    /* Session records */
    uint8_t *p = out + 10;
    for (uint16_t i = 0; i < bkt->slot_count; i++) {
        memcpy(p +  0, &bkt->slots[i].sess_id,   4);
        memcpy(p +  4, &bkt->slots[i].zone_id,   2);
        memcpy(p +  6, &bkt->slots[i].flags,     2);
        memcpy(p +  8, &bkt->slots[i].last_seen, 4);
        memcpy(p + 12,  bkt->slots[i].tuple,    40);
        p += SESSION_WIRE_SIZE;
    }

    return (int)needed;
}

/*
 * nat_bucket_age — evict sessions in a single bucket that are older than
 * cutoff_epoch.
 *
 * Sessions whose last_seen value is strictly less than cutoff_epoch are
 * removed.  Remaining sessions are compacted in place.  Returns the number
 * of sessions evicted, or -1 if the bucket is not found.
 */
int nat_bucket_age(mdn_ctx_t *ctx, uint16_t bucket_id, uint32_t cutoff_epoch)
{
    mdn_nat_bucket_t *bkt = nat_find_bucket(ctx, bucket_id);
    if (!bkt)
        return -1;

    uint16_t write = 0;
    int evicted = 0;

    for (uint16_t r = 0; r < bkt->slot_count; r++) {
        if (bkt->slots[r].last_seen < cutoff_epoch) {
            evicted++;
        } else {
            if (write != r)
                bkt->slots[write] = bkt->slots[r];
            write++;
        }
    }

    if (evicted > 0) {
        bkt->slot_count = write;
        bkt->epoch++;
    }
    return evicted;
}

/*
 * nat_bucket_hits_misses — collect per-bucket hit and miss counters.
 *
 * Scans all sessions in the bucket identified by bucket_id and tallies
 * sessions whose flags have bit 0x0001 set (hit) versus clear (miss).
 * Writes results into *hits_out and *misses_out.  Either pointer may be
 * NULL.  Returns 0 on success, -1 if the bucket is not found.
 */
int nat_bucket_hits_misses(mdn_ctx_t *ctx, uint16_t bucket_id,
                           uint32_t *hits_out, uint32_t *misses_out)
{
    mdn_nat_bucket_t *bkt = nat_find_bucket(ctx, bucket_id);
    if (!bkt)
        return -1;

    uint32_t hits   = 0;
    uint32_t misses = 0;

    for (uint16_t i = 0; i < bkt->slot_count; i++) {
        if (bkt->slots[i].flags & 0x0001)
            hits++;
        else
            misses++;
    }

    if (hits_out)
        *hits_out = hits;
    if (misses_out)
        *misses_out = misses;
    return 0;
}

/*
 * nat_zone_summary — format a text summary of NAT state for zone_id.
 *
 * Writes a null-terminated string into out_buf describing the number of
 * buckets and total sessions belonging to zone_id.  Returns the number of
 * bytes written (excluding the null terminator), or -1 if out_buf is NULL
 * or cap is 0.
 */
int nat_zone_summary(mdn_ctx_t *ctx, uint16_t zone_id,
                     char *out_buf, uint32_t cap)
{
    if (!out_buf || cap == 0)
        return -1;

    uint32_t bucket_n  = 0;
    uint32_t session_n = 0;

    for (int i = 0; i < MDN_MAX_NAT_BUCKETS; i++) {
        mdn_nat_bucket_t *bkt = ctx->nat_buckets[i];
        if (!bkt || bkt->zone_id != zone_id)
            continue;
        bucket_n++;
        session_n += bkt->slot_count;
    }

    int written = snprintf(out_buf, cap,
                           "zone=%u buckets=%u sessions=%u",
                           (unsigned)zone_id,
                           (unsigned)bucket_n,
                           (unsigned)session_n);
    if (written < 0)
        return -1;
    return written;
}

/*
 * nat_session_count — return the total number of sessions across all buckets.
 */
uint32_t nat_session_count(mdn_ctx_t *ctx)
{
    uint32_t total = 0;
    for (int i = 0; i < MDN_MAX_NAT_BUCKETS; i++) {
        if (ctx->nat_buckets[i])
            total += ctx->nat_buckets[i]->slot_count;
    }
    return total;
}

/*
 * nat_evict_oldest — LRU eviction pass for a zone.
 *
 * Collects up to max_evict sessions with the smallest last_seen values
 * across all buckets belonging to zone_id and removes them.  Buckets are
 * compacted after removal.  Returns the number of sessions evicted.
 */
int nat_evict_oldest(mdn_ctx_t *ctx, uint16_t zone_id, uint32_t max_evict)
{
    if (max_evict == 0)
        return 0;

    /* Find the smallest last_seen threshold that covers max_evict sessions. */
    uint32_t min_seen = UINT32_MAX;
    uint32_t total    = 0;

    /* Collect min last_seen across buckets for this zone */
    for (int i = 0; i < MDN_MAX_NAT_BUCKETS; i++) {
        mdn_nat_bucket_t *bkt = ctx->nat_buckets[i];
        if (!bkt || bkt->zone_id != zone_id)
            continue;
        for (uint16_t k = 0; k < bkt->slot_count; k++) {
            if (bkt->slots[k].last_seen < min_seen)
                min_seen = bkt->slots[k].last_seen;
            total++;
        }
    }

    if (total == 0)
        return 0;

    /* Evict sessions at or equal to the minimum timestamp up to max_evict. */
    int evicted = 0;

    for (int i = 0; i < MDN_MAX_NAT_BUCKETS && (uint32_t)evicted < max_evict; i++) {
        mdn_nat_bucket_t *bkt = ctx->nat_buckets[i];
        if (!bkt || bkt->zone_id != zone_id)
            continue;

        uint16_t write = 0;
        int removed = 0;

        for (uint16_t r = 0; r < bkt->slot_count; r++) {
            if ((uint32_t)evicted < max_evict &&
                bkt->slots[r].last_seen == min_seen) {
                evicted++;
                removed++;
            } else {
                if (write != r)
                    bkt->slots[write] = bkt->slots[r];
                write++;
            }
        }

        if (removed > 0) {
            bkt->slot_count = write;
            bkt->epoch++;
        }
    }

    return evicted;
}

/*
 * nat_tuple_hash — compute a fast hash of a session tuple.
 *
 * Uses a FNV-1a variant over the bytes of the tuple.  Returns a 32-bit
 * hash value.  tuple may be NULL only if len is 0.
 */
uint32_t nat_tuple_hash(const uint8_t *tuple, uint32_t len)
{
    uint32_t h = 2166136261U;
    for (uint32_t i = 0; i < len; i++) {
        h ^= (uint32_t)tuple[i];
        h *= 16777619U;
    }
    return h;
}

/*
 * nat_bucket_fill_ratio — return the fill ratio of a bucket as a
 * fixed-point value in units of 1/1000 (i.e. 1000 == 100%).
 *
 * The capacity is defined as the next power-of-two above slot_count, with
 * a minimum of 8.  Returns -1 if the bucket is not found.
 */
int nat_bucket_fill_ratio(mdn_ctx_t *ctx, uint16_t bucket_id)
{
    mdn_nat_bucket_t *bkt = nat_find_bucket(ctx, bucket_id);
    if (!bkt)
        return -1;

    /* Compute capacity: smallest power-of-two >= slot_count, min 8 */
    uint32_t cap = 8;
    while (cap < (uint32_t)bkt->slot_count)
        cap <<= 1;

    /* ratio in 1/1000 units */
    return (int)(((uint32_t)bkt->slot_count * 1000U) / cap);
}

/*
 * nat_bucket_epoch_advance — increment the epoch of a specific bucket.
 *
 * Returns the new epoch on success, or -1 if the bucket is not found.
 * Advancing the epoch signals to any open cursors that the bucket layout
 * may have changed.
 */
int nat_bucket_epoch_advance(mdn_ctx_t *ctx, uint16_t bucket_id)
{
    mdn_nat_bucket_t *bkt = nat_find_bucket(ctx, bucket_id);
    if (!bkt)
        return -1;
    bkt->epoch++;
    return (int)bkt->epoch;
}

/*
 * nat_zone_max_epoch — return the highest epoch across all buckets
 * belonging to zone_id.
 *
 * Returns 0 if zone_id has no buckets.
 */
uint32_t nat_zone_max_epoch(mdn_ctx_t *ctx, uint16_t zone_id)
{
    uint32_t max_ep = 0;

    for (int i = 0; i < MDN_MAX_NAT_BUCKETS; i++) {
        mdn_nat_bucket_t *bkt = ctx->nat_buckets[i];
        if (bkt && bkt->zone_id == zone_id && bkt->epoch > max_ep)
            max_ep = bkt->epoch;
    }

    return max_ep;
}

/*
 * nat_session_flags_or — bitwise OR the flags of all sessions in zone_id.
 *
 * Returns the combined flags word.  Returns 0 if no sessions exist.
 */
uint16_t nat_session_flags_or(mdn_ctx_t *ctx, uint16_t zone_id)
{
    uint16_t combined = 0;

    for (int i = 0; i < MDN_MAX_NAT_BUCKETS; i++) {
        mdn_nat_bucket_t *bkt = ctx->nat_buckets[i];
        if (!bkt || bkt->zone_id != zone_id)
            continue;
        for (uint16_t k = 0; k < bkt->slot_count; k++)
            combined |= bkt->slots[k].flags;
    }

    return combined;
}

/*
 * nat_compact_buckets — remove NULL bucket slots by shifting non-NULL
 * entries toward index 0.
 *
 * After compaction, all non-NULL entries occupy the lowest indices of
 * ctx->nat_buckets[].  Trailing slots are set to NULL.  Returns the
 * number of non-NULL buckets present after compaction.
 *
 * Note: after calling this function bucket_id-based fast lookup via
 * (bucket_id % MDN_MAX_NAT_BUCKETS) is no longer valid; use the linear
 * scan in nat_find_bucket instead.
 */
int nat_compact_buckets(mdn_ctx_t *ctx)
{
    int write = 0;

    for (int read = 0; read < MDN_MAX_NAT_BUCKETS; read++) {
        if (ctx->nat_buckets[read]) {
            if (write != read) {
                ctx->nat_buckets[write] = ctx->nat_buckets[read];
                ctx->nat_buckets[read]  = NULL;
            }
            write++;
        }
    }

    return write;
}

/*
 * nat_bucket_zone_remap — update the zone_id of a single bucket.
 *
 * Returns 0 on success, -1 if the bucket is not found.
 */
int nat_bucket_zone_remap(mdn_ctx_t *ctx, uint16_t bucket_id, uint16_t new_zone_id)
{
    mdn_nat_bucket_t *bkt = nat_find_bucket(ctx, bucket_id);
    if (!bkt)
        return -1;
    bkt->zone_id = new_zone_id;
    return 0;
}

/*
 * nat_session_max_last_seen — return the highest last_seen value across
 * all sessions in zone_id.
 *
 * Returns 0 if no sessions exist for the zone.
 */
uint32_t nat_session_max_last_seen(mdn_ctx_t *ctx, uint16_t zone_id)
{
    uint32_t max_ts = 0;

    for (int i = 0; i < MDN_MAX_NAT_BUCKETS; i++) {
        mdn_nat_bucket_t *bkt = ctx->nat_buckets[i];
        if (!bkt || bkt->zone_id != zone_id)
            continue;
        for (uint16_t k = 0; k < bkt->slot_count; k++) {
            if (bkt->slots[k].last_seen > max_ts)
                max_ts = bkt->slots[k].last_seen;
        }
    }

    return max_ts;
}
