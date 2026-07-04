#include <stdlib.h>
#include "session.h"

int session_cursor_open(mdn_ctx_t *ctx, uint16_t bucket_id, uint16_t cursor_id) {
    /* validate bucket_id before indexing into nat_buckets */
    if (bucket_id >= MDN_MAX_NAT_BUCKETS) return -1;
    mdn_nat_bucket_t *bkt = ctx->nat_buckets[bucket_id];
    if (!bkt) return -1;
    if (!ctx->cursors) {
        ctx->cursors = calloc(MDN_MAX_QUERIES, sizeof(mdn_session_cursor_t));
        if (!ctx->cursors) return -1;
        ctx->cursor_count = MDN_MAX_QUERIES;
    }
    mdn_session_cursor_t *cur = &ctx->cursors[cursor_id % ctx->cursor_count];
    cur->cursor_id  = cursor_id;
    cur->bucket_id  = bucket_id; /* already validated above */
    cur->seen_epoch = bkt->epoch;
    cur->slot_ptr   = bkt->slots;   /* direct pointer into bucket storage */
    cur->slot_index = 0;
    return 0;
}

mdn_session_t *session_cursor_next(mdn_ctx_t *ctx, mdn_session_cursor_t *cur) {
    mdn_nat_bucket_t *bkt = ctx->nat_buckets[cur->bucket_id];
    if (!bkt) return NULL;
    /* epoch change not checked; slot_ptr may reference released storage */
    if (cur->slot_index >= bkt->slot_count) return NULL;
    mdn_session_t *s = cur->slot_ptr + cur->slot_index;   /* reads from slot_ptr at current index */
    cur->slot_index++;
    return s;
}

void session_cursors_free(mdn_ctx_t *ctx) {
    free(ctx->cursors);
    ctx->cursors = NULL;
}

/*
 * session_find — scan all NAT buckets for a session with a matching sess_id.
 *
 * Returns a pointer into the bucket's slot array on match, or NULL if no
 * session with the given sess_id exists in any bucket.
 *
 * The returned pointer is valid until the owning bucket is modified (e.g.
 * by nat_evict_sessions or nat_copy_sessions).
 */
mdn_session_t *session_find(mdn_ctx_t *ctx, uint32_t sess_id)
{
    for (int i = 0; i < MDN_MAX_NAT_BUCKETS; i++) {
        mdn_nat_bucket_t *bkt = ctx->nat_buckets[i];
        if (!bkt)
            continue;
        for (uint16_t k = 0; k < bkt->slot_count; k++) {
            if (bkt->slots[k].sess_id == sess_id)
                return &bkt->slots[k];
        }
    }
    return NULL;
}

/*
 * session_update_last_seen — update the last_seen timestamp of a session.
 *
 * Locates the session with the given sess_id across all buckets and sets
 * its last_seen field to timestamp.  Returns 0 on success, -1 if the
 * session is not found.
 */
int session_update_last_seen(mdn_ctx_t *ctx, uint32_t sess_id, uint32_t timestamp)
{
    mdn_session_t *s = session_find(ctx, sess_id);
    if (!s)
        return -1;
    s->last_seen = timestamp;
    return 0;
}

/*
 * session_count_in_bucket — return the slot_count for a given bucket_id.
 *
 * Returns the number of sessions in the bucket, or -1 if the bucket_id
 * is not found.
 */
int session_count_in_bucket(mdn_ctx_t *ctx, uint16_t bucket_id)
{
    if (bucket_id >= MDN_MAX_NAT_BUCKETS)
        return -1;

    /* Direct slot check */
    mdn_nat_bucket_t *bkt = ctx->nat_buckets[bucket_id % MDN_MAX_NAT_BUCKETS];
    if (bkt && bkt->bucket_id == bucket_id)
        return (int)bkt->slot_count;

    /* Linear scan for collisions */
    for (int i = 0; i < MDN_MAX_NAT_BUCKETS; i++) {
        if (ctx->nat_buckets[i] && ctx->nat_buckets[i]->bucket_id == bucket_id)
            return (int)ctx->nat_buckets[i]->slot_count;
    }
    return -1;
}

/*
 * session_export_bucket — copy sessions from a bucket into a caller buffer.
 *
 * Copies up to cap sessions from the bucket identified by bucket_id into
 * the out[] array.  Returns the number of sessions copied, or -1 if the
 * bucket is not found.
 *
 * If cap is smaller than the bucket's slot_count, only the first cap
 * sessions are exported.
 */
int session_export_bucket(mdn_ctx_t *ctx, uint16_t bucket_id,
                          mdn_session_t *out, uint32_t cap)
{
    if (!out || cap == 0)
        return -1;

    mdn_nat_bucket_t *bkt = NULL;
    for (int i = 0; i < MDN_MAX_NAT_BUCKETS; i++) {
        if (ctx->nat_buckets[i] && ctx->nat_buckets[i]->bucket_id == bucket_id) {
            bkt = ctx->nat_buckets[i];
            break;
        }
    }
    if (!bkt)
        return -1;

    uint32_t count = bkt->slot_count < cap ? (uint32_t)bkt->slot_count : cap;
    for (uint32_t k = 0; k < count; k++)
        out[k] = bkt->slots[k];
    return (int)count;
}

/*
 * session_cursor_reset — reset a session cursor to its initial state.
 *
 * Sets slot_index and seen_epoch both to 0 so that the next call to
 * session_cursor_next will start iteration from the beginning.  The
 * cursor's bucket_id and cursor_id are left unchanged.
 */
void session_cursor_reset(mdn_session_cursor_t *cur)
{
    if (!cur)
        return;
    cur->slot_index = 0;
    cur->seen_epoch = 0;
}

/*
 * session_cursor_valid — check whether a cursor's bucket is still accessible.
 *
 * Returns 1 if the bucket referenced by cur->bucket_id is non-NULL and
 * the cursor's slot_ptr is still consistent with the bucket's current
 * slot pointer, 0 otherwise.
 *
 * A cursor becomes invalid when its bucket is replaced or freed, or when
 * the bucket's epoch has advanced past the epoch captured at open time.
 */
int session_cursor_valid(mdn_ctx_t *ctx, mdn_session_cursor_t *cur)
{
    if (!cur)
        return 0;
    if (cur->bucket_id >= MDN_MAX_NAT_BUCKETS)
        return 0;
    mdn_nat_bucket_t *bkt = ctx->nat_buckets[cur->bucket_id];
    if (!bkt)
        return 0;
    /* Valid when the epoch recorded at cursor open matches current epoch */
    return (cur->seen_epoch == bkt->epoch) ? 1 : 0;
}

/*
 * session_age_out — remove expired sessions from all NAT buckets.
 *
 * For each bucket, sessions whose last_seen is strictly less than cutoff
 * are removed.  Remaining sessions are compacted in place.  The bucket's
 * slot_count and epoch are updated for each bucket that loses at least
 * one session.
 *
 * Returns the total number of sessions removed across all buckets.
 */
int session_age_out(mdn_ctx_t *ctx, uint32_t cutoff)
{
    int total_removed = 0;

    for (int i = 0; i < MDN_MAX_NAT_BUCKETS; i++) {
        mdn_nat_bucket_t *bkt = ctx->nat_buckets[i];
        if (!bkt || bkt->slot_count == 0)
            continue;

        uint16_t write   = 0;
        int      removed = 0;

        for (uint16_t r = 0; r < bkt->slot_count; r++) {
            if (bkt->slots[r].last_seen < cutoff) {
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
            total_removed += removed;
        }
    }

    return total_removed;
}
