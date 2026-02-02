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
