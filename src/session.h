#ifndef MDN_SESSION_H
#define MDN_SESSION_H
#include "mdn_internal.h"
int            session_cursor_open(mdn_ctx_t *ctx, uint16_t bucket_id, uint16_t cursor_id);
mdn_session_t *session_cursor_next(mdn_ctx_t *ctx, mdn_session_cursor_t *cur);
void           session_cursors_free(mdn_ctx_t *ctx);

/* Extended session management */
mdn_session_t *session_find(mdn_ctx_t *ctx, uint32_t sess_id);
int            session_update_last_seen(mdn_ctx_t *ctx, uint32_t sess_id, uint32_t timestamp);
int            session_count_in_bucket(mdn_ctx_t *ctx, uint16_t bucket_id);
int            session_export_bucket(mdn_ctx_t *ctx, uint16_t bucket_id,
                                     mdn_session_t *out, uint32_t cap);
void           session_cursor_reset(mdn_session_cursor_t *cur);
int            session_cursor_valid(mdn_ctx_t *ctx, mdn_session_cursor_t *cur);
int            session_age_out(mdn_ctx_t *ctx, uint32_t cutoff);

/* Additional session operations */
int            session_age_out_zone(mdn_ctx_t *ctx, uint16_t zone_id,
                                    uint32_t cutoff_last_seen);
mdn_session_t *session_find_by_tuple(mdn_ctx_t *ctx,
                                     const uint8_t *tuple, uint32_t len);
uint32_t       session_count_by_zone(mdn_ctx_t *ctx, uint16_t zone_id);
int            session_dump_cursor(const mdn_session_cursor_t *cur,
                                   char *out, uint32_t cap);
int            session_cursor_rewind(mdn_ctx_t *ctx, mdn_session_cursor_t *cur);
int            session_tuple_compare(const mdn_session_t *a,
                                     const mdn_session_t *b);
int            session_clone(const mdn_session_t *src, mdn_session_t *dst);
uint32_t       session_total_count(mdn_ctx_t *ctx);
mdn_session_t *session_oldest_in_zone(mdn_ctx_t *ctx, uint16_t zone_id);
uint32_t       session_bucket_epoch(mdn_ctx_t *ctx, uint16_t bucket_id);
int            session_flag_set(mdn_ctx_t *ctx, uint32_t sess_id, uint16_t mask);
int            session_flag_clear(mdn_ctx_t *ctx, uint32_t sess_id, uint16_t mask);
uint32_t       session_scan_flags(mdn_ctx_t *ctx, uint16_t zone_id, uint16_t mask);

#endif
