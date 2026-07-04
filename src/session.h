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

#endif
