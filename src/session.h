#ifndef MDN_SESSION_H
#define MDN_SESSION_H
#include "mdn_internal.h"
int            session_cursor_open(mdn_ctx_t *ctx, uint16_t bucket_id, uint16_t cursor_id);
mdn_session_t *session_cursor_next(mdn_ctx_t *ctx, mdn_session_cursor_t *cur);
void           session_cursors_free(mdn_ctx_t *ctx);
#endif
