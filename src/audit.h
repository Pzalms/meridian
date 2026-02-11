#ifndef MDN_AUDIT_H
#define MDN_AUDIT_H

#include "mdn_internal.h"

int  audit_window_load(mdn_ctx_t *ctx, const uint8_t *data, uint32_t len, uint16_t id);
void audit_compact_window(mdn_audit_window_t *win);        /* called from POLICY_PATCH */
int  audit_expand_record(mdn_audit_window_t *win, uint32_t idx, uint8_t *out, uint32_t out_cap);
void audit_free_all(mdn_ctx_t *ctx);

#endif /* MDN_AUDIT_H */
