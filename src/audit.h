#ifndef MDN_AUDIT_H
#define MDN_AUDIT_H

#include "mdn_internal.h"

int  audit_window_load(mdn_ctx_t *ctx, const uint8_t *data, uint32_t len, uint16_t id);
void audit_compact_window(mdn_audit_window_t *win);        /* called from POLICY_PATCH */
int  audit_expand_record(mdn_audit_window_t *win, uint32_t idx, uint8_t *out, uint32_t out_cap);
void audit_free_all(mdn_ctx_t *ctx);

/* Extended API */
int  audit_record_count(mdn_audit_window_t *win);
int  audit_find_record(mdn_audit_window_t *win, uint16_t kind);
int  audit_append_record(mdn_audit_window_t *win, const uint8_t *data,
                          uint16_t len, uint16_t kind);
int  audit_remove_record(mdn_audit_window_t *win, uint32_t idx);
int  audit_window_serialize(mdn_audit_window_t *win, uint8_t *out, uint32_t cap);
void audit_stats(mdn_ctx_t *ctx, uint32_t *total_windows, uint32_t *total_records);
int  audit_merge_windows(mdn_audit_window_t *dst, mdn_audit_window_t *src);
int  audit_filter_by_kind(mdn_audit_window_t *win, uint16_t kind,
                           uint8_t *out, uint32_t cap);

#endif /* MDN_AUDIT_H */
