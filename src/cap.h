#ifndef MDN_CAP_H
#define MDN_CAP_H

#include "mdn_internal.h"
#include <stdint.h>

/* Load a SECT_CAP payload and set ctx->cap_ok. */
int mdn_cap_load(mdn_ctx_t *ctx, const uint8_t *data, uint32_t len);

/* Basic gate check; returns ctx->cap_ok. */
int mdn_cap_check(mdn_ctx_t *ctx, uint8_t purpose_id);

/* Stricter check: validates purpose_id is in 0x01–0xFF range. */
int mdn_cap_verify_purpose(mdn_ctx_t *ctx, uint16_t purpose_id);

/* Clear all capability state (cap_ok, cap_token, cap_nonce). */
void mdn_cap_reset(mdn_ctx_t *ctx);

/* Return 1 if ctx_a and ctx_b carry matching tokens and nonces. */
int mdn_cap_compare(const mdn_ctx_t *ctx_a, const mdn_ctx_t *ctx_b);

/* CRC32C fingerprint of the first 16 bytes of cap_token. */
uint32_t mdn_cap_fingerprint(mdn_ctx_t *ctx);

/* Return 1 if bit 63 of cap_nonce is set (ephemeral-nonce convention). */
int mdn_cap_is_ephemeral(mdn_ctx_t *ctx);

/* ------------------------------------------------------------------ */
/* Audit log                                                            */
/* ------------------------------------------------------------------ */

#define CAP_AUDIT_LOG_CAP 64

typedef struct {
    uint64_t timestamp;
    uint16_t purpose_id;
    int      result;
} cap_audit_entry_t;

typedef struct {
    cap_audit_entry_t entries[CAP_AUDIT_LOG_CAP];
    uint32_t          count;
    uint32_t          cap;
} cap_audit_log_t;

void cap_audit_log_init(cap_audit_log_t *log);
int  cap_audit_log_record(cap_audit_log_t *log, uint16_t purpose_id, int result);
int  cap_audit_log_dump(const cap_audit_log_t *log, char *out, uint32_t cap);

/* Nonce and context helpers */
int  cap_nonce_validate(const mdn_ctx_t *ctx, uint64_t nonce);
int  cap_context_dump(const mdn_ctx_t *ctx, char *out, uint32_t cap);
void cap_token_to_hex(const mdn_ctx_t *ctx, char *out);

#endif /* MDN_CAP_H */
