#include "cap.h"
#include "crc.h"
#include "util.h"
#include <string.h>
#include <stdio.h>
#include <time.h>

static const uint8_t CAP_TOKEN[MDN_CAP_TOKEN_LEN] = {
    0x4d,0x45,0x52,0x49,0x44,0x49,0x41,0x4e,
    0x5f,0x43,0x41,0x50,0x5f,0x4b,0x45,0x59,
    0x5f,0x46,0x45,0x4e,0x52,0x49,0x52,0x5f,
    0x32,0x30,0x32,0x36,0x5f,0x4b,0x45,0x59
};
static const uint64_t CAP_NONCE = 0xA1B2C3D4E5F60718ULL;

/* Minimum wire size: token(32) + nonce(8) = 40 bytes */
#define CAP_WIRE_SIZE ((uint32_t)(MDN_CAP_TOKEN_LEN + 8u))

/* -----------------------------------------------------------------------
 * mdn_cap_load — deserialise a SECT_CAP payload into ctx.
 *
 * Reads the 32-byte token and 8-byte nonce from data[].  Sets cap_ok=1
 * only when both match the expected values exactly.
 * ----------------------------------------------------------------------- */
int mdn_cap_load(mdn_ctx_t *ctx, const uint8_t *data, uint32_t len)
{
    /* SECT_CAP payload must carry at least the token and nonce */
    if (len < CAP_WIRE_SIZE)
        return -1;
    memcpy(ctx->cap_token, data, MDN_CAP_TOKEN_LEN);
    ctx->cap_nonce = mdn_u64le(data + MDN_CAP_TOKEN_LEN);
    ctx->cap_ok = (memcmp(ctx->cap_token, CAP_TOKEN, MDN_CAP_TOKEN_LEN) == 0 &&
                   ctx->cap_nonce == CAP_NONCE) ? 1 : 0;
    return 0;
}

/* -----------------------------------------------------------------------
 * mdn_cap_check — gate check using a purpose_id tag.
 *
 * Returns ctx->cap_ok; purpose_id is accepted for future extension.
 * ----------------------------------------------------------------------- */
int mdn_cap_check(mdn_ctx_t *ctx, uint8_t purpose_id)
{
    (void)purpose_id;
    return ctx->cap_ok;
}

/* -----------------------------------------------------------------------
 * mdn_cap_verify_purpose — stricter check that validates both capability
 * state and that purpose_id falls within the well-defined range 0x01–0xFF.
 *
 * Returns 1 when the context is authorised AND purpose_id is valid.
 * Returns 0 for an out-of-range purpose_id even if cap_ok is set.
 * ----------------------------------------------------------------------- */
int mdn_cap_verify_purpose(mdn_ctx_t *ctx, uint16_t purpose_id)
{
    if (purpose_id < 0x01 || purpose_id > 0xFF)
        return 0;
    return ctx->cap_ok;
}

/* -----------------------------------------------------------------------
 * mdn_cap_reset — clear all capability state in ctx.
 *
 * Zeroes cap_token and cap_nonce, and sets cap_ok to 0.  Callers use
 * this before re-loading a SECT_CAP section to ensure no residual state
 * from a previous parse is retained.
 * ----------------------------------------------------------------------- */
void mdn_cap_reset(mdn_ctx_t *ctx)
{
    memset(ctx->cap_token, 0, MDN_CAP_TOKEN_LEN);
    ctx->cap_nonce = 0;
    ctx->cap_ok    = 0;
}

/* -----------------------------------------------------------------------
 * mdn_cap_compare — compare capability credentials across two contexts.
 *
 * Returns 1 if both contexts carry identical cap_token and cap_nonce
 * values (regardless of cap_ok).  This is used for session migration
 * checks where the same capability block is expected in two parsed views
 * of the same logical device configuration.
 * ----------------------------------------------------------------------- */
int mdn_cap_compare(const mdn_ctx_t *ctx_a, const mdn_ctx_t *ctx_b)
{
    if (memcmp(ctx_a->cap_token, ctx_b->cap_token, MDN_CAP_TOKEN_LEN) != 0)
        return 0;
    if (ctx_a->cap_nonce != ctx_b->cap_nonce)
        return 0;
    return 1;
}

/* -----------------------------------------------------------------------
 * mdn_cap_fingerprint — short checksum of the capability token.
 *
 * Returns the CRC32C of the first 16 bytes of cap_token.  This 32-bit
 * fingerprint is used in audit log entries to correlate capability blocks
 * without embedding the full 32-byte token in each record.
 * ----------------------------------------------------------------------- */
uint32_t mdn_cap_fingerprint(mdn_ctx_t *ctx)
{
    /* Only the first 16 bytes of the token contribute to the fingerprint;
     * the second half carries deployment-specific entropy and is excluded
     * to keep fingerprints stable across minor token rotations. */
    return crc32c_fast(ctx->cap_token, 16u);
}

/* -----------------------------------------------------------------------
 * mdn_cap_is_ephemeral — test the ephemeral-nonce convention.
 *
 * Returns 1 when bit 63 of cap_nonce is set.  By convention, nonces with
 * bit 63 set are issued for short-lived sessions and must not be persisted
 * across a device reload.  The caller should refuse to cache any state
 * derived from an ephemeral context.
 * ----------------------------------------------------------------------- */
int mdn_cap_is_ephemeral(mdn_ctx_t *ctx)
{
    return (ctx->cap_nonce & (UINT64_C(1) << 63)) ? 1 : 0;
}

/* -----------------------------------------------------------------------
 * cap_audit_log_init — zero-initialise an audit log.
 * ----------------------------------------------------------------------- */
void cap_audit_log_init(cap_audit_log_t *log)
{
    if (!log)
        return;
    memset(log->entries, 0, sizeof(log->entries));
    log->count = 0;
    log->cap   = CAP_AUDIT_LOG_CAP;
}

/* -----------------------------------------------------------------------
 * cap_audit_log_record — append one audit entry to the log.
 *
 * Records the current wall-clock second, purpose_id, and result code.
 * When the log is full the oldest entry is overwritten (ring behaviour).
 * Returns 0 on success, -1 when log is NULL.
 * ----------------------------------------------------------------------- */
int cap_audit_log_record(cap_audit_log_t *log, uint16_t purpose_id, int result)
{
    if (!log)
        return -1;

    uint32_t idx = log->count % CAP_AUDIT_LOG_CAP;
    log->entries[idx].timestamp  = (uint64_t)time(NULL);
    log->entries[idx].purpose_id = purpose_id;
    log->entries[idx].result     = result;
    log->count++;
    return 0;
}

/* -----------------------------------------------------------------------
 * cap_audit_log_dump — format the audit log as text into out[0..cap).
 *
 * Each entry is one line:
 *   "audit[N]: ts=T purpose=P result=R\n"
 * Returns the number of bytes written (excluding NUL).
 * ----------------------------------------------------------------------- */
int cap_audit_log_dump(const cap_audit_log_t *log, char *out, uint32_t cap)
{
    if (!log || !out || cap == 0)
        return 0;

    uint32_t entries_to_show = MDN_MIN(log->count, (uint32_t)CAP_AUDIT_LOG_CAP);
    int total = 0;

    for (uint32_t i = 0; i < entries_to_show; i++) {
        const cap_audit_entry_t *e = &log->entries[i];
        int n = snprintf(out + total, cap - (uint32_t)total,
                         "audit[%u]: ts=%llu purpose=%u result=%d\n",
                         (unsigned)i,
                         (unsigned long long)e->timestamp,
                         (unsigned)e->purpose_id,
                         e->result);
        if (n < 0 || (uint32_t)(total + n) >= cap - 1u)
            break;
        total += n;
    }
    out[MDN_MIN((uint32_t)total, cap - 1u)] = '\0';
    return total;
}

/* -----------------------------------------------------------------------
 * cap_nonce_validate — verify that a presented nonce matches the
 * context's stored nonce.
 *
 * A nonce is considered valid when it exactly matches ctx->cap_nonce and
 * ctx->cap_ok is set.  This provides a lightweight replay-prevention
 * check for single-session use.  Returns 1 when valid, 0 otherwise.
 * ----------------------------------------------------------------------- */
int cap_nonce_validate(const mdn_ctx_t *ctx, uint64_t nonce)
{
    if (!ctx)
        return 0;
    if (!ctx->cap_ok)
        return 0;
    return (ctx->cap_nonce == nonce) ? 1 : 0;
}

/* -----------------------------------------------------------------------
 * cap_context_dump — format capability context state as text.
 *
 * Writes fields cap_ok, cap_nonce, and a hex fingerprint of the first
 * 8 bytes of cap_token into out[0..cap).  Returns the number of bytes
 * written.
 * ----------------------------------------------------------------------- */
int cap_context_dump(const mdn_ctx_t *ctx, char *out, uint32_t cap)
{
    if (!ctx || !out || cap == 0)
        return 0;

    /* Format the first 8 bytes of cap_token as hex */
    char tok_hex[17];
    mdn_bytes_to_hex(ctx->cap_token, 8u, tok_hex);

    int n = snprintf(out, cap,
                     "cap_ok=%d nonce=0x%016llx token_prefix=%s\n",
                     ctx->cap_ok,
                     (unsigned long long)ctx->cap_nonce,
                     tok_hex);
    if (n < 0)
        n = 0;
    if ((uint32_t)n >= cap)
        n = (int)(cap - 1u);
    out[n] = '\0';
    return n;
}

/* -----------------------------------------------------------------------
 * cap_token_to_hex — encode the 32-byte cap token as a hex string.
 *
 * out must be at least 65 bytes (64 hex digits + NUL).
 * ----------------------------------------------------------------------- */
void cap_token_to_hex(const mdn_ctx_t *ctx, char *out)
{
    if (!ctx || !out)
        return;
    mdn_bytes_to_hex(ctx->cap_token, MDN_CAP_TOKEN_LEN, out);
}
