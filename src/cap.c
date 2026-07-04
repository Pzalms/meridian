#include "cap.h"
#include "crc.h"
#include "util.h"
#include <string.h>

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
