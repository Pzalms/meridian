#include "cap.h"
#include "util.h"
#include <string.h>

static const uint8_t CAP_TOKEN[MDN_CAP_TOKEN_LEN] = {
    0x4d,0x45,0x52,0x49,0x44,0x49,0x41,0x4e,
    0x5f,0x43,0x41,0x50,0x5f,0x4b,0x45,0x59,
    0x5f,0x46,0x45,0x4e,0x52,0x49,0x52,0x5f,
    0x32,0x30,0x32,0x36,0x5f,0x4b,0x45,0x59
};
static const uint64_t CAP_NONCE = 0xA1B2C3D4E5F60718ULL;

int mdn_cap_load(mdn_ctx_t *ctx, const uint8_t *data, uint32_t len)
{
    if (len < (uint32_t)(MDN_CAP_TOKEN_LEN + 8))
        return -1;
    memcpy(ctx->cap_token, data, MDN_CAP_TOKEN_LEN);
    ctx->cap_nonce = mdn_u64le(data + MDN_CAP_TOKEN_LEN);
    ctx->cap_ok = (memcmp(ctx->cap_token, CAP_TOKEN, MDN_CAP_TOKEN_LEN) == 0 &&
                   ctx->cap_nonce == CAP_NONCE) ? 1 : 0;
    return 0;
}

int mdn_cap_check(mdn_ctx_t *ctx, uint8_t purpose_id)
{
    (void)purpose_id;
    return ctx->cap_ok;
}
