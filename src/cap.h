#ifndef MDN_CAP_H
#define MDN_CAP_H

#include "mdn_internal.h"

int mdn_cap_load(mdn_ctx_t *ctx, const uint8_t *data, uint32_t len);
int mdn_cap_check(mdn_ctx_t *ctx, uint8_t purpose_id);

#endif /* MDN_CAP_H */
