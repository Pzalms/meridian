#ifndef MDN_PARSE_H
#define MDN_PARSE_H

#include "mdn_internal.h"
#include <stddef.h>

int mdn_parse(mdn_ctx_t *ctx, const uint8_t *buf, size_t len);

/* Section loader interfaces — implemented in their respective modules */
int zone_load(mdn_ctx_t *ctx, const uint8_t *data, uint32_t len, uint16_t id);
int prefix_page_load(mdn_ctx_t *ctx, const uint8_t *data, uint32_t len, uint16_t id);
int rule_load(mdn_ctx_t *ctx, const uint8_t *data, uint32_t len);
int nat_bucket_load(mdn_ctx_t *ctx, const uint8_t *data, uint32_t len, uint16_t id);
int template_load(mdn_ctx_t *ctx, const uint8_t *data, uint32_t len, uint16_t id);
int audit_window_load(mdn_ctx_t *ctx, const uint8_t *data, uint32_t len, uint16_t id);
int export_profile_load(mdn_ctx_t *ctx, const uint8_t *data, uint32_t len, uint16_t id);
int query_load(mdn_ctx_t *ctx, const uint8_t *data, uint32_t len);
int policy_patch_apply(mdn_ctx_t *ctx, const uint8_t *data, uint32_t len);

#endif /* MDN_PARSE_H */
