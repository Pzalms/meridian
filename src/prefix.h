#ifndef MDN_PREFIX_H
#define MDN_PREFIX_H
#include "mdn_internal.h"
int prefix_page_load(mdn_ctx_t *ctx, const uint8_t *data, uint32_t len, uint16_t id);
void prefix_normalize_pages(mdn_ctx_t *ctx);   /* called from POLICY_PATCH handler */
void prefix_page_free(mdn_prefix_page_t *pg);
#endif
