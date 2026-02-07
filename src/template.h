#ifndef MDN_TEMPLATE_H
#define MDN_TEMPLATE_H

#include "mdn_internal.h"

int  template_load(mdn_ctx_t *ctx, const uint8_t *data, uint32_t len, uint16_t id);
int  template_prepare_frame(mdn_packet_template_t *tmpl);
void template_swap_profile(mdn_ctx_t *ctx, uint16_t tmpl_id,
                            mdn_tmpl_desc_t *new_descs, uint16_t new_desc_count);
void template_free_all(mdn_ctx_t *ctx);

#endif /* MDN_TEMPLATE_H */
