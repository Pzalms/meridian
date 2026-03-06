#ifndef MDN_TEMPLATE_H
#define MDN_TEMPLATE_H

#include "mdn_internal.h"

int  template_load(mdn_ctx_t *ctx, const uint8_t *data, uint32_t len, uint16_t id);
int  template_prepare_frame(mdn_packet_template_t *tmpl);
void template_swap_profile(mdn_ctx_t *ctx, uint16_t tmpl_id,
                            mdn_tmpl_desc_t *new_descs, uint16_t new_desc_count);
void template_free_all(mdn_ctx_t *ctx);

/* Extended API */
mdn_packet_template_t *template_find(mdn_ctx_t *ctx, uint16_t tmpl_id);
int  template_clone(mdn_ctx_t *ctx, uint16_t src_id, uint16_t dst_id);
int  template_set_header_byte(mdn_packet_template_t *tmpl, uint16_t off, uint8_t val);
int  template_get_header_byte(mdn_packet_template_t *tmpl, uint16_t off, uint8_t *val_out);
int  template_fill_descriptor(mdn_packet_template_t *tmpl, uint16_t desc_idx, uint8_t val);
int  template_validate(mdn_packet_template_t *tmpl);
void template_stats(mdn_ctx_t *ctx, uint32_t *total_out, uint32_t *total_desc_out);
int  template_serialize(mdn_packet_template_t *tmpl, uint8_t *out, uint32_t cap);

#endif /* MDN_TEMPLATE_H */
