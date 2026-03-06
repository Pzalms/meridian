#ifndef MDN_FRAGMENT_H
#define MDN_FRAGMENT_H

#include "mdn_internal.h"

int fragment_emit_headers(mdn_ctx_t *ctx, mdn_packet_template_t *tmpl);

/* Extended API */
int  fragment_count_headers(mdn_packet_template_t *tmpl);
int  fragment_validate_layout(mdn_packet_template_t *tmpl);
int  fragment_copy_region(mdn_packet_template_t *src, mdn_packet_template_t *dst,
                           uint16_t src_off, uint16_t dst_off, uint16_t len);
int  fragment_append_descriptor(mdn_packet_template_t *tmpl, mdn_tmpl_desc_t desc);
int  fragment_remove_descriptor(mdn_packet_template_t *tmpl, uint16_t idx);
void fragment_stats(mdn_ctx_t *ctx, uint32_t *total_templates, uint32_t *total_frags);

#endif /* MDN_FRAGMENT_H */
