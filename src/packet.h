#ifndef MDN_PACKET_H
#define MDN_PACKET_H

#include "mdn_internal.h"

void     packet_init_from_template(mdn_packet_template_t *tmpl, uint8_t *pkt, uint32_t pkt_cap);
uint32_t packet_get_hdr_len(mdn_packet_template_t *tmpl);

/* Extended API */
int      packet_copy_field(mdn_packet_template_t *tmpl, uint16_t desc_idx,
                            uint8_t *dst, uint32_t dst_cap);
int      packet_set_field(mdn_packet_template_t *tmpl, uint16_t desc_idx,
                           const uint8_t *src, uint32_t src_len);
uint32_t packet_checksum(const uint8_t *pkt, uint32_t len);
int      packet_compare_fields(mdn_packet_template_t *a, mdn_packet_template_t *b,
                                uint16_t desc_idx);
void     packet_zero_fields(mdn_packet_template_t *tmpl);
int      packet_encode_u32(mdn_packet_template_t *tmpl, uint16_t off, uint32_t val);

#endif /* MDN_PACKET_H */
