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

/* Network checksum and header helpers */
uint16_t packet_ipv4_checksum(const uint8_t *hdr, uint32_t len);
int      packet_ipv6_pseudo_header(const uint8_t *src, const uint8_t *dst,
                                    uint8_t next_hdr, uint32_t payload_len,
                                    uint8_t *out);
uint16_t packet_udp_checksum(const uint8_t *src, const uint8_t *dst,
                              const uint8_t *data, uint32_t len);
int      packet_encode_vlan_tag(uint16_t vid, uint8_t pcp, uint8_t *out);
int      packet_decode_vlan_tag(const uint8_t *data, uint16_t *vid_out,
                                 uint8_t *pcp_out);
int      packet_is_ipv4(const uint8_t *buf, uint32_t len);
int      packet_is_ipv6(const uint8_t *buf, uint32_t len);
int      packet_field_get(const uint8_t *buf, uint32_t len,
                           uint32_t field_off, uint32_t field_len,
                           uint8_t *out);
int      packet_field_set(uint8_t *buf, uint32_t len,
                           uint32_t field_off, uint32_t field_len,
                           const uint8_t *val);
int      packet_dump(const uint8_t *buf, uint32_t len, char *out, uint32_t cap);

#endif /* MDN_PACKET_H */
