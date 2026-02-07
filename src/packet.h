#ifndef MDN_PACKET_H
#define MDN_PACKET_H

#include "mdn_internal.h"

void     packet_init_from_template(mdn_packet_template_t *tmpl, uint8_t *pkt, uint32_t pkt_cap);
uint32_t packet_get_hdr_len(mdn_packet_template_t *tmpl);

#endif /* MDN_PACKET_H */
