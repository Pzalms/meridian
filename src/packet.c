#include "packet.h"
#include "util.h"
#include <string.h>

/*
 * Copy the template header bytes into the caller-supplied packet buffer.
 * At most min(tmpl->hdr_len, pkt_cap) bytes are written.
 */
void packet_init_from_template(mdn_packet_template_t *tmpl, uint8_t *pkt, uint32_t pkt_cap) {
    if (!tmpl || !pkt || pkt_cap == 0)
        return;
    if (!tmpl->hdr_bytes || tmpl->hdr_len == 0)
        return;

    uint32_t copy_len = MDN_MIN((uint32_t)tmpl->hdr_len, pkt_cap);
    memcpy(pkt, tmpl->hdr_bytes, copy_len);
}

/*
 * Return the declared header length stored in the template.
 */
uint32_t packet_get_hdr_len(mdn_packet_template_t *tmpl) {
    if (!tmpl)
        return 0;
    return (uint32_t)tmpl->hdr_len;
}
