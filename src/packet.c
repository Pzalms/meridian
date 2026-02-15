#include "packet.h"
#include "util.h"
#include <string.h>
#include <stdio.h>

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

/* ------------------------------------------------------------------ */
/* packet_copy_field                                                     */
/* ------------------------------------------------------------------ */

/*
 * Copy the bytes described by descs[desc_idx] out of tmpl->hdr_bytes
 * into the caller-supplied dst buffer.  At most dst_cap bytes are
 * written.  Returns the number of bytes actually copied, or -1 when
 * the descriptor index is invalid or the source region is out of range.
 */
int packet_copy_field(mdn_packet_template_t *tmpl, uint16_t desc_idx,
                      uint8_t *dst, uint32_t dst_cap)
{
    if (!tmpl || !tmpl->hdr_bytes || !tmpl->descs || !dst)
        return -1;
    if (desc_idx >= tmpl->desc_count)
        return -1;

    mdn_tmpl_desc_t *d = &tmpl->descs[desc_idx];
    uint32_t end = (uint32_t)d->field_off + (uint32_t)d->field_len;
    if (end > tmpl->hdr_cap)
        return -1;

    uint32_t copy_len = MDN_MIN((uint32_t)d->field_len, dst_cap);
    memcpy(dst, tmpl->hdr_bytes + d->field_off, copy_len);
    return (int)copy_len;
}

/* ------------------------------------------------------------------ */
/* packet_set_field                                                      */
/* ------------------------------------------------------------------ */

/*
 * Write src bytes into the field region described by descs[desc_idx]
 * within tmpl->hdr_bytes.  src_len bytes are copied; if src_len is
 * smaller than the field width the remainder is left unchanged.  If
 * src_len is larger than the field width only field_len bytes are
 * written.  Returns 0 on success, -1 on error.
 */
int packet_set_field(mdn_packet_template_t *tmpl, uint16_t desc_idx,
                     const uint8_t *src, uint32_t src_len)
{
    if (!tmpl || !tmpl->hdr_bytes || !tmpl->descs || !src)
        return -1;
    if (desc_idx >= tmpl->desc_count)
        return -1;

    mdn_tmpl_desc_t *d = &tmpl->descs[desc_idx];
    uint32_t end = (uint32_t)d->field_off + (uint32_t)d->field_len;
    if (end > tmpl->hdr_cap)
        return -1;

    uint32_t copy_len = MDN_MIN(src_len, (uint32_t)d->field_len);
    memcpy(tmpl->hdr_bytes + d->field_off, src, copy_len);
    return 0;
}

/* ------------------------------------------------------------------ */
/* packet_checksum                                                       */
/* ------------------------------------------------------------------ */

/*
 * Compute a simple 32-bit additive checksum over the given byte range.
 * Each byte is added to the accumulator as an unsigned 8-bit value.
 * The result wraps around at 2^32.
 */
uint32_t packet_checksum(const uint8_t *pkt, uint32_t len)
{
    if (!pkt || len == 0)
        return 0;

    uint32_t acc = 0;
    for (uint32_t i = 0; i < len; i++)
        acc += (uint32_t)pkt[i];
    return acc;
}

/* ------------------------------------------------------------------ */
/* packet_compare_fields                                                 */
/* ------------------------------------------------------------------ */

/*
 * Compare the field region at descs[desc_idx] in templates a and b.
 * Returns 0 when the field bytes are identical, -1 when they differ or
 * when any argument is invalid.
 *
 * Both templates must have at least desc_idx descriptors and must have
 * hdr_bytes allocated.  The descriptor from template a governs the
 * layout; only a->descs[desc_idx].field_len bytes are compared.
 */
int packet_compare_fields(mdn_packet_template_t *a, mdn_packet_template_t *b,
                           uint16_t desc_idx)
{
    if (!a || !b || !a->hdr_bytes || !b->hdr_bytes || !a->descs || !b->descs)
        return -1;
    if (desc_idx >= a->desc_count || desc_idx >= b->desc_count)
        return -1;

    mdn_tmpl_desc_t *da = &a->descs[desc_idx];
    mdn_tmpl_desc_t *db = &b->descs[desc_idx];

    uint32_t end_a = (uint32_t)da->field_off + (uint32_t)da->field_len;
    uint32_t end_b = (uint32_t)db->field_off + (uint32_t)db->field_len;
    if (end_a > a->hdr_cap || end_b > b->hdr_cap)
        return -1;

    uint16_t cmp_len = MDN_MIN(da->field_len, db->field_len);
    if (memcmp(a->hdr_bytes + da->field_off,
               b->hdr_bytes + db->field_off, cmp_len) != 0)
        return -1;

    /* If field widths differ the longer field has extra bytes — not equal */
    if (da->field_len != db->field_len)
        return -1;

    return 0;
}

/* ------------------------------------------------------------------ */
/* packet_zero_fields                                                    */
/* ------------------------------------------------------------------ */

/*
 * Zero the entire hdr_bytes allocation for the given template.
 * This resets every header field to 0x00 without changing the buffer
 * size or descriptor layout.
 */
void packet_zero_fields(mdn_packet_template_t *tmpl)
{
    if (!tmpl || !tmpl->hdr_bytes || tmpl->hdr_cap == 0)
        return;
    memset(tmpl->hdr_bytes, 0, tmpl->hdr_cap);
}

/* ------------------------------------------------------------------ */
/* packet_encode_u32                                                     */
/* ------------------------------------------------------------------ */

/*
 * Write a 32-bit unsigned integer at byte offset off inside
 * tmpl->hdr_bytes, using little-endian byte order.  Returns 0 on
 * success, -1 when the write would exceed hdr_cap.
 */
int packet_encode_u32(mdn_packet_template_t *tmpl, uint16_t off, uint32_t val)
{
    if (!tmpl || !tmpl->hdr_bytes)
        return -1;
    if ((uint32_t)off + 4u > tmpl->hdr_cap)
        return -1;

    uint8_t *p = tmpl->hdr_bytes + off;
    p[0] = (uint8_t)( val        & 0xFF);
    p[1] = (uint8_t)((val >>  8) & 0xFF);
    p[2] = (uint8_t)((val >> 16) & 0xFF);
    p[3] = (uint8_t)((val >> 24) & 0xFF);
    return 0;
}

/* ------------------------------------------------------------------ */
/* packet_ipv4_checksum                                                  */
/* ------------------------------------------------------------------ */

/*
 * Compute the standard one's-complement checksum used in IPv4 headers.
 * hdr points to the first byte of the IP header; len is the header
 * length in bytes (typically 20 for a header with no options).
 *
 * The function sums all 16-bit words, folds carries, and returns the
 * bitwise complement.  Per RFC 791 the caller should zero the checksum
 * field in the header before calling this function.
 */
uint16_t packet_ipv4_checksum(const uint8_t *hdr, uint32_t len)
{
    if (!hdr || len < 2u)
        return 0;

    uint32_t acc = 0;
    uint32_t i   = 0;

    for (; i + 1u < len; i += 2u) {
        uint16_t word = ((uint16_t)hdr[i] << 8) | (uint16_t)hdr[i + 1u];
        acc += (uint32_t)word;
    }
    /* If len is odd, pad the last byte with 0x00 */
    if (i < len)
        acc += (uint32_t)hdr[i] << 8;

    /* Fold 32-bit accumulator into 16 bits */
    while (acc >> 16)
        acc = (acc & 0xFFFFu) + (acc >> 16);

    return (uint16_t)(~acc & 0xFFFFu);
}

/* ------------------------------------------------------------------ */
/* packet_ipv6_pseudo_header                                             */
/* ------------------------------------------------------------------ */

/*
 * Build an IPv6 pseudo-header into out[0..39].  The pseudo-header
 * layout is:
 *   bytes  0-15 : source address (src[0..15])
 *   bytes 16-31 : destination address (dst[0..15])
 *   bytes 32-35 : upper-layer payload length (big-endian)
 *   bytes 36-38 : zero padding
 *   byte  39    : next header type (e.g. 17 for UDP, 6 for TCP)
 *
 * out must be at least 40 bytes.  Returns 0 on success, -1 on error.
 */
int packet_ipv6_pseudo_header(const uint8_t *src, const uint8_t *dst,
                               uint8_t next_hdr, uint32_t payload_len,
                               uint8_t *out)
{
    if (!src || !dst || !out)
        return -1;

    memcpy(out,      src, 16u);
    memcpy(out + 16, dst, 16u);
    out[32] = (uint8_t)((payload_len >> 24) & 0xFF);
    out[33] = (uint8_t)((payload_len >> 16) & 0xFF);
    out[34] = (uint8_t)((payload_len >>  8) & 0xFF);
    out[35] = (uint8_t)( payload_len        & 0xFF);
    out[36] = 0;
    out[37] = 0;
    out[38] = 0;
    out[39] = next_hdr;
    return 0;
}

/* ------------------------------------------------------------------ */
/* packet_udp_checksum                                                   */
/* ------------------------------------------------------------------ */

/*
 * Compute the UDP checksum over the pseudo-header and payload.  The
 * pseudo-header is constructed from the 16-byte src and dst IPv6
 * addresses together with the payload length.  The checksum covers:
 *   pseudo-header (40 bytes) + data[0..len).
 *
 * Returns the 16-bit checksum, or 0 on error.
 */
uint16_t packet_udp_checksum(const uint8_t *src, const uint8_t *dst,
                              const uint8_t *data, uint32_t len)
{
    if (!src || !dst)
        return 0;

    uint8_t pseudo[40];
    if (packet_ipv6_pseudo_header(src, dst, 17u, len, pseudo) != 0)
        return 0;

    uint32_t acc = 0;

    /* Sum pseudo-header */
    for (uint32_t i = 0; i + 1u < 40u; i += 2u) {
        uint16_t w = ((uint16_t)pseudo[i] << 8) | (uint16_t)pseudo[i + 1u];
        acc += (uint32_t)w;
    }

    /* Sum payload */
    if (data) {
        uint32_t i = 0;
        for (; i + 1u < len; i += 2u) {
            uint16_t w = ((uint16_t)data[i] << 8) | (uint16_t)data[i + 1u];
            acc += (uint32_t)w;
        }
        if (i < len)
            acc += (uint32_t)data[i] << 8;
    }

    while (acc >> 16)
        acc = (acc & 0xFFFFu) + (acc >> 16);

    uint16_t result = (uint16_t)(~acc & 0xFFFFu);
    return (result == 0) ? 0xFFFFu : result;
}

/* ------------------------------------------------------------------ */
/* packet_encode_vlan_tag / packet_decode_vlan_tag                       */
/* ------------------------------------------------------------------ */

/*
 * Encode an 802.1Q VLAN tag into out[0..3].  The tag is formatted as:
 *   bytes 0-1: EtherType 0x8100
 *   bytes 2-3: TCI = (pcp[2:0] << 13) | (dei=0 << 12) | vid[11:0]
 *
 * out must be at least 4 bytes.  Returns 0 on success, -1 on error.
 */
int packet_encode_vlan_tag(uint16_t vid, uint8_t pcp, uint8_t *out)
{
    if (!out)
        return -1;
    if (vid > 0x0FFFu)
        return -1;
    if (pcp > 7u)
        return -1;

    uint16_t tci = (uint16_t)(((uint16_t)(pcp & 0x07u) << 13) | (vid & 0x0FFFu));
    out[0] = 0x81;
    out[1] = 0x00;
    out[2] = (uint8_t)((tci >> 8) & 0xFF);
    out[3] = (uint8_t)( tci       & 0xFF);
    return 0;
}

/*
 * Decode an 802.1Q VLAN tag from data[0..3].  Writes the 12-bit VID to
 * *vid_out and the 3-bit PCP to *pcp_out.  Returns 0 on success, -1
 * when the EtherType is not 0x8100 or data is NULL.
 */
int packet_decode_vlan_tag(const uint8_t *data, uint16_t *vid_out, uint8_t *pcp_out)
{
    if (!data || !vid_out || !pcp_out)
        return -1;
    if (data[0] != 0x81 || data[1] != 0x00)
        return -1;

    uint16_t tci = ((uint16_t)data[2] << 8) | (uint16_t)data[3];
    *pcp_out = (uint8_t)((tci >> 13) & 0x07u);
    *vid_out = tci & 0x0FFFu;
    return 0;
}

/* ------------------------------------------------------------------ */
/* packet_is_ipv4 / packet_is_ipv6                                       */
/* ------------------------------------------------------------------ */

/*
 * Return 1 if buf[0] has IP version == 4, 0 otherwise.  Returns 0 when
 * buf is NULL or len is 0.
 */
int packet_is_ipv4(const uint8_t *buf, uint32_t len)
{
    if (!buf || len == 0)
        return 0;
    return ((buf[0] >> 4) == 4u) ? 1 : 0;
}

/*
 * Return 1 if buf[0] has IP version == 6, 0 otherwise.
 */
int packet_is_ipv6(const uint8_t *buf, uint32_t len)
{
    if (!buf || len == 0)
        return 0;
    return ((buf[0] >> 4) == 6u) ? 1 : 0;
}

/* ------------------------------------------------------------------ */
/* packet_field_get / packet_field_set                                   */
/* ------------------------------------------------------------------ */

/*
 * Extract field_len bytes starting at field_off from buf into out.
 * Returns 0 on success, -1 on bounds error or NULL pointer.
 */
int packet_field_get(const uint8_t *buf, uint32_t len,
                     uint32_t field_off, uint32_t field_len,
                     uint8_t *out)
{
    if (!buf || !out || field_len == 0)
        return -1;
    if (field_off >= len || field_off + field_len > len)
        return -1;
    memcpy(out, buf + field_off, field_len);
    return 0;
}

/*
 * Write field_len bytes from val into buf at field_off.
 * Returns 0 on success, -1 on bounds error or NULL pointer.
 */
int packet_field_set(uint8_t *buf, uint32_t len,
                     uint32_t field_off, uint32_t field_len,
                     const uint8_t *val)
{
    if (!buf || !val || field_len == 0)
        return -1;
    if (field_off >= len || field_off + field_len > len)
        return -1;
    memcpy(buf + field_off, val, field_len);
    return 0;
}

/* ------------------------------------------------------------------ */
/* packet_dump                                                           */
/* ------------------------------------------------------------------ */

/*
 * Format a packet buffer as a hex dump into out[0..cap).  Each row
 * shows 16 bytes in hex followed by a pipe and the ASCII representation
 * (non-printable bytes replaced with '.').  Returns the number of bytes
 * written (not counting the final NUL).
 */
int packet_dump(const uint8_t *buf, uint32_t len, char *out, uint32_t cap)
{
    if (!buf || !out || cap == 0)
        return 0;

    int total = 0;
    for (uint32_t row = 0; row < len; row += 16u) {
        int n = snprintf(out + total, cap - (uint32_t)total,
                         "%04x  ", (unsigned)row);
        if (n < 0 || (uint32_t)(total + n) >= cap - 1u)
            break;
        total += n;

        for (uint32_t col = 0; col < 16u; col++) {
            if (row + col < len) {
                n = snprintf(out + total, cap - (uint32_t)total,
                             "%02x ", (unsigned)buf[row + col]);
            } else {
                n = snprintf(out + total, cap - (uint32_t)total, "   ");
            }
            if (n < 0 || (uint32_t)(total + n) >= cap - 1u)
                goto done;
            total += n;
        }

        n = snprintf(out + total, cap - (uint32_t)total, "| ");
        if (n < 0 || (uint32_t)(total + n) >= cap - 1u)
            goto done;
        total += n;

        for (uint32_t col = 0; col < 16u && row + col < len; col++) {
            uint8_t c = buf[row + col];
            char ch = (c >= 0x20u && c < 0x7Fu) ? (char)c : '.';
            n = snprintf(out + total, cap - (uint32_t)total, "%c", ch);
            if (n < 0 || (uint32_t)(total + n) >= cap - 1u)
                goto done;
            total += n;
        }

        n = snprintf(out + total, cap - (uint32_t)total, "\n");
        if (n < 0 || (uint32_t)(total + n) >= cap - 1u)
            goto done;
        total += n;
    }
done:
    out[MDN_MIN((uint32_t)total, cap - 1u)] = '\0';
    return total;
}
