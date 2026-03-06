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
