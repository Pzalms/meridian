#ifndef MDN_FRAGMENT_H
#define MDN_FRAGMENT_H

#include "mdn_internal.h"
#include <stdint.h>

int fragment_emit_headers(mdn_ctx_t *ctx, mdn_packet_template_t *tmpl);

/* Extended API */
int  fragment_count_headers(mdn_packet_template_t *tmpl);
int  fragment_validate_layout(mdn_packet_template_t *tmpl);
int  fragment_copy_region(mdn_packet_template_t *src, mdn_packet_template_t *dst,
                           uint16_t src_off, uint16_t dst_off, uint16_t len);
int  fragment_append_descriptor(mdn_packet_template_t *tmpl, mdn_tmpl_desc_t desc);
int  fragment_remove_descriptor(mdn_packet_template_t *tmpl, uint16_t idx);
void fragment_stats(mdn_ctx_t *ctx, uint32_t *total_templates, uint32_t *total_frags);

/* Reassembly tracker */
typedef struct {
    uint16_t id;
    uint32_t offset;
    uint32_t total_len;
    uint32_t received_len;
} fragment_tracker_t;

/* One fragment piece: data pointer + length */
typedef struct {
    const uint8_t *data;
    uint32_t       len;
} fragment_piece_t;

void     fragment_tracker_init(fragment_tracker_t *t, uint16_t id, uint32_t total_len);
int      fragment_tracker_update(fragment_tracker_t *t, uint32_t frag_offset,
                                  uint32_t frag_len);
int      fragment_tracker_complete(fragment_tracker_t *t);
int      fragment_reassemble(mdn_ctx_t *ctx, mdn_packet_template_t *tmpl,
                              const fragment_piece_t *frags, uint16_t frag_count,
                              uint8_t *out, uint32_t out_cap);
uint16_t fragment_checksum(const uint8_t *data, uint32_t len);
int      fragment_hdr_dump(mdn_packet_template_t *tmpl, char *out, uint32_t cap);
int      fragment_count_fields(mdn_packet_template_t *tmpl);
int      fragment_validate_descriptors(mdn_packet_template_t *tmpl);

#endif /* MDN_FRAGMENT_H */
