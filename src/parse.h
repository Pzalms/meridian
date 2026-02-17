#ifndef MDN_PARSE_H
#define MDN_PARSE_H

#include "mdn_internal.h"
#include <stddef.h>
#include <stdint.h>

/* Full parse of a meridian buffer into ctx. */
int mdn_parse(mdn_ctx_t *ctx, const uint8_t *buf, size_t len);

/* Reset parse-time counters then parse (same as mdn_parse after counter clear). */
int mdn_reparse(mdn_ctx_t *ctx, const uint8_t *buf, size_t len);

/* Return the section count from the header without a full parse; -1 on error. */
int mdn_parse_section_count(const uint8_t *buf, size_t len);

/* Return 1 if a section of sect_type is present, 0 if not, -1 on error. */
int mdn_parse_has_section(const uint8_t *buf, size_t len, uint8_t sect_type);

/* Return payload offset of the first section of sect_type, or 0 if not found. */
uint32_t mdn_parse_section_offset(const uint8_t *buf, size_t len, uint8_t sect_type);

/* Verify CRC32C for every section; returns 0 if all pass, -1 on first mismatch. */
int mdn_parse_verify_all_crcs(const uint8_t *buf, size_t len);

/* Fill counts_out[16] with per-type section counts; returns 0 or -1 on error. */
int mdn_parse_section_stats(const uint8_t *buf, size_t len, uint32_t *counts_out);

/* Extended parse helpers */

/* Return string name for a section type constant (e.g. "SECT_CAP"). */
const char *parse_section_type_name(uint8_t type);

/* Count sections of a given type in the table; -1 on error. */
int parse_count_section_type(const uint8_t *buf, size_t len, uint8_t type);

/* Section entry as exposed by the iterator */
typedef struct {
    uint8_t  type;
    uint8_t  sect_flags;
    uint16_t id;
    uint32_t offset;
    uint32_t length;
    uint32_t crc32;
    uint32_t epoch;
} parse_section_entry_t;

/* Sequential section table iterator */
typedef struct {
    const uint8_t *buf;
    size_t         buf_len;
    uint16_t       total;
    uint16_t       current;
} parse_section_iterator_t;

int parse_section_iter_init(parse_section_iterator_t *it,
                             const uint8_t *buf, size_t len);
int parse_section_iter_next(parse_section_iterator_t *it,
                             parse_section_entry_t *entry_out);

/* Find and expose a section payload by type+id; returns 0 or -1. */
int parse_extract_section(const uint8_t *buf, size_t len,
                           uint8_t type, uint16_t id,
                           const uint8_t **data_out, uint32_t *len_out);

/* Pre-validate all section bounds; section_count must match the header. */
int parse_validate_table(const uint8_t *buf, size_t len, uint16_t section_count);

/* Format header fields as a one-line text summary; returns bytes written. */
int parse_header_summary(const uint8_t *buf, size_t len, char *out, uint32_t cap);

/* Format a section entry as a one-line text summary; returns bytes written. */
int parse_section_summary(const parse_section_entry_t *entry, char *out, uint32_t cap);

/* Section loader interfaces — implemented in their respective modules */
int zone_load(mdn_ctx_t *ctx, const uint8_t *data, uint32_t len, uint16_t id);
int prefix_page_load(mdn_ctx_t *ctx, const uint8_t *data, uint32_t len, uint16_t id);
int rule_load(mdn_ctx_t *ctx, const uint8_t *data, uint32_t len);
int nat_bucket_load(mdn_ctx_t *ctx, const uint8_t *data, uint32_t len, uint16_t id);
int template_load(mdn_ctx_t *ctx, const uint8_t *data, uint32_t len, uint16_t id);
int audit_window_load(mdn_ctx_t *ctx, const uint8_t *data, uint32_t len, uint16_t id);
int export_profile_load(mdn_ctx_t *ctx, const uint8_t *data, uint32_t len, uint16_t id);
int query_load(mdn_ctx_t *ctx, const uint8_t *data, uint32_t len);
int policy_patch_apply(mdn_ctx_t *ctx, const uint8_t *data, uint32_t len);

#endif /* MDN_PARSE_H */
