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
