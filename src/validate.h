#ifndef MDN_VALIDATE_H
#define MDN_VALIDATE_H

#include "mdn_internal.h"

/* Full post-load validation; calls all sub-validators. Returns 0 or -1. */
int mdn_validate(mdn_ctx_t *ctx);

/* Zone hierarchy: no self-referencing parent_id, all parents present. */
int validate_zones(mdn_ctx_t *ctx);

/* Rule chain: no out-of-range next pointers, no circular chains. */
int validate_rules(mdn_ctx_t *ctx);

/* NAT buckets: zone_id < MDN_MAX_ZONES, referenced zones present. */
int validate_nat_buckets(mdn_ctx_t *ctx);

/* Prefix pages: stride > 0, item_count <= 65535, dir_count <= item_count+1. */
int validate_prefix_pages(mdn_ctx_t *ctx);

/* Templates: hdr_bytes non-NULL when hdr_cap > 0, desc_count <= 64. */
int validate_templates(mdn_ctx_t *ctx);

/* Queries: start_rule within rule_count (or == 0 when rule_count == 0). */
int validate_queries(mdn_ctx_t *ctx);

/* Export profiles: field_count <= MDN_EXPORT_FIELDS_MAX. */
int validate_exports(mdn_ctx_t *ctx);

#endif /* MDN_VALIDATE_H */
