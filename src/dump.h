#ifndef MDN_DUMP_H
#define MDN_DUMP_H

#include <stdint.h>
#include "mdn_internal.h"

/* Print all non-NULL zone entries to stdout */
void dump_zones(mdn_ctx_t *ctx);

/* Print all rule nodes to stdout */
void dump_rules(mdn_ctx_t *ctx);

/* Print all non-NULL NAT buckets to stdout */
void dump_nat(mdn_ctx_t *ctx);

/* Print all packet templates to stdout */
void dump_templates(mdn_ctx_t *ctx);

/* Print all loaded queries to stdout */
void dump_queries(mdn_ctx_t *ctx);

/* Print all non-NULL prefix pages to stdout */
void dump_prefix_pages(mdn_ctx_t *ctx);

/* Print all audit windows to stdout */
void dump_audit_windows(mdn_ctx_t *ctx);

/* Print all export profiles to stdout */
void dump_exports(mdn_ctx_t *ctx);

/* Print all NAT buckets and their session counts */
void dump_sessions(mdn_ctx_t *ctx);

/* Hex dump a raw section payload */
void dump_hex_section(const uint8_t *data, uint32_t len);

/* Call all dump_* functions in sequence */
void dump_all(mdn_ctx_t *ctx);

/* Hex dump a memory region with configurable line width */
void dump_hex_region(const uint8_t *buf, size_t len, size_t line_width);

/* Print a formatted section header entry */
void dump_section_header(uint8_t sect_type, uint32_t sect_len, uint32_t offset);

/* Print a top-level summary of a parsed ctx */
void dump_mdn_summary(mdn_ctx_t *ctx);

/* Walk rule nodes and format as a chain of text lines */
void dump_rule_chain(mdn_ctx_t *ctx, uint32_t start_rule, uint32_t max_depth);

/* Dump a single rule node to a caller-supplied buffer (no newline trailing) */
int  dump_rule_node_str(const mdn_rule_node_t *r, char *buf, size_t buf_cap);

/* Dump count statistics for all sub-objects to stdout */
void dump_counts(mdn_ctx_t *ctx);

/* Dump all audit windows with their directory entries */
void dump_audit_detail(mdn_ctx_t *ctx);

/* Dump all export profile fields */
void dump_export_fields(mdn_ctx_t *ctx);

/* Dump prefix page items as hex rows */
void dump_prefix_items(mdn_ctx_t *ctx, uint32_t page_id, uint32_t max_items);

#endif /* MDN_DUMP_H */
