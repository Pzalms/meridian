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

#endif /* MDN_DUMP_H */
