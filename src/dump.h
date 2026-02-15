#ifndef MDN_DUMP_H
#define MDN_DUMP_H

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

/* Call all dump_* functions in sequence */
void dump_all(mdn_ctx_t *ctx);

#endif /* MDN_DUMP_H */
