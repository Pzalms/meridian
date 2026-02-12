#ifndef MDN_QUERY_H
#define MDN_QUERY_H

#include <stdint.h>
#include "mdn_internal.h"

/*
 * query_load: parse up to MDN_MAX_QUERIES query records from data.
 * Each record is 12 bytes: query_id(u16), start_rule(u16),
 * zone_id(u16), template_id(u16), flags(u32).
 * Stores parsed queries in ctx->queries[], sets ctx->query_count.
 * Returns 0 on success, -1 on invalid args.
 */
int query_load(mdn_ctx_t *ctx, const uint8_t *data, uint32_t len);

/*
 * query_run_all: execute all loaded queries through the DAG.
 * For each query: opens a session cursor, evaluates via dag_evaluate,
 * then emits export fields if any export profiles are loaded.
 * Returns 0.
 */
int query_run_all(mdn_ctx_t *ctx);

/*
 * policy_patch_apply: process SECT_POLICY_PATCH operations.
 * Parses a sequence of: op_type(u8), op_len(u16), op_data[op_len].
 * Dispatches each recognized op type to the appropriate subsystem.
 * Returns 0 on success, -1 on invalid args.
 */
int policy_patch_apply(mdn_ctx_t *ctx, const uint8_t *data, uint32_t len);

/* Query inspection and serialization utilities */
int  query_serialize(mdn_query_t *q, uint8_t *out, uint32_t cap);
int  query_deserialize(const uint8_t *data, uint32_t len, mdn_query_t *q_out);
int  query_validate(mdn_ctx_t *ctx, mdn_query_t *q);
int  query_dump(mdn_query_t *q, char *out, uint32_t cap);
void query_clone(mdn_query_t *src, mdn_query_t *dst);
int  query_find_by_zone(mdn_ctx_t *ctx, uint16_t zone_id,
                        uint16_t *out, uint32_t max);
int  query_count_by_action(mdn_ctx_t *ctx, uint32_t action);

#endif /* MDN_QUERY_H */
