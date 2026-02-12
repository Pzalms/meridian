#ifndef DAG_H
#define DAG_H

#include <stdint.h>
#include "mdn_internal.h"

/*
 * dag_evaluate: walk the rule DAG starting at q->start_rule.
 *
 * packet_key = (uint32_t)(q->zone_id ^ q->template_id ^ (uint16_t)q->flags)
 *
 * At each node, checks (packet_key & node->mask) == node->key.
 * On match, dispatches the node action and stores the result in *action_out.
 * On no match, follows node->next; if next is 0xFFFF or out of range,
 * stores ACTION_DROP in *action_out.
 *
 * Returns 0 on success, -1 if ctx, q, or action_out is NULL.
 */
int dag_evaluate(mdn_ctx_t *ctx, mdn_query_t *q, uint32_t *action_out);

/* DAG inspection utilities */
int dag_find_cycle(mdn_ctx_t *ctx, uint32_t start_rule, uint32_t *cycle_len_out);
int dag_count_reachable(mdn_ctx_t *ctx, uint32_t start_rule);
int dag_dump_chain(mdn_ctx_t *ctx, uint32_t start_rule, char *out, uint32_t cap);
void dag_action_histogram(mdn_ctx_t *ctx, uint32_t counts_out[7]);
int dag_max_depth(mdn_ctx_t *ctx, uint32_t start_rule);
int dag_node_summary(mdn_rule_node_t *node, char *out, uint32_t cap);

#endif /* DAG_H */
