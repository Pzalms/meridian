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

#endif /* DAG_H */
