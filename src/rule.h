#ifndef RULE_H
#define RULE_H

#include <stdint.h>
#include "mdn_internal.h"

/*
 * rule_load: parse a SECT_RULE payload into ctx->rules[].
 *
 * data layout:
 *   [0..3]  count (u32, little-endian)
 *   [4..]   count * 12 bytes: key(u32), mask(u32), action(u16), next(u16)
 *
 * Returns 0 on success, -1 on invalid input.
 */
int rule_load(mdn_ctx_t *ctx, const uint8_t *data, uint32_t len);

/* ------------------------------------------------------------------ */
/* Rule statistics                                                      */
/* ------------------------------------------------------------------ */
typedef struct {
    uint32_t count_allow;
    uint32_t count_drop;
    uint32_t count_mark;
    uint32_t count_redirect;
    uint32_t count_nat;
    uint32_t count_trie;
    uint32_t count_audit;
    uint32_t count_other;
    uint32_t max_chain_depth;
} rule_stats_t;

void rule_stats(const mdn_ctx_t *ctx, rule_stats_t *out);
void rule_stats_print(const rule_stats_t *rs);

/* ------------------------------------------------------------------ */
/* Rule tree / adjacency list                                           */
/* ------------------------------------------------------------------ */
#define RULE_TREE_MAX_NODES MDN_MAX_RULES
#define RULE_TREE_MAX_EDGES (MDN_MAX_RULES * 2)

typedef struct {
    uint32_t from;
    uint32_t to;
} rule_edge_t;

typedef struct {
    uint32_t   node_count;
    uint32_t   edge_count;
    rule_edge_t edges[RULE_TREE_MAX_EDGES];
    uint32_t   adj_head[RULE_TREE_MAX_NODES]; /* index into adj_list; UINT32_MAX = none */
    uint32_t   adj_next[RULE_TREE_MAX_EDGES]; /* linked list of edges from node */
    uint32_t   adj_dest[RULE_TREE_MAX_EDGES]; /* destination of edge */
} rule_tree_t;

int  rule_tree_build(const mdn_ctx_t *ctx, rule_tree_t *tree);
int  rule_tree_toposort(const rule_tree_t *tree, uint32_t *order_out, uint32_t max);

/* ------------------------------------------------------------------ */
/* Dead-rule analysis                                                   */
/* ------------------------------------------------------------------ */
int      rule_dead_mark(const mdn_ctx_t *ctx, uint8_t *reachable_out, uint32_t reachable_cap);
uint32_t rule_dead_count(const uint8_t *reachable, uint32_t rule_count);
void     rule_dead_sweep(mdn_ctx_t *ctx);

/* ------------------------------------------------------------------ */
/* Rule optimization passes                                             */
/* ------------------------------------------------------------------ */
uint32_t rule_merge_adjacent(mdn_ctx_t *ctx);
int      rule_validate_chain(const mdn_ctx_t *ctx, uint32_t start, char *err_buf, size_t err_cap);
uint32_t rule_count_by_action(const mdn_ctx_t *ctx, uint16_t action);

/* ------------------------------------------------------------------ */
/* Rule serialization helpers                                           */
/* ------------------------------------------------------------------ */
int rule_node_to_str(const mdn_rule_node_t *r, char *buf, size_t cap);
int rule_table_to_csv(const mdn_ctx_t *ctx, char *buf, size_t cap);

#endif /* RULE_H */
