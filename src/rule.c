#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "mdn_internal.h"
#include "rule.h"

/* Parse a little-endian u32 from an unaligned byte pointer. */
static uint32_t read_u32(const uint8_t *p)
{
    return (uint32_t)p[0]
         | ((uint32_t)p[1] << 8)
         | ((uint32_t)p[2] << 16)
         | ((uint32_t)p[3] << 24);
}

/* Parse a little-endian u16 from an unaligned byte pointer. */
static uint16_t read_u16(const uint8_t *p)
{
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

int rule_load(mdn_ctx_t *ctx, const uint8_t *data, uint32_t len)
{
    if (!ctx || !data) {
        return -1;
    }

    /* Need at least 4 bytes for the count field. */
    if (len < 4) {
        return -1;
    }

    uint32_t count = read_u32(data);

    /* Validate count bounds — cap at compile-time limit. */
    if (count > MDN_MAX_RULES) {
        /* rule table exceeds capacity; reject the section */
        return -1;
    }

    /* Each rule node is 12 bytes: key(4) + mask(4) + action(2) + next(2). */
    uint32_t required = 4u + count * 12u;
    if (len < required) {
        return -1;
    }

    /* Release any previously loaded rule table. */
    free(ctx->rules);
    ctx->rules = NULL;
    ctx->rule_count = 0;

    if (count == 0) {
        return 0;
    }

    mdn_rule_node_t *nodes = calloc(count, sizeof(mdn_rule_node_t));
    if (!nodes) {
        return -1;
    }

    const uint8_t *p = data + 4;
    for (uint32_t i = 0; i < count; i++) {
        nodes[i].key    = read_u32(p);      p += 4;
        nodes[i].mask   = read_u32(p);      p += 4;
        nodes[i].action = read_u16(p);      p += 2;
        nodes[i].next   = read_u16(p);      p += 2;
    }

    ctx->rules      = nodes;
    ctx->rule_count = count;
    return 0;
}

#include <stdio.h>

/* ================================================================== */
/* Rule statistics                                                      */
/* ================================================================== */

void rule_stats(const mdn_ctx_t *ctx, rule_stats_t *out)
{
    if (!ctx || !out) return;
    memset(out, 0, sizeof(*out));

    for (uint32_t i = 0; i < ctx->rule_count; i++) {
        switch (ctx->rules[i].action) {
        case ACTION_ALLOW:        out->count_allow++;    break;
        case ACTION_DROP:         out->count_drop++;     break;
        case ACTION_MARK:         out->count_mark++;     break;
        case ACTION_REDIRECT:     out->count_redirect++; break;
        case ACTION_NAT_LOOKUP:   out->count_nat++;      break;
        case ACTION_TRIE_LOOKUP:  out->count_trie++;     break;
        case ACTION_AUDIT_EXPORT: out->count_audit++;    break;
        default:                  out->count_other++;    break;
        }
    }

    /* Compute max chain depth from rule 0. */
    if (ctx->rule_count > 0) {
        uint32_t cur   = 0;
        uint32_t depth = 0;
        uint8_t  visited[MDN_MAX_RULES];
        memset(visited, 0, sizeof(visited));
        while (cur < ctx->rule_count && !visited[cur]) {
            visited[cur] = 1;
            depth++;
            uint32_t nxt = ctx->rules[cur].next;
            if (nxt == cur || nxt >= ctx->rule_count) break;
            cur = nxt;
        }
        out->max_chain_depth = depth;
    }
}

void rule_stats_print(const rule_stats_t *rs)
{
    if (!rs) return;
    printf("rule statistics:\n");
    printf("  allow:         %u\n", rs->count_allow);
    printf("  drop:          %u\n", rs->count_drop);
    printf("  mark:          %u\n", rs->count_mark);
    printf("  redirect:      %u\n", rs->count_redirect);
    printf("  nat_lookup:    %u\n", rs->count_nat);
    printf("  trie_lookup:   %u\n", rs->count_trie);
    printf("  audit_export:  %u\n", rs->count_audit);
    printf("  other:         %u\n", rs->count_other);
    printf("  max_chain_depth: %u\n", rs->max_chain_depth);
}

/* ================================================================== */
/* Rule tree (adjacency list)                                           */
/* ================================================================== */

int rule_tree_build(const mdn_ctx_t *ctx, rule_tree_t *tree)
{
    if (!ctx || !tree) return -1;
    memset(tree, 0, sizeof(*tree));
    tree->node_count = ctx->rule_count;

    /* Initialize adjacency list heads to UINT32_MAX (no edge). */
    for (uint32_t i = 0; i < RULE_TREE_MAX_NODES; i++)
        tree->adj_head[i] = UINT32_MAX;

    for (uint32_t i = 0; i < ctx->rule_count; i++) {
        uint32_t nxt = ctx->rules[i].next;
        if (nxt == i || nxt >= ctx->rule_count) continue;
        if (tree->edge_count >= RULE_TREE_MAX_EDGES) return -1;

        uint32_t eidx = tree->edge_count++;
        tree->edges[eidx].from = i;
        tree->edges[eidx].to   = nxt;

        /* Prepend to adjacency list of node i. */
        tree->adj_dest[eidx] = nxt;
        tree->adj_next[eidx] = tree->adj_head[i];
        tree->adj_head[i]    = eidx;
    }
    return 0;
}

int rule_tree_toposort(const rule_tree_t *tree, uint32_t *order_out, uint32_t max)
{
    if (!tree || !order_out || !max) return -1;
    uint32_t n = tree->node_count;
    if (n > max) n = max;

    /* Kahn's algorithm: compute in-degree for each node. */
    uint32_t indeg[RULE_TREE_MAX_NODES];
    memset(indeg, 0, sizeof(uint32_t) * n);
    for (uint32_t e = 0; e < tree->edge_count; e++) {
        uint32_t to = tree->edges[e].to;
        if (to < n) indeg[to]++;
    }

    /* Queue of zero-indegree nodes (simple array). */
    uint32_t queue[RULE_TREE_MAX_NODES];
    uint32_t qhead = 0, qtail = 0;
    for (uint32_t i = 0; i < n; i++)
        if (!indeg[i]) queue[qtail++] = i;

    uint32_t placed = 0;
    while (qhead < qtail && placed < max) {
        uint32_t u = queue[qhead++];
        order_out[placed++] = u;
        /* Reduce in-degree of successors. */
        for (uint32_t e = tree->adj_head[u]; e != UINT32_MAX; e = tree->adj_next[e]) {
            uint32_t v = tree->adj_dest[e];
            if (v < n && indeg[v] > 0) {
                indeg[v]--;
                if (!indeg[v]) queue[qtail++] = v;
            }
        }
    }
    return (int)placed;
}

/* ================================================================== */
/* Dead-rule analysis (BFS from rule 0)                                */
/* ================================================================== */

int rule_dead_mark(const mdn_ctx_t *ctx, uint8_t *reachable_out, uint32_t reachable_cap)
{
    if (!ctx || !reachable_out) return -1;
    uint32_t n = ctx->rule_count;
    if (n > reachable_cap) return -1;
    memset(reachable_out, 0, n);

    if (!n) return 0;

    /* BFS from rule 0. */
    uint32_t queue[MDN_MAX_RULES];
    uint32_t qhead = 0, qtail = 0;
    queue[qtail++]       = 0;
    reachable_out[0]     = 1;

    while (qhead < qtail) {
        uint32_t cur = queue[qhead++];
        uint32_t nxt = ctx->rules[cur].next;
        if (nxt != cur && nxt < n && !reachable_out[nxt]) {
            reachable_out[nxt] = 1;
            queue[qtail++]     = nxt;
        }
    }
    return 0;
}

uint32_t rule_dead_count(const uint8_t *reachable, uint32_t rule_count)
{
    if (!reachable) return 0;
    uint32_t dead = 0;
    for (uint32_t i = 0; i < rule_count; i++)
        if (!reachable[i]) dead++;
    return dead;
}

void rule_dead_sweep(mdn_ctx_t *ctx)
{
    if (!ctx || !ctx->rules || !ctx->rule_count) return;

    uint8_t reachable[MDN_MAX_RULES];
    if (rule_dead_mark(ctx, reachable, MDN_MAX_RULES) != 0) return;

    /* Zero out unreachable rule nodes in-place. */
    for (uint32_t i = 0; i < ctx->rule_count; i++) {
        if (!reachable[i])
            memset(&ctx->rules[i], 0, sizeof(mdn_rule_node_t));
    }
}

/* ================================================================== */
/* Rule optimization passes                                             */
/* ================================================================== */

uint32_t rule_merge_adjacent(mdn_ctx_t *ctx)
{
    if (!ctx || !ctx->rules || ctx->rule_count < 2) return 0;
    uint32_t merged = 0;

    for (uint32_t i = 0; i + 1 < ctx->rule_count; i++) {
        mdn_rule_node_t *cur  = &ctx->rules[i];
        mdn_rule_node_t *nxt  = &ctx->rules[i + 1];

        /* Merge if action and mask are identical and next of cur points to nxt. */
        if (cur->action == nxt->action &&
            cur->mask   == nxt->mask   &&
            cur->next   == (uint16_t)(i + 1))
        {
            /* Absorb nxt into cur: combine keys with OR, skip nxt. */
            cur->key  |= nxt->key;
            cur->next  = nxt->next;
            memset(nxt, 0, sizeof(*nxt));
            merged++;
        }
    }
    return merged;
}

int rule_validate_chain(const mdn_ctx_t *ctx, uint32_t start, char *err_buf, size_t err_cap)
{
    if (!ctx || !ctx->rules) {
        if (err_buf && err_cap) snprintf(err_buf, err_cap, "null context or rules");
        return -1;
    }
    if (start >= ctx->rule_count) {
        if (err_buf && err_cap)
            snprintf(err_buf, err_cap, "start rule %u out of range (count=%u)",
                     (unsigned)start, (unsigned)ctx->rule_count);
        return -1;
    }

    uint8_t visited[MDN_MAX_RULES];
    memset(visited, 0, sizeof(visited));
    uint32_t cur   = start;
    uint32_t steps = 0;

    while (cur < ctx->rule_count) {
        if (visited[cur]) {
            if (err_buf && err_cap)
                snprintf(err_buf, err_cap, "cycle detected at rule %u", (unsigned)cur);
            return -1;
        }
        visited[cur] = 1;
        steps++;
        uint32_t nxt = ctx->rules[cur].next;
        if (nxt == cur || nxt >= ctx->rule_count) break;
        cur = nxt;
    }
    (void)steps;
    return 0;
}

uint32_t rule_count_by_action(const mdn_ctx_t *ctx, uint16_t action)
{
    if (!ctx || !ctx->rules) return 0;
    uint32_t count = 0;
    for (uint32_t i = 0; i < ctx->rule_count; i++)
        if (ctx->rules[i].action == action) count++;
    return count;
}

/* ================================================================== */
/* Rule serialization                                                   */
/* ================================================================== */

int rule_node_to_str(const mdn_rule_node_t *r, char *buf, size_t cap)
{
    if (!r || !buf || !cap) return -1;
    static const char *anames[] = {
        "ALLOW","DROP","MARK","REDIRECT","NAT","TRIE","AUDIT"
    };
    const char *an = (r->action < 7) ? anames[r->action] : "OTHER";
    return snprintf(buf, cap, "key=0x%08x mask=0x%08x action=%s next=%u",
                    (unsigned)r->key, (unsigned)r->mask,
                    an, (unsigned)r->next);
}

int rule_table_to_csv(const mdn_ctx_t *ctx, char *buf, size_t cap)
{
    if (!ctx || !buf || !cap) return -1;
    int total = 0;

    /* Header row */
    int n = snprintf(buf, cap, "idx,key,mask,action,next\n");
    if (n <= 0 || (size_t)n >= cap) return total;
    buf += n; cap -= (size_t)n; total += n;

    for (uint32_t i = 0; i < ctx->rule_count && cap > 1; i++) {
        mdn_rule_node_t *r = &ctx->rules[i];
        n = snprintf(buf, cap, "%u,0x%08x,0x%08x,%u,%u\n",
                     (unsigned)i, (unsigned)r->key, (unsigned)r->mask,
                     (unsigned)r->action, (unsigned)r->next);
        if (n <= 0 || (size_t)n >= cap) break;
        buf += n; cap -= (size_t)n; total += n;
    }
    return total;
}
