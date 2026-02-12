#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>

#include "mdn_internal.h"
#include "dag.h"

/* ------------------------------------------------------------------ */
/* External interfaces provided by other subsystem modules             */
/* ------------------------------------------------------------------ */

extern int fragment_emit_headers(mdn_ctx_t *ctx, mdn_packet_template_t *tmpl);

extern mdn_session_t *session_cursor_next(mdn_ctx_t *ctx,
                                          mdn_session_cursor_t *cur);

extern int trie_lookup_prefix(mdn_ctx_t *ctx,
                               uint32_t   page_id,
                               uint32_t   query_key);

extern int audit_expand_record(mdn_audit_window_t *win,
                                uint32_t            idx,
                                uint8_t            *out,
                                uint32_t            out_cap);

extern void export_emit_fields(mdn_export_profile_t *prof, mdn_ctx_t *ctx);

extern int nat_rebucket_zone(mdn_ctx_t *ctx, uint16_t zone_id);

/* ------------------------------------------------------------------ */

int dag_evaluate(mdn_ctx_t *ctx, mdn_query_t *q, uint32_t *action_out)
{
    if (!ctx || !q || !action_out) {
        return -1;
    }

    /* Derive packet key from query fields. */
    uint32_t packet_key = (uint32_t)((uint16_t)q->zone_id
                                   ^ (uint16_t)q->template_id
                                   ^ (uint16_t)q->flags);

    uint32_t idx   = (uint32_t)q->start_rule;
    uint32_t steps = 0;

    while (steps < MDN_MAX_RULES) {
        /* Out-of-range index means no match — default drop. */
        if (idx >= ctx->rule_count) {
            *action_out = ACTION_DROP;
            return 0;
        }

        mdn_rule_node_t *node = &ctx->rules[idx];

        if ((packet_key & node->mask) == node->key) {
            /* Node matches — dispatch on action. */
            switch (node->action) {

            case ACTION_ALLOW:
            case ACTION_DROP:
            case ACTION_MARK:
                *action_out = node->action;
                return 0;

            case ACTION_REDIRECT: {
                /* Locate the packet template whose tmpl_id matches.
                 * If not found, tmpl remains NULL; fragment_emit_headers
                 * is expected to handle a NULL template gracefully. */
                mdn_packet_template_t *tmpl = NULL;
                for (uint32_t t = 0; t < ctx->template_count; t++) {
                    if (ctx->templates[t].tmpl_id == q->template_id) {
                        tmpl = &ctx->templates[t];
                        break;
                    }
                }
                /* proceed regardless — NULL tmpl is a valid no-op */
                fragment_emit_headers(ctx, tmpl);
                *action_out = ACTION_REDIRECT;
                return 0;
            }

            case ACTION_NAT_LOOKUP: {
                nat_rebucket_zone(ctx, q->zone_id);
                if (ctx->cursor_count > 0) {
                    mdn_session_cursor_t *cur =
                        &ctx->cursors[q->query_id % ctx->cursor_count];
                    mdn_session_t *sess = session_cursor_next(ctx, cur);
                    if (sess) *action_out = sess->sess_id; /* log session id as action */
                }
                *action_out = ACTION_NAT_LOOKUP;
                return 0;
            }

            case ACTION_TRIE_LOOKUP: {
                uint32_t page_id = (uint32_t)q->zone_id;
                trie_lookup_prefix(ctx, page_id, packet_key);
                *action_out = ACTION_TRIE_LOOKUP;
                return 0;
            }

            case ACTION_AUDIT_EXPORT: {
                if (ctx->audit_count > 0) {
                    uint8_t expand_buf[256];
                    audit_expand_record(&ctx->audit_windows[0], 1,
                                        expand_buf, sizeof(expand_buf));
                }
                if (ctx->export_count > 0) {
                    export_emit_fields(&ctx->exports[0], ctx);
                }
                *action_out = ACTION_AUDIT_EXPORT;
                return 0;
            }

            default:
                /* Unknown action — treat as drop. */
                *action_out = ACTION_DROP;
                return 0;
            }
        }

        /* No match — follow the next-hop index. */
        uint16_t nxt = node->next;
        if (nxt == 0xFFFFu || (uint32_t)nxt >= ctx->rule_count) {
            *action_out = ACTION_DROP;
            return 0;
        }
        idx = (uint32_t)nxt;
        steps++;
    }

    /* Exhausted maximum steps without a terminal action — drop. */
    *action_out = ACTION_DROP;
    return 0;
}

/* ------------------------------------------------------------------ */
/* DAG inspection utilities                                             */
/* ------------------------------------------------------------------ */

/*
 * dag_find_cycle — detect a cycle reachable from start_rule.
 *
 * Follows the next-hop chain from start_rule up to MDN_MAX_RULES steps,
 * recording each visited rule index in a local visited[] table.  If the
 * same index is encountered twice, a cycle is detected.
 *
 * Writes the cycle path length into *cycle_len_out if non-NULL.
 *
 * Returns 1 if a cycle is detected, 0 if the chain terminates cleanly,
 * -1 on invalid arguments.
 */
int dag_find_cycle(mdn_ctx_t *ctx, uint32_t start_rule, uint32_t *cycle_len_out)
{
    if (!ctx)
        return -1;

    /* visited[] tracks which rule indices have been seen */
    uint8_t visited[MDN_MAX_RULES];
    memset(visited, 0, sizeof(visited));

    uint32_t idx   = start_rule;
    uint32_t steps = 0;

    while (steps < MDN_MAX_RULES) {
        if (idx >= ctx->rule_count) {
            /* Chain terminated at an out-of-range index — no cycle */
            break;
        }

        if (visited[idx]) {
            if (cycle_len_out)
                *cycle_len_out = steps;
            return 1;
        }

        visited[idx] = 1;
        mdn_rule_node_t *node = &ctx->rules[idx];

        /* Terminal actions end the chain */
        if (node->action == ACTION_ALLOW ||
            node->action == ACTION_DROP  ||
            node->action == ACTION_MARK) {
            break;
        }

        uint16_t nxt = node->next;
        if (nxt == 0xFFFFu || (uint32_t)nxt >= ctx->rule_count)
            break;

        idx = (uint32_t)nxt;
        steps++;
    }

    if (cycle_len_out)
        *cycle_len_out = 0;
    return 0;
}

/*
 * dag_count_reachable — count all rule nodes reachable from start_rule.
 *
 * Follows next-hop links from start_rule, counting each unique node
 * visited until a terminal action, an out-of-range index, or the
 * MDN_MAX_RULES step limit is reached.
 *
 * Returns the count of reachable nodes, or -1 if ctx is NULL.
 */
int dag_count_reachable(mdn_ctx_t *ctx, uint32_t start_rule)
{
    if (!ctx)
        return -1;

    uint8_t visited[MDN_MAX_RULES];
    memset(visited, 0, sizeof(visited));

    uint32_t idx   = start_rule;
    int count = 0;

    for (uint32_t steps = 0; steps < MDN_MAX_RULES; steps++) {
        if (idx >= ctx->rule_count)
            break;
        if (visited[idx])
            break;

        visited[idx] = 1;
        count++;

        mdn_rule_node_t *node = &ctx->rules[idx];

        if (node->action == ACTION_ALLOW ||
            node->action == ACTION_DROP  ||
            node->action == ACTION_MARK) {
            break;
        }

        uint16_t nxt = node->next;
        if (nxt == 0xFFFFu || (uint32_t)nxt >= ctx->rule_count)
            break;

        idx = (uint32_t)nxt;
    }

    return count;
}

/*
 * dag_dump_chain — format the rule chain starting at start_rule as text.
 *
 * Writes a line for each reachable rule in next-hop order:
 *   rule[idx] key=0x... mask=0x... action=N next=N
 *
 * Stops at a terminal action, an out-of-range next, or when the buffer
 * is nearly full.  NUL-terminates the output.
 *
 * Returns the number of characters written (excluding NUL), or -1 on error.
 */
int dag_dump_chain(mdn_ctx_t *ctx, uint32_t start_rule, char *out, uint32_t cap)
{
    if (!ctx || !out || cap == 0)
        return -1;

    uint32_t pos = 0;
    uint32_t idx = start_rule;

    for (uint32_t steps = 0; steps < MDN_MAX_RULES && pos + 80 < cap; steps++) {
        if (idx >= ctx->rule_count)
            break;

        mdn_rule_node_t *node = &ctx->rules[idx];

        int r = snprintf(out + pos, cap - pos,
                         "rule[%3u] key=0x%08x mask=0x%08x action=%u next=%u\n",
                         idx, node->key, node->mask,
                         (unsigned)node->action, (unsigned)node->next);
        if (r < 0 || (uint32_t)r >= cap - pos)
            break;
        pos += (uint32_t)r;

        if (node->action == ACTION_ALLOW ||
            node->action == ACTION_DROP  ||
            node->action == ACTION_MARK) {
            break;
        }

        uint16_t nxt = node->next;
        if (nxt == 0xFFFFu || (uint32_t)nxt >= ctx->rule_count)
            break;

        idx = (uint32_t)nxt;
    }

    out[pos] = '\0';
    return (int)pos;
}

/*
 * dag_action_histogram — count rules per action type.
 *
 * Iterates over all rules in ctx->rules[] and increments counts_out[action]
 * for each rule.  counts_out must point to an array of at least 7 elements
 * (one for each ACTION_* constant, 0–6).
 *
 * Elements beyond ACTION_AUDIT_EXPORT (6) are not written.
 */
void dag_action_histogram(mdn_ctx_t *ctx, uint32_t counts_out[7])
{
    if (!ctx || !counts_out)
        return;

    for (int i = 0; i < 7; i++)
        counts_out[i] = 0;

    for (uint32_t i = 0; i < ctx->rule_count; i++) {
        uint16_t action = ctx->rules[i].action;
        if (action < 7)
            counts_out[action]++;
    }
}

/*
 * dag_max_depth — compute the longest non-looping path from start_rule.
 *
 * Follows the next-hop chain, stopping when a visited node is encountered
 * (loop detected), a terminal action is reached, or the chain leaves the
 * valid rule range.
 *
 * Returns the number of hops traversed (0 if start_rule is itself
 * terminal or out of range), or -1 if ctx is NULL.
 */
int dag_max_depth(mdn_ctx_t *ctx, uint32_t start_rule)
{
    if (!ctx)
        return -1;

    uint8_t visited[MDN_MAX_RULES];
    memset(visited, 0, sizeof(visited));

    uint32_t idx  = start_rule;
    int depth = 0;

    for (uint32_t steps = 0; steps < MDN_MAX_RULES; steps++) {
        if (idx >= ctx->rule_count)
            break;
        if (visited[idx])
            break;

        visited[idx] = 1;

        mdn_rule_node_t *node = &ctx->rules[idx];

        if (node->action == ACTION_ALLOW ||
            node->action == ACTION_DROP  ||
            node->action == ACTION_MARK) {
            depth++;
            break;
        }

        uint16_t nxt = node->next;
        depth++;

        if (nxt == 0xFFFFu || (uint32_t)nxt >= ctx->rule_count)
            break;

        idx = (uint32_t)nxt;
    }

    return depth;
}

/*
 * dag_node_summary — format a single rule node as a text summary.
 *
 * Writes a single line of the form:
 *   key=0x<hex> mask=0x<hex> action=<N> next=<N>
 *
 * Returns the number of characters written (excluding NUL), or -1 on error.
 */
int dag_node_summary(mdn_rule_node_t *node, char *out, uint32_t cap)
{
    if (!node || !out || cap == 0)
        return -1;

    int r = snprintf(out, cap,
                     "key=0x%08x mask=0x%08x action=%u next=%u",
                     node->key, node->mask,
                     (unsigned)node->action, (unsigned)node->next);
    if (r < 0 || (uint32_t)r >= cap)
        return -1;
    return r;
}
