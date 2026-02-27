#include <stdint.h>
#include <stddef.h>

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
                /* Locate the packet template whose tmpl_id matches. */
                mdn_packet_template_t *tmpl = NULL;
                for (uint32_t t = 0; t < ctx->template_count; t++) {
                    if (ctx->templates[t].tmpl_id == q->template_id) {
                        tmpl = &ctx->templates[t];
                        break;
                    }
                }
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
