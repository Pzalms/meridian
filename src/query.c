#include <stdlib.h>
#include <string.h>
#include "query.h"
#include "session.h"
#include "dag.h"
#include "export.h"
#include "zone.h"
#include "prefix.h"
#include "template.h"
#include "audit.h"

/* ------------------------------------------------------------------ */
/* Internal helpers                                                     */
/* ------------------------------------------------------------------ */

static inline uint16_t read_u16(const uint8_t *p)
{
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

static inline uint32_t read_u32(const uint8_t *p)
{
    return (uint32_t)p[0]
         | ((uint32_t)p[1] << 8)
         | ((uint32_t)p[2] << 16)
         | ((uint32_t)p[3] << 24);
}

/* ------------------------------------------------------------------ */
/* query_load                                                           */
/* ------------------------------------------------------------------ */

int query_load(mdn_ctx_t *ctx, const uint8_t *data, uint32_t len)
{
    if (!ctx || !data) return -1;

    const uint32_t rec_size = 12; /* query_id(2) + start_rule(2) + zone_id(2) + template_id(2) + flags(4) */
    if (len < rec_size) return -1;
    uint32_t count = len / rec_size;
    if (count > MDN_MAX_QUERIES) count = MDN_MAX_QUERIES;

    for (uint32_t i = 0; i < count; i++) {
        const uint8_t *p = data + i * rec_size;
        ctx->queries[i].query_id    = read_u16(p + 0);
        ctx->queries[i].start_rule  = read_u16(p + 2);
        ctx->queries[i].zone_id     = read_u16(p + 4);
        ctx->queries[i].template_id = read_u16(p + 6);
        ctx->queries[i].flags       = read_u32(p + 8);
    }

    ctx->query_count = (uint16_t)count;
    return 0;
}

/* ------------------------------------------------------------------ */
/* query_run_all                                                        */
/* ------------------------------------------------------------------ */

int query_run_all(mdn_ctx_t *ctx)
{
    if (!ctx) return -1;

    for (uint16_t i = 0; i < ctx->query_count; i++) {
        mdn_query_t *q = &ctx->queries[i];
        uint32_t action_out = 0;

        session_cursor_open(ctx, q->zone_id, q->query_id);
        dag_evaluate(ctx, q, &action_out);

        if (ctx->export_count > 0) {
            export_emit_fields(&ctx->exports[0], ctx);
        }
    }

    return 0;
}

/* ------------------------------------------------------------------ */
/* policy_patch_apply                                                   */
/* ------------------------------------------------------------------ */

#define OP_MERGE_ZONES        0x01
#define OP_NORMALIZE_PREFIXES 0x02
#define OP_SWAP_TEMPLATE      0x03
#define OP_COMPACT_AUDIT      0x04
#define OP_TRANSITION_EXPORT  0x05

int policy_patch_apply(mdn_ctx_t *ctx, const uint8_t *data, uint32_t len)
{
    if (!ctx || !data) return -1;

    uint32_t pos = 0;

    while (pos + 3 <= len) {
        uint8_t  op_type = data[pos];
        uint16_t op_len  = read_u16(data + pos + 1);
        pos += 3;

        /* Guard: ensure op_data is fully within buffer */
        if (pos + op_len > len) break;

        const uint8_t *op_data = data + pos;

        switch (op_type) {
        case OP_MERGE_ZONES: {
            if (op_len < 4) break;
            uint16_t zone_a = read_u16(op_data + 0);
            uint16_t zone_b = read_u16(op_data + 2);
            zone_merge(ctx, zone_a, zone_b);
            break;
        }

        case OP_NORMALIZE_PREFIXES: {
            if (ctx->cap_ok)
                prefix_normalize_pages(ctx);
            break;
        }

        case OP_SWAP_TEMPLATE: {
            if (op_len < 4) break;
            uint16_t tmpl_id    = read_u16(op_data + 0);
            uint16_t desc_count = read_u16(op_data + 2);
            uint32_t descs_size = (uint32_t)desc_count * sizeof(mdn_tmpl_desc_t);
            if (op_len < (uint32_t)(4 + descs_size)) break;

            mdn_tmpl_desc_t *descs = NULL;
            if (desc_count > 0) {
                descs = malloc(descs_size);
                if (!descs) break;
                memcpy(descs, op_data + 4, descs_size);
            }
            if (ctx->cap_ok) {
                /* cap_ok: template_swap_profile takes ownership of descs */
                template_swap_profile(ctx, tmpl_id, descs, desc_count);
            } else {
                free(descs);
            }
            break;
        }

        case OP_COMPACT_AUDIT: {
            if (op_len < 2) break;
            if (!ctx->cap_ok) break;
            uint16_t win_id = read_u16(op_data + 0);
            for (uint32_t w = 0; w < ctx->audit_count; w++) {
                if (ctx->audit_windows[w].win_id == win_id) {
                    audit_compact_window(&ctx->audit_windows[w]);
                    break;
                }
            }
            break;
        }

        case OP_TRANSITION_EXPORT: {
            if (op_len < 4) break;
            uint16_t profile_id  = read_u16(op_data + 0);
            uint16_t field_count = read_u16(op_data + 2);
            uint32_t fields_size = (uint32_t)field_count * sizeof(mdn_export_field_t);
            if (op_len < (uint32_t)(4 + fields_size)) break;

            mdn_export_field_t *fields = NULL;
            if (field_count > 0) {
                fields = malloc(fields_size);
                if (!fields) break;
                memcpy(fields, op_data + 4, fields_size);
            }
            if (ctx->cap_ok) {
                /* cap_ok: export_transition_profile takes ownership of fields */
                export_transition_profile(ctx, profile_id, fields, field_count);
            } else {
                free(fields);
            }
            break;
        }

        default:
            /* unknown op type — skip silently */
            break;
        }

        pos += op_len;
    }

    return 0;
}
