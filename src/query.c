#include <stdlib.h>
#include <string.h>
#include <stdio.h>
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
    /* enforce hard cap at MDN_MAX_QUERIES */
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

/* ------------------------------------------------------------------ */
/* Query serialization and inspection utilities                         */
/* ------------------------------------------------------------------ */

/*
 * query_serialize — write a single query record to a binary buffer.
 *
 * Wire layout (12 bytes):
 *   [0..1]  query_id    (u16 LE)
 *   [2..3]  start_rule  (u16 LE)
 *   [4..5]  zone_id     (u16 LE)
 *   [6..7]  template_id (u16 LE)
 *   [8..11] flags       (u32 LE)
 *
 * Returns 12 on success, -1 if cap < 12 or q/out are NULL.
 */
int query_serialize(mdn_query_t *q, uint8_t *out, uint32_t cap)
{
    if (!q || !out || cap < 12)
        return -1;

    out[0]  = (uint8_t)(q->query_id);
    out[1]  = (uint8_t)(q->query_id >> 8);
    out[2]  = (uint8_t)(q->start_rule);
    out[3]  = (uint8_t)(q->start_rule >> 8);
    out[4]  = (uint8_t)(q->zone_id);
    out[5]  = (uint8_t)(q->zone_id >> 8);
    out[6]  = (uint8_t)(q->template_id);
    out[7]  = (uint8_t)(q->template_id >> 8);
    out[8]  = (uint8_t)(q->flags);
    out[9]  = (uint8_t)(q->flags >> 8);
    out[10] = (uint8_t)(q->flags >> 16);
    out[11] = (uint8_t)(q->flags >> 24);

    return 12;
}

/*
 * query_deserialize — parse a query record from a binary buffer.
 *
 * Expects exactly the 12-byte wire format produced by query_serialize.
 * Writes the decoded fields into *q_out.
 *
 * Returns 0 on success, -1 if data is NULL, len < 12, or q_out is NULL.
 */
int query_deserialize(const uint8_t *data, uint32_t len, mdn_query_t *q_out)
{
    if (!data || !q_out || len < 12)
        return -1;

    q_out->query_id    = (uint16_t)(data[0] | ((uint16_t)data[1] << 8));
    q_out->start_rule  = (uint16_t)(data[2] | ((uint16_t)data[3] << 8));
    q_out->zone_id     = (uint16_t)(data[4] | ((uint16_t)data[5] << 8));
    q_out->template_id = (uint16_t)(data[6] | ((uint16_t)data[7] << 8));
    q_out->flags       = (uint32_t)data[8]
                       | ((uint32_t)data[9]  << 8)
                       | ((uint32_t)data[10] << 16)
                       | ((uint32_t)data[11] << 24);

    return 0;
}

/*
 * query_validate — check that a query's referenced entities exist in ctx.
 *
 * Verifies:
 *   - q->start_rule is within ctx->rule_count
 *   - q->zone_id references a non-NULL slot in ctx->zones[]
 *   - q->template_id is 0 (wildcard) OR a matching template exists
 *
 * Returns 0 if all checks pass, -1 if any check fails or args are NULL.
 */
int query_validate(mdn_ctx_t *ctx, mdn_query_t *q)
{
    if (!ctx || !q)
        return -1;

    /* start_rule must be within the loaded rule table */
    if ((uint32_t)q->start_rule >= ctx->rule_count)
        return -1;

    /* zone_id must index a loaded zone */
    if (q->zone_id >= MDN_MAX_ZONES || !ctx->zones[q->zone_id])
        return -1;

    /* template_id == 0 is a wildcard; otherwise require a matching template */
    if (q->template_id != 0) {
        int found = 0;
        for (uint32_t t = 0; t < ctx->template_count; t++) {
            if (ctx->templates[t].tmpl_id == q->template_id) {
                found = 1;
                break;
            }
        }
        if (!found)
            return -1;
    }

    return 0;
}

/*
 * query_dump — format a query record as a human-readable text line.
 *
 * Writes:
 *   qid=<N> rule=<N> zone=<N> tmpl=<N> flags=0x<hex>
 *
 * Returns the number of characters written (excluding NUL), or -1 on error.
 */
int query_dump(mdn_query_t *q, char *out, uint32_t cap)
{
    if (!q || !out || cap == 0)
        return -1;

    int r = snprintf(out, cap,
                     "qid=%u rule=%u zone=%u tmpl=%u flags=0x%08x",
                     (unsigned)q->query_id,
                     (unsigned)q->start_rule,
                     (unsigned)q->zone_id,
                     (unsigned)q->template_id,
                     (unsigned)q->flags);
    if (r < 0 || (uint32_t)r >= cap)
        return -1;

    return r;
}

/*
 * query_clone — copy a query record field-by-field.
 *
 * A simple struct copy; both src and dst must be non-NULL.
 */
void query_clone(mdn_query_t *src, mdn_query_t *dst)
{
    if (!src || !dst)
        return;
    dst->query_id    = src->query_id;
    dst->start_rule  = src->start_rule;
    dst->zone_id     = src->zone_id;
    dst->template_id = src->template_id;
    dst->flags       = src->flags;
}

/*
 * query_find_by_zone — collect query IDs that belong to a given zone.
 *
 * Scans ctx->queries[] for entries whose zone_id matches zone_id, writing
 * each matching query_id into out[].  At most max entries are written.
 *
 * Returns the number of matches found, or -1 on invalid args.
 */
int query_find_by_zone(mdn_ctx_t *ctx, uint16_t zone_id,
                       uint16_t *out, uint32_t max)
{
    if (!ctx || !out || max == 0)
        return -1;

    int count = 0;

    for (uint16_t i = 0; i < ctx->query_count && (uint32_t)count < max; i++) {
        if (ctx->queries[i].zone_id == zone_id)
            out[count++] = ctx->queries[i].query_id;
    }

    return count;
}

/*
 * query_count_by_action — count queries whose DAG evaluation resolves to
 * a given action.
 *
 * Runs dag_evaluate for each query in ctx->queries[] using a temporary
 * action output variable.  The function does NOT modify ctx beyond what
 * dag_evaluate already does.
 *
 * Returns the number of queries that resolved to action, or -1 on error.
 */
int query_count_by_action(mdn_ctx_t *ctx, uint32_t action)
{
    if (!ctx)
        return -1;

    int count = 0;

    for (uint16_t i = 0; i < ctx->query_count; i++) {
        uint32_t result = 0;
        int r = dag_evaluate(ctx, &ctx->queries[i], &result);
        if (r == 0 && result == action)
            count++;
    }

    return count;
}
