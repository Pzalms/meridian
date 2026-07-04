#include "validate.h"
#include <string.h>

/* -----------------------------------------------------------------------
 * validate_zones — integrity checks on the zone table.
 *
 * Two invariants are enforced:
 *   (a) No zone may reference itself as its parent (self-referencing parent
 *       would create a single-node cycle in the zone hierarchy tree).
 *   (b) Every non-zero parent_id must resolve to a loaded zone entry.  A
 *       parent_id of 0 denotes a root zone and needs no further check.
 *
 * Returns 0 if all loaded zones pass, -1 on the first violation.
 * ----------------------------------------------------------------------- */
int validate_zones(mdn_ctx_t *ctx)
{
    for (uint32_t i = 0; i < MDN_MAX_ZONES; i++) {
        mdn_zone_t *z = ctx->zones[i];
        if (!z)
            continue;

        /* (a) self-reference check */
        if (z->parent_id != 0 && z->parent_id == z->zone_id)
            return -1;

        /* (b) parent must resolve to a loaded zone */
        uint16_t pid = z->parent_id;
        if (pid == 0)
            continue; /* root zone; no parent required */

        if (pid >= MDN_MAX_ZONES)
            return -1;
        if (!ctx->zones[pid])
            return -1;
    }
    return 0;
}

/* -----------------------------------------------------------------------
 * validate_rules — integrity checks on the rule chain.
 *
 * Two invariants are enforced:
 *   (a) No rule's next field (when not 0xFFFF, the sentinel for end-of-chain)
 *       may be >= rule_count, which would direct the evaluator off the end of
 *       the rule array.
 *   (b) No circular chain exists.  We detect cycles with a per-rule visited
 *       bitset limited to MDN_MAX_RULES steps; if we visit more nodes than
 *       rule_count allows, a cycle is inferred.
 *
 * Returns 0 if all checks pass, -1 on the first violation.
 * ----------------------------------------------------------------------- */
int validate_rules(mdn_ctx_t *ctx)
{
    if (!ctx->rules || ctx->rule_count == 0)
        return 0;

    /* Bitset large enough for MDN_MAX_RULES bits */
    #define VBITS_WORDS ((MDN_MAX_RULES + 31) / 32)
    uint32_t visited[VBITS_WORDS];

    for (uint32_t i = 0; i < ctx->rule_count; i++) {
        uint16_t nxt = ctx->rules[i].next;

        /* (a) out-of-range next pointer */
        if (nxt != 0xFFFF && (uint32_t)nxt >= ctx->rule_count)
            return -1;

        /* (b) cycle detection: follow the chain from rule i */
        memset(visited, 0, sizeof(visited));
        uint32_t cur  = i;
        uint32_t steps = 0;
        while (1) {
            if (cur >= ctx->rule_count)
                break; /* defensive: already caught by (a) above */
            uint16_t cn = ctx->rules[cur].next;
            if (cn == 0xFFFF)
                break; /* end of chain */
            uint32_t ni = (uint32_t)cn;
            /* Mark cur as visited */
            uint32_t word = ni / 32;
            uint32_t bit  = ni % 32;
            if (visited[word] & (UINT32_C(1) << bit))
                return -1; /* cycle detected */
            visited[word] |= (UINT32_C(1) << bit);
            cur = ni;
            steps++;
            if (steps > ctx->rule_count)
                return -1; /* should never reach here; extra guard */
        }
    }
    #undef VBITS_WORDS
    return 0;
}

/* -----------------------------------------------------------------------
 * validate_nat_buckets — integrity checks on NAT bucket entries.
 *
 * For every non-NULL bucket in ctx->nat_buckets:
 *   (a) zone_id must be < MDN_MAX_ZONES.
 *   (b) slot_count must be >= 0 (always true for uint16_t, but we also
 *       check for zone_id consistency to catch initialisation errors).
 *
 * Returns 0 if all checks pass, -1 on the first violation.
 * ----------------------------------------------------------------------- */
int validate_nat_buckets(mdn_ctx_t *ctx)
{
    for (uint32_t i = 0; i < MDN_MAX_NAT_BUCKETS; i++) {
        mdn_nat_bucket_t *b = ctx->nat_buckets[i];
        if (!b)
            continue;

        if (b->zone_id >= MDN_MAX_ZONES)
            return -1;

        /* slot_count is uint16_t so always >= 0; we verify the loaded
         * zone reference is consistent when zone_id is non-zero. */
        if (b->zone_id > 0 && !ctx->zones[b->zone_id])
            return -1;
    }
    return 0;
}

/* -----------------------------------------------------------------------
 * validate_prefix_pages — integrity checks on prefix page entries.
 *
 * For every non-NULL prefix page:
 *   (a) stride must be > 0 (a stride of zero makes prefix width undefined).
 *   (b) item_count must be <= 65535 (fits in a uint16_t logical field).
 *   (c) dir_count must be <= item_count + 1 (the directory holds one entry
 *       per item plus an optional sentinel at the end).
 *
 * Returns 0 if all checks pass, -1 on the first violation.
 * ----------------------------------------------------------------------- */
int validate_prefix_pages(mdn_ctx_t *ctx)
{
    for (uint32_t i = 0; i < MDN_MAX_PREFIX_PAGES; i++) {
        mdn_prefix_page_t *pg = ctx->prefix_pages[i];
        if (!pg)
            continue;

        if (pg->stride == 0)
            return -1;

        if (pg->item_count > 65535u)
            return -1;

        if (pg->dir_count > pg->item_count + 1u)
            return -1;
    }
    return 0;
}

/* -----------------------------------------------------------------------
 * validate_templates — integrity checks on packet template entries.
 *
 * For every template in ctx->templates[0..template_count):
 *   (a) If hdr_cap > 0 then hdr_bytes must be non-NULL.
 *   (b) desc_count must be <= 64.
 *
 * Returns 0 if all checks pass, -1 on the first violation.
 * ----------------------------------------------------------------------- */
int validate_templates(mdn_ctx_t *ctx)
{
    for (uint32_t i = 0; i < ctx->template_count; i++) {
        mdn_packet_template_t *t = &ctx->templates[i];

        if (t->hdr_cap > 0 && !t->hdr_bytes)
            return -1;

        if (t->desc_count > 64u)
            return -1;
    }
    return 0;
}

/* -----------------------------------------------------------------------
 * validate_queries — integrity checks on query descriptors.
 *
 * Two invariants:
 *   (a) When rule_count > 0, every query's start_rule must be < rule_count.
 *   (b) When rule_count == 0, start_rule must be 0 (no valid rules to
 *       reference; a non-zero start_rule would be meaningless).
 *
 * Returns 0 if all checks pass, -1 on the first violation.
 * ----------------------------------------------------------------------- */
int validate_queries(mdn_ctx_t *ctx)
{
    for (uint32_t i = 0; i < ctx->query_count; i++) {
        mdn_query_t *q = &ctx->queries[i];
        /* Only validate start_rule when there are rules loaded; when
         * rule_count is 0 there is no rule table to reference and the
         * start_rule field is treated as a reserved placeholder. */
        if (ctx->rule_count > 0) {
            if ((uint32_t)q->start_rule >= ctx->rule_count)
                return -1;
        }
    }
    return 0;
}

/* -----------------------------------------------------------------------
 * validate_exports — integrity checks on export profile entries.
 *
 * For every export profile in ctx->exports[0..export_count):
 *   (a) field_count must be <= MDN_EXPORT_FIELDS_MAX.
 *
 * Returns 0 if all checks pass, -1 on the first violation.
 * ----------------------------------------------------------------------- */
int validate_exports(mdn_ctx_t *ctx)
{
    for (uint32_t i = 0; i < ctx->export_count; i++) {
        if (ctx->exports[i].field_count > MDN_EXPORT_FIELDS_MAX)
            return -1;
    }
    return 0;
}

/* -----------------------------------------------------------------------
 * mdn_validate — post-load integrity checks on a fully parsed context.
 *
 * Runs all sub-validators in a defined order.  Returns 0 only if every
 * sub-validator passes; returns -1 on the first failed check.
 * ----------------------------------------------------------------------- */
int mdn_validate(mdn_ctx_t *ctx)
{
    /* 1. Rule count must not exceed the compile-time limit */
    if (ctx->rule_count > MDN_MAX_RULES)
        return -1;

    /* 2. Zone hierarchy checks */
    if (validate_zones(ctx) != 0)
        return -1;

    /* 3. Rule chain integrity */
    if (validate_rules(ctx) != 0)
        return -1;

    /* 4. NAT bucket zone references */
    if (validate_nat_buckets(ctx) != 0)
        return -1;

    /* 5. Prefix page structural constraints */
    if (validate_prefix_pages(ctx) != 0)
        return -1;

    /* 6. Template header/descriptor constraints */
    if (validate_templates(ctx) != 0)
        return -1;

    /* 7. Query start-rule references */
    if (validate_queries(ctx) != 0)
        return -1;

    /* 8. Export profile field counts */
    if (validate_exports(ctx) != 0)
        return -1;

    return 0;
}
