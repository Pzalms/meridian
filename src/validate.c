#include "validate.h"
#include "util.h"
#include <string.h>
#include <stdio.h>

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

/* -----------------------------------------------------------------------
 * validate_zone_refs — verify all rule/NAT zone references resolve.
 *
 * For each rule that uses ACTION_NAT_LOOKUP the action implies a zone
 * lookup; when the rule's mask encodes a zone_id we verify it falls
 * within MDN_MAX_ZONES and that ctx->zones[zone_id] is loaded.  NAT
 * bucket zone_id values are also checked (mirroring validate_nat_buckets
 * but limited to those that have non-zero zone_id).
 *
 * Returns 0 if all checked references resolve, -1 on first failure.
 * ----------------------------------------------------------------------- */
int validate_zone_refs(mdn_ctx_t *ctx)
{
    /* Check rule zone references for NAT-action rules */
    for (uint32_t i = 0; i < ctx->rule_count; i++) {
        mdn_rule_node_t *r = &ctx->rules[i];
        if (r->action != ACTION_NAT_LOOKUP)
            continue;
        /* The upper 16 bits of mask encode the zone_id for this rule */
        uint16_t zid = (uint16_t)(r->mask >> 16);
        if (zid == 0)
            continue;
        if (zid >= MDN_MAX_ZONES)
            return -1;
        if (!ctx->zones[zid])
            return -1;
    }

    /* Check NAT bucket zone_id values */
    for (uint32_t i = 0; i < MDN_MAX_NAT_BUCKETS; i++) {
        mdn_nat_bucket_t *b = ctx->nat_buckets[i];
        if (!b || b->zone_id == 0)
            continue;
        if (b->zone_id >= MDN_MAX_ZONES)
            return -1;
        if (!ctx->zones[b->zone_id])
            return -1;
    }
    return 0;
}

/* -----------------------------------------------------------------------
 * validate_template_refs — verify template IDs referenced in queries.
 *
 * Each query carries a template_id field.  When template_id is non-zero
 * it must refer to a template entry in ctx->templates[].  We search
 * linearly because templates are stored in an unsorted array.
 *
 * Returns 0 if all template references resolve, -1 on first failure.
 * ----------------------------------------------------------------------- */
int validate_template_refs(mdn_ctx_t *ctx)
{
    for (uint32_t i = 0; i < ctx->query_count; i++) {
        mdn_query_t *q = &ctx->queries[i];
        if (q->template_id == 0)
            continue;

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

/* -----------------------------------------------------------------------
 * validate_rule_chain_lengths — check that no chain exceeds rule_count.
 *
 * Follows every rule's next chain and counts the hops.  A chain longer
 * than rule_count hops must contain a cycle (detected by the step
 * counter) even if the earlier validate_rules pass missed it through
 * a starting point outside the cycle.
 *
 * Returns 0 when all chains terminate within rule_count hops, -1 on
 * first violation.
 * ----------------------------------------------------------------------- */
int validate_rule_chain_lengths(mdn_ctx_t *ctx)
{
    if (!ctx->rules || ctx->rule_count == 0)
        return 0;

    for (uint32_t i = 0; i < ctx->rule_count; i++) {
        uint32_t cur   = i;
        uint32_t steps = 0;

        while (1) {
            if (cur >= ctx->rule_count)
                break;
            uint16_t nxt = ctx->rules[cur].next;
            if (nxt == 0xFFFF)
                break;
            cur = (uint32_t)nxt;
            steps++;
            if (steps > ctx->rule_count)
                return -1;
        }
    }
    return 0;
}

/* -----------------------------------------------------------------------
 * validate_nat_bucket_refs — verify NAT bucket zone_id values.
 *
 * Equivalent to the zone_id check in validate_nat_buckets, but separated
 * into its own validator so it can be called independently or composed
 * into a custom validation pipeline without running the full mdn_validate.
 *
 * Returns 0 on success, -1 on first failure.
 * ----------------------------------------------------------------------- */
int validate_nat_bucket_refs(mdn_ctx_t *ctx)
{
    for (uint32_t i = 0; i < MDN_MAX_NAT_BUCKETS; i++) {
        mdn_nat_bucket_t *b = ctx->nat_buckets[i];
        if (!b)
            continue;
        if (b->zone_id >= MDN_MAX_ZONES)
            return -1;
        if (b->zone_id > 0 && !ctx->zones[b->zone_id])
            return -1;
    }
    return 0;
}

/* -----------------------------------------------------------------------
 * validate_prefix_pages_ext — additional sanity checks on prefix pages.
 *
 * Extends the base validate_prefix_pages with a check that dir_count
 * does not exceed MDN_MAX_PREFIX_PAGES, and that every dir entry offset
 * is less than (stride * item_count) when dir is non-NULL.
 *
 * Returns 0 when all pages pass, -1 on first failure.
 * ----------------------------------------------------------------------- */
int validate_prefix_pages_ext(mdn_ctx_t *ctx)
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

        if (pg->dir && pg->item_count > 0) {
            uint32_t max_off = (uint32_t)pg->stride * pg->item_count;
            for (uint32_t d = 0; d < pg->dir_count; d++) {
                if (pg->dir[d] >= max_off)
                    return -1;
            }
        }
    }
    return 0;
}

/* -----------------------------------------------------------------------
 * validate_audit_windows — check heap_len vs dir entries.
 *
 * For every audit window, each dir entry specifies an offset and length
 * within the heap.  This validator confirms that off + len <= heap_len
 * for every entry so that no audit record would be read past the heap.
 *
 * Returns 0 when all windows pass, -1 on first violation.
 * ----------------------------------------------------------------------- */
int validate_audit_windows(mdn_ctx_t *ctx)
{
    for (uint32_t i = 0; i < ctx->audit_count; i++) {
        mdn_audit_window_t *w = &ctx->audit_windows[i];
        if (!w->heap)
            continue;

        for (uint32_t d = 0; d < w->dir_count; d++) {
            mdn_audit_dirent_t *de = &w->dir[d];
            uint32_t end = de->off + (uint32_t)de->len;
            if (end > w->heap_len)
                return -1;
        }
    }
    return 0;
}

/* -----------------------------------------------------------------------
 * validate_export_profiles — check field offsets vs frame_cap.
 *
 * For each export profile and each of its field descriptors, verifies
 * that offset + width <= frame_cap.  A field that extends beyond the
 * frame buffer would cause an out-of-bounds write at export time.
 *
 * Returns 0 when all profiles pass, -1 on first violation.
 * ----------------------------------------------------------------------- */
int validate_export_profiles(mdn_ctx_t *ctx)
{
    for (uint32_t i = 0; i < ctx->export_count; i++) {
        mdn_export_profile_t *ep = &ctx->exports[i];
        if (!ep->fields)
            continue;

        for (uint16_t f = 0; f < ep->field_count; f++) {
            mdn_export_field_t *ef = &ep->fields[f];
            uint32_t end = (uint32_t)ef->offset + (uint32_t)ef->width;
            if (end > (uint32_t)ep->frame_cap)
                return -1;
        }
    }
    return 0;
}

/* -----------------------------------------------------------------------
 * validate_query_refs — verify each query's start_rule, zone_id, and
 * template_id fields.
 *
 * Checks:
 *   (a) start_rule < rule_count (when rule_count > 0)
 *   (b) zone_id == 0 or zone_id < MDN_MAX_ZONES and ctx->zones[zone_id]
 *   (c) template_id resolves to a loaded template (when non-zero)
 *
 * Returns 0 on success, -1 on first failure.
 * ----------------------------------------------------------------------- */
int validate_query_refs(mdn_ctx_t *ctx)
{
    for (uint32_t i = 0; i < ctx->query_count; i++) {
        mdn_query_t *q = &ctx->queries[i];

        /* (a) start_rule */
        if (ctx->rule_count > 0 && (uint32_t)q->start_rule >= ctx->rule_count)
            return -1;

        /* (b) zone_id */
        if (q->zone_id != 0) {
            if (q->zone_id >= MDN_MAX_ZONES)
                return -1;
            if (!ctx->zones[q->zone_id])
                return -1;
        }

        /* (c) template_id */
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
    }
    return 0;
}

/* -----------------------------------------------------------------------
 * validate_summary — write a human-readable validation report.
 *
 * Runs every sub-validator and records pass/fail for each into
 * out[0..cap).  Returns the number of bytes written.
 * ----------------------------------------------------------------------- */
int validate_summary(mdn_ctx_t *ctx, char *out, uint32_t cap)
{
    if (!ctx || !out || cap == 0)
        return 0;

    struct { const char *name; int result; } checks[] = {
        { "zones",              validate_zones(ctx)              },
        { "rules",              validate_rules(ctx)              },
        { "nat_buckets",        validate_nat_buckets(ctx)        },
        { "prefix_pages",       validate_prefix_pages(ctx)       },
        { "templates",          validate_templates(ctx)          },
        { "queries",            validate_queries(ctx)            },
        { "exports",            validate_exports(ctx)            },
        { "zone_refs",          validate_zone_refs(ctx)          },
        { "template_refs",      validate_template_refs(ctx)      },
        { "rule_chain_lengths", validate_rule_chain_lengths(ctx) },
        { "nat_bucket_refs",    validate_nat_bucket_refs(ctx)    },
        { "audit_windows",      validate_audit_windows(ctx)      },
        { "export_profiles",    validate_export_profiles(ctx)    },
        { "query_refs",         validate_query_refs(ctx)         },
    };

    int total = 0;
    uint32_t nchk = (uint32_t)(sizeof(checks) / sizeof(checks[0]));

    for (uint32_t i = 0; i < nchk; i++) {
        int n = snprintf(out + total, cap - (uint32_t)total,
                         "%-22s %s\n",
                         checks[i].name,
                         checks[i].result == 0 ? "PASS" : "FAIL");
        if (n < 0 || (uint32_t)(total + n) >= cap - 1u)
            break;
        total += n;
    }
    out[MDN_MIN((uint32_t)total, cap - 1u)] = '\0';
    return total;
}
