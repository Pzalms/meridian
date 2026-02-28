#include <stdio.h>
#include "dump.h"

/* ------------------------------------------------------------------ */
/* dump_zones                                                           */
/* ------------------------------------------------------------------ */

void dump_zones(mdn_ctx_t *ctx)
{
    if (!ctx) return;
    printf("=== zones ===\n");
    for (int i = 0; i < MDN_MAX_ZONES; i++) {
        mdn_zone_t *z = ctx->zones[i];
        if (!z) continue;
        printf("  zone_id=%u parent_id=%u if_count=%u flags=0x%04x epoch=%u\n",
               (unsigned)z->zone_id,
               (unsigned)z->parent_id,
               (unsigned)z->if_count,
               (unsigned)z->flags,
               (unsigned)z->epoch);
    }
}

/* ------------------------------------------------------------------ */
/* dump_rules                                                           */
/* ------------------------------------------------------------------ */

void dump_rules(mdn_ctx_t *ctx)
{
    if (!ctx) return;
    printf("=== rules (count=%u) ===\n", (unsigned)ctx->rule_count);
    for (uint32_t i = 0; i < ctx->rule_count; i++) {
        mdn_rule_node_t *r = &ctx->rules[i];
        printf("  [%u] key=0x%08x mask=0x%08x action=%u next=%u\n",
               (unsigned)i,
               (unsigned)r->key,
               (unsigned)r->mask,
               (unsigned)r->action,
               (unsigned)r->next);
    }
}

/* ------------------------------------------------------------------ */
/* dump_nat                                                             */
/* ------------------------------------------------------------------ */

void dump_nat(mdn_ctx_t *ctx)
{
    if (!ctx) return;
    printf("=== nat_buckets ===\n");
    for (int i = 0; i < MDN_MAX_NAT_BUCKETS; i++) {
        mdn_nat_bucket_t *b = ctx->nat_buckets[i];
        if (!b) continue;
        printf("  bucket_id=%u zone_id=%u slot_count=%u epoch=%u\n",
               (unsigned)b->bucket_id,
               (unsigned)b->zone_id,
               (unsigned)b->slot_count,
               (unsigned)b->epoch);
    }
}

/* ------------------------------------------------------------------ */
/* dump_templates                                                       */
/* ------------------------------------------------------------------ */

void dump_templates(mdn_ctx_t *ctx)
{
    if (!ctx) return;
    printf("=== templates (count=%u) ===\n", (unsigned)ctx->template_count);
    for (uint32_t i = 0; i < ctx->template_count; i++) {
        mdn_packet_template_t *t = &ctx->templates[i];
        printf("  tmpl_id=%u hdr_len=%u frag_count=%u flags=0x%04x desc_count=%u profile=%u\n",
               (unsigned)t->tmpl_id,
               (unsigned)t->hdr_len,
               (unsigned)t->frag_count,
               (unsigned)t->flags,
               (unsigned)t->desc_count,
               (unsigned)t->profile);
    }
}

/* ------------------------------------------------------------------ */
/* dump_queries                                                         */
/* ------------------------------------------------------------------ */

void dump_queries(mdn_ctx_t *ctx)
{
    if (!ctx) return;
    printf("=== queries (count=%u) ===\n", (unsigned)ctx->query_count);
    for (uint16_t i = 0; i < ctx->query_count; i++) {
        mdn_query_t *q = &ctx->queries[i];
        printf("  query_id=%u start_rule=%u zone_id=%u template_id=%u flags=0x%08x\n",
               (unsigned)q->query_id,
               (unsigned)q->start_rule,
               (unsigned)q->zone_id,
               (unsigned)q->template_id,
               (unsigned)q->flags);
    }
}

/* ------------------------------------------------------------------ */
/* dump_all                                                             */
/* ------------------------------------------------------------------ */

void dump_all(mdn_ctx_t *ctx)
{
    dump_zones(ctx);
    dump_rules(ctx);
    dump_nat(ctx);
    dump_templates(ctx);
    dump_queries(ctx);
}
