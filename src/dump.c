#include <stdio.h>
#include "dump.h"
#include "util.h"

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
/* dump_prefix_pages                                                    */
/* Prints all non-NULL prefix pages: page_id, kind, stride,           */
/* item_count, and dir_count.                                          */
/* ------------------------------------------------------------------ */

void dump_prefix_pages(mdn_ctx_t *ctx)
{
    if (!ctx) return;
    printf("=== prefix_pages ===\n");
    for (int i = 0; i < MDN_MAX_PREFIX_PAGES; i++) {
        mdn_prefix_page_t *pg = ctx->prefix_pages[i];
        if (!pg) continue;
        printf("  page_id=%u kind=%u stride=%u item_count=%u dir_count=%u\n",
               (unsigned)pg->page_id,
               (unsigned)pg->kind,
               (unsigned)pg->stride,
               (unsigned)pg->item_count,
               (unsigned)pg->dir_count);
    }
}

/* ------------------------------------------------------------------ */
/* dump_audit_windows                                                   */
/* Prints all audit windows: win_id, flags, heap_len, dir_count.      */
/* ------------------------------------------------------------------ */

void dump_audit_windows(mdn_ctx_t *ctx)
{
    if (!ctx) return;
    printf("=== audit_windows (count=%u) ===\n", (unsigned)ctx->audit_count);
    for (uint32_t i = 0; i < ctx->audit_count; i++) {
        mdn_audit_window_t *w = &ctx->audit_windows[i];
        printf("  win_id=%u flags=0x%04x heap_len=%u dir_count=%u\n",
               (unsigned)w->win_id,
               (unsigned)w->flags,
               (unsigned)w->heap_len,
               (unsigned)w->dir_count);
    }
}

/* ------------------------------------------------------------------ */
/* dump_exports                                                         */
/* Prints all export profiles: profile_id, mode, field_count,         */
/* frame_cap.                                                           */
/* ------------------------------------------------------------------ */

void dump_exports(mdn_ctx_t *ctx)
{
    if (!ctx) return;
    printf("=== export_profiles (count=%u) ===\n", (unsigned)ctx->export_count);
    for (uint32_t i = 0; i < ctx->export_count; i++) {
        mdn_export_profile_t *ep = &ctx->exports[i];
        printf("  profile_id=%u mode=%u field_count=%u frame_cap=%u\n",
               (unsigned)ep->profile_id,
               (unsigned)ep->mode,
               (unsigned)ep->field_count,
               (unsigned)ep->frame_cap);
    }
}

/* ------------------------------------------------------------------ */
/* dump_sessions                                                        */
/* Prints each non-NULL NAT bucket along with its session count.       */
/* ------------------------------------------------------------------ */

void dump_sessions(mdn_ctx_t *ctx)
{
    if (!ctx) return;
    printf("=== sessions (by nat bucket) ===\n");
    for (int i = 0; i < MDN_MAX_NAT_BUCKETS; i++) {
        mdn_nat_bucket_t *b = ctx->nat_buckets[i];
        if (!b) continue;
        printf("  bucket_id=%u session_count=%u\n",
               (unsigned)b->bucket_id,
               (unsigned)b->slot_count);
    }
}

/* ------------------------------------------------------------------ */
/* dump_hex_section                                                     */
/* Hex-dumps a raw section payload using mdn_hex_dump.                */
/* ------------------------------------------------------------------ */

void dump_hex_section(const uint8_t *data, uint32_t len)
{
    if (!data || !len) return;
    printf("=== section payload (%u bytes) ===\n", (unsigned)len);
    mdn_hex_dump(data, len, stdout);
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
    dump_prefix_pages(ctx);
    dump_audit_windows(ctx);
    dump_exports(ctx);
    dump_sessions(ctx);
}
