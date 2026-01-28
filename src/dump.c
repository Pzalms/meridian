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

#include <string.h>
#include <ctype.h>

/* ================================================================== */
/* dump_hex_region                                                      */
/* Hex dump with configurable columns (like mdn_hex_dump but no        */
/* fixed 16-col assumption).                                            */
/* ================================================================== */
void dump_hex_region(const uint8_t *buf, size_t len, size_t line_width)
{
    if (!buf || !len) return;
    if (!line_width || line_width > 64) line_width = 16;

    for (size_t off = 0; off < len; off += line_width) {
        printf("%08zx  ", off);
        for (size_t c = 0; c < line_width; c++) {
            if (off + c < len)
                printf("%02x ", (unsigned)buf[off + c]);
            else
                printf("   ");
        }
        printf(" |");
        for (size_t c = 0; c < line_width && off + c < len; c++) {
            unsigned char ch = buf[off + c];
            printf("%c", isprint(ch) ? (char)ch : '.');
        }
        printf("|\n");
    }
}

/* ================================================================== */
/* dump_section_header                                                  */
/* ================================================================== */
void dump_section_header(uint8_t sect_type, uint32_t sect_len, uint32_t offset)
{
    static const char *sect_names[] = {
        "unknown",    /* 0x00 */
        "cap",        /* 0x01 */
        "zone",       /* 0x02 */
        "rule",       /* 0x03 */
        "prefix",     /* 0x04 */
        "nat",        /* 0x05 */
        "session",    /* 0x06 */
        "template",   /* 0x07 */
        "audit",      /* 0x08 */
        "export",     /* 0x09 */
        "policy",     /* 0x0A */
        "query",      /* 0x0B */
    };
    const char *name = (sect_type < 12) ? sect_names[sect_type] : "unknown";
    printf("  [%08x] type=0x%02x (%s) len=%u\n",
           (unsigned)offset, (unsigned)sect_type, name, (unsigned)sect_len);
}

/* ================================================================== */
/* dump_mdn_summary                                                     */
/* ================================================================== */
void dump_mdn_summary(mdn_ctx_t *ctx)
{
    if (!ctx) return;

    uint32_t zone_count = 0;
    for (int i = 0; i < MDN_MAX_ZONES; i++)
        if (ctx->zones[i]) zone_count++;

    uint32_t nat_count = 0;
    for (int i = 0; i < MDN_MAX_NAT_BUCKETS; i++)
        if (ctx->nat_buckets[i]) nat_count++;

    uint32_t prefix_count = 0;
    for (int i = 0; i < MDN_MAX_PREFIX_PAGES; i++)
        if (ctx->prefix_pages[i]) prefix_count++;

    printf("=== mdn_ctx summary ===\n");
    printf("  flags:          0x%04x\n", (unsigned)ctx->flags);
    printf("  cap_ok:         %d\n",     ctx->cap_ok);
    printf("  zones:          %u\n",     (unsigned)zone_count);
    printf("  rules:          %u\n",     (unsigned)ctx->rule_count);
    printf("  nat_buckets:    %u\n",     (unsigned)nat_count);
    printf("  prefix_pages:   %u\n",     (unsigned)prefix_count);
    printf("  templates:      %u\n",     (unsigned)ctx->template_count);
    printf("  audit_windows:  %u\n",     (unsigned)ctx->audit_count);
    printf("  export_profiles:%u\n",     (unsigned)ctx->export_count);
    printf("  queries:        %u\n",     (unsigned)ctx->query_count);
    printf("  cursors:        %u\n",     (unsigned)ctx->cursor_count);
    printf("  crc_mismatches: %u\n",     (unsigned)ctx->stats_crc_miss);
    printf("  sections_loaded:%u\n",     (unsigned)ctx->stats_sections_loaded);
}

/* ================================================================== */
/* dump_rule_node_str                                                   */
/* ================================================================== */
int dump_rule_node_str(const mdn_rule_node_t *r, char *buf, size_t buf_cap)
{
    if (!r || !buf || !buf_cap) return -1;

    static const char *action_names[] = {
        "ALLOW", "DROP", "MARK", "REDIRECT",
        "NAT_LOOKUP", "TRIE_LOOKUP", "AUDIT_EXPORT"
    };
    const char *aname = (r->action < 7) ? action_names[r->action] : "UNKNOWN";

    int n = snprintf(buf, buf_cap,
        "rule{key=0x%08x mask=0x%08x action=%s(%u) next=%u}",
        (unsigned)r->key, (unsigned)r->mask,
        aname, (unsigned)r->action, (unsigned)r->next);
    return n;
}

/* ================================================================== */
/* dump_rule_chain                                                      */
/* ================================================================== */
void dump_rule_chain(mdn_ctx_t *ctx, uint32_t start_rule, uint32_t max_depth)
{
    if (!ctx || !ctx->rules) return;
    if (start_rule >= ctx->rule_count) return;
    if (!max_depth) max_depth = ctx->rule_count;

    char buf[256];
    uint32_t cur   = start_rule;
    uint32_t depth = 0;

    printf("=== rule chain from rule %u ===\n", (unsigned)start_rule);
    while (cur < ctx->rule_count && depth < max_depth) {
        mdn_rule_node_t *r = &ctx->rules[cur];
        dump_rule_node_str(r, buf, sizeof(buf));
        printf("  [%3u] %s\n", (unsigned)cur, buf);

        /* Follow the chain if next != cur and next is valid. */
        if (r->next == cur || r->next >= ctx->rule_count)
            break;
        cur = r->next;
        depth++;
    }
}

/* ================================================================== */
/* dump_counts                                                          */
/* ================================================================== */
void dump_counts(mdn_ctx_t *ctx)
{
    if (!ctx) return;
    printf("=== object counts ===\n");
    printf("  rule_count:      %u\n", (unsigned)ctx->rule_count);
    printf("  template_count:  %u\n", (unsigned)ctx->template_count);
    printf("  audit_count:     %u\n", (unsigned)ctx->audit_count);
    printf("  export_count:    %u\n", (unsigned)ctx->export_count);
    printf("  query_count:     %u\n", (unsigned)ctx->query_count);
    printf("  cursor_count:    %u\n", (unsigned)ctx->cursor_count);
}

/* ================================================================== */
/* dump_audit_detail                                                    */
/* ================================================================== */
void dump_audit_detail(mdn_ctx_t *ctx)
{
    if (!ctx) return;
    printf("=== audit windows (detail, count=%u) ===\n", (unsigned)ctx->audit_count);
    for (uint32_t i = 0; i < ctx->audit_count; i++) {
        mdn_audit_window_t *w = &ctx->audit_windows[i];
        printf("  win_id=%u flags=0x%04x heap_len=%u dir_count=%u\n",
               (unsigned)w->win_id, (unsigned)w->flags,
               (unsigned)w->heap_len, (unsigned)w->dir_count);
        if (w->dir) {
            uint32_t show = w->dir_count < 8 ? w->dir_count : 8;
            for (uint32_t d = 0; d < show; d++) {
                printf("    dir[%u]: off=%u len=%u kind=%u\n",
                       (unsigned)d,
                       (unsigned)w->dir[d].off,
                       (unsigned)w->dir[d].len,
                       (unsigned)w->dir[d].kind);
            }
            if (w->dir_count > 8)
                printf("    ... (%u more)\n", (unsigned)(w->dir_count - 8));
        }
    }
}

/* ================================================================== */
/* dump_export_fields                                                   */
/* ================================================================== */
void dump_export_fields(mdn_ctx_t *ctx)
{
    if (!ctx) return;
    printf("=== export fields (profiles=%u) ===\n", (unsigned)ctx->export_count);
    for (uint32_t i = 0; i < ctx->export_count; i++) {
        mdn_export_profile_t *ep = &ctx->exports[i];
        printf("  profile_id=%u mode=%u field_count=%u frame_cap=%u\n",
               (unsigned)ep->profile_id, (unsigned)ep->mode,
               (unsigned)ep->field_count, (unsigned)ep->frame_cap);
        if (ep->fields) {
            uint32_t show = ep->field_count < 16 ? ep->field_count : 16;
            for (uint32_t f = 0; f < show; f++) {
                printf("    field[%u]: id=%u off=%u width=%u src=%u\n",
                       (unsigned)f,
                       (unsigned)ep->fields[f].field_id,
                       (unsigned)ep->fields[f].offset,
                       (unsigned)ep->fields[f].width,
                       (unsigned)ep->fields[f].source);
            }
        }
    }
}

/* ================================================================== */
/* dump_prefix_items                                                    */
/* ================================================================== */
void dump_prefix_items(mdn_ctx_t *ctx, uint32_t page_id, uint32_t max_items)
{
    if (!ctx) return;
    if (page_id >= MDN_MAX_PREFIX_PAGES) return;
    mdn_prefix_page_t *pg = ctx->prefix_pages[page_id];
    if (!pg) { printf("prefix page %u: not loaded\n", (unsigned)page_id); return; }

    if (!max_items || max_items > pg->item_count)
        max_items = pg->item_count;

    printf("=== prefix page %u (kind=%u stride=%u items=%u) ===\n",
           (unsigned)pg->page_id, (unsigned)pg->kind,
           (unsigned)pg->stride, (unsigned)pg->item_count);

    if (pg->items && pg->stride) {
        for (uint32_t i = 0; i < max_items; i++) {
            uint8_t *item = pg->items + (size_t)i * pg->stride;
            printf("  item[%4u]: ", (unsigned)i);
            uint32_t show = pg->stride < 16 ? pg->stride : 16;
            for (uint32_t b = 0; b < show; b++)
                printf("%02x ", (unsigned)item[b]);
            if (pg->stride > 16) printf("...");
            printf("\n");
        }
    }
}
