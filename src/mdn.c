#include "meridian.h"
#include "mdn_internal.h"
#include "parse.h"
#include "validate.h"
#include "query.h"
#include "zone.h"
#include "nat.h"
#include "session.h"
#include "template.h"
#include "audit.h"
#include "export.h"
#include "prefix.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>

mdn_ctx_t *mdn_load(const uint8_t *buf, size_t len) {
    if (!buf || len == 0) return NULL;
    mdn_ctx_t *ctx = calloc(1, sizeof(mdn_ctx_t));
    if (!ctx) return NULL;
    if (mdn_parse(ctx, buf, len) != 0) { mdn_free(ctx); return NULL; }
    if (mdn_validate(ctx) != 0)        { mdn_free(ctx); return NULL; }
    return ctx;
}

int mdn_run(mdn_ctx_t *ctx) {
    if (!ctx) return -1;
    return query_run_all(ctx);
}

void mdn_free(mdn_ctx_t *ctx) {
    if (!ctx) return;
    zone_free_all(ctx);
    free(ctx->rules);
    for (int i = 0; i < MDN_MAX_PREFIX_PAGES; i++)
        prefix_page_free(ctx->prefix_pages[i]);
    nat_free_all(ctx);
    session_cursors_free(ctx);
    template_free_all(ctx);
    audit_free_all(ctx);
    export_free_all(ctx);
    free(ctx);
}

int mdn_fuzz(const uint8_t *data, size_t len) {
    mdn_ctx_t *ctx = mdn_load(data, len);
    if (!ctx) return 0;
    (void)mdn_run(ctx);
    mdn_free(ctx);
    return 0;
}

/*
 * mdn_ctx_init — zero-initialise a caller-supplied mdn_ctx_t.
 *
 * All pointer fields are set to NULL, numeric fields to 0.  This is
 * equivalent to the calloc initialisation performed inside mdn_load but
 * is exposed for callers that allocate the structure on the stack or in a
 * custom arena.
 */
void mdn_ctx_init(mdn_ctx_t *ctx)
{
    if (!ctx)
        return;
    memset(ctx, 0, sizeof(mdn_ctx_t));
}

/*
 * MDN wire format version constants.
 * Offset 0: magic byte 0x4D ('M'), offset 1: major version, offset 2: minor.
 */
#define MDN_FORMAT_MAGIC    0x4D
#define MDN_FORMAT_MAJOR    1
#define MDN_FORMAT_MINOR_LO 0
#define MDN_FORMAT_MINOR_HI 9

/*
 * mdn_ctx_version_check — inspect the leading bytes of a buffer for
 * format version compatibility.
 *
 * The function checks:
 *   buf[0] == MDN_FORMAT_MAGIC (0x4D)
 *   buf[1] == MDN_FORMAT_MAJOR (1)
 *   buf[2] is in [MDN_FORMAT_MINOR_LO, MDN_FORMAT_MINOR_HI]
 *
 * Returns 0 if compatible, 1 if the magic or major version does not
 * match, 2 if the minor version is outside the accepted range, or -1
 * if buf is NULL or len < 3.
 */
int mdn_ctx_version_check(const uint8_t *buf, uint32_t len)
{
    if (!buf || len < 3)
        return -1;
    if (buf[0] != MDN_FORMAT_MAGIC)
        return 1;
    if (buf[1] != MDN_FORMAT_MAJOR)
        return 1;
    if (buf[2] < MDN_FORMAT_MINOR_LO || buf[2] > MDN_FORMAT_MINOR_HI)
        return 2;
    return 0;
}

/*
 * mdn_ctx_summary — write a one-line summary of the context into out.
 *
 * Includes: number of zones, NAT buckets, total sessions, templates,
 * audit windows, export profiles, rules and queries loaded.
 * Returns bytes written (excluding null terminator), or -1 on error.
 */
int mdn_ctx_summary(const mdn_ctx_t *ctx, char *out, uint32_t cap)
{
    if (!out || cap == 0)
        return -1;
    if (!ctx) {
        int n = snprintf(out, cap, "(null)");
        return n < 0 ? -1 : n;
    }

    /* Count zones and NAT buckets */
    uint32_t zone_n = 0;
    for (uint32_t i = 0; i < MDN_MAX_ZONES; i++) {
        if (ctx->zones[i])
            zone_n++;
    }

    uint32_t nat_n    = 0;
    uint32_t sess_n   = 0;
    for (uint32_t i = 0; i < MDN_MAX_NAT_BUCKETS; i++) {
        if (ctx->nat_buckets[i]) {
            nat_n++;
            sess_n += ctx->nat_buckets[i]->slot_count;
        }
    }

    int n = snprintf(out, cap,
                     "zones=%u nat_buckets=%u sessions=%u "
                     "templates=%u audits=%u exports=%u "
                     "rules=%u queries=%u",
                     zone_n, nat_n, sess_n,
                     ctx->template_count,
                     ctx->audit_count,
                     ctx->export_count,
                     ctx->rule_count,
                     (unsigned)ctx->query_count);
    return n < 0 ? -1 : n;
}

/*
 * mdn_section_count_by_type — return the number of sections loaded per
 * major subsystem.
 *
 * Writes counts into the caller-supplied array indexed by section type
 * (SECT_ZONE == 0x02, SECT_NAT == 0x05, etc.).  The array must be at
 * least 12 elements.  Elements not corresponding to a known subsystem
 * are set to 0.
 */
void mdn_section_count_by_type(const mdn_ctx_t *ctx, uint32_t counts[12])
{
    if (!counts)
        return;

    memset(counts, 0, 12 * sizeof(uint32_t));

    if (!ctx)
        return;

    /* SECT_ZONE = 0x02 → index 2 */
    for (uint32_t i = 0; i < MDN_MAX_ZONES; i++) {
        if (ctx->zones[i])
            counts[SECT_ZONE]++;
    }

    /* SECT_NAT = 0x05 → index 5 */
    for (uint32_t i = 0; i < MDN_MAX_NAT_BUCKETS; i++) {
        if (ctx->nat_buckets[i])
            counts[SECT_NAT]++;
    }

    /* SECT_TEMPLATE = 0x07 → index 7 */
    counts[SECT_TEMPLATE] = ctx->template_count;

    /* SECT_AUDIT = 0x08 → index 8 */
    counts[SECT_AUDIT] = ctx->audit_count;

    /* SECT_EXPORT = 0x09 → index 9 */
    counts[SECT_EXPORT] = ctx->export_count;

    /* SECT_RULE = 0x03 → index 3 */
    counts[SECT_RULE] = ctx->rule_count;

    /* SECT_QUERY = 0x0B → index 11 */
    counts[SECT_QUERY] = (uint32_t)ctx->query_count;
}

/*
 * mdn_tick_version — return a monotonically increasing version counter.
 *
 * The counter is global to the process and is advanced by 1 on each call.
 * It is implemented with a static variable; the first call returns 1.
 * This is used to stamp context snapshots for cache-invalidation purposes.
 */
uint64_t mdn_tick_version(void)
{
    static uint64_t counter = 0;
    return ++counter;
}

/*
 * mdn_estimate_memory — estimate total heap bytes consumed by ctx.
 *
 * Sums the sizes of all dynamically allocated sub-objects including
 * zones, NAT bucket arrays, session slot arrays, cursors, templates,
 * audit windows, export profiles, rules, and prefix pages.
 *
 * Returns the estimate in bytes.  Returns 0 if ctx is NULL.
 */
size_t mdn_estimate_memory(const mdn_ctx_t *ctx)
{
    if (!ctx)
        return 0;

    size_t total = sizeof(mdn_ctx_t);

    /* Zones */
    for (uint32_t i = 0; i < MDN_MAX_ZONES; i++) {
        if (ctx->zones[i])
            total += sizeof(mdn_zone_t);
    }

    /* NAT buckets + session slot arrays */
    for (uint32_t i = 0; i < MDN_MAX_NAT_BUCKETS; i++) {
        mdn_nat_bucket_t *bkt = ctx->nat_buckets[i];
        if (bkt) {
            total += sizeof(mdn_nat_bucket_t);
            total += (size_t)bkt->slot_count * sizeof(mdn_session_t);
        }
    }

    /* Cursor array */
    if (ctx->cursors)
        total += (size_t)ctx->cursor_count * sizeof(mdn_session_cursor_t);

    /* Rules */
    total += (size_t)ctx->rule_count * sizeof(mdn_rule_node_t);

    /* Templates */
    if (ctx->templates) {
        total += (size_t)ctx->template_count * sizeof(mdn_packet_template_t);
        for (uint32_t i = 0; i < ctx->template_count; i++) {
            total += ctx->templates[i].hdr_cap;
            total += (size_t)ctx->templates[i].desc_count * sizeof(mdn_tmpl_desc_t);
        }
    }

    /* Audit windows */
    if (ctx->audit_windows) {
        total += (size_t)ctx->audit_count * sizeof(mdn_audit_window_t);
        for (uint32_t i = 0; i < ctx->audit_count; i++) {
            total += ctx->audit_windows[i].heap_len;
            total += (size_t)ctx->audit_windows[i].dir_count * sizeof(mdn_audit_dirent_t);
        }
    }

    /* Export profiles */
    if (ctx->exports) {
        total += (size_t)ctx->export_count * sizeof(mdn_export_profile_t);
        for (uint32_t i = 0; i < ctx->export_count; i++) {
            total += (size_t)ctx->exports[i].field_count * sizeof(mdn_export_field_t);
            total += ctx->exports[i].frame_cap;
        }
    }

    /* Prefix pages */
    for (uint32_t i = 0; i < MDN_MAX_PREFIX_PAGES; i++) {
        mdn_prefix_page_t *pp = ctx->prefix_pages[i];
        if (pp) {
            total += sizeof(mdn_prefix_page_t);
            total += pp->item_count * pp->stride;
            total += (size_t)pp->dir_count * sizeof(uint32_t);
        }
    }

    return total;
}

/*
 * mdn_free_zones — release all zone objects without freeing ctx itself.
 *
 * Called as part of the mdn_free teardown sequence; may also be used
 * stand-alone when a partial reload is needed.
 */
void mdn_free_zones(mdn_ctx_t *ctx)
{
    if (!ctx)
        return;
    zone_free_all(ctx);
}

/*
 * mdn_free_nat — release all NAT bucket objects and their session arrays.
 */
void mdn_free_nat(mdn_ctx_t *ctx)
{
    if (!ctx)
        return;
    nat_free_all(ctx);
}

/*
 * mdn_free_sessions — release the session cursor array.
 */
void mdn_free_sessions(mdn_ctx_t *ctx)
{
    if (!ctx)
        return;
    session_cursors_free(ctx);
}

/*
 * mdn_stats_snapshot — copy parse-time counters into caller-supplied vars.
 *
 * Writes ctx->stats_crc_miss into *crc_miss and
 * ctx->stats_sections_loaded into *sections_loaded.
 * Either pointer may be NULL.
 */
void mdn_stats_snapshot(const mdn_ctx_t *ctx,
                        uint32_t *crc_miss, uint32_t *sections_loaded)
{
    if (!ctx)
        return;
    if (crc_miss)
        *crc_miss = ctx->stats_crc_miss;
    if (sections_loaded)
        *sections_loaded = ctx->stats_sections_loaded;
}
