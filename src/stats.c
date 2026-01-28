#include "stats.h"
#include <string.h>
#include <stdio.h>

/* ------------------------------------------------------------------ */
/* stats_init                                                           */
/* ------------------------------------------------------------------ */
void stats_init(mdn_stats_t *s)
{
    memset(s, 0, sizeof(*s));
}

/* ------------------------------------------------------------------ */
/* stats_record_hit                                                     */
/* Increments the field pointed to by field. The stats handle s is     */
/* passed for context but is not used directly; only the field is      */
/* modified, allowing callers to target any counter in the struct.     */
/* ------------------------------------------------------------------ */
void stats_record_hit(mdn_stats_t *s, uint32_t *field)
{
    (void)s;
    (*field)++;
}

/* ------------------------------------------------------------------ */
/* stats_print                                                          */
/* Prints all counters in s to stdout in a human-readable format.      */
/* ------------------------------------------------------------------ */
void stats_print(const mdn_stats_t *s)
{
    if (!s) return;
    printf("sections_parsed:  %u\n", s->sections_parsed);
    printf("rules_evaluated:  %u\n", s->rules_evaluated);
    printf("queries_run:      %u\n", s->queries_run);
    printf("nat_lookups:      %u\n", s->nat_lookups);
    printf("export_frames:    %u\n", s->export_frames);
    printf("crc_mismatches:   %u\n", s->crc_mismatches);
}

/* ------------------------------------------------------------------ */
/* stats_reset                                                          */
/* Zeroes every counter in s without releasing any memory.             */
/* Equivalent to stats_init but named to reflect intentional reset     */
/* semantics (e.g. between processing runs).                           */
/* ------------------------------------------------------------------ */
void stats_reset(mdn_stats_t *s)
{
    if (!s) return;
    memset(s, 0, sizeof(*s));
}

/* ------------------------------------------------------------------ */
/* stats_accumulate                                                     */
/* Adds each counter from src into dst. Useful for aggregating         */
/* statistics collected across multiple contexts or load passes.       */
/* ------------------------------------------------------------------ */
void stats_accumulate(mdn_stats_t *dst, const mdn_stats_t *src)
{
    if (!dst || !src) return;
    dst->sections_parsed += src->sections_parsed;
    dst->rules_evaluated += src->rules_evaluated;
    dst->queries_run     += src->queries_run;
    dst->nat_lookups     += src->nat_lookups;
    dst->export_frames   += src->export_frames;
    dst->crc_mismatches  += src->crc_mismatches;
}

/* ------------------------------------------------------------------ */
/* stats_total_sections                                                 */
/* Returns the sections_parsed counter from s. Provided as a named    */
/* accessor so callers do not need to reach into the struct directly.  */
/* ------------------------------------------------------------------ */
uint32_t stats_total_sections(const mdn_stats_t *s)
{
    if (!s) return 0;
    return s->sections_parsed;
}

/* ------------------------------------------------------------------ */
/* stats_is_clean                                                       */
/* Returns 1 if all counters are zero (no activity recorded), which    */
/* can be used to detect a fresh or unused stats block.                */
/* ------------------------------------------------------------------ */
int stats_is_clean(const mdn_stats_t *s)
{
    if (!s) return 1;
    return (s->sections_parsed == 0 &&
            s->rules_evaluated == 0 &&
            s->queries_run     == 0 &&
            s->nat_lookups     == 0 &&
            s->export_frames   == 0 &&
            s->crc_mismatches  == 0) ? 1 : 0;
}

/* ------------------------------------------------------------------ */
/* stats_has_errors                                                     */
/* Returns 1 if any error-class counter (currently crc_mismatches) is */
/* non-zero. Allows a quick health check after a parse pass.           */
/* ------------------------------------------------------------------ */
int stats_has_errors(const mdn_stats_t *s)
{
    if (!s) return 0;
    return (s->crc_mismatches > 0) ? 1 : 0;
}

/* ------------------------------------------------------------------ */
/* stats_dump_delta                                                     */
/* Prints the per-field difference between after and before, showing   */
/* only fields that changed. Useful for tracing the effect of a single */
/* parsing or evaluation pass.                                         */
/* ------------------------------------------------------------------ */
void stats_dump_delta(const mdn_stats_t *before, const mdn_stats_t *after)
{
    if (!before || !after) return;

    uint32_t ds = after->sections_parsed - before->sections_parsed;
    uint32_t dr = after->rules_evaluated - before->rules_evaluated;
    uint32_t dq = after->queries_run     - before->queries_run;
    uint32_t dn = after->nat_lookups     - before->nat_lookups;
    uint32_t de = after->export_frames   - before->export_frames;
    uint32_t dc = after->crc_mismatches  - before->crc_mismatches;

    printf("stats delta:\n");
    if (ds) printf("  +sections_parsed:  %u\n", ds);
    if (dr) printf("  +rules_evaluated:  %u\n", dr);
    if (dq) printf("  +queries_run:      %u\n", dq);
    if (dn) printf("  +nat_lookups:      %u\n", dn);
    if (de) printf("  +export_frames:    %u\n", de);
    if (dc) printf("  +crc_mismatches:   %u\n", dc);
    if (!ds && !dr && !dq && !dn && !de && !dc)
        printf("  (no change)\n");
}

/* ------------------------------------------------------------------ */
/* stats_snapshot                                                       */
/* Copies the current values from src into dst as a point-in-time      */
/* snapshot. dst need not have been previously initialised.            */
/* ------------------------------------------------------------------ */
void stats_snapshot(mdn_stats_t *dst, const mdn_stats_t *src)
{
    if (!dst || !src) return;
    memcpy(dst, src, sizeof(*dst));
}

#include <stdlib.h>

/* ================================================================== */
/* Section histogram                                                    */
/* ================================================================== */

void stats_section_histogram_init(mdn_sect_histogram_t *h)
{
    if (!h) return;
    memset(h, 0, sizeof(*h));
}

void stats_section_histogram_record(mdn_sect_histogram_t *h, uint8_t sect_type)
{
    if (!h) return;
    uint8_t idx = sect_type < STATS_SECT_TYPES ? sect_type : (STATS_SECT_TYPES - 1);
    h->counts[idx]++;
    h->total++;
}

void stats_section_histogram_print(const mdn_sect_histogram_t *h)
{
    if (!h) return;
    printf("section histogram (total=%u):\n", h->total);
    for (int i = 0; i < STATS_SECT_TYPES; i++) {
        if (h->counts[i])
            printf("  type[%2d]: %u\n", i, h->counts[i]);
    }
}

void stats_section_histogram_merge(mdn_sect_histogram_t *dst, const mdn_sect_histogram_t *src)
{
    if (!dst || !src) return;
    for (int i = 0; i < STATS_SECT_TYPES; i++)
        dst->counts[i] += src->counts[i];
    dst->total += src->total;
}

uint32_t stats_section_histogram_mode(const mdn_sect_histogram_t *h)
{
    if (!h) return 0;
    uint32_t best = 0, best_type = 0;
    for (int i = 0; i < STATS_SECT_TYPES; i++) {
        if (h->counts[i] > best) { best = h->counts[i]; best_type = (uint32_t)i; }
    }
    return best_type;
}

/* ================================================================== */
/* Rolling average                                                      */
/* ================================================================== */

void stats_rolling_init(stats_rolling_t *r)
{
    if (!r) return;
    memset(r, 0, sizeof(*r));
}

void stats_rolling_update(stats_rolling_t *r, uint32_t val)
{
    if (!r) return;
    if (r->count == STATS_ROLLING_WINDOW) {
        /* Remove the oldest sample from the sum. */
        r->sum -= r->samples[r->head];
    } else {
        r->count++;
    }
    r->samples[r->head] = val;
    r->sum += val;
    r->head = (r->head + 1) % STATS_ROLLING_WINDOW;
}

uint32_t stats_rolling_get(const stats_rolling_t *r)
{
    if (!r || !r->count) return 0;
    return (uint32_t)(r->sum / r->count);
}

uint32_t stats_rolling_min(const stats_rolling_t *r)
{
    if (!r || !r->count) return 0;
    uint32_t mn = r->samples[0];
    for (uint32_t i = 1; i < r->count; i++)
        if (r->samples[i] < mn) mn = r->samples[i];
    return mn;
}

uint32_t stats_rolling_max(const stats_rolling_t *r)
{
    if (!r || !r->count) return 0;
    uint32_t mx = r->samples[0];
    for (uint32_t i = 1; i < r->count; i++)
        if (r->samples[i] > mx) mx = r->samples[i];
    return mx;
}

void stats_rolling_reset(stats_rolling_t *r)
{
    if (!r) return;
    memset(r, 0, sizeof(*r));
}

/* ================================================================== */
/* Percentile approximation (partial sort via selection)               */
/* ================================================================== */

/* Simple insertion-sort on a small scratch copy, then index. */
static void isort_u32(uint32_t *a, uint32_t n)
{
    for (uint32_t i = 1; i < n; i++) {
        uint32_t key = a[i];
        uint32_t j = i;
        while (j > 0 && a[j-1] > key) { a[j] = a[j-1]; j--; }
        a[j] = key;
    }
}

uint32_t stats_percentile_approx(const uint32_t *arr, uint32_t n, int pct)
{
    if (!arr || !n) return 0;
    if (pct <= 0)   return arr[0];
    if (pct >= 100) return arr[n - 1];

    /* Use a scratch buffer of up to 512 samples (or all if n <= 512). */
#define PCTILE_SCRATCH 512
    uint32_t scratch[PCTILE_SCRATCH];
    uint32_t sn = n < PCTILE_SCRATCH ? n : PCTILE_SCRATCH;
    memcpy(scratch, arr, sn * sizeof(uint32_t));
    isort_u32(scratch, sn);
    uint32_t idx = (uint32_t)((uint64_t)sn * (uint32_t)pct / 100);
    if (idx >= sn) idx = sn - 1;
    return scratch[idx];
#undef PCTILE_SCRATCH
}

/* ================================================================== */
/* EWMA                                                                 */
/* ================================================================== */

void stats_ewma_init(stats_ewma_t *e, uint32_t alpha_pct)
{
    if (!e) return;
    if (alpha_pct < 1)   alpha_pct = 1;
    if (alpha_pct > 99)  alpha_pct = 99;
    e->alpha_pct  = alpha_pct;
    e->value      = 0;
    e->initialized = 0;
}

void stats_ewma_update(stats_ewma_t *e, uint32_t sample)
{
    if (!e) return;
    if (!e->initialized) {
        e->value      = sample * 256u;
        e->initialized = 1;
        return;
    }
    /* value = alpha*sample + (1-alpha)*prev_value
     * Multiply by 256 to avoid floating point. */
    uint32_t alpha = e->alpha_pct;
    e->value = (alpha * sample * 256u + (100u - alpha) * e->value) / 100u;
}

uint32_t stats_ewma_get(const stats_ewma_t *e)
{
    if (!e || !e->initialized) return 0;
    return e->value / 256u;
}

void stats_ewma_reset(stats_ewma_t *e)
{
    if (!e) return;
    e->value = 0;
    e->initialized = 0;
}

/* ================================================================== */
/* Rate tracker                                                         */
/* ================================================================== */

void stats_rate_init(stats_rate_t *rt)
{
    if (!rt) return;
    memset(rt, 0, sizeof(*rt));
}

uint32_t stats_rate_tick(stats_rate_t *rt, uint32_t current_value)
{
    if (!rt) return 0;
    uint32_t delta = current_value - rt->prev_value;
    rt->prev_value = current_value;
    rt->last_rate  = delta;
    rt->tick_count++;
    return delta;
}

uint32_t stats_rate_get(const stats_rate_t *rt)
{
    if (!rt) return 0;
    return rt->last_rate;
}

/* ================================================================== */
/* Extended summary                                                     */
/* ================================================================== */

void stats_compute_summary(const mdn_stats_t *s, mdn_stats_summary_t *out)
{
    if (!s || !out) return;
    memset(out, 0, sizeof(*out));
    out->total_events = s->sections_parsed + s->rules_evaluated
                      + s->queries_run    + s->nat_lookups
                      + s->export_frames;
    out->error_pct = s->sections_parsed
        ? (s->crc_mismatches * 100u / s->sections_parsed)
        : 0u;
    /* peak_rate and avg_rate are not tracked here; set to 0. */
    out->peak_rate = 0;
    out->avg_rate  = 0;
}

void stats_summary_print(const mdn_stats_summary_t *sum)
{
    if (!sum) return;
    printf("stats summary:\n");
    printf("  total_events: %u\n", sum->total_events);
    printf("  peak_rate:    %u\n", sum->peak_rate);
    printf("  avg_rate:     %u\n", sum->avg_rate);
    printf("  error_pct:    %u%%\n", sum->error_pct);
}

int stats_compare(const mdn_stats_t *a, const mdn_stats_t *b)
{
    if (!a || !b) return 0;
    uint64_t sa = (uint64_t)a->sections_parsed + a->rules_evaluated + a->queries_run;
    uint64_t sb = (uint64_t)b->sections_parsed + b->rules_evaluated + b->queries_run;
    if (sa < sb) return -1;
    if (sa > sb) return  1;
    return 0;
}
