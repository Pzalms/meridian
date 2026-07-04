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
