#ifndef MDN_STATS_H
#define MDN_STATS_H

#include <stdint.h>

typedef struct {
    uint32_t sections_parsed;
    uint32_t rules_evaluated;
    uint32_t queries_run;
    uint32_t nat_lookups;
    uint32_t export_frames;
    uint32_t crc_mismatches;
} mdn_stats_t;

void     stats_init(mdn_stats_t *s);
void     stats_record_hit(mdn_stats_t *s, uint32_t *field);
void     stats_print(const mdn_stats_t *s);
void     stats_reset(mdn_stats_t *s);
void     stats_accumulate(mdn_stats_t *dst, const mdn_stats_t *src);
uint32_t stats_total_sections(const mdn_stats_t *s);
int      stats_is_clean(const mdn_stats_t *s);
int      stats_has_errors(const mdn_stats_t *s);
void     stats_dump_delta(const mdn_stats_t *before, const mdn_stats_t *after);
void     stats_snapshot(mdn_stats_t *dst, const mdn_stats_t *src);

/* ------------------------------------------------------------------ */
/* Section histogram                                                    */
/* ------------------------------------------------------------------ */
#define STATS_SECT_TYPES 16

typedef struct {
    uint32_t counts[STATS_SECT_TYPES]; /* indexed by section type 0..15 */
    uint32_t total;
} mdn_sect_histogram_t;

void stats_section_histogram_init(mdn_sect_histogram_t *h);
void stats_section_histogram_record(mdn_sect_histogram_t *h, uint8_t sect_type);
void stats_section_histogram_print(const mdn_sect_histogram_t *h);
void stats_section_histogram_merge(mdn_sect_histogram_t *dst, const mdn_sect_histogram_t *src);
uint32_t stats_section_histogram_mode(const mdn_sect_histogram_t *h);

/* ------------------------------------------------------------------ */
/* Rolling average (circular buffer of uint32_t samples)              */
/* ------------------------------------------------------------------ */
#define STATS_ROLLING_WINDOW 32

typedef struct {
    uint32_t samples[STATS_ROLLING_WINDOW];
    uint32_t head;
    uint32_t count;
    uint64_t sum;
} stats_rolling_t;

void     stats_rolling_init(stats_rolling_t *r);
void     stats_rolling_update(stats_rolling_t *r, uint32_t val);
uint32_t stats_rolling_get(const stats_rolling_t *r);
uint32_t stats_rolling_min(const stats_rolling_t *r);
uint32_t stats_rolling_max(const stats_rolling_t *r);
void     stats_rolling_reset(stats_rolling_t *r);

/* ------------------------------------------------------------------ */
/* Percentile approximation over a uint32_t array                     */
/* ------------------------------------------------------------------ */
uint32_t stats_percentile_approx(const uint32_t *arr, uint32_t n, int pct);

/* ------------------------------------------------------------------ */
/* Exponentially weighted moving average                               */
/* ------------------------------------------------------------------ */
typedef struct {
    uint32_t value;      /* current EWMA value (fixed-point * 256) */
    uint32_t alpha_pct;  /* smoothing factor as integer 1..99        */
    int      initialized;
} stats_ewma_t;

void     stats_ewma_init(stats_ewma_t *e, uint32_t alpha_pct);
void     stats_ewma_update(stats_ewma_t *e, uint32_t sample);
uint32_t stats_ewma_get(const stats_ewma_t *e);
void     stats_ewma_reset(stats_ewma_t *e);

/* ------------------------------------------------------------------ */
/* Counter rate tracker                                                 */
/* ------------------------------------------------------------------ */
typedef struct {
    uint32_t prev_value;
    uint32_t last_rate;
    uint32_t tick_count;
} stats_rate_t;

void     stats_rate_init(stats_rate_t *rt);
uint32_t stats_rate_tick(stats_rate_t *rt, uint32_t current_value);
uint32_t stats_rate_get(const stats_rate_t *rt);

/* ------------------------------------------------------------------ */
/* Extended stats summary                                               */
/* ------------------------------------------------------------------ */
typedef struct {
    uint32_t total_events;
    uint32_t peak_rate;
    uint32_t avg_rate;
    uint32_t error_pct;  /* crc_mismatches * 100 / sections_parsed */
} mdn_stats_summary_t;

void stats_compute_summary(const mdn_stats_t *s, mdn_stats_summary_t *out);
void stats_summary_print(const mdn_stats_summary_t *sum);
int  stats_compare(const mdn_stats_t *a, const mdn_stats_t *b);

#endif /* MDN_STATS_H */
