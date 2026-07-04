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

#endif /* MDN_STATS_H */
