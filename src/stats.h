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

void stats_init(mdn_stats_t *s);
void stats_record_hit(mdn_stats_t *s, uint32_t *field);

#endif /* MDN_STATS_H */
