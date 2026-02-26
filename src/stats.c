#include "stats.h"
#include <string.h>
#include <stdio.h>

void stats_init(mdn_stats_t *s)
{
    memset(s, 0, sizeof(*s));
}

void stats_record_hit(mdn_stats_t *s, uint32_t *field)
{
    (void)s;
    (*field)++;
}

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
