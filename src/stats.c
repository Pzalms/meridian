#include "stats.h"
#include <string.h>

void stats_init(mdn_stats_t *s)
{
    memset(s, 0, sizeof(*s));
}

void stats_record_hit(mdn_stats_t *s, uint32_t *field)
{
    (void)s;
    (*field)++;
}
