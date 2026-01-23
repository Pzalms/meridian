#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "mdn_internal.h"
#include "rule.h"

/* Parse a little-endian u32 from an unaligned byte pointer. */
static uint32_t read_u32(const uint8_t *p)
{
    return (uint32_t)p[0]
         | ((uint32_t)p[1] << 8)
         | ((uint32_t)p[2] << 16)
         | ((uint32_t)p[3] << 24);
}

/* Parse a little-endian u16 from an unaligned byte pointer. */
static uint16_t read_u16(const uint8_t *p)
{
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

int rule_load(mdn_ctx_t *ctx, const uint8_t *data, uint32_t len)
{
    if (!ctx || !data) {
        return -1;
    }

    /* Need at least 4 bytes for the count field. */
    if (len < 4) {
        return -1;
    }

    uint32_t count = read_u32(data);

    /* Validate count bounds — cap at compile-time limit. */
    if (count > MDN_MAX_RULES) {
        /* rule table exceeds capacity; reject the section */
        return -1;
    }

    /* Each rule node is 12 bytes: key(4) + mask(4) + action(2) + next(2). */
    uint32_t required = 4u + count * 12u;
    if (len < required) {
        return -1;
    }

    /* Release any previously loaded rule table. */
    free(ctx->rules);
    ctx->rules = NULL;
    ctx->rule_count = 0;

    if (count == 0) {
        return 0;
    }

    mdn_rule_node_t *nodes = calloc(count, sizeof(mdn_rule_node_t));
    if (!nodes) {
        return -1;
    }

    const uint8_t *p = data + 4;
    for (uint32_t i = 0; i < count; i++) {
        nodes[i].key    = read_u32(p);      p += 4;
        nodes[i].mask   = read_u32(p);      p += 4;
        nodes[i].action = read_u16(p);      p += 2;
        nodes[i].next   = read_u16(p);      p += 2;
    }

    ctx->rules      = nodes;
    ctx->rule_count = count;
    return 0;
}
