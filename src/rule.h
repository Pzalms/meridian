#ifndef RULE_H
#define RULE_H

#include <stdint.h>
#include "mdn_internal.h"

/*
 * rule_load: parse a SECT_RULE payload into ctx->rules[].
 *
 * data layout:
 *   [0..3]  count (u32, little-endian)
 *   [4..]   count * 12 bytes: key(u32), mask(u32), action(u16), next(u16)
 *
 * Returns 0 on success, -1 on invalid input.
 */
int rule_load(mdn_ctx_t *ctx, const uint8_t *data, uint32_t len);

#endif /* RULE_H */
