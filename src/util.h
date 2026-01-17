#ifndef MDN_UTIL_H
#define MDN_UTIL_H

#include <stdint.h>
#include <stddef.h>

uint16_t mdn_u16le(const uint8_t *p);
uint32_t mdn_u32le(const uint8_t *p);
uint64_t mdn_u64le(const uint8_t *p);

#define MDN_MIN(a, b) ((a) < (b) ? (a) : (b))
#define MDN_MAX(a, b) ((a) > (b) ? (a) : (b))

#endif /* MDN_UTIL_H */
