#ifndef MDN_CRC_H
#define MDN_CRC_H

#include <stdint.h>
#include <stddef.h>

uint32_t crc32_compute(const uint8_t *data, size_t len);

#endif /* MDN_CRC_H */
