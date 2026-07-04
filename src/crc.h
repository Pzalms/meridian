#ifndef MDN_CRC_H
#define MDN_CRC_H

#include <stdint.h>
#include <stddef.h>

/* Legacy one-shot CRC32C computation (delegates to crc32c_fast). */
uint32_t crc32_compute(const uint8_t *data, size_t len);

/* Table-driven CRC32C (Castagnoli) over a contiguous buffer. */
uint32_t crc32c_fast(const uint8_t *data, uint32_t len);

/* Streaming/incremental CRC32C update step.
 * Initialise crc with 0xFFFFFFFF; finalise by XOR-ing result with 0xFFFFFFFF. */
uint32_t crc32c_update(uint32_t crc, const uint8_t *data, uint32_t len);

/* IEEE 802.3 CRC32 (Ethernet polynomial 0xEDB88320). */
uint32_t crc32_ieee(const uint8_t *data, uint32_t len);

/* Combine two finalised CRC32C values: CRC(A||B) from CRC(A), CRC(B), |B|. */
uint32_t crc32c_combine(uint32_t crc1, uint32_t crc2, uint32_t len2);

#endif /* MDN_CRC_H */
