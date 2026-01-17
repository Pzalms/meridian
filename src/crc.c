#include "crc.h"

/* CRC32 Castagnoli — polynomial 0x82F63B78 */

static uint32_t crc32c_table[256];
static int      crc32c_table_ready = 0;

static void crc32c_build_table(void)
{
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t crc = i;
        for (int j = 0; j < 8; j++) {
            if (crc & 1)
                crc = (crc >> 1) ^ UINT32_C(0x82F63B78);
            else
                crc >>= 1;
        }
        crc32c_table[i] = crc;
    }
    crc32c_table_ready = 1;
}

uint32_t crc32_compute(const uint8_t *data, size_t len)
{
    if (!crc32c_table_ready)
        crc32c_build_table();

    uint32_t crc = UINT32_C(0xFFFFFFFF);
    for (size_t i = 0; i < len; i++)
        crc = (crc >> 8) ^ crc32c_table[(crc ^ data[i]) & 0xFF];

    return crc ^ UINT32_C(0xFFFFFFFF);
}
