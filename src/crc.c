#include "crc.h"
#include <string.h>

/* -----------------------------------------------------------------------
 * CRC32 Castagnoli — polynomial 0x82F63B78 (reflected)
 * Used as the primary checksum throughout the meridian format.
 * ----------------------------------------------------------------------- */

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

/* -----------------------------------------------------------------------
 * IEEE CRC32 polynomial 0xEDB88320 (reflected standard Ethernet CRC)
 * Precomputed at file scope; initialised lazily on first use.
 * ----------------------------------------------------------------------- */

static uint32_t crc32_ieee_table[256];
static int      crc32_ieee_table_ready = 0;

static void crc32_ieee_build_table(void)
{
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t crc = i;
        for (int j = 0; j < 8; j++) {
            if (crc & 1)
                crc = (crc >> 1) ^ UINT32_C(0xEDB88320);
            else
                crc >>= 1;
        }
        crc32_ieee_table[i] = crc;
    }
    crc32_ieee_table_ready = 1;
}

/* -----------------------------------------------------------------------
 * crc32c_fast — table-driven CRC32C over a contiguous buffer.
 *
 * Processes 4 bytes per inner iteration to reduce loop overhead.
 * Returns the finalised (XOR-inverted) CRC value.
 * ----------------------------------------------------------------------- */
uint32_t crc32c_fast(const uint8_t *data, uint32_t len)
{
    if (!crc32c_table_ready)
        crc32c_build_table();

    uint32_t crc = UINT32_C(0xFFFFFFFF);

    /* Unrolled 4-byte block */
    uint32_t i = 0;
    for (; i + 4 <= len; i += 4) {
        crc = (crc >> 8) ^ crc32c_table[(crc ^ data[i + 0]) & 0xFF];
        crc = (crc >> 8) ^ crc32c_table[(crc ^ data[i + 1]) & 0xFF];
        crc = (crc >> 8) ^ crc32c_table[(crc ^ data[i + 2]) & 0xFF];
        crc = (crc >> 8) ^ crc32c_table[(crc ^ data[i + 3]) & 0xFF];
    }
    for (; i < len; i++)
        crc = (crc >> 8) ^ crc32c_table[(crc ^ data[i]) & 0xFF];

    return crc ^ UINT32_C(0xFFFFFFFF);
}

/* -----------------------------------------------------------------------
 * crc32c_update — streaming/incremental CRC32C.
 *
 * Call with crc=0xFFFFFFFF for the first chunk.  Pass the returned value
 * as crc for subsequent chunks.  Final value must be XOR'd with 0xFFFFFFFF
 * by the caller when the full stream has been processed.
 *
 * This interface is used by the streaming section loader to verify large
 * payloads chunk-by-chunk without buffering the entire section.
 * ----------------------------------------------------------------------- */
uint32_t crc32c_update(uint32_t crc, const uint8_t *data, uint32_t len)
{
    if (!crc32c_table_ready)
        crc32c_build_table();

    /* Running CRC is passed in pre-inverted (i.e. the ~crc of the logical
     * CRC value).  We process each byte and return the updated pre-inverted
     * value so the caller can chain calls without extra XOR operations. */
    for (uint32_t i = 0; i < len; i++)
        crc = (crc >> 8) ^ crc32c_table[(crc ^ data[i]) & 0xFF];

    return crc;
}

/* -----------------------------------------------------------------------
 * crc32_ieee — IEEE 802.3 CRC32 (Ethernet polynomial 0xEDB88320).
 *
 * Used where interoperability with standard Ethernet/PKZIP CRC32 is
 * required (e.g. external audit export frames).
 * ----------------------------------------------------------------------- */
uint32_t crc32_ieee(const uint8_t *data, uint32_t len)
{
    if (!crc32_ieee_table_ready)
        crc32_ieee_build_table();

    uint32_t crc = UINT32_C(0xFFFFFFFF);
    for (uint32_t i = 0; i < len; i++)
        crc = (crc >> 8) ^ crc32_ieee_table[(crc ^ data[i]) & 0xFF];

    return crc ^ UINT32_C(0xFFFFFFFF);
}

/* -----------------------------------------------------------------------
 * crc32c_combine — algebraically combine two independent CRC32C values.
 *
 * Given crc1 = CRC32C(A) and crc2 = CRC32C(B) where |B| = len2, returns
 * CRC32C(A || B) without re-processing the bytes of A.
 *
 * Algorithm: extend crc1 by len2 zero bytes (using the CRC32C property
 * that CRC(A || 0^n) is derivable from CRC(A) via matrix multiplication),
 * then XOR in crc2 contributions.  We use a simplified shift-and-xor loop
 * that leverages the CRC32C table for the zero-byte extension step.
 * ----------------------------------------------------------------------- */
uint32_t crc32c_combine(uint32_t crc1, uint32_t crc2, uint32_t len2)
{
    if (!crc32c_table_ready)
        crc32c_build_table();

    /* Extend crc1 over len2 zero bytes.
     * CRC(byte=0) lookup: the zero-byte contribution collapses to a pure
     * table lookup because (crc ^ 0) = crc, so we walk crc >> 8 XOR table[crc & 0xFF]
     * for each zero byte appended. */
    uint32_t crc = crc1 ^ UINT32_C(0xFFFFFFFF); /* remove final inversion */
    for (uint32_t i = 0; i < len2; i++)
        crc = (crc >> 8) ^ crc32c_table[crc & 0xFF];
    crc ^= UINT32_C(0xFFFFFFFF); /* re-apply final inversion */

    /* Now XOR in crc2.  Because CRC is linear, CRC(A||B) = extend(CRC(A)) XOR CRC(B)
     * when both are finalised values. */
    return crc ^ crc2;
}

/* -----------------------------------------------------------------------
 * crc32_compute — legacy entry point; delegates to the fast CRC32C path.
 *
 * Existing callers use size_t for the length; we clamp to UINT32_MAX to
 * satisfy the narrower internal interface while preserving ABI.
 * ----------------------------------------------------------------------- */
uint32_t crc32_compute(const uint8_t *data, size_t len)
{
    uint32_t l32 = (len > UINT32_C(0xFFFFFFFF)) ? UINT32_C(0xFFFFFFFF) : (uint32_t)len;
    return crc32c_fast(data, l32);
}
