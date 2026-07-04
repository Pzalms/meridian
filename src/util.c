#include "util.h"
#include <stdio.h>
#include <string.h>
#include <ctype.h>

/* ------------------------------------------------------------------ */
/* Existing readers                                                     */
/* ------------------------------------------------------------------ */

uint16_t mdn_u16le(const uint8_t *p)
{
    return (uint16_t)(p[0] | ((uint16_t)p[1] << 8));
}

uint32_t mdn_u32le(const uint8_t *p)
{
    return (uint32_t)p[0]
         | ((uint32_t)p[1] << 8)
         | ((uint32_t)p[2] << 16)
         | ((uint32_t)p[3] << 24);
}

uint64_t mdn_u64le(const uint8_t *p)
{
    return (uint64_t)p[0]
         | ((uint64_t)p[1] << 8)
         | ((uint64_t)p[2] << 16)
         | ((uint64_t)p[3] << 24)
         | ((uint64_t)p[4] << 32)
         | ((uint64_t)p[5] << 40)
         | ((uint64_t)p[6] << 48)
         | ((uint64_t)p[7] << 56);
}

/* ------------------------------------------------------------------ */
/* Little-endian writers                                                */
/* ------------------------------------------------------------------ */

/* Write a 16-bit value in little-endian byte order to p. */
void mdn_write_u16le(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v);
    p[1] = (uint8_t)(v >> 8);
}

/* Write a 32-bit value in little-endian byte order to p. */
void mdn_write_u32le(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v);
    p[1] = (uint8_t)(v >>  8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

/* Write a 64-bit value in little-endian byte order to p. */
void mdn_write_u64le(uint8_t *p, uint64_t v)
{
    p[0] = (uint8_t)(v);
    p[1] = (uint8_t)(v >>  8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
    p[4] = (uint8_t)(v >> 32);
    p[5] = (uint8_t)(v >> 40);
    p[6] = (uint8_t)(v >> 48);
    p[7] = (uint8_t)(v >> 56);
}

/* ------------------------------------------------------------------ */
/* mdn_hex_dump                                                         */
/* Prints a classic hex dump with 16 bytes per line and a printable    */
/* ASCII sidebar. Each row shows: offset | hex bytes | ascii chars.    */
/* ------------------------------------------------------------------ */
void mdn_hex_dump(const uint8_t *data, uint32_t len, FILE *out)
{
    if (!data || !out) return;

    const uint32_t COLS = 16;
    for (uint32_t off = 0; off < len; off += COLS) {
        /* offset column */
        fprintf(out, "%08x  ", (unsigned)off);

        /* hex columns */
        for (uint32_t c = 0; c < COLS; c++) {
            if (off + c < len)
                fprintf(out, "%02x ", (unsigned)data[off + c]);
            else
                fprintf(out, "   ");
            if (c == 7)
                fprintf(out, " "); /* extra gap in the middle */
        }

        /* ASCII sidebar */
        fprintf(out, " |");
        for (uint32_t c = 0; c < COLS && off + c < len; c++) {
            uint8_t ch = data[off + c];
            fprintf(out, "%c", isprint((unsigned char)ch) ? (char)ch : '.');
        }
        fprintf(out, "|\n");
    }
}

/* ------------------------------------------------------------------ */
/* mdn_str_to_hex                                                       */
/* Decodes a null-terminated hex string (e.g. "deadbeef") into raw    */
/* bytes. Both upper and lower case hex digits are accepted.           */
/* Returns the number of decoded bytes on success, or -1 on error     */
/* (odd length, invalid character, or output buffer too small).        */
/* ------------------------------------------------------------------ */
int mdn_str_to_hex(const char *hex, uint8_t *out, uint32_t out_cap)
{
    if (!hex || !out) return -1;

    size_t slen = strlen(hex);
    if (slen & 1) return -1; /* must be even */

    uint32_t nbytes = (uint32_t)(slen / 2);
    if (nbytes > out_cap) return -1;

    for (uint32_t i = 0; i < nbytes; i++) {
        unsigned int hi, lo;
        char ch;

        ch = hex[i * 2];
        if      (ch >= '0' && ch <= '9') hi = (unsigned int)(ch - '0');
        else if (ch >= 'a' && ch <= 'f') hi = (unsigned int)(ch - 'a' + 10);
        else if (ch >= 'A' && ch <= 'F') hi = (unsigned int)(ch - 'A' + 10);
        else return -1;

        ch = hex[i * 2 + 1];
        if      (ch >= '0' && ch <= '9') lo = (unsigned int)(ch - '0');
        else if (ch >= 'a' && ch <= 'f') lo = (unsigned int)(ch - 'a' + 10);
        else if (ch >= 'A' && ch <= 'F') lo = (unsigned int)(ch - 'A' + 10);
        else return -1;

        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return (int)nbytes;
}

/* ------------------------------------------------------------------ */
/* mdn_bytes_to_hex                                                     */
/* Encodes len raw bytes into a null-terminated lower-case hex string. */
/* out must point to a buffer of at least 2*len+1 bytes.              */
/* ------------------------------------------------------------------ */
void mdn_bytes_to_hex(const uint8_t *data, uint32_t len, char *out)
{
    if (!data || !out) return;

    static const char hex_chars[] = "0123456789abcdef";
    for (uint32_t i = 0; i < len; i++) {
        out[i * 2]     = hex_chars[(data[i] >> 4) & 0x0f];
        out[i * 2 + 1] = hex_chars[data[i] & 0x0f];
    }
    out[len * 2] = '\0';
}

/* ------------------------------------------------------------------ */
/* mdn_align_up                                                         */
/* Rounds x up to the next multiple of align (must be power of two).  */
/* ------------------------------------------------------------------ */
size_t mdn_align_up(size_t x, size_t align)
{
    if (!align) return x;
    return (x + (align - 1)) & ~(align - 1);
}

/* ------------------------------------------------------------------ */
/* mdn_clamp_u32                                                        */
/* Clamps a 32-bit value to [lo, hi].                                  */
/* ------------------------------------------------------------------ */
uint32_t mdn_clamp_u32(uint32_t v, uint32_t lo, uint32_t hi)
{
    if (v < lo) return lo;
    if (v > hi) return hi;
    return v;
}

/* ------------------------------------------------------------------ */
/* mdn_popcount32                                                       */
/* Returns the number of set bits in a 32-bit word.                   */
/* ------------------------------------------------------------------ */
uint32_t mdn_popcount32(uint32_t x)
{
    x = x - ((x >> 1) & 0x55555555u);
    x = (x & 0x33333333u) + ((x >> 2) & 0x33333333u);
    x = (x + (x >> 4)) & 0x0f0f0f0fu;
    return (x * 0x01010101u) >> 24;
}
