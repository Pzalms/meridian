#ifndef MDN_UTIL_H
#define MDN_UTIL_H

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

/* ------------------------------------------------------------------ */
/* Little-endian readers                                                */
/* ------------------------------------------------------------------ */
uint16_t mdn_u16le(const uint8_t *p);
uint32_t mdn_u32le(const uint8_t *p);
uint64_t mdn_u64le(const uint8_t *p);

/* ------------------------------------------------------------------ */
/* Little-endian writers                                                */
/* ------------------------------------------------------------------ */
void mdn_write_u16le(uint8_t *p, uint16_t v);
void mdn_write_u32le(uint8_t *p, uint32_t v);
void mdn_write_u64le(uint8_t *p, uint64_t v);

/* ------------------------------------------------------------------ */
/* Hex utilities                                                        */
/* ------------------------------------------------------------------ */

/* Print a hex dump with ASCII sidebar to out, 16 bytes per row. */
void mdn_hex_dump(const uint8_t *data, uint32_t len, FILE *out);

/* Decode hex string to bytes. Returns byte count or -1 on error. */
int  mdn_str_to_hex(const char *hex, uint8_t *out, uint32_t out_cap);

/* Encode bytes to null-terminated lower-case hex. out must be 2*len+1 bytes. */
void mdn_bytes_to_hex(const uint8_t *data, uint32_t len, char *out);

/* ------------------------------------------------------------------ */
/* Arithmetic helpers                                                   */
/* ------------------------------------------------------------------ */
size_t   mdn_align_up(size_t x, size_t align);
uint32_t mdn_clamp_u32(uint32_t v, uint32_t lo, uint32_t hi);
uint32_t mdn_popcount32(uint32_t x);

/* ------------------------------------------------------------------ */
/* Inline helpers                                                       */
/* ------------------------------------------------------------------ */

/* Return the byte size of a section table with n_sections entries (20 bytes each). */
static inline size_t mdn_sect_table_size(uint16_t n_sections)
{
    return (size_t)n_sections * 20u;
}

#define MDN_MIN(a, b) ((a) < (b) ? (a) : (b))
#define MDN_MAX(a, b) ((a) > (b) ? (a) : (b))

#endif /* MDN_UTIL_H */
