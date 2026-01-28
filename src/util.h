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

/* ------------------------------------------------------------------ */
/* Bitfield helpers (packed uint32_t array)                            */
/* ------------------------------------------------------------------ */
void     bf_set(uint32_t *words, uint32_t bit);
void     bf_clear(uint32_t *words, uint32_t bit);
int      bf_test(const uint32_t *words, uint32_t bit);
uint32_t bf_count_set(const uint32_t *words, uint32_t n_bits);
int      bf_first_clear(const uint32_t *words, uint32_t n_bits);
int      bf_first_set(const uint32_t *words, uint32_t n_bits);
void     bf_and(uint32_t *dst, const uint32_t *src, uint32_t n_words);
void     bf_or(uint32_t *dst, const uint32_t *src, uint32_t n_words);

/* ------------------------------------------------------------------ */
/* Fixed-point Q16.16 helpers                                          */
/* ------------------------------------------------------------------ */
typedef int32_t fp16_t;  /* Q16.16 signed fixed-point */

fp16_t fp16_from_int(int v);
fp16_t fp16_from_float(float f);
float  fp16_to_float(fp16_t x);
fp16_t fp16_mul(fp16_t a, fp16_t b);
fp16_t fp16_div(fp16_t a, fp16_t b);
fp16_t fp16_add(fp16_t a, fp16_t b);
fp16_t fp16_sub(fp16_t a, fp16_t b);
fp16_t fp16_abs(fp16_t x);
int    fp16_cmp(fp16_t a, fp16_t b);

/* ------------------------------------------------------------------ */
/* String pool (intern table)                                           */
/* ------------------------------------------------------------------ */
#define STRPOOL_BUCKETS 64
#define STRPOOL_MAX_LEN 128

typedef struct strpool_entry {
    char                 str[STRPOOL_MAX_LEN];
    uint32_t             hash;
    struct strpool_entry *next;
} strpool_entry_t;

typedef struct {
    strpool_entry_t *buckets[STRPOOL_BUCKETS];
    uint32_t         count;
    uint32_t         collisions;
} strpool_t;

void        strpool_init(strpool_t *sp);
const char *strpool_intern(strpool_t *sp, const char *s);
const char *strpool_lookup(const strpool_t *sp, const char *s);
void        strpool_free(strpool_t *sp);
uint32_t    strpool_count(const strpool_t *sp);

/* ------------------------------------------------------------------ */
/* Hash functions                                                       */
/* ------------------------------------------------------------------ */
uint32_t hash_fnv32(const void *data, size_t len);
uint32_t hash_murmur32(const void *data, size_t len, uint32_t seed);
uint32_t hash_djb2(const char *s);
uint32_t hash_combine(uint32_t h1, uint32_t h2);

/* ------------------------------------------------------------------ */
/* Miscellaneous numeric helpers                                        */
/* ------------------------------------------------------------------ */
uint32_t mdn_next_pow2_u32(uint32_t x);
uint64_t mdn_next_pow2_u64(uint64_t x);
int      mdn_is_pow2(size_t x);
uint32_t mdn_log2_u32(uint32_t x);
int32_t  mdn_abs32(int32_t x);
uint32_t mdn_rotate_left32(uint32_t v, int n);
uint32_t mdn_rotate_right32(uint32_t v, int n);

#endif /* MDN_UTIL_H */
