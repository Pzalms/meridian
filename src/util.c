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

#include <stdlib.h>

/* ================================================================== */
/* Bitfield helpers                                                     */
/* ================================================================== */

void bf_set(uint32_t *words, uint32_t bit)
{
    words[bit >> 5] |= (1u << (bit & 31));
}

void bf_clear(uint32_t *words, uint32_t bit)
{
    words[bit >> 5] &= ~(1u << (bit & 31));
}

int bf_test(const uint32_t *words, uint32_t bit)
{
    return (words[bit >> 5] >> (bit & 31)) & 1u;
}

uint32_t bf_count_set(const uint32_t *words, uint32_t n_bits)
{
    uint32_t count = 0;
    uint32_t full_words = n_bits >> 5;
    for (uint32_t i = 0; i < full_words; i++)
        count += mdn_popcount32(words[i]);
    uint32_t rem = n_bits & 31;
    if (rem) {
        uint32_t mask = (1u << rem) - 1u;
        count += mdn_popcount32(words[full_words] & mask);
    }
    return count;
}

int bf_first_clear(const uint32_t *words, uint32_t n_bits)
{
    uint32_t full_words = (n_bits + 31) >> 5;
    for (uint32_t w = 0; w < full_words; w++) {
        uint32_t inv = ~words[w];
        if (!inv) continue;
        uint32_t bit = w * 32;
        uint32_t x = inv & (uint32_t)(-(int32_t)inv);
        uint32_t idx = 0;
        if (!(x & 0x0000FFFFu)) idx += 16;
        if (!(x & 0x00FF00FFu)) idx +=  8;
        if (!(x & 0x0F0F0F0Fu)) idx +=  4;
        if (!(x & 0x33333333u)) idx +=  2;
        if (!(x & 0x55555555u)) idx +=  1;
        bit += idx;
        if (bit < n_bits) return (int)bit;
    }
    return -1;
}

int bf_first_set(const uint32_t *words, uint32_t n_bits)
{
    uint32_t full_words = (n_bits + 31) >> 5;
    for (uint32_t w = 0; w < full_words; w++) {
        uint32_t wv = words[w];
        if (!wv) continue;
        uint32_t bit = w * 32;
        uint32_t x = wv & (uint32_t)(-(int32_t)wv);
        uint32_t idx = 0;
        if (!(x & 0x0000FFFFu)) idx += 16;
        if (!(x & 0x00FF00FFu)) idx +=  8;
        if (!(x & 0x0F0F0F0Fu)) idx +=  4;
        if (!(x & 0x33333333u)) idx +=  2;
        if (!(x & 0x55555555u)) idx +=  1;
        bit += idx;
        if (bit < n_bits) return (int)bit;
    }
    return -1;
}

void bf_and(uint32_t *dst, const uint32_t *src, uint32_t n_words)
{
    for (uint32_t i = 0; i < n_words; i++)
        dst[i] &= src[i];
}

void bf_or(uint32_t *dst, const uint32_t *src, uint32_t n_words)
{
    for (uint32_t i = 0; i < n_words; i++)
        dst[i] |= src[i];
}

/* ================================================================== */
/* Fixed-point Q16.16                                                   */
/* ================================================================== */

#define FP16_FRAC_BITS 16
#define FP16_ONE       (1 << FP16_FRAC_BITS)

fp16_t fp16_from_int(int v)
{
    return (fp16_t)(v * FP16_ONE);
}

fp16_t fp16_from_float(float f)
{
    return (fp16_t)(f * (float)FP16_ONE);
}

float fp16_to_float(fp16_t x)
{
    return (float)x / (float)FP16_ONE;
}

fp16_t fp16_add(fp16_t a, fp16_t b)
{
    return a + b;
}

fp16_t fp16_sub(fp16_t a, fp16_t b)
{
    return a - b;
}

fp16_t fp16_mul(fp16_t a, fp16_t b)
{
    int64_t r = (int64_t)a * (int64_t)b;
    return (fp16_t)(r >> FP16_FRAC_BITS);
}

fp16_t fp16_div(fp16_t a, fp16_t b)
{
    if (b == 0) return 0;
    int64_t r = ((int64_t)a << FP16_FRAC_BITS) / b;
    return (fp16_t)r;
}

fp16_t fp16_abs(fp16_t x)
{
    return x < 0 ? -x : x;
}

int fp16_cmp(fp16_t a, fp16_t b)
{
    if (a < b) return -1;
    if (a > b) return  1;
    return 0;
}

/* ================================================================== */
/* String pool                                                          */
/* ================================================================== */

void strpool_init(strpool_t *sp)
{
    if (!sp) return;
    memset(sp, 0, sizeof(*sp));
}

static uint32_t strpool_hash(const char *s)
{
    uint32_t h = 5381;
    unsigned char c;
    while ((c = (unsigned char)*s++) != 0)
        h = ((h << 5) + h) ^ c;
    return h;
}

const char *strpool_intern(strpool_t *sp, const char *s)
{
    if (!sp || !s) return NULL;
    size_t slen = strlen(s);
    if (slen >= STRPOOL_MAX_LEN) return NULL;

    uint32_t h   = strpool_hash(s);
    uint32_t idx = h % STRPOOL_BUCKETS;

    for (strpool_entry_t *e = sp->buckets[idx]; e; e = e->next) {
        if (e->hash == h && strcmp(e->str, s) == 0)
            return e->str;
    }

    strpool_entry_t *entry = calloc(1, sizeof(strpool_entry_t));
    if (!entry) return NULL;
    memcpy(entry->str, s, slen + 1);
    entry->hash      = h;
    entry->next      = sp->buckets[idx];
    sp->buckets[idx] = entry;
    sp->count++;
    return entry->str;
}

const char *strpool_lookup(const strpool_t *sp, const char *s)
{
    if (!sp || !s) return NULL;
    uint32_t h   = strpool_hash(s);
    uint32_t idx = h % STRPOOL_BUCKETS;
    for (const strpool_entry_t *e = sp->buckets[idx]; e; e = e->next) {
        if (e->hash == h && strcmp(e->str, s) == 0)
            return e->str;
    }
    return NULL;
}

void strpool_free(strpool_t *sp)
{
    if (!sp) return;
    for (int i = 0; i < STRPOOL_BUCKETS; i++) {
        strpool_entry_t *e = sp->buckets[i];
        while (e) {
            strpool_entry_t *nxt = e->next;
            free(e);
            e = nxt;
        }
        sp->buckets[i] = NULL;
    }
    sp->count      = 0;
    sp->collisions = 0;
}

uint32_t strpool_count(const strpool_t *sp)
{
    if (!sp) return 0;
    return sp->count;
}

/* ================================================================== */
/* Hash functions                                                       */
/* ================================================================== */

uint32_t hash_fnv32(const void *data, size_t len)
{
    const uint8_t *p = (const uint8_t *)data;
    uint32_t h = 2166136261u;
    for (size_t i = 0; i < len; i++)
        h = (h ^ p[i]) * 16777619u;
    return h;
}

uint32_t hash_murmur32(const void *data, size_t len, uint32_t seed)
{
    const uint8_t *p = (const uint8_t *)data;
    uint32_t h = seed;
    size_t nblocks = len / 4;

    for (size_t i = 0; i < nblocks; i++) {
        uint32_t k;
        memcpy(&k, p + i * 4, 4);
        k *= 0xcc9e2d51u;
        k  = (k << 15) | (k >> 17);
        k *= 0x1b873593u;
        h ^= k;
        h  = (h << 13) | (h >> 19);
        h  = h * 5u + 0xe6546b64u;
    }

    const uint8_t *tail = p + nblocks * 4;
    uint32_t k = 0;
    switch (len & 3) {
    case 3: k ^= (uint32_t)tail[2] << 16; /* fall through */
    case 2: k ^= (uint32_t)tail[1] << 8;  /* fall through */
    case 1: k ^= tail[0];
            k *= 0xcc9e2d51u;
            k  = (k << 15) | (k >> 17);
            k *= 0x1b873593u;
            h ^= k;
            break;
    default: break;
    }

    h ^= (uint32_t)len;
    h ^= h >> 16; h *= 0x85ebca6bu;
    h ^= h >> 13; h *= 0xc2b2ae35u;
    h ^= h >> 16;
    return h;
}

uint32_t hash_djb2(const char *s)
{
    uint32_t h = 5381;
    unsigned char c;
    while ((c = (unsigned char)*s++) != 0)
        h = ((h << 5) + h) ^ c;
    return h;
}

uint32_t hash_combine(uint32_t h1, uint32_t h2)
{
    return h1 ^ (h2 * 0x9e3779b9u + (h1 << 6) + (h1 >> 2));
}

/* ================================================================== */
/* Miscellaneous numeric helpers                                        */
/* ================================================================== */

uint32_t mdn_next_pow2_u32(uint32_t x)
{
    if (x == 0) return 1;
    x--;
    x |= x >> 1; x |= x >> 2; x |= x >> 4;
    x |= x >> 8; x |= x >> 16;
    return x + 1;
}

uint64_t mdn_next_pow2_u64(uint64_t x)
{
    if (x == 0) return 1;
    x--;
    x |= x >> 1;  x |= x >> 2;  x |= x >> 4;
    x |= x >> 8;  x |= x >> 16; x |= x >> 32;
    return x + 1;
}

int mdn_is_pow2(size_t x)
{
    return (x > 0 && (x & (x - 1)) == 0) ? 1 : 0;
}

uint32_t mdn_log2_u32(uint32_t x)
{
    if (!x) return 0;
    uint32_t r = 0;
    if (x >> 16) { r += 16; x >>= 16; }
    if (x >>  8) { r +=  8; x >>=  8; }
    if (x >>  4) { r +=  4; x >>=  4; }
    if (x >>  2) { r +=  2; x >>=  2; }
    if (x >>  1) { r +=  1; }
    return r;
}

int32_t mdn_abs32(int32_t x)
{
    return x < 0 ? -x : x;
}

uint32_t mdn_rotate_left32(uint32_t v, int n)
{
    n &= 31;
    return (v << n) | (v >> (32 - n));
}

uint32_t mdn_rotate_right32(uint32_t v, int n)
{
    n &= 31;
    return (v >> n) | (v << (32 - n));
}
