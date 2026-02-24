/*
 * test_main.c - comprehensive test suite for the meridian library.
 * Compilation:
 *   cc -Iinclude -Isrc -Wall -Wextra -std=c11 tests/test_main.c src/[*].c -lm -o tests/test_main
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>

/* Public API */
#include "meridian.h"

/* Internal types and constants — needed for direct module testing */
#include "mdn_internal.h"
#include "cap.h"
#include "crc.h"
#include "zone.h"
#include "nat.h"
#include "session.h"
#include "prefix.h"
#include "rule.h"
#include "template.h"
#include "audit.h"
#include "export.h"
#include "query.h"
#include "validate.h"
#include "trie.h"

/* ------------------------------------------------------------------ */
/* Test framework                                                       */
/* ------------------------------------------------------------------ */

static int passed = 0, failed = 0;

#define ASSERT(cond) do { if(cond){passed++;}else{failed++;fprintf(stderr,"FAIL %s:%d: %s\n",__FILE__,__LINE__,#cond);} } while(0)
#define ASSERT_EQ(a,b) ASSERT((a)==(b))
#define ASSERT_NE(a,b) ASSERT((a)!=(b))
#define ASSERT_NULL(p) ASSERT((p)==NULL)
#define ASSERT_NOT_NULL(p) ASSERT((p)!=NULL)

/* ------------------------------------------------------------------ */
/* LE helpers                                                           */
/* ------------------------------------------------------------------ */

static void put_u16(uint8_t *p, uint16_t v) { p[0]=v&0xFF; p[1]=(v>>8)&0xFF; }
static void put_u32(uint8_t *p, uint32_t v) {
    p[0]=v&0xFF; p[1]=(v>>8)&0xFF; p[2]=(v>>16)&0xFF; p[3]=(v>>24)&0xFF;
}
static void put_u64(uint8_t *p, uint64_t v) {
    for(int i=0;i<8;i++) p[i]=(uint8_t)((v>>(8*i))&0xFF);
}

/* ------------------------------------------------------------------ */
/* build_mdn helper                                                     */
/* ------------------------------------------------------------------ */

static uint8_t *build_mdn(uint16_t flags, uint16_t n_sects,
                           uint8_t *sect_types, uint16_t *sect_ids,
                           const uint8_t **sect_data, uint32_t *sect_lens,
                           size_t *out_len)
{
    uint32_t data_offset = 12 + (uint32_t)n_sects * 20;
    uint32_t total = data_offset;
    for (uint16_t i = 0; i < n_sects; i++) total += sect_lens[i];

    uint8_t *buf = calloc(1, total);
    if (!buf) return NULL;

    buf[0]='M'; buf[1]='D'; buf[2]='N'; buf[3]='1';
    put_u16(buf+4, flags);
    put_u16(buf+6, n_sects);
    put_u16(buf+8, 0);
    put_u16(buf+10, 0);

    uint32_t cur_off = data_offset;
    for (uint16_t i = 0; i < n_sects; i++) {
        uint8_t *entry = buf + 12 + (uint32_t)i * 20;
        entry[0] = sect_types[i];
        entry[1] = 0;
        put_u16(entry+2, sect_ids[i]);
        put_u32(entry+4, cur_off);
        put_u32(entry+8, sect_lens[i]);
        uint32_t crc = crc32_compute(sect_data[i], sect_lens[i]);
        put_u32(entry+12, crc);
        put_u32(entry+16, 0);

        memcpy(buf + cur_off, sect_data[i], sect_lens[i]);
        cur_off += sect_lens[i];
    }

    *out_len = total;
    return buf;
}

/* ------------------------------------------------------------------ */
/* Helper: build zone payload (12 bytes)                               */
/* ------------------------------------------------------------------ */
static void make_zone_payload(uint8_t *buf,
                               uint16_t zone_id, uint16_t parent_id,
                               uint16_t if_count, uint16_t z_flags,
                               uint32_t epoch)
{
    put_u16(buf+0, zone_id);
    put_u16(buf+2, parent_id);
    put_u16(buf+4, if_count);
    put_u16(buf+6, z_flags);
    put_u32(buf+8, epoch);
}

/* ------------------------------------------------------------------ */
/* Helper: build rule payload                                           */
/* count(u32) + count * 12 bytes (key u32, mask u32, action u16, next u16) */
/* ------------------------------------------------------------------ */
static uint8_t *make_rule_payload(uint32_t count,
                                  uint32_t *keys, uint32_t *masks,
                                  uint16_t *actions, uint16_t *nexts,
                                  uint32_t *out_len)
{
    uint32_t len = 4 + count * 12;
    uint8_t *buf = calloc(1, len);
    if (!buf) return NULL;
    put_u32(buf, count);
    for (uint32_t i = 0; i < count; i++) {
        uint8_t *p = buf + 4 + i*12;
        put_u32(p+0, keys[i]);
        put_u32(p+4, masks[i]);
        put_u16(p+8, actions[i]);
        put_u16(p+10, nexts[i]);
    }
    *out_len = len;
    return buf;
}

/* ------------------------------------------------------------------ */
/* CAP token constants                                                  */
/* ------------------------------------------------------------------ */
static const uint8_t CAP_TOKEN_GOOD[32] = {
    0x4d,0x45,0x52,0x49,0x44,0x49,0x41,0x4e,
    0x5f,0x43,0x41,0x50,0x5f,0x4b,0x45,0x59,
    0x5f,0x46,0x45,0x4e,0x52,0x49,0x52,0x5f,
    0x32,0x30,0x32,0x36,0x5f,0x4b,0x45,0x59
};
static const uint64_t CAP_NONCE_GOOD = 0xA1B2C3D4E5F60718ULL;

/* ------------------------------------------------------------------ */
/* 1. CRC SUITE (~60 assertions)                                        */
/* ------------------------------------------------------------------ */
static void test_crc(void)
{
    printf("--- CRC suite ---\n");

    /* Empty input */
    uint32_t c0 = crc32_compute(NULL, 0);
    /* CRC32C of empty: XOR of 0xFFFFFFFF ^ 0xFFFFFFFF = 0 */
    ASSERT_EQ(c0, 0x00000000U);

    /* Known CRC32C vector: "123456789" -> 0xE3069283 */
    const uint8_t digits[] = "123456789";
    uint32_t c1 = crc32_compute(digits, 9);
    ASSERT_EQ(c1, 0xE3069283U);

    /* Idempotency: same data produces same result */
    uint32_t c1b = crc32_compute(digits, 9);
    ASSERT_EQ(c1, c1b);

    /* Single byte 0x00 — should be nonzero (CRC32C(0x00) != 0) */
    uint8_t b0 = 0x00;
    uint32_t c2 = crc32_compute(&b0, 1);
    ASSERT_NE(c2, 0U); /* CRC32C(0x00) = 0xAA36918A */

    /* Single byte 0xFF */
    uint8_t bff = 0xFF;
    uint32_t c3 = crc32_compute(&bff, 1);
    ASSERT_NE(c3, 0U);

    /* Idempotency of single bytes */
    ASSERT_EQ(crc32_compute(&b0, 1), crc32_compute(&b0, 1));
    ASSERT_EQ(crc32_compute(&bff, 1), crc32_compute(&bff, 1));

    /* Different bytes produce different CRCs */
    ASSERT_NE(crc32_compute(&b0, 1), crc32_compute(&bff, 1));

    /* 4-byte input */
    uint8_t four[4] = {0x01, 0x02, 0x03, 0x04};
    uint32_t c4 = crc32_compute(four, 4);
    ASSERT_NE(c4, 0U);
    ASSERT_EQ(c4, crc32_compute(four, 4));

    /* 8-byte input */
    uint8_t eight[8] = {0xDE,0xAD,0xBE,0xEF,0xCA,0xFE,0xBA,0xBE};
    uint32_t c5 = crc32_compute(eight, 8);
    ASSERT_NE(c5, 0U);
    ASSERT_EQ(c5, crc32_compute(eight, 8));

    /* 16-byte input */
    uint8_t sixteen[16];
    for(int i=0;i<16;i++) sixteen[i]=(uint8_t)i;
    uint32_t c6 = crc32_compute(sixteen, 16);
    ASSERT_NE(c6, 0U);
    ASSERT_EQ(c6, crc32_compute(sixteen, 16));

    /* 32-byte input */
    uint8_t thirtytwo[32];
    for(int i=0;i<32;i++) thirtytwo[i]=(uint8_t)(255-i);
    uint32_t c7 = crc32_compute(thirtytwo, 32);
    ASSERT_NE(c7, 0U);
    ASSERT_EQ(c7, crc32_compute(thirtytwo, 32));

    /* Length sensitivity: different lengths produce different CRCs */
    ASSERT_NE(crc32_compute(digits, 9), crc32_compute(digits, 8));
    ASSERT_NE(crc32_compute(digits, 9), crc32_compute(digits, 1));

    /* All-zero 16 bytes */
    uint8_t zeros16[16] = {0};
    uint32_t czero = crc32_compute(zeros16, 16);
    ASSERT_NE(czero, 0U);
    ASSERT_EQ(czero, crc32_compute(zeros16, 16));

    /* All-ones 8 bytes */
    uint8_t ones8[8] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
    uint32_t cones = crc32_compute(ones8, 8);
    ASSERT_NE(cones, 0U);
    ASSERT_EQ(cones, crc32_compute(ones8, 8));

    /* Single byte 0x41 'A' */
    uint8_t ba = 0x41;
    uint32_t ca = crc32_compute(&ba, 1);
    ASSERT_NE(ca, 0U);
    ASSERT_EQ(ca, crc32_compute(&ba, 1));

    /* Flip one bit changes the CRC */
    uint8_t flipped[9];
    memcpy(flipped, digits, 9);
    flipped[0] ^= 0x01;
    ASSERT_NE(crc32_compute(flipped, 9), c1);

    /* 64-byte block */
    uint8_t block64[64];
    for(int i=0;i<64;i++) block64[i]=(uint8_t)(i*3+7);
    uint32_t c64 = crc32_compute(block64, 64);
    ASSERT_NE(c64, 0U);
    ASSERT_EQ(c64, crc32_compute(block64, 64));

    /* Prefix does not equal full */
    ASSERT_NE(crc32_compute(block64, 32), crc32_compute(block64, 64));

    /* 2-byte input */
    uint8_t two[2] = {0xAB, 0xCD};
    uint32_t c2b = crc32_compute(two, 2);
    ASSERT_NE(c2b, 0U);
    ASSERT_EQ(c2b, crc32_compute(two, 2));

    /* 3-byte input */
    uint8_t three[3] = {0x01, 0x23, 0x45};
    uint32_t c3b = crc32_compute(three, 3);
    ASSERT_NE(c3b, 0U);
    ASSERT_EQ(c3b, crc32_compute(three, 3));

    /* Order matters */
    uint8_t rev[9];
    for(int i=0;i<9;i++) rev[i]=digits[8-i];
    ASSERT_NE(crc32_compute(rev, 9), c1);

    /* 128-byte block */
    uint8_t block128[128];
    for(int i=0;i<128;i++) block128[i]=(uint8_t)(i^0x5A);
    uint32_t c128 = crc32_compute(block128, 128);
    ASSERT_NE(c128, 0U);
    ASSERT_EQ(c128, crc32_compute(block128, 128));

    /* Known: single 0x01 byte */
    uint8_t b1 = 0x01;
    uint32_t c_b1 = crc32_compute(&b1, 1);
    ASSERT_NE(c_b1, 0U);
    ASSERT_EQ(c_b1, crc32_compute(&b1, 1));

    /* Ensure 4-byte and 8-byte differ */
    ASSERT_NE(crc32_compute(four, 4), crc32_compute(eight, 8));

    printf("CRC assertions done\n");
}

/* ------------------------------------------------------------------ */
/* 2. CAP SUITE (~60 assertions)                                        */
/* ------------------------------------------------------------------ */
static void test_cap(void)
{
    printf("--- CAP suite ---\n");

    mdn_ctx_t *ctx = calloc(1, sizeof(mdn_ctx_t));
    ASSERT_NOT_NULL(ctx);

    /* Build correct 40-byte payload */
    uint8_t payload[40];
    memcpy(payload, CAP_TOKEN_GOOD, 32);
    put_u64(payload+32, CAP_NONCE_GOOD);

    /* Correct token + correct nonce */
    int rc = mdn_cap_load(ctx, payload, 40);
    ASSERT_EQ(rc, 0);
    ASSERT_EQ(ctx->cap_ok, 1);

    /* cap_check returns 1 for any purpose_id when cap_ok=1 */
    ASSERT_EQ(mdn_cap_check(ctx, 0),    1);
    ASSERT_EQ(mdn_cap_check(ctx, 1),    1);
    ASSERT_EQ(mdn_cap_check(ctx, 0x51), 1);
    ASSERT_EQ(mdn_cap_check(ctx, 0xFF), 1);
    ASSERT_EQ(mdn_cap_check(ctx, 0x53), 1);
    ASSERT_EQ(mdn_cap_check(ctx, 0x55), 1);

    /* Token bytes copied correctly */
    ASSERT_EQ(memcmp(ctx->cap_token, CAP_TOKEN_GOOD, 32), 0);

    /* Correct nonce stored */
    ASSERT_EQ(ctx->cap_nonce, CAP_NONCE_GOOD);

    /* Wrong nonce */
    uint8_t payload_wn[40];
    memcpy(payload_wn, CAP_TOKEN_GOOD, 32);
    put_u64(payload_wn+32, CAP_NONCE_GOOD ^ 0x01ULL);
    rc = mdn_cap_load(ctx, payload_wn, 40);
    ASSERT_EQ(rc, 0);
    ASSERT_EQ(ctx->cap_ok, 0);
    ASSERT_EQ(mdn_cap_check(ctx, 0), 0);
    ASSERT_EQ(mdn_cap_check(ctx, 1), 0);

    /* Wrong token */
    uint8_t payload_wt[40];
    memset(payload_wt, 0xAA, 32);
    put_u64(payload_wt+32, CAP_NONCE_GOOD);
    rc = mdn_cap_load(ctx, payload_wt, 40);
    ASSERT_EQ(rc, 0);
    ASSERT_EQ(ctx->cap_ok, 0);
    ASSERT_EQ(mdn_cap_check(ctx, 0x51), 0);

    /* All-zero payload */
    uint8_t zeros40[40] = {0};
    rc = mdn_cap_load(ctx, zeros40, 40);
    ASSERT_EQ(rc, 0);
    ASSERT_EQ(ctx->cap_ok, 0);
    ASSERT_EQ(mdn_cap_check(ctx, 0), 0);

    /* Short payload (39 bytes) */
    rc = mdn_cap_load(ctx, payload, 39);
    ASSERT_EQ(rc, -1);

    /* Short payload (0 bytes) */
    rc = mdn_cap_load(ctx, payload, 0);
    ASSERT_EQ(rc, -1);

    /* Short payload (1 byte) */
    rc = mdn_cap_load(ctx, payload, 1);
    ASSERT_EQ(rc, -1);

    /* Exactly 40 bytes — minimum accepted */
    rc = mdn_cap_load(ctx, payload, 40);
    ASSERT_EQ(rc, 0);
    ASSERT_EQ(ctx->cap_ok, 1);

    /* 41 bytes — also accepted */
    uint8_t payload41[41];
    memcpy(payload41, payload, 40);
    payload41[40] = 0xFF;
    rc = mdn_cap_load(ctx, payload41, 41);
    ASSERT_EQ(rc, 0);
    ASSERT_EQ(ctx->cap_ok, 1);

    /* Wrong token byte-by-byte: flip first byte */
    uint8_t payload_fb[40];
    memcpy(payload_fb, payload, 40);
    payload_fb[0] ^= 0x01;
    rc = mdn_cap_load(ctx, payload_fb, 40);
    ASSERT_EQ(rc, 0);
    ASSERT_EQ(ctx->cap_ok, 0);

    /* Wrong token: flip last byte of token */
    uint8_t payload_lb[40];
    memcpy(payload_lb, payload, 40);
    payload_lb[31] ^= 0x01;
    rc = mdn_cap_load(ctx, payload_lb, 40);
    ASSERT_EQ(rc, 0);
    ASSERT_EQ(ctx->cap_ok, 0);

    /* Both wrong */
    uint8_t payload_both[40];
    memset(payload_both, 0x55, 40);
    rc = mdn_cap_load(ctx, payload_both, 40);
    ASSERT_EQ(rc, 0);
    ASSERT_EQ(ctx->cap_ok, 0);

    /* Reload correct — cap_ok recovers to 1 */
    rc = mdn_cap_load(ctx, payload, 40);
    ASSERT_EQ(rc, 0);
    ASSERT_EQ(ctx->cap_ok, 1);

    /* cap_nonce stored correctly after good load */
    ASSERT_EQ(ctx->cap_nonce, CAP_NONCE_GOOD);

    /* All token bytes match */
    for (int i = 0; i < 32; i++) {
        ASSERT_EQ(ctx->cap_token[i], CAP_TOKEN_GOOD[i]);
    }

    free(ctx);
    printf("CAP assertions done\n");
}

/* ------------------------------------------------------------------ */
/* 3. ZONE SUITE (~80 assertions)                                       */
/* ------------------------------------------------------------------ */
static void test_zone(void)
{
    printf("--- Zone suite ---\n");

    mdn_ctx_t *ctx = calloc(1, sizeof(mdn_ctx_t));
    ASSERT_NOT_NULL(ctx);

    /* Build zone payload id=1 */
    uint8_t zp[12];
    make_zone_payload(zp, 1, 0, 3, 0, 100);
    int rc = zone_load(ctx, zp, 12, 0);
    ASSERT_EQ(rc, 0);

    mdn_zone_t *z = zone_lookup(ctx, 1);
    ASSERT_NOT_NULL(z);
    ASSERT_EQ(z->zone_id,   1);
    ASSERT_EQ(z->parent_id, 0);
    ASSERT_EQ(z->if_count,  3);
    ASSERT_EQ(z->flags,     0);
    ASSERT_EQ(z->epoch,     100U);

    /* zone_lookup for non-existent zone */
    ASSERT_NULL(zone_lookup(ctx, 99));

    /* Load zone id=2, parent=1 */
    uint8_t zp2[12];
    make_zone_payload(zp2, 2, 1, 5, 0x01, 200);
    rc = zone_load(ctx, zp2, 12, 0);
    ASSERT_EQ(rc, 0);

    mdn_zone_t *z2 = zone_lookup(ctx, 2);
    ASSERT_NOT_NULL(z2);
    ASSERT_EQ(z2->zone_id,   2);
    ASSERT_EQ(z2->parent_id, 1);
    ASSERT_EQ(z2->if_count,  5);
    ASSERT_EQ(z2->flags,     0x01);
    ASSERT_EQ(z2->epoch,     200U);

    /* zone_lookup zone_id=2 succeeds, zone_id=3 fails */
    ASSERT_NOT_NULL(zone_lookup(ctx, 2));
    ASSERT_NULL(zone_lookup(ctx, 3));

    /* Short payload (< 12) -> -1 */
    uint8_t short_z[11] = {0};
    rc = zone_load(ctx, short_z, 11, 0);
    ASSERT_EQ(rc, -1);

    rc = zone_load(ctx, short_z, 0, 0);
    ASSERT_EQ(rc, -1);

    /* Boundary zone_id = MDN_MAX_ZONES-1 = 127 */
    uint8_t zpb[12];
    make_zone_payload(zpb, 127, 0, 1, 0, 300);
    rc = zone_load(ctx, zpb, 12, 0);
    ASSERT_EQ(rc, 0);
    mdn_zone_t *zb = zone_lookup(ctx, 127);
    ASSERT_NOT_NULL(zb);
    ASSERT_EQ(zb->zone_id, 127);
    ASSERT_EQ(zb->epoch,   300U);

    /* zone_id=0 works (stores at index 0) */
    uint8_t zp0[12];
    make_zone_payload(zp0, 0, 0, 0, 0, 50);
    rc = zone_load(ctx, zp0, 12, 0);
    ASSERT_EQ(rc, 0);
    mdn_zone_t *z0 = zone_lookup(ctx, 0);
    ASSERT_NOT_NULL(z0);
    ASSERT_EQ(z0->zone_id, 0);
    ASSERT_EQ(z0->epoch,   50U);

    /* Load zone id=10 with various fields */
    uint8_t zp10[12];
    make_zone_payload(zp10, 10, 5, 8, 0xFF, 9999);
    rc = zone_load(ctx, zp10, 12, 0);
    ASSERT_EQ(rc, 0);
    mdn_zone_t *z10 = zone_lookup(ctx, 10);
    ASSERT_NOT_NULL(z10);
    ASSERT_EQ(z10->zone_id,   10);
    ASSERT_EQ(z10->parent_id, 5);
    ASSERT_EQ(z10->if_count,  8);
    ASSERT_EQ(z10->flags,     0xFF);
    ASSERT_EQ(z10->epoch,     9999U);

    /* Load zone id=50 */
    uint8_t zp50[12];
    make_zone_payload(zp50, 50, 10, 2, 0, 12345);
    rc = zone_load(ctx, zp50, 12, 0);
    ASSERT_EQ(rc, 0);
    ASSERT_NOT_NULL(zone_lookup(ctx, 50));
    ASSERT_EQ(zone_lookup(ctx, 50)->if_count, 2);

    /* Overwrite zone id=1 with new epoch */
    make_zone_payload(zp, 1, 0, 3, 0, 999);
    rc = zone_load(ctx, zp, 12, 0);
    ASSERT_EQ(rc, 0);
    ASSERT_EQ(zone_lookup(ctx, 1)->epoch, 999U);

    /* Exact 12-byte payload still accepted */
    uint8_t zp_exact[12];
    make_zone_payload(zp_exact, 20, 0, 1, 0, 1);
    rc = zone_load(ctx, zp_exact, 12, 0);
    ASSERT_EQ(rc, 0);
    ASSERT_NOT_NULL(zone_lookup(ctx, 20));

    /* Extra bytes in payload accepted (len > 12) */
    uint8_t zp_extra[20] = {0};
    make_zone_payload(zp_extra, 30, 0, 2, 0, 77);
    rc = zone_load(ctx, zp_extra, 20, 0);
    ASSERT_EQ(rc, 0);
    ASSERT_NOT_NULL(zone_lookup(ctx, 30));
    ASSERT_EQ(zone_lookup(ctx, 30)->if_count, 2);

    /* Lookup by each loaded zone_id still works */
    ASSERT_NOT_NULL(zone_lookup(ctx, 2));
    ASSERT_NOT_NULL(zone_lookup(ctx, 127));
    ASSERT_NOT_NULL(zone_lookup(ctx, 10));
    ASSERT_NOT_NULL(zone_lookup(ctx, 50));

    /* zone_free_all clears without crash */
    zone_free_all(ctx);
    ASSERT_NULL(zone_lookup(ctx, 1));
    ASSERT_NULL(zone_lookup(ctx, 2));
    ASSERT_NULL(zone_lookup(ctx, 127));

    /* Can load again after free */
    make_zone_payload(zp, 5, 0, 1, 0, 42);
    rc = zone_load(ctx, zp, 12, 0);
    ASSERT_EQ(rc, 0);
    ASSERT_NOT_NULL(zone_lookup(ctx, 5));

    /* Second free is safe */
    zone_free_all(ctx);
    zone_free_all(ctx);

    free(ctx);
    printf("Zone assertions done\n");
}

/* ------------------------------------------------------------------ */
/* 4. RULE SUITE (~70 assertions)                                       */
/* ------------------------------------------------------------------ */
static void test_rule(void)
{
    printf("--- Rule suite ---\n");

    mdn_ctx_t *ctx = calloc(1, sizeof(mdn_ctx_t));
    ASSERT_NOT_NULL(ctx);

    /* rule_load count=0 */
    uint8_t r0[4] = {0,0,0,0};
    int rc = rule_load(ctx, r0, 4);
    ASSERT_EQ(rc, 0);
    ASSERT_EQ(ctx->rule_count, 0U);
    ASSERT_NULL(ctx->rules);

    /* Short payload (< 4) -> -1 */
    rc = rule_load(ctx, r0, 3);
    ASSERT_EQ(rc, -1);
    rc = rule_load(ctx, r0, 0);
    ASSERT_EQ(rc, -1);

    /* rule_load count=1, action=ACTION_ALLOW=0 */
    uint32_t k1[1] = {0xDEADBEEF};
    uint32_t m1[1] = {0xFFFFFFFF};
    uint16_t a1[1] = {ACTION_ALLOW};
    uint16_t n1[1] = {0xFFFF};
    uint32_t rlen1;
    uint8_t *rbuf1 = make_rule_payload(1, k1, m1, a1, n1, &rlen1);
    ASSERT_NOT_NULL(rbuf1);
    rc = rule_load(ctx, rbuf1, rlen1);
    ASSERT_EQ(rc, 0);
    ASSERT_EQ(ctx->rule_count, 1U);
    ASSERT_NOT_NULL(ctx->rules);
    ASSERT_EQ(ctx->rules[0].key,    0xDEADBEEFU);
    ASSERT_EQ(ctx->rules[0].mask,   0xFFFFFFFFU);
    ASSERT_EQ(ctx->rules[0].action, ACTION_ALLOW);
    ASSERT_EQ(ctx->rules[0].next,   0xFFFFU);
    free(rbuf1);

    /* rule_load count=3, mixed actions */
    uint32_t k3[3] = {0x01020304, 0x05060708, 0x090A0B0C};
    uint32_t m3[3] = {0xFF000000, 0xFFFF0000, 0xFFFFFF00};
    uint16_t a3[3] = {ACTION_DROP, ACTION_MARK, ACTION_REDIRECT};
    uint16_t n3[3] = {1, 2, 0xFFFF};
    uint32_t rlen3;
    uint8_t *rbuf3 = make_rule_payload(3, k3, m3, a3, n3, &rlen3);
    ASSERT_NOT_NULL(rbuf3);
    rc = rule_load(ctx, rbuf3, rlen3);
    ASSERT_EQ(rc, 0);
    ASSERT_EQ(ctx->rule_count, 3U);
    ASSERT_EQ(ctx->rules[0].key,    0x01020304U);
    ASSERT_EQ(ctx->rules[0].mask,   0xFF000000U);
    ASSERT_EQ(ctx->rules[0].action, ACTION_DROP);
    ASSERT_EQ(ctx->rules[0].next,   1U);
    ASSERT_EQ(ctx->rules[1].key,    0x05060708U);
    ASSERT_EQ(ctx->rules[1].action, ACTION_MARK);
    ASSERT_EQ(ctx->rules[2].key,    0x090A0B0CU);
    ASSERT_EQ(ctx->rules[2].action, ACTION_REDIRECT);
    free(rbuf3);

    /* ACTION constants */
    ASSERT_EQ(ACTION_ALLOW,        0);
    ASSERT_EQ(ACTION_DROP,         1);
    ASSERT_EQ(ACTION_MARK,         2);
    ASSERT_EQ(ACTION_REDIRECT,     3);
    ASSERT_EQ(ACTION_NAT_LOOKUP,   4);
    ASSERT_EQ(ACTION_TRIE_LOOKUP,  5);
    ASSERT_EQ(ACTION_AUDIT_EXPORT, 6);

    /* Load rules with ACTION_NAT_LOOKUP */
    uint32_t k_nat[1] = {0x12345678};
    uint32_t m_nat[1] = {0xFFFFFFFF};
    uint16_t a_nat[1] = {ACTION_NAT_LOOKUP};
    uint16_t n_nat[1] = {0};
    uint32_t rlen_nat;
    uint8_t *rbuf_nat = make_rule_payload(1, k_nat, m_nat, a_nat, n_nat, &rlen_nat);
    ASSERT_NOT_NULL(rbuf_nat);
    rc = rule_load(ctx, rbuf_nat, rlen_nat);
    ASSERT_EQ(rc, 0);
    ASSERT_EQ(ctx->rules[0].action, ACTION_NAT_LOOKUP);
    free(rbuf_nat);

    /* ACTION_TRIE_LOOKUP */
    uint16_t a_trie[1] = {ACTION_TRIE_LOOKUP};
    uint32_t rlen_trie;
    uint8_t *rbuf_trie = make_rule_payload(1, k_nat, m_nat, a_trie, n_nat, &rlen_trie);
    ASSERT_NOT_NULL(rbuf_trie);
    rc = rule_load(ctx, rbuf_trie, rlen_trie);
    ASSERT_EQ(rc, 0);
    ASSERT_EQ(ctx->rules[0].action, ACTION_TRIE_LOOKUP);
    free(rbuf_trie);

    /* ACTION_AUDIT_EXPORT */
    uint16_t a_audit[1] = {ACTION_AUDIT_EXPORT};
    uint32_t rlen_audit;
    uint8_t *rbuf_audit = make_rule_payload(1, k_nat, m_nat, a_audit, n_nat, &rlen_audit);
    ASSERT_NOT_NULL(rbuf_audit);
    rc = rule_load(ctx, rbuf_audit, rlen_audit);
    ASSERT_EQ(rc, 0);
    ASSERT_EQ(ctx->rules[0].action, ACTION_AUDIT_EXPORT);
    free(rbuf_audit);

    /* count > MDN_MAX_RULES -> -1 */
    uint8_t toobig[4];
    put_u32(toobig, MDN_MAX_RULES + 1);
    rc = rule_load(ctx, toobig, 4);
    ASSERT_EQ(rc, -1);

    /* count = MDN_MAX_RULES exactly, but truncated payload -> -1 */
    uint8_t exact_count[4];
    put_u32(exact_count, MDN_MAX_RULES);
    /* only 4 bytes (no rule data) -> truncated */
    rc = rule_load(ctx, exact_count, 4);
    ASSERT_EQ(rc, -1);

    /* count says 2 but only 1 worth of data -> -1 */
    uint32_t k_trunc[2] = {1, 2};
    uint32_t m_trunc[2] = {0, 0};
    uint16_t a_trunc[2] = {0, 0};
    uint16_t n_trunc[2] = {0, 0};
    uint32_t rlen_trunc;
    uint8_t *rbuf_trunc = make_rule_payload(2, k_trunc, m_trunc, a_trunc, n_trunc, &rlen_trunc);
    ASSERT_NOT_NULL(rbuf_trunc);
    /* lie: say count=2 but cut to 1 rule worth of bytes */
    rbuf_trunc[0] = 2; rbuf_trunc[1] = 0; rbuf_trunc[2] = 0; rbuf_trunc[3] = 0;
    rc = rule_load(ctx, rbuf_trunc, 4 + 12); /* only 1 rule */
    ASSERT_EQ(rc, -1);
    free(rbuf_trunc);

    /* Rule key/mask/next round-trip */
    uint32_t k_rt[1] = {0xCAFEBABE};
    uint32_t m_rt[1] = {0x0F0F0F0F};
    uint16_t a_rt[1] = {ACTION_MARK};
    uint16_t n_rt[1] = {0x0ABC};
    uint32_t rlen_rt;
    uint8_t *rbuf_rt = make_rule_payload(1, k_rt, m_rt, a_rt, n_rt, &rlen_rt);
    ASSERT_NOT_NULL(rbuf_rt);
    rc = rule_load(ctx, rbuf_rt, rlen_rt);
    ASSERT_EQ(rc, 0);
    ASSERT_EQ(ctx->rules[0].key,  0xCAFEBABEU);
    ASSERT_EQ(ctx->rules[0].mask, 0x0F0F0F0FU);
    ASSERT_EQ(ctx->rules[0].next, 0x0ABCU);
    free(rbuf_rt);

    free(ctx->rules);
    free(ctx);
    printf("Rule assertions done\n");
}

/* ------------------------------------------------------------------ */
/* 5. PREFIX/TRIE SUITE (~100 assertions)                              */
/* ------------------------------------------------------------------ */
static void test_prefix_trie(void)
{
    printf("--- Prefix/Trie suite ---\n");

    mdn_ctx_t *ctx = calloc(1, sizeof(mdn_ctx_t));
    ASSERT_NOT_NULL(ctx);

    /* Build V4 page payload: page_id=1, kind=1, stride=4, item_count=2 */
    /* Header: page_id(4) kind(2) stride(2) item_count(4) = 12 bytes */
    /* Items: 2 * 4 = 8 bytes */
    uint8_t v4_payload[20];
    memset(v4_payload, 0, sizeof(v4_payload));
    put_u32(v4_payload+0, 1);          /* page_id */
    put_u16(v4_payload+4, PREFIX_KIND_V4);  /* kind */
    put_u16(v4_payload+6, 4);          /* stride */
    put_u32(v4_payload+8, 2);          /* item_count */
    /* item 0: key = 0x0A000001 */
    put_u32(v4_payload+12, 0x0A000001);
    /* item 1: key = 0xC0A80001 */
    put_u32(v4_payload+16, 0xC0A80001);

    int rc = prefix_page_load(ctx, v4_payload, sizeof(v4_payload), 0);
    ASSERT_EQ(rc, 0);

    mdn_prefix_page_t *pg = ctx->prefix_pages[1 % MDN_MAX_PREFIX_PAGES];
    ASSERT_NOT_NULL(pg);
    ASSERT_EQ(pg->page_id,    1U);
    ASSERT_EQ(pg->kind,       PREFIX_KIND_V4);
    ASSERT_EQ(pg->stride,     4U);
    ASSERT_EQ(pg->item_count, 2U);
    ASSERT_EQ(pg->dir_count,  2U);
    ASSERT_NOT_NULL(pg->items);
    ASSERT_NOT_NULL(pg->dir);

    /* dir entries contain byte offsets: dir[0]=0, dir[1]=4 */
    ASSERT_EQ(pg->dir[0], 0U);
    ASSERT_EQ(pg->dir[1], 4U);

    /* trie_lookup_prefix: existing key -> index >= 0 */
    int idx0 = trie_lookup_prefix(ctx, 1, 0x0A000001);
    ASSERT(idx0 >= 0);

    int idx1 = trie_lookup_prefix(ctx, 1, 0xC0A80001);
    ASSERT(idx1 >= 0);

    /* trie_lookup_prefix: missing key -> -1 */
    int idx_miss = trie_lookup_prefix(ctx, 1, 0x01020304);
    ASSERT_EQ(idx_miss, -1);

    /* trie_lookup_prefix: missing page_id -> -1 */
    int idx_nopg = trie_lookup_prefix(ctx, 999, 0x0A000001);
    ASSERT_EQ(idx_nopg, -1);

    /* Build V6 page: page_id=2, kind=2, stride=16, item_count=1 */
    uint8_t v6_payload[28];
    memset(v6_payload, 0, sizeof(v6_payload));
    put_u32(v6_payload+0, 2);
    put_u16(v6_payload+4, PREFIX_KIND_V6);
    put_u16(v6_payload+6, 16);
    put_u32(v6_payload+8, 1);
    /* IPv6 item: 16 bytes */
    memset(v6_payload+12, 0x20, 16);

    rc = prefix_page_load(ctx, v6_payload, sizeof(v6_payload), 0);
    ASSERT_EQ(rc, 0);

    mdn_prefix_page_t *pg6 = ctx->prefix_pages[2 % MDN_MAX_PREFIX_PAGES];
    ASSERT_NOT_NULL(pg6);
    ASSERT_EQ(pg6->kind,       PREFIX_KIND_V6);
    ASSERT_EQ(pg6->stride,     16U);
    ASSERT_EQ(pg6->item_count, 1U);
    ASSERT_EQ(pg6->dir_count,  1U);
    ASSERT_EQ(pg6->dir[0],     0U);

    /* Build MIXED page: page_id=3, kind=0, stride=5 */
    /* item 0: 0x04 + 4-byte IPv4 */
    /* item 1: 0x06 + 4-byte (fake IPv6 indicator) */
    uint8_t mixed_payload[12 + 10];
    memset(mixed_payload, 0, sizeof(mixed_payload));
    put_u32(mixed_payload+0, 3);
    put_u16(mixed_payload+4, PREFIX_KIND_MIXED);
    put_u16(mixed_payload+6, 5);
    put_u32(mixed_payload+8, 2);
    /* item 0: IPv4 indicator 0x04 + 0xAC100001 */
    mixed_payload[12] = 0x04;
    put_u32(mixed_payload+13, 0xAC100001);
    /* item 1: 0x06 + some bytes */
    mixed_payload[17] = 0x06;
    put_u32(mixed_payload+18, 0x20010DB8);

    rc = prefix_page_load(ctx, mixed_payload, sizeof(mixed_payload), 0);
    ASSERT_EQ(rc, 0);

    mdn_prefix_page_t *pgm = ctx->prefix_pages[3 % MDN_MAX_PREFIX_PAGES];
    ASSERT_NOT_NULL(pgm);
    ASSERT_EQ(pgm->kind,       PREFIX_KIND_MIXED);
    ASSERT_EQ(pgm->stride,     5U);
    ASSERT_EQ(pgm->item_count, 2U);

    /* Short payload -> -1 */
    uint8_t short_pg[11] = {0};
    rc = prefix_page_load(ctx, short_pg, 11, 0);
    ASSERT_EQ(rc, -1);

    /* stride=0 -> -1 */
    uint8_t zero_stride[12] = {0};
    put_u32(zero_stride+0, 99);
    put_u16(zero_stride+4, PREFIX_KIND_V4);
    put_u16(zero_stride+6, 0);  /* stride=0 */
    put_u32(zero_stride+8, 0);
    rc = prefix_page_load(ctx, zero_stride, 12, 0);
    ASSERT_EQ(rc, -1);

    /* Item count too large for buffer -> -1 */
    uint8_t trunc_pg[12] = {0};
    put_u32(trunc_pg+0, 50);
    put_u16(trunc_pg+4, PREFIX_KIND_V4);
    put_u16(trunc_pg+6, 4);
    put_u32(trunc_pg+8, 100); /* 100 items * 4 = 400 bytes but only 12 total */
    rc = prefix_page_load(ctx, trunc_pg, 12, 0);
    ASSERT_EQ(rc, -1);

    /* prefix_page_free on NULL -> no crash */
    prefix_page_free(NULL);
    ASSERT(1); /* reached here */

    /* prefix_page_free on a standalone page */
    uint8_t free_pg_data[16];
    memset(free_pg_data, 0, sizeof(free_pg_data));
    put_u32(free_pg_data+0, 77);
    put_u16(free_pg_data+4, PREFIX_KIND_V4);
    put_u16(free_pg_data+6, 4);
    put_u32(free_pg_data+8, 1);
    put_u32(free_pg_data+12, 0xDEADBEEF);

    mdn_ctx_t *tmp_ctx = calloc(1, sizeof(mdn_ctx_t));
    ASSERT_NOT_NULL(tmp_ctx);
    rc = prefix_page_load(tmp_ctx, free_pg_data, 16, 0);
    ASSERT_EQ(rc, 0);
    mdn_prefix_page_t *free_pg = tmp_ctx->prefix_pages[77 % MDN_MAX_PREFIX_PAGES];
    ASSERT_NOT_NULL(free_pg);
    tmp_ctx->prefix_pages[77 % MDN_MAX_PREFIX_PAGES] = NULL;
    prefix_page_free(free_pg);
    ASSERT(1);
    free(tmp_ctx);

    /* prefix_normalize_pages on V4 page (kind != MIXED) -> no change */
    uint32_t old_ic = pg->item_count;
    uint16_t old_kind = pg->kind;
    prefix_normalize_pages(ctx);
    /* V4 page should be unchanged */
    ASSERT_EQ(pg->kind,       old_kind);
    ASSERT_EQ(pg->item_count, old_ic);

    /* MIXED page normalized: kind becomes V4, only IPv4 entries kept */
    /* pgm was mixed with 2 items: one IPv4 (0x04) and one non-IPv4 (0x06) */
    ASSERT_EQ(pgm->kind, PREFIX_KIND_V4); /* after normalize */
    ASSERT_EQ(pgm->item_count, 1U);       /* only IPv4 entry retained */
    ASSERT_EQ(pgm->stride, 4U);           /* new stride = 4 for IPv4 */

    /* V6 page (kind=2) not touched by normalize */
    ASSERT_EQ(pg6->kind, PREFIX_KIND_V6);
    ASSERT_EQ(pg6->item_count, 1U);

    /* trie_lookup after another V4 load */
    /* Already loaded V4 page 1 with items 0x0A000001 and 0xC0A80001 */
    /* Note: normalize_pages was called but page 1 is V4 so unchanged */
    idx0 = trie_lookup_prefix(ctx, 1, 0x0A000001);
    ASSERT(idx0 >= 0);

    idx_miss = trie_lookup_prefix(ctx, 1, 0xFFFFFFFF);
    ASSERT_EQ(idx_miss, -1);

    /* Load another V4 page and look up */
    uint8_t v4b_payload[16];
    memset(v4b_payload, 0, sizeof(v4b_payload));
    put_u32(v4b_payload+0, 10);
    put_u16(v4b_payload+4, PREFIX_KIND_V4);
    put_u16(v4b_payload+6, 4);
    put_u32(v4b_payload+8, 1);
    put_u32(v4b_payload+12, 0x7F000001);

    rc = prefix_page_load(ctx, v4b_payload, 16, 0);
    ASSERT_EQ(rc, 0);

    int idx_lo = trie_lookup_prefix(ctx, 10, 0x7F000001);
    ASSERT(idx_lo >= 0);

    int idx_lo_miss = trie_lookup_prefix(ctx, 10, 0x7F000002);
    ASSERT_EQ(idx_lo_miss, -1);

    /* Item count=0 page is valid */
    uint8_t empty_pg[12] = {0};
    put_u32(empty_pg+0, 20);
    put_u16(empty_pg+4, PREFIX_KIND_V4);
    put_u16(empty_pg+6, 4);
    put_u32(empty_pg+8, 0); /* item_count = 0 */
    rc = prefix_page_load(ctx, empty_pg, 12, 0);
    ASSERT_EQ(rc, 0);
    mdn_prefix_page_t *pg_empty = ctx->prefix_pages[20 % MDN_MAX_PREFIX_PAGES];
    ASSERT_NOT_NULL(pg_empty);
    ASSERT_EQ(pg_empty->item_count, 0U);
    ASSERT_EQ(pg_empty->dir_count,  0U);

    int idx_empty = trie_lookup_prefix(ctx, 20, 0xABCDEF01);
    ASSERT_EQ(idx_empty, -1);

    /* Free all prefix pages via mdn_free path */
    for (int i = 0; i < MDN_MAX_PREFIX_PAGES; i++) {
        if (ctx->prefix_pages[i]) {
            prefix_page_free(ctx->prefix_pages[i]);
            ctx->prefix_pages[i] = NULL;
        }
    }
    free(ctx);

    printf("Prefix/Trie assertions done\n");
}

/* ------------------------------------------------------------------ */
/* 6. NAT SUITE (~80 assertions)                                        */
/* ------------------------------------------------------------------ */
static void test_nat(void)
{
    printf("--- NAT suite ---\n");

    mdn_ctx_t *ctx = calloc(1, sizeof(mdn_ctx_t));
    ASSERT_NOT_NULL(ctx);

    /* Build NAT bucket payload with 0 slots */
    /* bucket_id(2) zone_id(2) slot_count(2) epoch(4) = 10 bytes */
    uint8_t nat0[10];
    put_u16(nat0+0, 7);     /* bucket_id */
    put_u16(nat0+2, 1);     /* zone_id */
    put_u16(nat0+4, 0);     /* slot_count */
    put_u32(nat0+6, 42);    /* epoch */

    int rc = nat_bucket_load(ctx, nat0, 10, 0);
    ASSERT_EQ(rc, 0);

    mdn_nat_bucket_t *bkt = ctx->nat_buckets[7 % MDN_MAX_NAT_BUCKETS];
    ASSERT_NOT_NULL(bkt);
    ASSERT_EQ(bkt->bucket_id,  7);
    ASSERT_EQ(bkt->zone_id,    1);
    ASSERT_EQ(bkt->slot_count, 0);
    ASSERT_EQ(bkt->epoch,      42U);
    ASSERT_NULL(bkt->slots);

    /* Short payload -> -1 */
    uint8_t short_nat[9] = {0};
    rc = nat_bucket_load(ctx, short_nat, 9, 0);
    ASSERT_EQ(rc, -1);

    rc = nat_bucket_load(ctx, short_nat, 0, 0);
    ASSERT_EQ(rc, -1);

    /* NAT bucket with 2 slots */
    /* 10-byte header + 2 * 52 = 114 bytes */
    uint8_t nat2[10 + 2*52];
    memset(nat2, 0, sizeof(nat2));
    put_u16(nat2+0, 15);    /* bucket_id */
    put_u16(nat2+2, 5);     /* zone_id */
    put_u16(nat2+4, 2);     /* slot_count */
    put_u32(nat2+6, 100);   /* epoch */

    /* slot 0: sess_id=0xAABBCCDD, zone_id=5, flags=0x0001, last_seen=999 */
    uint8_t *s0 = nat2 + 10;
    put_u32(s0+0,  0xAABBCCDD);
    put_u16(s0+4,  5);
    put_u16(s0+6,  0x0001);
    put_u32(s0+8,  999);
    memset(s0+12,  0xAA, 40);

    /* slot 1: sess_id=0x11223344, zone_id=5, flags=0x0002, last_seen=1234 */
    uint8_t *s1 = nat2 + 10 + 52;
    put_u32(s1+0,  0x11223344);
    put_u16(s1+4,  5);
    put_u16(s1+6,  0x0002);
    put_u32(s1+8,  1234);
    memset(s1+12,  0xBB, 40);

    rc = nat_bucket_load(ctx, nat2, sizeof(nat2), 0);
    ASSERT_EQ(rc, 0);

    mdn_nat_bucket_t *bkt2 = ctx->nat_buckets[15 % MDN_MAX_NAT_BUCKETS];
    ASSERT_NOT_NULL(bkt2);
    ASSERT_EQ(bkt2->bucket_id,  15);
    ASSERT_EQ(bkt2->zone_id,    5);
    ASSERT_EQ(bkt2->slot_count, 2);
    ASSERT_EQ(bkt2->epoch,      100U);
    ASSERT_NOT_NULL(bkt2->slots);

    ASSERT_EQ(bkt2->slots[0].sess_id,   0xAABBCCDDU);
    ASSERT_EQ(bkt2->slots[0].zone_id,   5);
    ASSERT_EQ(bkt2->slots[0].flags,     0x0001);
    ASSERT_EQ(bkt2->slots[0].last_seen, 999U);

    ASSERT_EQ(bkt2->slots[1].sess_id,   0x11223344U);
    ASSERT_EQ(bkt2->slots[1].zone_id,   5);
    ASSERT_EQ(bkt2->slots[1].flags,     0x0002);
    ASSERT_EQ(bkt2->slots[1].last_seen, 1234U);

    /* Bucket stored at bucket_id % MDN_MAX_NAT_BUCKETS */
    ASSERT_EQ(ctx->nat_buckets[15 % MDN_MAX_NAT_BUCKETS]->bucket_id, 15);

    /* session_cursor_open on valid bucket -> 0 */
    rc = session_cursor_open(ctx, 15, 0);
    ASSERT_EQ(rc, 0);
    ASSERT_NOT_NULL(ctx->cursors);

    mdn_session_cursor_t *cur = &ctx->cursors[0];
    ASSERT_EQ(cur->cursor_id,  0);
    ASSERT_EQ(cur->bucket_id,  15 % MDN_MAX_NAT_BUCKETS);
    ASSERT_EQ(cur->seen_epoch, 100U);
    ASSERT_EQ(cur->slot_index, 0U);
    ASSERT_NOT_NULL(cur->slot_ptr);

    /* session_cursor_open on missing bucket -> -1 */
    rc = session_cursor_open(ctx, 200, 1);
    ASSERT_EQ(rc, -1);

    /* session_cursor_next iterates through slots */
    mdn_session_t *sess = session_cursor_next(ctx, cur);
    ASSERT_NOT_NULL(sess);
    ASSERT_EQ(sess->sess_id, 0xAABBCCDDU);

    sess = session_cursor_next(ctx, cur);
    ASSERT_NOT_NULL(sess);
    ASSERT_EQ(sess->sess_id, 0x11223344U);

    /* session_cursor_next at end returns NULL */
    sess = session_cursor_next(ctx, cur);
    ASSERT_NULL(sess);

    /* session_cursors_free cleans up */
    session_cursors_free(ctx);
    ASSERT_NULL(ctx->cursors);

    /* Load bucket with id=255 (boundary) */
    uint8_t nat255[10];
    put_u16(nat255+0, 255);
    put_u16(nat255+2, 0);
    put_u16(nat255+4, 0);
    put_u32(nat255+6, 0);
    rc = nat_bucket_load(ctx, nat255, 10, 0);
    ASSERT_EQ(rc, 0);
    ASSERT_NOT_NULL(ctx->nat_buckets[255 % MDN_MAX_NAT_BUCKETS]);
    ASSERT_EQ(ctx->nat_buckets[255 % MDN_MAX_NAT_BUCKETS]->bucket_id, 255);

    /* Load bucket with id=0 */
    uint8_t nat_id0[10];
    put_u16(nat_id0+0, 0);
    put_u16(nat_id0+2, 3);
    put_u16(nat_id0+4, 0);
    put_u32(nat_id0+6, 77);
    rc = nat_bucket_load(ctx, nat_id0, 10, 0);
    ASSERT_EQ(rc, 0);
    ASSERT_EQ(ctx->nat_buckets[0]->bucket_id, 0);
    ASSERT_EQ(ctx->nat_buckets[0]->zone_id,   3);

    /* Overwrite bucket 15 */
    rc = nat_bucket_load(ctx, nat2, sizeof(nat2), 0);
    ASSERT_EQ(rc, 0);
    ASSERT_EQ(ctx->nat_buckets[15 % MDN_MAX_NAT_BUCKETS]->slot_count, 2);

    /* cursor_open on bucket 7 (0 slots) */
    rc = session_cursor_open(ctx, 7, 2);
    ASSERT_EQ(rc, 0);
    mdn_session_cursor_t *cur7 = &ctx->cursors[2 % ctx->cursor_count];
    sess = session_cursor_next(ctx, cur7);
    ASSERT_NULL(sess); /* slot_count=0 -> immediately NULL */

    /* nat_free_all cleans up without crash */
    nat_free_all(ctx);
    for (int i = 0; i < MDN_MAX_NAT_BUCKETS; i++) {
        ASSERT_NULL(ctx->nat_buckets[i]);
    }

    /* Double free is safe */
    nat_free_all(ctx);
    ASSERT(1);

    session_cursors_free(ctx);
    free(ctx);

    printf("NAT assertions done\n");
}

/* ------------------------------------------------------------------ */
/* 7. TEMPLATE SUITE (~80 assertions)                                   */
/* ------------------------------------------------------------------ */
static void test_template(void)
{
    printf("--- Template suite ---\n");

    mdn_ctx_t *ctx = calloc(1, sizeof(mdn_ctx_t));
    ASSERT_NOT_NULL(ctx);

    /* Template payload header: tmpl_id(2) hdr_len(2) frag_count(2) flags(2)
       profile(2) desc_count(2) = 12 bytes */

    /* template_load with desc_count=0 */
    uint8_t tp0[12];
    memset(tp0, 0, sizeof(tp0));
    put_u16(tp0+0,  42);    /* tmpl_id */
    put_u16(tp0+2,  20);    /* hdr_len */
    put_u16(tp0+4,  3);     /* frag_count */
    put_u16(tp0+6,  0xAB);  /* flags */
    put_u16(tp0+8,  0);     /* profile=0 (base) */
    put_u16(tp0+10, 0);     /* desc_count=0 */

    int rc = template_load(ctx, tp0, 12, 0);
    ASSERT_EQ(rc, 0);
    ASSERT_EQ(ctx->template_count, 1U);

    mdn_packet_template_t *t = &ctx->templates[0];
    ASSERT_EQ(t->tmpl_id,    42);
    ASSERT_EQ(t->hdr_len,    20);
    ASSERT_EQ(t->frag_count, 3);
    ASSERT_EQ(t->flags,      0xAB);
    ASSERT_EQ(t->profile,    0);     /* base */
    ASSERT_EQ(t->desc_count, 0);

    /* hdr_cap = 64 when no descriptors */
    ASSERT_EQ(t->hdr_cap,    64U);
    ASSERT_NOT_NULL(t->hdr_bytes);

    /* Short payload -> -1 */
    rc = template_load(ctx, tp0, 11, 0);
    ASSERT_EQ(rc, -1);

    rc = template_load(ctx, tp0, 0, 0);
    ASSERT_EQ(rc, -1);

    /* template_load with desc_count=2 */
    /* 12 + 2*8 = 28 bytes */
    uint8_t tp2[28];
    memset(tp2, 0, sizeof(tp2));
    put_u16(tp2+0,  55);    /* tmpl_id */
    put_u16(tp2+2,  0);     /* hdr_len */
    put_u16(tp2+4,  1);     /* frag_count */
    put_u16(tp2+6,  0);     /* flags */
    put_u16(tp2+8,  1);     /* profile=1 (encapsulated) */
    put_u16(tp2+10, 2);     /* desc_count=2 */

    /* descriptor 0: field_off=0, field_len=10, field_type=1, field_src=0 */
    put_u16(tp2+12, 0);
    put_u16(tp2+14, 10);
    put_u16(tp2+16, 1);
    put_u16(tp2+18, 0);

    /* descriptor 1: field_off=10, field_len=20, field_type=2, field_src=1 */
    put_u16(tp2+20, 10);
    put_u16(tp2+22, 20);
    put_u16(tp2+24, 2);
    put_u16(tp2+26, 1);

    rc = template_load(ctx, tp2, 28, 0);
    ASSERT_EQ(rc, 0);
    ASSERT_EQ(ctx->template_count, 2U);

    mdn_packet_template_t *t2 = &ctx->templates[1];
    ASSERT_EQ(t2->tmpl_id,    55);
    ASSERT_EQ(t2->profile,    1);     /* encapsulated */
    ASSERT_EQ(t2->desc_count, 2);
    ASSERT_NOT_NULL(t2->descs);

    ASSERT_EQ(t2->descs[0].field_off,  0);
    ASSERT_EQ(t2->descs[0].field_len,  10);
    ASSERT_EQ(t2->descs[0].field_type, 1);
    ASSERT_EQ(t2->descs[0].field_src,  0);

    ASSERT_EQ(t2->descs[1].field_off,  10);
    ASSERT_EQ(t2->descs[1].field_len,  20);
    ASSERT_EQ(t2->descs[1].field_type, 2);
    ASSERT_EQ(t2->descs[1].field_src,  1);

    /* hdr_cap = sum of field_lens = 10 + 20 = 30 */
    ASSERT_EQ(t2->hdr_cap, 30U);
    ASSERT_NOT_NULL(t2->hdr_bytes);

    /* profile=0 means base, profile=1 means encapsulated */
    ASSERT_EQ(t->profile,  0);
    ASSERT_EQ(t2->profile, 1);

    /* Truncated: desc_count=2 but only 1 desc worth of data (12+8=20 < 28) */
    uint8_t tp2_trunc[20];
    memset(tp2_trunc, 0, sizeof(tp2_trunc));
    put_u16(tp2_trunc+0,  66);
    put_u16(tp2_trunc+10, 2); /* desc_count=2 but no data for second desc */
    rc = template_load(ctx, tp2_trunc, 20, 0);
    ASSERT_EQ(rc, -1);
    /* template_count unchanged */
    ASSERT_EQ(ctx->template_count, 2U);

    /* template_prepare_frame standalone test */
    mdn_packet_template_t standalone;
    memset(&standalone, 0, sizeof(standalone));
    standalone.desc_count = 0;
    rc = template_prepare_frame(&standalone);
    ASSERT_EQ(rc, 0);
    ASSERT_EQ(standalone.hdr_cap, 64U);
    ASSERT_NOT_NULL(standalone.hdr_bytes);
    free(standalone.hdr_bytes);

    /* template_prepare_frame with descs */
    mdn_packet_template_t standalone2;
    memset(&standalone2, 0, sizeof(standalone2));
    mdn_tmpl_desc_t descs_sa[2];
    descs_sa[0].field_len = 8;
    descs_sa[1].field_len = 16;
    standalone2.descs = descs_sa;
    standalone2.desc_count = 2;
    rc = template_prepare_frame(&standalone2);
    ASSERT_EQ(rc, 0);
    ASSERT_EQ(standalone2.hdr_cap, 24U);
    ASSERT_NOT_NULL(standalone2.hdr_bytes);
    free(standalone2.hdr_bytes);

    /* template_count correctly incremented */
    ASSERT_EQ(ctx->template_count, 2U);

    /* Load a third template */
    uint8_t tp3[12];
    memset(tp3, 0, sizeof(tp3));
    put_u16(tp3+0, 100);
    rc = template_load(ctx, tp3, 12, 0);
    ASSERT_EQ(rc, 0);
    ASSERT_EQ(ctx->template_count, 3U);

    /* template_free_all cleans up */
    template_free_all(ctx);
    ASSERT_NULL(ctx->templates);
    ASSERT_EQ(ctx->template_count, 0U);

    /* Double free is safe */
    template_free_all(ctx);
    ASSERT(1);

    free(ctx);
    printf("Template assertions done\n");
}

/* ------------------------------------------------------------------ */
/* 8. AUDIT SUITE (~80 assertions)                                      */
/* ------------------------------------------------------------------ */
static void test_audit(void)
{
    printf("--- Audit suite ---\n");

    mdn_ctx_t *ctx = calloc(1, sizeof(mdn_ctx_t));
    ASSERT_NOT_NULL(ctx);

    /* Build audit window payload:
       win_id(2) flags(2) heap_len(4) heap[heap_len] dir_count(4) dir_count*8 */

    /* heap_len=8, dir_count=1 */
    uint8_t heap_data[8] = {0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88};

    /* Total: 2+2+4+8+4+8 = 28 bytes */
    uint8_t aw[28];
    memset(aw, 0, sizeof(aw));
    uint32_t pos = 0;
    put_u16(aw+pos, 10); pos += 2;   /* win_id */
    put_u16(aw+pos, 0x0F); pos += 2; /* flags */
    put_u32(aw+pos, 8); pos += 4;    /* heap_len */
    memcpy(aw+pos, heap_data, 8); pos += 8;
    put_u32(aw+pos, 1); pos += 4;    /* dir_count */
    /* dir entry 0: off=0, len=4, kind=1 */
    put_u32(aw+pos, 0); pos += 4;    /* off */
    put_u16(aw+pos, 4); pos += 2;    /* len */
    put_u16(aw+pos, 1); pos += 2;    /* kind */

    int rc = audit_window_load(ctx, aw, 28, 0);
    ASSERT_EQ(rc, 0);
    ASSERT_EQ(ctx->audit_count, 1U);

    mdn_audit_window_t *win = &ctx->audit_windows[0];
    ASSERT_EQ(win->win_id,    10);
    ASSERT_EQ(win->flags,     0x0F);
    ASSERT_EQ(win->heap_len,  8U);
    ASSERT_EQ(win->dir_count, 1U);
    ASSERT_NOT_NULL(win->heap);
    ASSERT_NOT_NULL(win->dir);

    /* Dir entry 0 fields */
    ASSERT_EQ(win->dir[0].off,  0U);
    ASSERT_EQ(win->dir[0].len,  4);
    ASSERT_EQ(win->dir[0].kind, 1);

    /* audit_expand_record: valid entry, out_cap >= len */
    uint8_t out[64];
    memset(out, 0, sizeof(out));
    rc = audit_expand_record(win, 0, out, 64);
    ASSERT_EQ(rc, 4);
    ASSERT_EQ(out[0], 0x11);
    ASSERT_EQ(out[1], 0x22);
    ASSERT_EQ(out[2], 0x33);
    ASSERT_EQ(out[3], 0x44);

    /* audit_expand_record out_cap smaller than de->len -> returns out_cap */
    memset(out, 0, sizeof(out));
    rc = audit_expand_record(win, 0, out, 2);
    ASSERT_EQ(rc, 2);
    ASSERT_EQ(out[0], 0x11);
    ASSERT_EQ(out[1], 0x22);

    /* audit_expand_record idx >= dir_count -> -1 */
    rc = audit_expand_record(win, 1, out, 64);
    ASSERT_EQ(rc, -1);

    rc = audit_expand_record(win, 100, out, 64);
    ASSERT_EQ(rc, -1);

    /* Build window with dir entry whose off >= heap_len -> -1 from audit_expand_record */
    uint8_t aw2[28];
    memset(aw2, 0, sizeof(aw2));
    pos = 0;
    put_u16(aw2+pos, 20); pos += 2;
    put_u16(aw2+pos, 0); pos += 2;
    put_u32(aw2+pos, 8); pos += 4;
    memcpy(aw2+pos, heap_data, 8); pos += 8;
    put_u32(aw2+pos, 1); pos += 4;
    /* dir entry: off=8 (== heap_len), len=4, kind=0 */
    put_u32(aw2+pos, 8); pos += 4;
    put_u16(aw2+pos, 4); pos += 2;
    put_u16(aw2+pos, 0); pos += 2;

    rc = audit_window_load(ctx, aw2, 28, 0);
    ASSERT_EQ(rc, 0);
    ASSERT_EQ(ctx->audit_count, 2U);

    mdn_audit_window_t *win2 = &ctx->audit_windows[1];
    rc = audit_expand_record(win2, 0, out, 64);
    ASSERT_EQ(rc, -1); /* de->off=8 >= heap_len=8 */

    /* Empty heap (heap_len=0), dir_count=0 */
    uint8_t aw_empty[12];
    memset(aw_empty, 0, sizeof(aw_empty));
    put_u16(aw_empty+0, 30);
    put_u16(aw_empty+2, 0);
    put_u32(aw_empty+4, 0); /* heap_len=0 */
    put_u32(aw_empty+8, 0); /* dir_count=0 */

    rc = audit_window_load(ctx, aw_empty, 12, 0);
    ASSERT_EQ(rc, 0);
    ASSERT_EQ(ctx->audit_count, 3U);

    mdn_audit_window_t *win3 = &ctx->audit_windows[2];
    ASSERT_EQ(win3->heap_len,  0U);
    ASSERT_EQ(win3->dir_count, 0U);

    rc = audit_expand_record(win3, 0, out, 64);
    ASSERT_EQ(rc, -1); /* idx=0 >= dir_count=0 */

    /* Short payload -> -1 */
    uint8_t short_aw[11] = {0};
    rc = audit_window_load(ctx, short_aw, 11, 0);
    ASSERT_EQ(rc, -1);

    rc = audit_window_load(ctx, short_aw, 0, 0);
    ASSERT_EQ(rc, -1);

    /* dir entry with off=0, len=0 -> returns 0 (copies 0 bytes) */
    uint8_t aw4[20];
    memset(aw4, 0, sizeof(aw4));
    pos = 0;
    put_u16(aw4+pos, 40); pos += 2;
    put_u16(aw4+pos, 0); pos += 2;
    put_u32(aw4+pos, 4); pos += 4;   /* heap_len=4 */
    memset(aw4+pos, 0xDD, 4); pos += 4;
    put_u32(aw4+pos, 1); pos += 4;
    put_u32(aw4+pos, 0); pos += 4;   /* off=0 */
    /* But we need the full entry */
    /* aw4 is only 20 bytes; dir needs 8 bytes but we only have 4 after dir_count */
    /* Let's use a larger buffer */
    uint8_t aw4b[24];
    memset(aw4b, 0, sizeof(aw4b));
    pos = 0;
    put_u16(aw4b+pos, 40); pos += 2;
    put_u16(aw4b+pos, 0); pos += 2;
    put_u32(aw4b+pos, 4); pos += 4;
    memset(aw4b+pos, 0xDD, 4); pos += 4;
    put_u32(aw4b+pos, 1); pos += 4;
    put_u32(aw4b+pos, 0); pos += 4; /* off */
    put_u16(aw4b+pos, 0); pos += 2; /* len=0 */
    put_u16(aw4b+pos, 5); pos += 2; /* kind */

    rc = audit_window_load(ctx, aw4b, 24, 0);
    ASSERT_EQ(rc, 0);
    ASSERT_EQ(ctx->audit_count, 4U);

    mdn_audit_window_t *win4 = &ctx->audit_windows[3];
    memset(out, 0xCC, sizeof(out));
    rc = audit_expand_record(win4, 0, out, 64);
    ASSERT_EQ(rc, 0); /* len=0, copies 0 bytes */

    /* audit_free_all cleans up */
    audit_free_all(ctx);
    ASSERT_NULL(ctx->audit_windows);
    ASSERT_EQ(ctx->audit_count, 0U);

    /* Double free is safe */
    audit_free_all(ctx);
    ASSERT(1);

    /* Reload after free */
    rc = audit_window_load(ctx, aw, 28, 0);
    ASSERT_EQ(rc, 0);
    ASSERT_EQ(ctx->audit_count, 1U);

    audit_free_all(ctx);
    free(ctx);

    printf("Audit assertions done\n");
}

/* ------------------------------------------------------------------ */
/* 9. EXPORT SUITE (~80 assertions)                                     */
/* ------------------------------------------------------------------ */
static void test_export(void)
{
    printf("--- Export suite ---\n");

    mdn_ctx_t *ctx = calloc(1, sizeof(mdn_ctx_t));
    ASSERT_NOT_NULL(ctx);

    /* Build export profile payload:
       profile_id(2) mode(2) field_count(2) [fields...] */

    /* field_count=0 */
    uint8_t ep0[6];
    memset(ep0, 0, sizeof(ep0));
    put_u16(ep0+0, 7);     /* profile_id */
    put_u16(ep0+2, 3);     /* mode */
    put_u16(ep0+4, 0);     /* field_count=0 */

    int rc = export_profile_load(ctx, ep0, 6, 0);
    ASSERT_EQ(rc, 0);
    ASSERT_EQ(ctx->export_count, 1U);

    mdn_export_profile_t *prof = &ctx->exports[0];
    ASSERT_EQ(prof->profile_id,  7);
    ASSERT_EQ(prof->mode,        3);
    ASSERT_EQ(prof->field_count, 0);

    /* frame_cap=32 when field_count=0 (sum==0 -> default 32) */
    ASSERT_EQ(prof->frame_cap, 32U);
    ASSERT_NOT_NULL(prof->frame);

    /* Short payload -> -1 */
    uint8_t short_ep[5] = {0};
    rc = export_profile_load(ctx, short_ep, 5, 0);
    ASSERT_EQ(rc, -1);

    rc = export_profile_load(ctx, short_ep, 0, 0);
    ASSERT_EQ(rc, -1);

    /* field_count=2 */
    /* 6 + 2*8 = 22 bytes */
    uint8_t ep2[22];
    memset(ep2, 0, sizeof(ep2));
    put_u16(ep2+0, 12);    /* profile_id */
    put_u16(ep2+2, 0);     /* mode */
    put_u16(ep2+4, 2);     /* field_count=2 */

    /* field 0: field_id=1, offset=0, width=4, source=0 */
    put_u16(ep2+6,  1);
    put_u16(ep2+8,  0);
    put_u16(ep2+10, 4);
    put_u16(ep2+12, 0);

    /* field 1: field_id=2, offset=4, width=8, source=1 */
    put_u16(ep2+14, 2);
    put_u16(ep2+16, 4);
    put_u16(ep2+18, 8);
    put_u16(ep2+20, 1);

    rc = export_profile_load(ctx, ep2, 22, 0);
    ASSERT_EQ(rc, 0);
    ASSERT_EQ(ctx->export_count, 2U);

    mdn_export_profile_t *prof2 = &ctx->exports[1];
    ASSERT_EQ(prof2->profile_id,  12);
    ASSERT_EQ(prof2->field_count, 2);
    ASSERT_NOT_NULL(prof2->fields);

    ASSERT_EQ(prof2->fields[0].field_id, 1);
    ASSERT_EQ(prof2->fields[0].offset,   0);
    ASSERT_EQ(prof2->fields[0].width,    4);
    ASSERT_EQ(prof2->fields[0].source,   0);

    ASSERT_EQ(prof2->fields[1].field_id, 2);
    ASSERT_EQ(prof2->fields[1].offset,   4);
    ASSERT_EQ(prof2->fields[1].width,    8);
    ASSERT_EQ(prof2->fields[1].source,   1);

    /* frame_cap = 4 + 8 = 12 */
    ASSERT_EQ(prof2->frame_cap, 12U);
    ASSERT_NOT_NULL(prof2->frame);

    /* export_profile_prepare standalone */
    mdn_export_profile_t standalone;
    memset(&standalone, 0, sizeof(standalone));
    mdn_export_field_t fields_sa[3];
    fields_sa[0].width = 5;
    fields_sa[1].width = 10;
    fields_sa[2].width = 15;
    standalone.fields      = fields_sa;
    standalone.field_count = 3;
    rc = export_profile_prepare(&standalone);
    ASSERT_EQ(rc, 0);
    ASSERT_EQ(standalone.frame_cap, 30U);
    ASSERT_NOT_NULL(standalone.frame);
    free(standalone.frame);

    /* export_emit_fields on valid profile -> no crash */
    export_emit_fields(prof2, ctx);
    ASSERT(1);
    /* frame should be zeroed */
    int all_zero = 1;
    for (int i = 0; i < prof2->frame_cap; i++) {
        if (prof2->frame[i] != 0) { all_zero = 0; break; }
    }
    ASSERT(all_zero);

    /* export_emit_fields on NULL -> no crash */
    export_emit_fields(NULL, ctx);
    ASSERT(1);

    /* export_count incremented correctly */
    ASSERT_EQ(ctx->export_count, 2U);

    /* Load a third export profile */
    uint8_t ep3[6];
    put_u16(ep3+0, 99);
    put_u16(ep3+2, 1);
    put_u16(ep3+4, 0);
    rc = export_profile_load(ctx, ep3, 6, 0);
    ASSERT_EQ(rc, 0);
    ASSERT_EQ(ctx->export_count, 3U);

    /* truncated field data -> -1 */
    uint8_t ep_trunc[6+4]; /* says field_count=1 but only 4 bytes (need 8) */
    memset(ep_trunc, 0, sizeof(ep_trunc));
    put_u16(ep_trunc+0, 50);
    put_u16(ep_trunc+2, 0);
    put_u16(ep_trunc+4, 1); /* field_count=1 requires 8 bytes but only 4 present */
    rc = export_profile_load(ctx, ep_trunc, sizeof(ep_trunc), 0);
    ASSERT_EQ(rc, -1);
    ASSERT_EQ(ctx->export_count, 3U); /* unchanged */

    /* export_free_all cleans up */
    export_free_all(ctx);
    ASSERT_NULL(ctx->exports);
    ASSERT_EQ(ctx->export_count, 0U);

    /* Double free is safe */
    export_free_all(ctx);
    ASSERT(1);

    free(ctx);
    printf("Export assertions done\n");
}

/* ------------------------------------------------------------------ */
/* 10. QUERY SUITE (~70 assertions)                                     */
/* ------------------------------------------------------------------ */
static void test_query(void)
{
    printf("--- Query suite ---\n");

    mdn_ctx_t *ctx = calloc(1, sizeof(mdn_ctx_t));
    ASSERT_NOT_NULL(ctx);

    /* query_load with 0 bytes -> -1 */
    uint8_t qbuf[0];
    int rc = query_load(ctx, qbuf, 0);
    ASSERT_EQ(rc, -1);

    /* 11 bytes (< 12) -> -1 */
    uint8_t short_q[11] = {0};
    rc = query_load(ctx, short_q, 11);
    ASSERT_EQ(rc, -1);

    /* 1 record = 12 bytes */
    /* query_id(2) start_rule(2) zone_id(2) template_id(2) flags(4) */
    uint8_t q1[12];
    memset(q1, 0, sizeof(q1));
    put_u16(q1+0,  99);         /* query_id */
    put_u16(q1+2,  0);          /* start_rule */
    put_u16(q1+4,  7);          /* zone_id */
    put_u16(q1+6,  42);         /* template_id */
    put_u32(q1+8,  0xDEADBEEF); /* flags */

    rc = query_load(ctx, q1, 12);
    ASSERT_EQ(rc, 0);
    ASSERT_EQ(ctx->query_count, 1);
    ASSERT_EQ(ctx->queries[0].query_id,    99);
    ASSERT_EQ(ctx->queries[0].start_rule,  0);
    ASSERT_EQ(ctx->queries[0].zone_id,     7);
    ASSERT_EQ(ctx->queries[0].template_id, 42);
    ASSERT_EQ(ctx->queries[0].flags,       0xDEADBEEFU);

    /* 3 records */
    uint8_t q3[36];
    memset(q3, 0, sizeof(q3));

    put_u16(q3+0,  1);  put_u16(q3+2, 0); put_u16(q3+4, 1); put_u16(q3+6, 10); put_u32(q3+8,  0x01);
    put_u16(q3+12, 2);  put_u16(q3+14,1); put_u16(q3+16,2); put_u16(q3+18,20); put_u32(q3+20, 0x02);
    put_u16(q3+24, 3);  put_u16(q3+26,2); put_u16(q3+28,3); put_u16(q3+30,30); put_u32(q3+32, 0x03);

    rc = query_load(ctx, q3, 36);
    ASSERT_EQ(rc, 0);
    ASSERT_EQ(ctx->query_count, 3);

    ASSERT_EQ(ctx->queries[0].query_id,    1);
    ASSERT_EQ(ctx->queries[0].start_rule,  0);
    ASSERT_EQ(ctx->queries[0].zone_id,     1);
    ASSERT_EQ(ctx->queries[0].template_id, 10);
    ASSERT_EQ(ctx->queries[0].flags,       0x01U);

    ASSERT_EQ(ctx->queries[1].query_id,    2);
    ASSERT_EQ(ctx->queries[1].start_rule,  1);
    ASSERT_EQ(ctx->queries[1].zone_id,     2);
    ASSERT_EQ(ctx->queries[1].template_id, 20);
    ASSERT_EQ(ctx->queries[1].flags,       0x02U);

    ASSERT_EQ(ctx->queries[2].query_id,    3);
    ASSERT_EQ(ctx->queries[2].start_rule,  2);
    ASSERT_EQ(ctx->queries[2].zone_id,     3);
    ASSERT_EQ(ctx->queries[2].template_id, 30);
    ASSERT_EQ(ctx->queries[2].flags,       0x03U);

    /* Extra bytes (not multiple of 12): 37 bytes -> count = floor(37/12) = 3 */
    uint8_t q37[37];
    memcpy(q37, q3, 36);
    q37[36] = 0xFF;
    rc = query_load(ctx, q37, 37);
    ASSERT_EQ(rc, 0);
    ASSERT_EQ(ctx->query_count, 3); /* still 3 */

    /* 25 bytes -> floor(25/12) = 2 */
    rc = query_load(ctx, q3, 25);
    ASSERT_EQ(rc, 0);
    ASSERT_EQ(ctx->query_count, 2);

    ASSERT_EQ(ctx->queries[0].query_id, 1);
    ASSERT_EQ(ctx->queries[1].query_id, 2);

    /* Single record with flags=0 */
    uint8_t q_flags[12];
    memset(q_flags, 0, sizeof(q_flags));
    put_u16(q_flags+0, 77);
    put_u32(q_flags+8, 0);
    rc = query_load(ctx, q_flags, 12);
    ASSERT_EQ(rc, 0);
    ASSERT_EQ(ctx->queries[0].flags, 0U);
    ASSERT_EQ(ctx->queries[0].query_id, 77);

    /* Large flags value */
    uint8_t q_lf[12];
    memset(q_lf, 0, sizeof(q_lf));
    put_u16(q_lf+0, 1);
    put_u32(q_lf+8, 0xFFFFFFFF);
    rc = query_load(ctx, q_lf, 12);
    ASSERT_EQ(rc, 0);
    ASSERT_EQ(ctx->queries[0].flags, 0xFFFFFFFFU);

    /* NULL data -> -1 */
    rc = query_load(ctx, NULL, 12);
    ASSERT_EQ(rc, -1);

    free(ctx);
    printf("Query assertions done\n");
}

/* ------------------------------------------------------------------ */
/* 11. VALIDATE SUITE (~60 assertions)                                  */
/* ------------------------------------------------------------------ */
static void test_validate(void)
{
    printf("--- Validate suite ---\n");

    mdn_ctx_t *ctx = calloc(1, sizeof(mdn_ctx_t));
    ASSERT_NOT_NULL(ctx);

    /* Empty ctx: rule_count=0, query_count=0 -> 0 */
    int rc = mdn_validate(ctx);
    ASSERT_EQ(rc, 0);

    /* rule_count=1, query_count=1, start_rule=0 -> 0 (valid) */
    ctx->rule_count = 1;
    ctx->query_count = 1;
    ctx->queries[0].start_rule = 0;
    rc = mdn_validate(ctx);
    ASSERT_EQ(rc, 0);

    /* rule_count=1, query_count=1, start_rule=1 -> -1 (out of range) */
    ctx->queries[0].start_rule = 1;
    rc = mdn_validate(ctx);
    ASSERT_EQ(rc, -1);

    /* rule_count=0, query_count=1, start_rule=0 -> 0 (skip check when rule_count==0) */
    ctx->rule_count = 0;
    ctx->queries[0].start_rule = 0;
    rc = mdn_validate(ctx);
    ASSERT_EQ(rc, 0);

    /* rule_count=0, query_count=1, start_rule=999 -> 0 (skip check) */
    ctx->queries[0].start_rule = 999;
    rc = mdn_validate(ctx);
    ASSERT_EQ(rc, 0);

    /* rule_count > MDN_MAX_RULES -> -1 */
    ctx->rule_count = MDN_MAX_RULES + 1;
    ctx->query_count = 0;
    rc = mdn_validate(ctx);
    ASSERT_EQ(rc, -1);

    /* rule_count = MDN_MAX_RULES -> 0 */
    ctx->rule_count = MDN_MAX_RULES;
    ctx->query_count = 0;
    rc = mdn_validate(ctx);
    ASSERT_EQ(rc, 0);

    /* Multiple queries, one valid, one invalid -> -1 */
    ctx->rule_count = 5;
    ctx->query_count = 3;
    ctx->queries[0].start_rule = 0;
    ctx->queries[1].start_rule = 4;
    ctx->queries[2].start_rule = 5; /* >= rule_count=5 -> invalid */
    rc = mdn_validate(ctx);
    ASSERT_EQ(rc, -1);

    /* All queries valid */
    ctx->queries[0].start_rule = 0;
    ctx->queries[1].start_rule = 1;
    ctx->queries[2].start_rule = 4;
    rc = mdn_validate(ctx);
    ASSERT_EQ(rc, 0);

    /* rule_count=2, query_count=2, one query with start_rule=2 (== rule_count) -> -1 */
    ctx->rule_count = 2;
    ctx->query_count = 2;
    ctx->queries[0].start_rule = 0;
    ctx->queries[1].start_rule = 2;
    rc = mdn_validate(ctx);
    ASSERT_EQ(rc, -1);

    /* rule_count=2, query_count=2, both valid */
    ctx->queries[1].start_rule = 1;
    rc = mdn_validate(ctx);
    ASSERT_EQ(rc, 0);

    /* rule_count=1, query_count=MDN_MAX_QUERIES all start_rule=0 -> 0 */
    ctx->rule_count = 1;
    ctx->query_count = MDN_MAX_QUERIES;
    for (int i = 0; i < MDN_MAX_QUERIES; i++)
        ctx->queries[i].start_rule = 0;
    rc = mdn_validate(ctx);
    ASSERT_EQ(rc, 0);

    /* rule_count=1, last query invalid */
    ctx->queries[MDN_MAX_QUERIES-1].start_rule = 1;
    rc = mdn_validate(ctx);
    ASSERT_EQ(rc, -1);

    /* MDN_MAX_RULES constant */
    ASSERT_EQ(MDN_MAX_RULES, 512U);

    /* MDN_MAX_QUERIES constant */
    ASSERT_EQ(MDN_MAX_QUERIES, 128U);

    /* MDN_MAX_ZONES constant */
    ASSERT_EQ(MDN_MAX_ZONES, 128U);

    /* MDN_MAX_NAT_BUCKETS constant */
    ASSERT_EQ(MDN_MAX_NAT_BUCKETS, 256U);

    /* MDN_MAX_PREFIX_PAGES constant */
    ASSERT_EQ(MDN_MAX_PREFIX_PAGES, 256U);

    /* MDN_CAP_TOKEN_LEN constant */
    ASSERT_EQ(MDN_CAP_TOKEN_LEN, 32U);

    /* MDN_FLAG_STRICT */
    ASSERT_EQ(MDN_FLAG_STRICT, 0x0001U);

    free(ctx);
    printf("Validate assertions done\n");
}

/* ------------------------------------------------------------------ */
/* 12. INTEGRATION SUITE (~80 assertions)                               */
/* ------------------------------------------------------------------ */
static void test_integration(void)
{
    printf("--- Integration suite ---\n");

    /* mdn_load(NULL, 0) -> NULL */
    mdn_ctx_t *ctx = mdn_load(NULL, 0);
    ASSERT_NULL(ctx);

    /* mdn_load with bad magic -> NULL */
    uint8_t bad_magic[12] = {'X','X','X','X',0,0,0,0,0,0,0,0};
    ctx = mdn_load(bad_magic, 12);
    ASSERT_NULL(ctx);

    /* mdn_load with truncated buffer (< 12 bytes) -> NULL */
    uint8_t trunc[4] = {'M','D','N','1'};
    ctx = mdn_load(trunc, 4);
    ASSERT_NULL(ctx);

    /* mdn_load with valid empty (0 sections) -> not NULL */
    uint8_t empty_mdn[12] = {0};
    empty_mdn[0]='M'; empty_mdn[1]='D'; empty_mdn[2]='N'; empty_mdn[3]='1';
    /* flags=0, section_count=0, query_count=0, reserved=0 */
    ctx = mdn_load(empty_mdn, 12);
    ASSERT_NOT_NULL(ctx);
    ASSERT_EQ(ctx->rule_count, 0U);
    ASSERT_EQ(ctx->query_count, 0);
    mdn_free(ctx);

    /* mdn_free(NULL) -> no crash */
    mdn_free(NULL);
    ASSERT(1);

    /* mdn_load with 1 zone section */
    uint8_t zp[12];
    make_zone_payload(zp, 3, 0, 2, 0, 77);

    uint8_t sect_types[1] = {SECT_ZONE};
    uint16_t sect_ids[1]  = {0};
    const uint8_t *sect_data[1] = {zp};
    uint32_t sect_lens[1] = {12};
    size_t out_len;
    uint8_t *buf = build_mdn(0, 1, sect_types, sect_ids, sect_data, sect_lens, &out_len);
    ASSERT_NOT_NULL(buf);

    ctx = mdn_load(buf, out_len);
    ASSERT_NOT_NULL(ctx);
    mdn_zone_t *z = zone_lookup(ctx, 3);
    ASSERT_NOT_NULL(z);
    ASSERT_EQ(z->zone_id,  3);
    ASSERT_EQ(z->if_count, 2);
    ASSERT_EQ(z->epoch,    77U);
    mdn_free(ctx);
    free(buf);

    /* mdn_load with CAP section (correct token) -> cap_ok==1 */
    uint8_t cap_payload[40];
    memcpy(cap_payload, CAP_TOKEN_GOOD, 32);
    put_u64(cap_payload+32, CAP_NONCE_GOOD);

    sect_types[0] = SECT_CAP;
    sect_data[0]  = cap_payload;
    sect_lens[0]  = 40;
    buf = build_mdn(0, 1, sect_types, sect_ids, sect_data, sect_lens, &out_len);
    ASSERT_NOT_NULL(buf);

    ctx = mdn_load(buf, out_len);
    ASSERT_NOT_NULL(ctx);
    ASSERT_EQ(ctx->cap_ok, 1);
    ASSERT_EQ(mdn_cap_check(ctx, 0), 1);
    mdn_free(ctx);
    free(buf);

    /* mdn_load with CAP section (wrong token) -> not NULL but cap_ok==0 */
    uint8_t cap_bad[40];
    memset(cap_bad, 0xAA, 40);
    put_u64(cap_bad+32, CAP_NONCE_GOOD);

    sect_data[0] = cap_bad;
    buf = build_mdn(0, 1, sect_types, sect_ids, sect_data, sect_lens, &out_len);
    ASSERT_NOT_NULL(buf);

    ctx = mdn_load(buf, out_len);
    ASSERT_NOT_NULL(ctx);
    ASSERT_EQ(ctx->cap_ok, 0);
    ASSERT_EQ(mdn_cap_check(ctx, 0), 0);
    mdn_free(ctx);
    free(buf);

    /* mdn_load with zone + rule(count=1, start_rule=0) + query(start_rule=0) */
    uint8_t zp2[12];
    make_zone_payload(zp2, 1, 0, 1, 0, 1);

    uint32_t k_i[1] = {0x01020304};
    uint32_t m_i[1] = {0xFFFFFFFF};
    uint16_t a_i[1] = {ACTION_ALLOW};
    uint16_t n_i[1] = {0xFFFF};
    uint32_t rule_len;
    uint8_t *rule_buf = make_rule_payload(1, k_i, m_i, a_i, n_i, &rule_len);
    ASSERT_NOT_NULL(rule_buf);

    /* query record: query_id=1, start_rule=0, zone_id=1, template_id=0, flags=0 */
    uint8_t query_rec[12];
    memset(query_rec, 0, sizeof(query_rec));
    put_u16(query_rec+0, 1);

    /* zone + rule */
    uint8_t  s2_types[2]  = {SECT_ZONE, SECT_RULE};
    uint16_t s2_ids[2]    = {0, 0};
    const uint8_t *s2_data[2] = {zp2, rule_buf};
    uint32_t s2_lens[2]   = {12, rule_len};

    buf = build_mdn(0, 2, s2_types, s2_ids, (const uint8_t **)s2_data, s2_lens, &out_len);
    ASSERT_NOT_NULL(buf);
    ctx = mdn_load(buf, out_len);
    ASSERT_NOT_NULL(ctx);
    ASSERT_EQ(ctx->rule_count, 1U);
    ASSERT_EQ(ctx->rules[0].action, ACTION_ALLOW);
    mdn_free(ctx);
    free(buf);
    free(rule_buf);

    /* mdn_run on valid ctx -> returns 0 */
    buf = build_mdn(0, 0, NULL, NULL, NULL, NULL, &out_len);
    ASSERT_NOT_NULL(buf);
    ctx = mdn_load(buf, out_len);
    ASSERT_NOT_NULL(ctx);
    int run_rc = mdn_run(ctx);
    ASSERT_EQ(run_rc, 0);
    mdn_free(ctx);
    free(buf);

    /* mdn_load with bad CRC in strict mode -> NULL */
    {
        uint8_t zone_bad_crc[12];
        make_zone_payload(zone_bad_crc, 5, 0, 1, 0, 999);
        sect_types[0] = SECT_ZONE;
        sect_data[0]  = zone_bad_crc;
        sect_lens[0]  = 12;

        /* Build without strict first, then corrupt the CRC field */
        buf = build_mdn(MDN_FLAG_STRICT, 1, sect_types, sect_ids,
                        sect_data, sect_lens, &out_len);
        ASSERT_NOT_NULL(buf);

        /* Corrupt the CRC in the section table entry (offset 12 + 12 = 24) */
        buf[12 + 12] ^= 0xFF;

        ctx = mdn_load(buf, out_len);
        ASSERT_NULL(ctx); /* strict mode -> load fails */
        free(buf);
    }

    /* mdn_load with bad CRC in non-strict mode -> not NULL (section skipped) */
    {
        uint8_t zone_ok[12];
        make_zone_payload(zone_ok, 9, 0, 1, 0, 111);
        sect_types[0] = SECT_ZONE;
        sect_data[0]  = zone_ok;
        sect_lens[0]  = 12;

        buf = build_mdn(0, 1, sect_types, sect_ids,
                        sect_data, sect_lens, &out_len);
        ASSERT_NOT_NULL(buf);

        /* Corrupt CRC */
        buf[12 + 12] ^= 0xFF;

        ctx = mdn_load(buf, out_len);
        ASSERT_NOT_NULL(ctx); /* non-strict: section skipped, load succeeds */
        /* zone 9 was NOT loaded (CRC mismatch -> skipped) */
        ASSERT_NULL(zone_lookup(ctx, 9));
        mdn_free(ctx);
        free(buf);
    }

    /* mdn_load + mdn_free cycle repeated 3 times (no crash) */
    for (int i = 0; i < 3; i++) {
        buf = build_mdn(0, 0, NULL, NULL, NULL, NULL, &out_len);
        ASSERT_NOT_NULL(buf);
        ctx = mdn_load(buf, out_len);
        ASSERT_NOT_NULL(ctx);
        mdn_free(ctx);
        free(buf);
    }
    ASSERT(1); /* survived all 3 cycles */

    /* mdn_run(NULL) -> -1 */
    int r = mdn_run(NULL);
    ASSERT_EQ(r, -1);

    /* load with only header bytes (section_count=0) */
    uint8_t hdr_only[12] = {'M','D','N','1', 0,0, 0,0, 0,0, 0,0};
    ctx = mdn_load(hdr_only, 12);
    ASSERT_NOT_NULL(ctx);
    ASSERT_EQ(ctx->rule_count, 0U);
    mdn_free(ctx);

    /* Non-null but too-small buf */
    uint8_t tiny[3] = {'M','D','N'};
    ctx = mdn_load(tiny, 3);
    ASSERT_NULL(ctx);

    printf("Integration assertions done\n");
}

/* ------------------------------------------------------------------ */
/* 13. EXTENDED COVERAGE (~60+ assertions)                             */
/* ------------------------------------------------------------------ */
static void test_extended(void)
{
    printf("--- Extended suite ---\n");

    /* CRC: additional known inputs */
    {
        /* "a" = 0x61 */
        uint8_t ca = 0x61;
        uint32_t v = crc32_compute(&ca, 1);
        ASSERT_NE(v, 0U);
        ASSERT_EQ(v, crc32_compute(&ca, 1));

        /* "abc" */
        const uint8_t abc[] = {0x61, 0x62, 0x63};
        uint32_t vabc = crc32_compute(abc, 3);
        ASSERT_NE(vabc, 0U);
        ASSERT_EQ(vabc, crc32_compute(abc, 3));
        ASSERT_NE(vabc, crc32_compute(&ca, 1));

        /* 256-byte pattern */
        uint8_t pat256[256];
        for (int i = 0; i < 256; i++) pat256[i] = (uint8_t)i;
        uint32_t v256 = crc32_compute(pat256, 256);
        ASSERT_NE(v256, 0U);
        ASSERT_EQ(v256, crc32_compute(pat256, 256));
    }

    /* Zone: zone_id stored by modulo */
    {
        mdn_ctx_t *ctx = calloc(1, sizeof(mdn_ctx_t));
        ASSERT_NOT_NULL(ctx);

        /* zone_id = MDN_MAX_ZONES: stored at index 0 (MDN_MAX_ZONES % MDN_MAX_ZONES = 0) */
        uint8_t zp[12];
        make_zone_payload(zp, (uint16_t)MDN_MAX_ZONES, 0, 1, 0, 7);
        int rc = zone_load(ctx, zp, 12, 0);
        ASSERT_EQ(rc, 0);
        /* lookup by zone_id=MDN_MAX_ZONES */
        mdn_zone_t *z = zone_lookup(ctx, (uint16_t)MDN_MAX_ZONES);
        ASSERT_NOT_NULL(z);
        ASSERT_EQ(z->epoch, 7U);

        /* zone with if_count=0 */
        make_zone_payload(zp, 60, 0, 0, 0, 1);
        rc = zone_load(ctx, zp, 12, 0);
        ASSERT_EQ(rc, 0);
        z = zone_lookup(ctx, 60);
        ASSERT_NOT_NULL(z);
        ASSERT_EQ(z->if_count, 0);

        /* Large epoch value */
        make_zone_payload(zp, 70, 0, 1, 0, 0xFFFFFFFF);
        rc = zone_load(ctx, zp, 12, 0);
        ASSERT_EQ(rc, 0);
        ASSERT_EQ(zone_lookup(ctx, 70)->epoch, 0xFFFFFFFFU);

        zone_free_all(ctx);
        free(ctx);
    }

    /* Rule: reload clears previous */
    {
        mdn_ctx_t *ctx = calloc(1, sizeof(mdn_ctx_t));
        ASSERT_NOT_NULL(ctx);

        uint32_t k1[1] = {0x11111111};
        uint32_t m1[1] = {0xFFFFFFFF};
        uint16_t a1[1] = {ACTION_ALLOW};
        uint16_t n1[1] = {0};
        uint32_t rlen1;
        uint8_t *rb1 = make_rule_payload(1, k1, m1, a1, n1, &rlen1);
        rule_load(ctx, rb1, rlen1);
        ASSERT_EQ(ctx->rule_count, 1U);
        free(rb1);

        /* Reload with 0 clears rules */
        uint8_t r0[4] = {0};
        rule_load(ctx, r0, 4);
        ASSERT_EQ(ctx->rule_count, 0U);
        ASSERT_NULL(ctx->rules);

        free(ctx);
    }

    /* NAT: bucket id modulo wraps correctly */
    {
        mdn_ctx_t *ctx = calloc(1, sizeof(mdn_ctx_t));
        ASSERT_NOT_NULL(ctx);

        /* bucket_id=256 stored at index 0 (256 % 256 = 0) */
        uint8_t nat[10];
        put_u16(nat+0, 256); /* stored little-endian as 0 (u16 truncation: 256=0x100 -> stored as 0x00,0x01 -> u16 = 256 but bucket_id is u16 so it holds 256) */
        /* Actually memcpy(&bucket_id, data, 2) with 256 LE: data={0x00, 0x01} -> 0x0100=256 */
        /* 256 % 256 = 0, so stored at index 0 */
        put_u16(nat+2, 0);
        put_u16(nat+4, 0);
        put_u32(nat+6, 5);
        int rc = nat_bucket_load(ctx, nat, 10, 0);
        ASSERT_EQ(rc, 0);
        ASSERT_EQ(ctx->nat_buckets[0]->epoch, 5U);

        nat_free_all(ctx);
        free(ctx);
    }

    /* Audit: multiple dir entries */
    {
        mdn_ctx_t *ctx = calloc(1, sizeof(mdn_ctx_t));
        ASSERT_NOT_NULL(ctx);

        /* heap=10 bytes, 2 dir entries */
        uint8_t heap[10] = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A};
        /* Total: 2+2+4+10+4+2*8 = 38 bytes */
        uint8_t aw[38];
        uint32_t pos = 0;
        put_u16(aw+pos, 77); pos += 2;
        put_u16(aw+pos, 0);  pos += 2;
        put_u32(aw+pos, 10); pos += 4;
        memcpy(aw+pos, heap, 10); pos += 10;
        put_u32(aw+pos, 2); pos += 4;
        /* dir[0]: off=0, len=5, kind=10 */
        put_u32(aw+pos, 0); pos += 4;
        put_u16(aw+pos, 5); pos += 2;
        put_u16(aw+pos, 10); pos += 2;
        /* dir[1]: off=5, len=5, kind=20 */
        put_u32(aw+pos, 5); pos += 4;
        put_u16(aw+pos, 5); pos += 2;
        put_u16(aw+pos, 20); pos += 2;

        int rc = audit_window_load(ctx, aw, 38, 0);
        ASSERT_EQ(rc, 0);
        mdn_audit_window_t *win = &ctx->audit_windows[0];
        ASSERT_EQ(win->dir_count, 2U);
        ASSERT_EQ(win->dir[0].off, 0U);
        ASSERT_EQ(win->dir[0].len, 5);
        ASSERT_EQ(win->dir[0].kind, 10);
        ASSERT_EQ(win->dir[1].off, 5U);
        ASSERT_EQ(win->dir[1].len, 5);
        ASSERT_EQ(win->dir[1].kind, 20);

        uint8_t out[16];
        rc = audit_expand_record(win, 0, out, 16);
        ASSERT_EQ(rc, 5);
        ASSERT_EQ(out[0], 0x01);
        ASSERT_EQ(out[4], 0x05);

        rc = audit_expand_record(win, 1, out, 16);
        ASSERT_EQ(rc, 5);
        ASSERT_EQ(out[0], 0x06);

        audit_free_all(ctx);
        free(ctx);
    }

    /* Export: emit_fields with non-null fields no crash */
    {
        mdn_export_profile_t prof;
        memset(&prof, 0, sizeof(prof));
        mdn_export_field_t f[2];
        f[0].field_id = 1; f[0].offset = 0; f[0].width = 4; f[0].source = 0;
        f[1].field_id = 2; f[1].offset = 4; f[1].width = 4; f[1].source = 0;
        prof.fields      = f;
        prof.field_count = 2;
        prof.frame_cap   = 8;
        prof.frame       = calloc(1, 8);
        ASSERT_NOT_NULL(prof.frame);
        memset(prof.frame, 0xFF, 8);

        export_emit_fields(&prof, NULL);
        /* frame should be zeroed by emit_fields */
        ASSERT_EQ(prof.frame[0], 0);
        ASSERT_EQ(prof.frame[4], 0);
        free(prof.frame);
    }

    /* Validate: boundary rule_count = MDN_MAX_RULES, 1 query with start_rule = MDN_MAX_RULES-1 */
    {
        mdn_ctx_t *ctx = calloc(1, sizeof(mdn_ctx_t));
        ASSERT_NOT_NULL(ctx);
        ctx->rule_count = MDN_MAX_RULES;
        ctx->query_count = 1;
        ctx->queries[0].start_rule = (uint16_t)(MDN_MAX_RULES - 1);
        int rc = mdn_validate(ctx);
        ASSERT_EQ(rc, 0);

        ctx->queries[0].start_rule = (uint16_t)MDN_MAX_RULES;
        rc = mdn_validate(ctx);
        ASSERT_EQ(rc, -1);

        free(ctx);
    }

    /* Section type constants */
    ASSERT_EQ(SECT_CAP,          0x01);
    ASSERT_EQ(SECT_ZONE,         0x02);
    ASSERT_EQ(SECT_RULE,         0x03);
    ASSERT_EQ(SECT_PREFIX,       0x04);
    ASSERT_EQ(SECT_NAT,          0x05);
    ASSERT_EQ(SECT_SESSION,      0x06);
    ASSERT_EQ(SECT_TEMPLATE,     0x07);
    ASSERT_EQ(SECT_AUDIT,        0x08);
    ASSERT_EQ(SECT_EXPORT,       0x09);
    ASSERT_EQ(SECT_POLICY_PATCH, 0x0A);

    /* Prefix kind constants */
    ASSERT_EQ(PREFIX_KIND_MIXED, 0);
    ASSERT_EQ(PREFIX_KIND_V4,    1);
    ASSERT_EQ(PREFIX_KIND_V6,    2);

    printf("Extended assertions done\n");
}

/* ------------------------------------------------------------------ */
/* main                                                                 */
/* ------------------------------------------------------------------ */

int main(void)
{
    test_crc();
    test_cap();
    test_zone();
    test_rule();
    test_prefix_trie();
    test_nat();
    test_template();
    test_audit();
    test_export();
    test_query();
    test_validate();
    test_integration();
    test_extended();

    printf("=== Results: %d passed, %d failed ===\n", passed, failed);
    return failed != 0;
}
