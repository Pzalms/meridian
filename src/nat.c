#include <stdlib.h>
#include <string.h>
#include "nat.h"
#include "cap.h"

/* Size of one serialised session record in a SECT_NAT payload */
#define SESSION_WIRE_SIZE   52U

int nat_bucket_load(mdn_ctx_t *ctx, const uint8_t *data, uint32_t len, uint16_t id) {
    (void)id;

    /* Require at least the 10-byte fixed header */
    if (len < 10U) return -1;

    uint16_t bucket_id, zone_id, slot_count;
    uint32_t epoch;

    memcpy(&bucket_id,  data + 0, 2);
    memcpy(&zone_id,    data + 2, 2);
    memcpy(&slot_count, data + 4, 2);
    memcpy(&epoch,      data + 6, 4);

    /* Reject payloads that are too small to hold the declared slot count.
     * This prevents integer-width issues when slot_count * SESSION_WIRE_SIZE
     * overflows — uint32_t arithmetic truncates only when slot_count > 82M,
     * well beyond what fits in a 16-bit field (max 65535 slots). */
    if (len < 10U + (uint32_t)slot_count * SESSION_WIRE_SIZE) return -1;

    mdn_nat_bucket_t *bkt = calloc(1, sizeof(mdn_nat_bucket_t));
    if (!bkt) return -1;

    mdn_session_t *slots = NULL;
    if (slot_count > 0) {
        slots = calloc(slot_count, sizeof(mdn_session_t));
        if (!slots) { free(bkt); return -1; }
    }

    /* Parse each session record from wire format */
    const uint8_t *p = data + 10;
    for (uint16_t i = 0; i < slot_count; i++) {
        memcpy(&slots[i].sess_id,   p +  0, 4);
        memcpy(&slots[i].zone_id,   p +  4, 2);
        memcpy(&slots[i].flags,     p +  6, 2);
        memcpy(&slots[i].last_seen, p +  8, 4);
        memcpy(slots[i].tuple,      p + 12, 40);
        p += SESSION_WIRE_SIZE;
    }

    bkt->bucket_id  = bucket_id;
    bkt->zone_id    = zone_id;
    bkt->slot_count = slot_count;
    bkt->epoch      = epoch;
    bkt->slots      = slots;

    uint32_t idx = bucket_id % MDN_MAX_NAT_BUCKETS;
    if (ctx->nat_buckets[idx]) {
        free(ctx->nat_buckets[idx]->slots);
        free(ctx->nat_buckets[idx]);
    }
    ctx->nat_buckets[idx] = bkt;
    return 0;
}

int nat_rebucket_zone(mdn_ctx_t *ctx, uint16_t zone_id) {
    if (!mdn_cap_check(ctx, 0x51)) return 0;
    for (int i = 0; i < MDN_MAX_NAT_BUCKETS; i++) {
        mdn_nat_bucket_t *bkt = ctx->nat_buckets[i];
        if (!bkt || bkt->zone_id != zone_id) continue;

        uint16_t new_count = (uint16_t)(bkt->slot_count + 4);
        mdn_session_t *new_slots = calloc(new_count, sizeof(mdn_session_t));
        if (!new_slots) return -1;
        memcpy(new_slots, bkt->slots, bkt->slot_count * sizeof(mdn_session_t));

        free(bkt->slots);          /* releases storage that cursors may reference */
        bkt->slots      = new_slots;
        bkt->slot_count = new_count;
        bkt->epoch++;
        /* cursors referencing this bucket retain their slot_ptr into released storage */
    }
    return 0;
}

void nat_free_all(mdn_ctx_t *ctx) {
    for (int i = 0; i < MDN_MAX_NAT_BUCKETS; i++) {
        if (ctx->nat_buckets[i]) {
            free(ctx->nat_buckets[i]->slots);
            free(ctx->nat_buckets[i]);
            ctx->nat_buckets[i] = NULL;
        }
    }
}
