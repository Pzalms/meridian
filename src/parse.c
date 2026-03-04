#include "parse.h"
#include "cap.h"
#include "crc.h"
#include "util.h"
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* Forward declarations for section loaders implemented in other modules */
extern int zone_load(mdn_ctx_t *ctx, const uint8_t *data, uint32_t len, uint16_t id);
extern int prefix_page_load(mdn_ctx_t *ctx, const uint8_t *data, uint32_t len, uint16_t id);
extern int rule_load(mdn_ctx_t *ctx, const uint8_t *data, uint32_t len);
extern int nat_bucket_load(mdn_ctx_t *ctx, const uint8_t *data, uint32_t len, uint16_t id);
extern int template_load(mdn_ctx_t *ctx, const uint8_t *data, uint32_t len, uint16_t id);
extern int audit_window_load(mdn_ctx_t *ctx, const uint8_t *data, uint32_t len, uint16_t id);
extern int export_profile_load(mdn_ctx_t *ctx, const uint8_t *data, uint32_t len, uint16_t id);
extern int query_load(mdn_ctx_t *ctx, const uint8_t *data, uint32_t len);
extern int policy_patch_apply(mdn_ctx_t *ctx, const uint8_t *data, uint32_t len);

/* Section table entry — 20 bytes on the wire */
typedef struct {
    uint8_t  type;
    uint8_t  sect_flags;
    uint16_t id;
    uint32_t offset;
    uint32_t length;
    uint32_t crc32;
    uint32_t epoch;
} sect_entry_t;

#define MDN_MAGIC       "MDN1"
#define MDN_HEADER_LEN  12u
#define SECT_ENTRY_LEN  20u

int mdn_parse(mdn_ctx_t *ctx, const uint8_t *buf, size_t len)
{
    /* 1. Verify magic */
    if (len < MDN_HEADER_LEN)
        return -1;
    if (memcmp(buf, MDN_MAGIC, 4) != 0)
        return -1;

    /* 2. Read header fields */
    uint16_t flags         = mdn_u16le(buf + 4);
    uint16_t section_count = mdn_u16le(buf + 6);
    uint16_t query_count   = mdn_u16le(buf + 8);

    ctx->flags       = flags;
    ctx->query_count = query_count;

    /* 3. Bounds-check the section table */
    size_t table_size = (size_t)section_count * SECT_ENTRY_LEN;
    if (len < MDN_HEADER_LEN + table_size)
        return -1;
    if (section_count > MDN_MAX_SECTIONS)
        return -1;

    /* Parse section table entries */
    sect_entry_t entries[MDN_MAX_SECTIONS];
    for (uint16_t i = 0; i < section_count; i++) {
        const uint8_t *p = buf + MDN_HEADER_LEN + (size_t)i * SECT_ENTRY_LEN;
        entries[i].type       = p[0];
        entries[i].sect_flags = p[1];
        entries[i].id         = mdn_u16le(p + 2);
        entries[i].offset     = mdn_u32le(p + 4);
        entries[i].length     = mdn_u32le(p + 8);
        entries[i].crc32      = mdn_u32le(p + 12);
        entries[i].epoch      = mdn_u32le(p + 16);
    }

    /* Track policy-patch indices for deferred processing.
     * Per spec, SECT_POLICY_PATCH sections must be processed last, after all
     * other section types.  We defer them into patch_idx[] and apply them in
     * a second pass below, preserving the ordering invariant regardless of
     * their position in the section table.
     */
    uint16_t patch_idx[MDN_MAX_SECTIONS];
    uint16_t patch_count = 0;

    /* 4 & 5. Process non-patch sections */
    for (uint16_t i = 0; i < section_count; i++) {
        sect_entry_t *e = &entries[i];

        /* Defer SECT_POLICY_PATCH */
        if (e->type == SECT_POLICY_PATCH) {
            if (patch_count < MDN_MAX_SECTIONS)
                patch_idx[patch_count++] = i;
            continue;
        }

        /* Bounds check */
        if ((size_t)e->offset + (size_t)e->length > len)
            return -1;

        const uint8_t *data = buf + e->offset;

        /* CRC32 verification */
        uint32_t computed = crc32_compute(data, e->length);
        if (computed != e->crc32) {
            if (ctx->flags & MDN_FLAG_STRICT)
                return -1;
            /* non-strict: count the mismatch and skip the section */
            ctx->stats_crc_miss++;
            continue; /* skip CRC-mismatch section in non-strict mode */
        }

        /* Dispatch */
        int rc = 0;
        switch (e->type) {
        case SECT_CAP:
            rc = mdn_cap_load(ctx, data, e->length);
            break;
        case SECT_ZONE:
            rc = zone_load(ctx, data, e->length, e->id);
            break;
        case SECT_RULE:
            rc = rule_load(ctx, data, e->length);
            break;
        case SECT_PREFIX:
            rc = prefix_page_load(ctx, data, e->length, e->id);
            break;
        case SECT_NAT:
            rc = nat_bucket_load(ctx, data, e->length, e->id);
            break;
        case SECT_TEMPLATE:
            rc = template_load(ctx, data, e->length, e->id);
            break;
        case SECT_AUDIT:
            rc = audit_window_load(ctx, data, e->length, e->id);
            break;
        case SECT_EXPORT:
            rc = export_profile_load(ctx, data, e->length, e->id);
            break;
        case SECT_SESSION:
            /* session sections handled externally; skip */
            break;
        case SECT_QUERY:
            rc = query_load(ctx, data, e->length);
            break;
        default:
            /* unknown section type — skip */
            break;
        }
        if (rc != 0)
            return rc;
        ctx->stats_sections_loaded++;
    }

    /* 6. Process SECT_POLICY_PATCH sections last, in order */
    for (uint16_t pi = 0; pi < patch_count; pi++) {
        sect_entry_t *e = &entries[patch_idx[pi]];

        /* Bounds check */
        if ((size_t)e->offset + (size_t)e->length > len)
            return -1;

        const uint8_t *data = buf + e->offset;

        /* CRC32 verification */
        uint32_t computed = crc32_compute(data, e->length);
        if (computed != e->crc32) {
            if (ctx->flags & MDN_FLAG_STRICT)
                return -1;
            continue;
        }

        int rc = policy_patch_apply(ctx, data, e->length);
        if (rc != 0)
            return rc;
    }

    /* Store query_count as parsed (may be updated by query_load) */
    (void)query_count; /* already stored above */

    return 0;
}
