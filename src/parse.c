#include "parse.h"
#include "cap.h"
#include "crc.h"
#include "util.h"
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

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

/* -----------------------------------------------------------------------
 * parse_read_header — internal helper: read and validate the fixed header.
 *
 * Checks the magic bytes, minimum length, and extracts flags + section
 * count into the out-parameters.  Returns 0 on success, -1 on any error.
 * Does not modify any mdn_ctx_t fields; it is a pure read-only probe.
 * ----------------------------------------------------------------------- */
static int parse_read_header(const uint8_t *buf, size_t len,
                             uint16_t *flags_out, uint16_t *count_out)
{
    if (len < MDN_HEADER_LEN)
        return -1;
    if (memcmp(buf, MDN_MAGIC, 4) != 0)
        return -1;

    *flags_out = mdn_u16le(buf + 4);
    *count_out = mdn_u16le(buf + 6);

    /* Validate that the section table fits in the supplied buffer */
    size_t table_size = (size_t)(*count_out) * SECT_ENTRY_LEN;
    if (len < MDN_HEADER_LEN + table_size)
        return -1;
    if (*count_out > MDN_MAX_SECTIONS)
        return -1;

    return 0;
}

/* -----------------------------------------------------------------------
 * mdn_parse_section_count — probe a buffer for section count.
 *
 * Returns the number of sections encoded in the header without performing
 * a full parse.  Returns -1 if the buffer is malformed or too short.
 * ----------------------------------------------------------------------- */
int mdn_parse_section_count(const uint8_t *buf, size_t len)
{
    uint16_t flags = 0;
    uint16_t count = 0;
    if (parse_read_header(buf, len, &flags, &count) != 0)
        return -1;
    return (int)count;
}

/* -----------------------------------------------------------------------
 * mdn_parse_has_section — probe for presence of a given section type.
 *
 * Scans the section table in buf[] without loading anything into a
 * context.  Returns 1 if at least one section of sect_type is present,
 * 0 if none found, or -1 if the buffer is malformed.
 * ----------------------------------------------------------------------- */
int mdn_parse_has_section(const uint8_t *buf, size_t len, uint8_t sect_type)
{
    uint16_t flags = 0;
    uint16_t count = 0;
    if (parse_read_header(buf, len, &flags, &count) != 0)
        return -1;

    for (uint16_t i = 0; i < count; i++) {
        const uint8_t *p = buf + MDN_HEADER_LEN + (size_t)i * SECT_ENTRY_LEN;
        if (p[0] == sect_type)
            return 1;
    }
    return 0;
}

/* -----------------------------------------------------------------------
 * mdn_parse_section_offset — locate the first section of a given type.
 *
 * Returns the byte offset (relative to buf) of the first section whose
 * type matches sect_type, or 0 if no matching section is found.  The
 * offset returned is the section's data payload offset, not the offset
 * of the section table entry.
 *
 * A return value of 0 is ambiguous only if a section payload genuinely
 * begins at byte 0, which cannot happen because the header occupies at
 * least MDN_HEADER_LEN bytes.
 * ----------------------------------------------------------------------- */
uint32_t mdn_parse_section_offset(const uint8_t *buf, size_t len, uint8_t sect_type)
{
    uint16_t flags = 0;
    uint16_t count = 0;
    if (parse_read_header(buf, len, &flags, &count) != 0)
        return 0;

    for (uint16_t i = 0; i < count; i++) {
        const uint8_t *p = buf + MDN_HEADER_LEN + (size_t)i * SECT_ENTRY_LEN;
        if (p[0] == sect_type) {
            uint32_t off = mdn_u32le(p + 4);
            uint32_t slen = mdn_u32le(p + 8);
            /* Validate that the payload is within bounds before returning */
            if ((size_t)off + (size_t)slen <= len)
                return off;
            return 0;
        }
    }
    return 0;
}

/* -----------------------------------------------------------------------
 * mdn_parse_verify_all_crcs — verify checksums for every section.
 *
 * Iterates the section table and recomputes CRC32C for each payload.
 * Returns 0 if all checksums pass, or -1 on the first mismatch.
 * Sections whose payload would exceed the buffer bounds are also treated
 * as failures.
 * ----------------------------------------------------------------------- */
int mdn_parse_verify_all_crcs(const uint8_t *buf, size_t len)
{
    uint16_t flags = 0;
    uint16_t count = 0;
    if (parse_read_header(buf, len, &flags, &count) != 0)
        return -1;

    for (uint16_t i = 0; i < count; i++) {
        const uint8_t *p = buf + MDN_HEADER_LEN + (size_t)i * SECT_ENTRY_LEN;
        uint32_t off   = mdn_u32le(p + 4);
        uint32_t slen  = mdn_u32le(p + 8);
        uint32_t stored = mdn_u32le(p + 12);

        if ((size_t)off + (size_t)slen > len)
            return -1;

        uint32_t computed = crc32_compute(buf + off, slen);
        if (computed != stored)
            return -1;
    }
    return 0;
}

/* -----------------------------------------------------------------------
 * mdn_parse_section_stats — count occurrences of each section type.
 *
 * Fills counts_out[16] with the number of sections observed for each of
 * the 16 possible type values (types 0x00–0x0F).  Types outside this
 * range are silently ignored.  Returns 0 on success, -1 if the header is
 * malformed.
 *
 * counts_out must point to an array of at least 16 uint32_t elements;
 * the caller is responsible for zeroing it before passing it in, or the
 * function will zero it internally.
 * ----------------------------------------------------------------------- */
int mdn_parse_section_stats(const uint8_t *buf, size_t len, uint32_t *counts_out)
{
    if (!counts_out)
        return -1;

    /* Zero the output array so partial failures leave a clean state */
    memset(counts_out, 0, 16 * sizeof(uint32_t));

    uint16_t flags = 0;
    uint16_t count = 0;
    if (parse_read_header(buf, len, &flags, &count) != 0)
        return -1;

    for (uint16_t i = 0; i < count; i++) {
        const uint8_t *p = buf + MDN_HEADER_LEN + (size_t)i * SECT_ENTRY_LEN;
        uint8_t t = p[0];
        if (t < 16)
            counts_out[t]++;
    }
    return 0;
}

/* -----------------------------------------------------------------------
 * mdn_reparse — reset parse-time counters then re-parse.
 *
 * Clears stats_sections_loaded and stats_crc_miss before delegating to
 * mdn_parse, so callers that re-use a context across multiple parse
 * attempts get fresh counters each time rather than accumulating values
 * from prior runs.
 * ----------------------------------------------------------------------- */
int mdn_reparse(mdn_ctx_t *ctx, const uint8_t *buf, size_t len)
{
    ctx->stats_sections_loaded = 0;
    ctx->stats_crc_miss        = 0;
    return mdn_parse(ctx, buf, len);
}

/* -----------------------------------------------------------------------
 * mdn_parse — full parse of a meridian format buffer into ctx.
 * ----------------------------------------------------------------------- */
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

/* -----------------------------------------------------------------------
 * parse_section_type_name — return a string name for a section type.
 *
 * Returns a static string label for each well-known section type.
 * Unknown types are returned as "UNKNOWN".
 * ----------------------------------------------------------------------- */
const char *parse_section_type_name(uint8_t type)
{
    switch (type) {
    case SECT_CAP:          return "SECT_CAP";
    case SECT_ZONE:         return "SECT_ZONE";
    case SECT_RULE:         return "SECT_RULE";
    case SECT_PREFIX:       return "SECT_PREFIX";
    case SECT_NAT:          return "SECT_NAT";
    case SECT_SESSION:      return "SECT_SESSION";
    case SECT_TEMPLATE:     return "SECT_TEMPLATE";
    case SECT_AUDIT:        return "SECT_AUDIT";
    case SECT_EXPORT:       return "SECT_EXPORT";
    case SECT_POLICY_PATCH: return "SECT_POLICY_PATCH";
    case SECT_QUERY:        return "SECT_QUERY";
    default:                return "UNKNOWN";
    }
}

/* -----------------------------------------------------------------------
 * parse_count_section_type — count sections of a given type in the table.
 *
 * Scans the section table and counts entries whose type byte matches the
 * requested type.  Returns the count, or -1 when the buffer is malformed.
 * ----------------------------------------------------------------------- */
int parse_count_section_type(const uint8_t *buf, size_t len, uint8_t type)
{
    uint16_t flags = 0;
    uint16_t count = 0;
    if (parse_read_header(buf, len, &flags, &count) != 0)
        return -1;

    int found = 0;
    for (uint16_t i = 0; i < count; i++) {
        const uint8_t *p = buf + MDN_HEADER_LEN + (size_t)i * SECT_ENTRY_LEN;
        if (p[0] == type)
            found++;
    }
    return found;
}

/* -----------------------------------------------------------------------
 * Section iterator implementation.
 *
 * parse_section_iter_init and parse_section_iter_next walk the section
 * table sequentially without copying data into a context.
 * ----------------------------------------------------------------------- */

/*
 * Initialise an iterator for the section table in buf[0..len).
 * Returns 0 on success, -1 when buf is malformed.
 */
int parse_section_iter_init(parse_section_iterator_t *it,
                             const uint8_t *buf, size_t len)
{
    if (!it || !buf)
        return -1;

    uint16_t flags = 0;
    uint16_t count = 0;
    if (parse_read_header(buf, len, &flags, &count) != 0)
        return -1;

    it->buf     = buf;
    it->buf_len = len;
    it->total   = count;
    it->current = 0;
    return 0;
}

/*
 * Advance the iterator.  Returns 1 when an entry was written to
 * *entry_out, 0 when all entries are consumed, -1 on error.
 */
int parse_section_iter_next(parse_section_iterator_t *it,
                             parse_section_entry_t *entry_out)
{
    if (!it || !entry_out)
        return -1;
    if (it->current >= it->total)
        return 0;

    const uint8_t *p = it->buf + MDN_HEADER_LEN +
                       (size_t)it->current * SECT_ENTRY_LEN;

    entry_out->type       = p[0];
    entry_out->sect_flags = p[1];
    entry_out->id         = mdn_u16le(p + 2);
    entry_out->offset     = mdn_u32le(p + 4);
    entry_out->length     = mdn_u32le(p + 8);
    entry_out->crc32      = mdn_u32le(p + 12);
    entry_out->epoch      = mdn_u32le(p + 16);

    it->current++;
    return 1;
}

/* -----------------------------------------------------------------------
 * parse_extract_section — find and expose a section payload.
 *
 * Searches the section table for the first entry whose type and id both
 * match.  On success sets *data_out to the payload start and *len_out
 * to the payload length.  Returns 0 on success, -1 if not found or if
 * the buffer is malformed.
 * ----------------------------------------------------------------------- */
int parse_extract_section(const uint8_t *buf, size_t len,
                           uint8_t type, uint16_t id,
                           const uint8_t **data_out, uint32_t *len_out)
{
    if (!buf || !data_out || !len_out)
        return -1;

    uint16_t flags = 0;
    uint16_t count = 0;
    if (parse_read_header(buf, len, &flags, &count) != 0)
        return -1;

    for (uint16_t i = 0; i < count; i++) {
        const uint8_t *p = buf + MDN_HEADER_LEN + (size_t)i * SECT_ENTRY_LEN;
        uint8_t  t    = p[0];
        uint16_t sid  = mdn_u16le(p + 2);
        uint32_t off  = mdn_u32le(p + 4);
        uint32_t slen = mdn_u32le(p + 8);

        if (t != type || sid != id)
            continue;
        if ((size_t)off + (size_t)slen > len)
            return -1;

        *data_out = buf + off;
        *len_out  = slen;
        return 0;
    }
    return -1;
}

/* -----------------------------------------------------------------------
 * parse_validate_table — pre-validate all section bounds.
 *
 * Confirms that every section's payload region lies within buf[0..len)
 * and that the header's section count matches section_count.  Returns 0
 * when all sections pass, -1 on first failure.
 * ----------------------------------------------------------------------- */
int parse_validate_table(const uint8_t *buf, size_t len, uint16_t section_count)
{
    if (!buf)
        return -1;

    uint16_t flags = 0;
    uint16_t count = 0;
    if (parse_read_header(buf, len, &flags, &count) != 0)
        return -1;

    if (count != section_count)
        return -1;

    for (uint16_t i = 0; i < count; i++) {
        const uint8_t *p = buf + MDN_HEADER_LEN + (size_t)i * SECT_ENTRY_LEN;
        uint32_t off  = mdn_u32le(p + 4);
        uint32_t slen = mdn_u32le(p + 8);

        if ((size_t)off + (size_t)slen > len)
            return -1;
    }
    return 0;
}

/* -----------------------------------------------------------------------
 * parse_header_summary — format header fields as text.
 *
 * Writes a one-line summary into out[0..cap).  Returns the number of
 * bytes written (excluding NUL).
 * ----------------------------------------------------------------------- */
int parse_header_summary(const uint8_t *buf, size_t len, char *out, uint32_t cap)
{
    if (!buf || !out || cap == 0)
        return 0;

    if (len < MDN_HEADER_LEN) {
        int n = snprintf(out, cap, "<buffer too short>\n");
        return n < 0 ? 0 : (uint32_t)n >= cap ? (int)(cap - 1u) : n;
    }

    if (memcmp(buf, MDN_MAGIC, 4) != 0) {
        int n = snprintf(out, cap, "<bad magic>\n");
        return n < 0 ? 0 : (uint32_t)n >= cap ? (int)(cap - 1u) : n;
    }

    uint16_t flags  = mdn_u16le(buf + 4);
    uint16_t nsect  = mdn_u16le(buf + 6);
    uint16_t nquery = mdn_u16le(buf + 8);

    int n = snprintf(out, cap,
                     "magic=MDN1 flags=0x%04x sections=%u queries=%u\n",
                     (unsigned)flags, (unsigned)nsect, (unsigned)nquery);
    if (n < 0)
        n = 0;
    if ((uint32_t)n >= cap)
        n = (int)(cap - 1u);
    out[n] = '\0';
    return n;
}

/* -----------------------------------------------------------------------
 * parse_section_summary — format a section entry as text.
 *
 * Writes one line per section entry into out[0..cap).  Returns the
 * number of bytes written (excluding NUL).
 * ----------------------------------------------------------------------- */
int parse_section_summary(const parse_section_entry_t *entry, char *out, uint32_t cap)
{
    if (!entry || !out || cap == 0)
        return 0;

    int n = snprintf(out, cap,
                     "type=%-18s id=%u off=%u len=%u crc=0x%08x epoch=%u\n",
                     parse_section_type_name(entry->type),
                     (unsigned)entry->id,
                     (unsigned)entry->offset,
                     (unsigned)entry->length,
                     (unsigned)entry->crc32,
                     (unsigned)entry->epoch);
    if (n < 0)
        n = 0;
    if ((uint32_t)n >= cap)
        n = (int)(cap - 1u);
    out[n] = '\0';
    return n;
}
