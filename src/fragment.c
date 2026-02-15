#include "fragment.h"
#include "util.h"
#include <stdlib.h>
#include <string.h>

int fragment_emit_headers(mdn_ctx_t *ctx, mdn_packet_template_t *tmpl) {
    (void)ctx;
    if (!tmpl || !tmpl->hdr_bytes || !tmpl->descs) return -1;
    for (uint16_t i = 0; i < tmpl->desc_count; i++) {
        mdn_tmpl_desc_t *d = &tmpl->descs[i];
        /* write field at descriptor offset into header buffer */
        memset(tmpl->hdr_bytes + d->field_off, 0, d->field_len);
        tmpl->hdr_len = (uint16_t)MDN_MAX(tmpl->hdr_len,
                                           (uint16_t)(d->field_off + d->field_len));
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* fragment_count_headers                                                */
/* ------------------------------------------------------------------ */

/*
 * Returns the number of header-field descriptors registered on the
 * given template, which equals tmpl->desc_count.  Returns -1 when
 * tmpl is NULL.
 */
int fragment_count_headers(mdn_packet_template_t *tmpl)
{
    if (!tmpl)
        return -1;
    return (int)tmpl->desc_count;
}

/* ------------------------------------------------------------------ */
/* fragment_validate_layout                                              */
/* ------------------------------------------------------------------ */

/*
 * Walk every descriptor and verify that none extends past hdr_cap.
 * Also checks for any pair of overlapping descriptors: two descriptors
 * overlap when their field regions intersect.
 * Returns 0 when the layout is clean, -1 on any violation.
 */
int fragment_validate_layout(mdn_packet_template_t *tmpl)
{
    if (!tmpl || !tmpl->hdr_bytes)
        return -1;

    for (uint16_t i = 0; i < tmpl->desc_count; i++) {
        mdn_tmpl_desc_t *di = &tmpl->descs[i];
        uint32_t end_i = (uint32_t)di->field_off + (uint32_t)di->field_len;
        if (end_i > tmpl->hdr_cap)
            return -1;

        /* Check against every subsequent descriptor for overlap */
        for (uint16_t j = (uint16_t)(i + 1); j < tmpl->desc_count; j++) {
            mdn_tmpl_desc_t *dj = &tmpl->descs[j];
            uint32_t end_j = (uint32_t)dj->field_off + (uint32_t)dj->field_len;

            /* Overlap: one starts before the other ends */
            if (di->field_off < end_j && dj->field_off < end_i)
                return -1;
        }
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* fragment_copy_region                                                  */
/* ------------------------------------------------------------------ */

/*
 * Copy len bytes starting at src_off in src->hdr_bytes to dst_off in
 * dst->hdr_bytes.  Both source and destination regions must lie
 * entirely within their respective hdr_cap values.
 * Returns 0 on success, -1 on any bounds violation.
 */
int fragment_copy_region(mdn_packet_template_t *src, mdn_packet_template_t *dst,
                          uint16_t src_off, uint16_t dst_off, uint16_t len)
{
    if (!src || !dst || !src->hdr_bytes || !dst->hdr_bytes)
        return -1;
    if (len == 0)
        return 0;

    uint32_t src_end = (uint32_t)src_off + (uint32_t)len;
    uint32_t dst_end = (uint32_t)dst_off + (uint32_t)len;

    if (src_end > src->hdr_cap)
        return -1;
    if (dst_end > dst->hdr_cap)
        return -1;

    memcpy(dst->hdr_bytes + dst_off, src->hdr_bytes + src_off, len);
    return 0;
}

/* ------------------------------------------------------------------ */
/* fragment_append_descriptor                                            */
/* ------------------------------------------------------------------ */

/*
 * Append one descriptor to the end of tmpl->descs.  The descs array is
 * grown via realloc.  Returns 0 on success, -1 on allocation failure.
 */
int fragment_append_descriptor(mdn_packet_template_t *tmpl, mdn_tmpl_desc_t desc)
{
    if (!tmpl)
        return -1;

    uint32_t new_count = (uint32_t)tmpl->desc_count + 1u;
    mdn_tmpl_desc_t *arr = realloc(tmpl->descs, new_count * sizeof(mdn_tmpl_desc_t));
    if (!arr)
        return -1;

    tmpl->descs = arr;
    tmpl->descs[tmpl->desc_count] = desc;
    tmpl->desc_count = (uint16_t)(new_count <= 0xFFFFu ? new_count : tmpl->desc_count);
    return 0;
}

/* ------------------------------------------------------------------ */
/* fragment_remove_descriptor                                            */
/* ------------------------------------------------------------------ */

/*
 * Remove the descriptor at position idx by shifting all subsequent
 * entries one slot toward the front.  The descs array is shrunk via
 * realloc; if the array becomes empty the pointer is freed and set to
 * NULL.  Returns 0 on success, -1 when idx is out of range.
 */
int fragment_remove_descriptor(mdn_packet_template_t *tmpl, uint16_t idx)
{
    if (!tmpl || !tmpl->descs)
        return -1;
    if (idx >= tmpl->desc_count)
        return -1;

    uint16_t new_count = (uint16_t)(tmpl->desc_count - 1u);

    /* Shift remaining descriptors left */
    for (uint16_t i = idx; i < new_count; i++)
        tmpl->descs[i] = tmpl->descs[i + 1];

    tmpl->desc_count = new_count;

    if (new_count == 0) {
        free(tmpl->descs);
        tmpl->descs = NULL;
    } else {
        mdn_tmpl_desc_t *arr = realloc(tmpl->descs,
                                        (uint32_t)new_count * sizeof(mdn_tmpl_desc_t));
        if (arr)
            tmpl->descs = arr;
        /* if realloc fails, keep the existing larger allocation — still valid */
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* fragment_stats                                                        */
/* ------------------------------------------------------------------ */

/*
 * Walk all templates in ctx and accumulate:
 *   total_templates — number of templates registered
 *   total_frags     — sum of frag_count across all templates
 */
void fragment_stats(mdn_ctx_t *ctx, uint32_t *total_templates, uint32_t *total_frags)
{
    if (!ctx) {
        if (total_templates) *total_templates = 0;
        if (total_frags)     *total_frags     = 0;
        return;
    }

    uint32_t frags = 0;
    for (uint32_t i = 0; i < ctx->template_count; i++)
        frags += ctx->templates[i].frag_count;

    if (total_templates) *total_templates = ctx->template_count;
    if (total_frags)     *total_frags     = frags;
}

/* ------------------------------------------------------------------ */
/* fragment_tracker_t — lightweight per-reassembly tracking record      */
/* ------------------------------------------------------------------ */

/*
 * Initialize a fragment tracker to the given total PDU length.
 * All received bookkeeping is cleared; id is set to the caller-supplied
 * fragment-group identifier.
 */
void fragment_tracker_init(fragment_tracker_t *t, uint16_t id, uint32_t total_len)
{
    if (!t)
        return;
    t->id           = id;
    t->offset       = 0;
    t->total_len    = total_len;
    t->received_len = 0;
}

/*
 * Record that a fragment spanning [frag_offset, frag_offset+frag_len)
 * has arrived for the tracker.  received_len accumulates the fragment
 * payloads; callers are responsible for de-duplication when fragments
 * overlap (this tracker keeps only the running total).
 *
 * Returns 0 on success, -1 when the addition would cause received_len
 * to exceed total_len (indicating a malformed fragment stream).
 */
int fragment_tracker_update(fragment_tracker_t *t, uint32_t frag_offset,
                             uint32_t frag_len)
{
    if (!t)
        return -1;
    /* A fragment that starts past the declared total is invalid */
    if (frag_offset >= t->total_len)
        return -1;
    uint32_t clipped = MDN_MIN(frag_len, t->total_len - frag_offset);
    uint32_t new_total = t->received_len + clipped;
    if (new_total < t->received_len)
        return -1; /* wrap guard */
    if (new_total > t->total_len)
        return -1;
    t->received_len = new_total;
    t->offset       = frag_offset + clipped;
    return 0;
}

/*
 * Returns 1 when the tracker has seen enough payload bytes to cover
 * total_len, indicating that reassembly is complete.  Returns 0
 * otherwise.
 */
int fragment_tracker_complete(fragment_tracker_t *t)
{
    if (!t)
        return 0;
    return (t->received_len >= t->total_len) ? 1 : 0;
}

/* ------------------------------------------------------------------ */
/* fragment_reassemble                                                   */
/* ------------------------------------------------------------------ */

/*
 * Reassemble frag_count fragment buffers into out[0..out_cap).  Each
 * element of frags[] is a (data, len) pair describing one fragment
 * payload; they are concatenated in order.  The number of bytes written
 * is returned, or -1 when out_cap is insufficient to hold all fragments.
 *
 * ctx and tmpl are accepted for future extension; they are not used in
 * this revision.
 */
int fragment_reassemble(mdn_ctx_t *ctx, mdn_packet_template_t *tmpl,
                        const fragment_piece_t *frags, uint16_t frag_count,
                        uint8_t *out, uint32_t out_cap)
{
    (void)ctx;
    (void)tmpl;
    if (!frags || !out || out_cap == 0)
        return -1;

    uint32_t written = 0;
    for (uint16_t i = 0; i < frag_count; i++) {
        if (!frags[i].data || frags[i].len == 0)
            continue;
        if (written + frags[i].len > out_cap)
            return -1;
        memcpy(out + written, frags[i].data, frags[i].len);
        written += frags[i].len;
    }
    return (int)written;
}

/* ------------------------------------------------------------------ */
/* fragment_checksum                                                     */
/* ------------------------------------------------------------------ */

/*
 * Compute a Fletcher-16 checksum over data[0..len).  The algorithm
 * produces two 8-bit sums that are packed into the high and low bytes
 * of the returned uint16_t.  A return value of 0xFFFF with len == 0 is
 * not meaningful; callers should guard against zero-length inputs.
 */
uint16_t fragment_checksum(const uint8_t *data, uint32_t len)
{
    if (!data || len == 0)
        return 0;

    uint32_t sum1 = 0;
    uint32_t sum2 = 0;

    for (uint32_t i = 0; i < len; i++) {
        sum1 = (sum1 + (uint32_t)data[i]) % 255u;
        sum2 = (sum2 + sum1) % 255u;
    }
    return (uint16_t)((sum2 << 8) | sum1);
}

/* ------------------------------------------------------------------ */
/* fragment_hdr_dump                                                     */
/* ------------------------------------------------------------------ */

/*
 * Write a human-readable representation of all descriptor fields in
 * tmpl to out[0..cap).  Each descriptor is formatted as one line:
 *   "desc[N]: off=X len=Y type=Z src=W\n"
 * The number of bytes written (excluding the terminating NUL) is
 * returned.  Returns 0 if tmpl is NULL or has no descriptors.
 */
int fragment_hdr_dump(mdn_packet_template_t *tmpl, char *out, uint32_t cap)
{
    if (!tmpl || !out || cap == 0)
        return 0;

    int total = 0;
    for (uint16_t i = 0; i < tmpl->desc_count; i++) {
        mdn_tmpl_desc_t *d = &tmpl->descs[i];
        int n = snprintf(out + total, cap - (uint32_t)total,
                         "desc[%u]: off=%u len=%u type=%u src=%u\n",
                         (unsigned)i,
                         (unsigned)d->field_off,
                         (unsigned)d->field_len,
                         (unsigned)d->field_type,
                         (unsigned)d->field_src);
        if (n < 0)
            break;
        total += n;
        if ((uint32_t)total >= cap - 1u)
            break;
    }
    out[MDN_MIN((uint32_t)total, cap - 1u)] = '\0';
    return total;
}

/* ------------------------------------------------------------------ */
/* fragment_count_fields                                                 */
/* ------------------------------------------------------------------ */

/*
 * Return the number of descriptor entries (i.e. tmpl->desc_count).
 * Equivalent to fragment_count_headers but semantically named for the
 * field-counting use-case.  Returns -1 when tmpl is NULL.
 */
int fragment_count_fields(mdn_packet_template_t *tmpl)
{
    if (!tmpl)
        return -1;
    return (int)tmpl->desc_count;
}

/* ------------------------------------------------------------------ */
/* fragment_validate_descriptors                                         */
/* ------------------------------------------------------------------ */

/*
 * For each descriptor verify that field_off + field_len <= hdr_cap.
 * This is a lightweight bounds check that does not look for overlaps
 * (see fragment_validate_layout for full overlap detection).  Returns 0
 * if every descriptor is within bounds, -1 on the first violation.
 */
int fragment_validate_descriptors(mdn_packet_template_t *tmpl)
{
    if (!tmpl)
        return -1;

    for (uint16_t i = 0; i < tmpl->desc_count; i++) {
        mdn_tmpl_desc_t *d = &tmpl->descs[i];
        uint32_t end = (uint32_t)d->field_off + (uint32_t)d->field_len;
        if (end > tmpl->hdr_cap)
            return -1;
    }
    return 0;
}
