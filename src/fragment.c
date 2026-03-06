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
