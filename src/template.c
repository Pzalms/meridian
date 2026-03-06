#include "template.h"
#include "cap.h"
#include "util.h"
#include <stdlib.h>
#include <string.h>

/* Minimum header size: 6 x u16 = 12 bytes */
#define TMPL_HDR_MIN  12
/* Each descriptor: field_off(u16) + field_len(u16) + field_type(u16) + field_src(u16) = 8 bytes */
#define TMPL_DESC_SZ   8

/* Wire-format header for serialized template */
#define TMPL_SERIAL_HDR 12

int template_prepare_frame(mdn_packet_template_t *tmpl) {
    uint32_t cap = 0;
    for (uint16_t i = 0; i < tmpl->desc_count; i++)
        cap += tmpl->descs[i].field_len;
    if (cap == 0) cap = 64;
    tmpl->hdr_cap   = cap;
    tmpl->hdr_bytes = calloc(1, cap);
    return tmpl->hdr_bytes ? 0 : -1;
}

int template_load(mdn_ctx_t *ctx, const uint8_t *data, uint32_t len, uint16_t id) {
    (void)id;

    if (len < TMPL_HDR_MIN)
        return -1;

    uint16_t tmpl_id    = mdn_u16le(data + 0);
    uint16_t hdr_len    = mdn_u16le(data + 2);
    uint16_t frag_count = mdn_u16le(data + 4);
    uint16_t flags      = mdn_u16le(data + 6);
    uint16_t profile    = mdn_u16le(data + 8);
    uint16_t desc_count = mdn_u16le(data + 10);

    uint32_t need = TMPL_HDR_MIN + (uint32_t)desc_count * TMPL_DESC_SZ;
    if (len < need)
        return -1;

    /* Grow the templates array by one slot */
    mdn_packet_template_t *arr = realloc(ctx->templates,
        (ctx->template_count + 1) * sizeof(mdn_packet_template_t));
    if (!arr)
        return -1;
    ctx->templates = arr;

    mdn_packet_template_t *t = &ctx->templates[ctx->template_count];
    memset(t, 0, sizeof(*t));
    t->tmpl_id    = tmpl_id;
    t->hdr_len    = hdr_len;
    t->frag_count = frag_count;
    t->flags      = flags;
    t->profile    = profile;
    t->desc_count = desc_count;

    if (desc_count > 0) {
        t->descs = malloc((uint32_t)desc_count * sizeof(mdn_tmpl_desc_t));
        if (!t->descs)
            return -1;
        const uint8_t *p = data + TMPL_HDR_MIN;
        for (uint16_t i = 0; i < desc_count; i++, p += TMPL_DESC_SZ) {
            t->descs[i].field_off  = mdn_u16le(p + 0);
            t->descs[i].field_len  = mdn_u16le(p + 2);
            t->descs[i].field_type = mdn_u16le(p + 4);
            t->descs[i].field_src  = mdn_u16le(p + 6);
        }
    }

    if (template_prepare_frame(t) != 0) {
        free(t->descs);
        return -1;
    }

    ctx->template_count++;
    return 0;
}

void template_swap_profile(mdn_ctx_t *ctx, uint16_t tmpl_id,
                            mdn_tmpl_desc_t *new_descs, uint16_t new_desc_count) {
    if (!mdn_cap_check(ctx, 0x53)) return;
    for (uint32_t i = 0; i < ctx->template_count; i++) {
        mdn_packet_template_t *t = &ctx->templates[i];
        if (t->tmpl_id != tmpl_id) continue;
        free(t->descs);
        t->descs      = new_descs;
        t->desc_count = new_desc_count;
        t->profile    = 1;  /* encapsulated */
        /* hdr_bytes retains capacity from earlier profile */
        return;
    }
}

void template_free_all(mdn_ctx_t *ctx) {
    for (uint32_t i = 0; i < ctx->template_count; i++) {
        mdn_packet_template_t *t = &ctx->templates[i];
        free(t->descs);
        free(t->hdr_bytes);
    }
    free(ctx->templates);
    ctx->templates      = NULL;
    ctx->template_count = 0;
}

/* ------------------------------------------------------------------ */
/* template_find                                                         */
/* ------------------------------------------------------------------ */

/*
 * Scan the context's template array for a template whose tmpl_id
 * matches the requested id.  Returns a pointer into the live array,
 * or NULL when no match is found.
 */
mdn_packet_template_t *template_find(mdn_ctx_t *ctx, uint16_t tmpl_id)
{
    if (!ctx || !ctx->templates)
        return NULL;
    for (uint32_t i = 0; i < ctx->template_count; i++) {
        if (ctx->templates[i].tmpl_id == tmpl_id)
            return &ctx->templates[i];
    }
    return NULL;
}

/* ------------------------------------------------------------------ */
/* template_clone                                                        */
/* ------------------------------------------------------------------ */

/*
 * Copy template src_id into a new slot identified by dst_id.
 * Descriptors and header bytes are deep-copied so each template owns
 * its own allocations.  Returns 0 on success, -1 on error.
 */
int template_clone(mdn_ctx_t *ctx, uint16_t src_id, uint16_t dst_id)
{
    if (!ctx)
        return -1;

    mdn_packet_template_t *src = template_find(ctx, src_id);
    if (!src)
        return -1;

    /* Grow the templates array */
    mdn_packet_template_t *arr = realloc(ctx->templates,
        (ctx->template_count + 1) * sizeof(mdn_packet_template_t));
    if (!arr)
        return -1;
    ctx->templates = arr;

    /* Re-derive src pointer after potential realloc move */
    src = template_find(ctx, src_id);
    if (!src)
        return -1;

    mdn_packet_template_t *dst = &ctx->templates[ctx->template_count];
    memset(dst, 0, sizeof(*dst));

    dst->tmpl_id    = dst_id;
    dst->hdr_len    = src->hdr_len;
    dst->frag_count = src->frag_count;
    dst->flags      = src->flags;
    dst->profile    = src->profile;
    dst->desc_count = src->desc_count;
    dst->hdr_cap    = src->hdr_cap;

    if (src->desc_count > 0 && src->descs) {
        size_t dsz = (uint32_t)src->desc_count * sizeof(mdn_tmpl_desc_t);
        dst->descs = malloc(dsz);
        if (!dst->descs)
            return -1;
        memcpy(dst->descs, src->descs, dsz);
    }

    if (src->hdr_cap > 0 && src->hdr_bytes) {
        dst->hdr_bytes = malloc(src->hdr_cap);
        if (!dst->hdr_bytes) {
            free(dst->descs);
            return -1;
        }
        memcpy(dst->hdr_bytes, src->hdr_bytes, src->hdr_cap);
    }

    ctx->template_count++;
    return 0;
}

/* ------------------------------------------------------------------ */
/* template_set_header_byte / template_get_header_byte                  */
/* ------------------------------------------------------------------ */

/*
 * Write a single byte into the template's hdr_bytes buffer at the
 * given offset.  Returns 0 on success, -1 if the offset is out of
 * range or the buffer is not allocated.
 */
int template_set_header_byte(mdn_packet_template_t *tmpl, uint16_t off, uint8_t val)
{
    if (!tmpl || !tmpl->hdr_bytes)
        return -1;
    if ((uint32_t)off >= tmpl->hdr_cap)
        return -1;
    tmpl->hdr_bytes[off] = val;
    return 0;
}

/*
 * Read a single byte from the template's hdr_bytes buffer at the given
 * offset, writing the result into *val_out.  Returns 0 on success,
 * -1 on range error.
 */
int template_get_header_byte(mdn_packet_template_t *tmpl, uint16_t off, uint8_t *val_out)
{
    if (!tmpl || !tmpl->hdr_bytes || !val_out)
        return -1;
    if ((uint32_t)off >= tmpl->hdr_cap)
        return -1;
    *val_out = tmpl->hdr_bytes[off];
    return 0;
}

/* ------------------------------------------------------------------ */
/* template_fill_descriptor                                              */
/* ------------------------------------------------------------------ */

/*
 * Fill the byte region described by descs[desc_idx] with the constant
 * value val.  All bytes in [field_off, field_off + field_len) are set.
 * Returns 0 on success, -1 when the descriptor index is out of range or
 * the region extends past hdr_cap.
 */
int template_fill_descriptor(mdn_packet_template_t *tmpl, uint16_t desc_idx, uint8_t val)
{
    if (!tmpl || !tmpl->hdr_bytes || !tmpl->descs)
        return -1;
    if (desc_idx >= tmpl->desc_count)
        return -1;

    mdn_tmpl_desc_t *d = &tmpl->descs[desc_idx];
    uint32_t end = (uint32_t)d->field_off + (uint32_t)d->field_len;
    if (end > tmpl->hdr_cap)
        return -1;

    memset(tmpl->hdr_bytes + d->field_off, (int)(uint32_t)val, d->field_len);
    return 0;
}

/* ------------------------------------------------------------------ */
/* template_validate                                                     */
/* ------------------------------------------------------------------ */

/*
 * Check internal consistency of a template:
 *   - hdr_cap must be non-zero
 *   - hdr_bytes must be non-NULL
 *   - every descriptor's field region must fit inside hdr_cap
 * Returns 0 when valid, -1 on any violation.
 */
int template_validate(mdn_packet_template_t *tmpl)
{
    if (!tmpl)
        return -1;
    if (tmpl->hdr_cap == 0)
        return -1;
    if (!tmpl->hdr_bytes)
        return -1;

    for (uint16_t i = 0; i < tmpl->desc_count; i++) {
        mdn_tmpl_desc_t *d = &tmpl->descs[i];
        uint32_t end = (uint32_t)d->field_off + (uint32_t)d->field_len;
        if (end > tmpl->hdr_cap)
            return -1;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* template_stats                                                        */
/* ------------------------------------------------------------------ */

/*
 * Aggregate counts across all templates registered in ctx.
 *  total_out       — set to ctx->template_count
 *  total_desc_out  — set to the sum of desc_count across all templates
 */
void template_stats(mdn_ctx_t *ctx, uint32_t *total_out, uint32_t *total_desc_out)
{
    if (!ctx) {
        if (total_out)      *total_out      = 0;
        if (total_desc_out) *total_desc_out = 0;
        return;
    }

    uint32_t ndesc = 0;
    for (uint32_t i = 0; i < ctx->template_count; i++)
        ndesc += ctx->templates[i].desc_count;

    if (total_out)      *total_out      = ctx->template_count;
    if (total_desc_out) *total_desc_out = ndesc;
}

/* ------------------------------------------------------------------ */
/* template_serialize                                                    */
/* ------------------------------------------------------------------ */

/*
 * Write the template to a flat byte buffer in the same wire format that
 * template_load() expects.  Returns the number of bytes written on
 * success, or -1 when the output buffer is too small.
 *
 * Layout (little-endian):
 *   tmpl_id    u16
 *   hdr_len    u16
 *   frag_count u16
 *   flags      u16
 *   profile    u16
 *   desc_count u16
 *   [desc_count × 8-byte descriptor records]
 */
int template_serialize(mdn_packet_template_t *tmpl, uint8_t *out, uint32_t cap)
{
    if (!tmpl || !out)
        return -1;

    uint32_t need = TMPL_SERIAL_HDR + (uint32_t)tmpl->desc_count * TMPL_DESC_SZ;
    if (cap < need)
        return -1;

    uint32_t pos = 0;

    /* tmpl_id */
    out[pos++] = (uint8_t)(tmpl->tmpl_id & 0xFF);
    out[pos++] = (uint8_t)(tmpl->tmpl_id >> 8);
    /* hdr_len */
    out[pos++] = (uint8_t)(tmpl->hdr_len & 0xFF);
    out[pos++] = (uint8_t)(tmpl->hdr_len >> 8);
    /* frag_count */
    out[pos++] = (uint8_t)(tmpl->frag_count & 0xFF);
    out[pos++] = (uint8_t)(tmpl->frag_count >> 8);
    /* flags */
    out[pos++] = (uint8_t)(tmpl->flags & 0xFF);
    out[pos++] = (uint8_t)(tmpl->flags >> 8);
    /* profile */
    out[pos++] = (uint8_t)(tmpl->profile & 0xFF);
    out[pos++] = (uint8_t)(tmpl->profile >> 8);
    /* desc_count */
    out[pos++] = (uint8_t)(tmpl->desc_count & 0xFF);
    out[pos++] = (uint8_t)(tmpl->desc_count >> 8);

    for (uint16_t i = 0; i < tmpl->desc_count; i++) {
        mdn_tmpl_desc_t *d = &tmpl->descs[i];
        out[pos++] = (uint8_t)(d->field_off & 0xFF);
        out[pos++] = (uint8_t)(d->field_off >> 8);
        out[pos++] = (uint8_t)(d->field_len & 0xFF);
        out[pos++] = (uint8_t)(d->field_len >> 8);
        out[pos++] = (uint8_t)(d->field_type & 0xFF);
        out[pos++] = (uint8_t)(d->field_type >> 8);
        out[pos++] = (uint8_t)(d->field_src & 0xFF);
        out[pos++] = (uint8_t)(d->field_src >> 8);
    }

    return (int)pos;
}
