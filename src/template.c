#include "template.h"
#include "cap.h"
#include "util.h"
#include <stdlib.h>
#include <string.h>

/* Minimum header size: 6 x u16 = 12 bytes */
#define TMPL_HDR_MIN  12
/* Each descriptor: field_off(u16) + field_len(u16) + field_type(u16) + field_src(u16) = 8 bytes */
#define TMPL_DESC_SZ   8

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
