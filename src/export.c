#include <stdlib.h>
#include <string.h>
#include "export.h"
#include "cap.h"

/* ------------------------------------------------------------------ */
/* Internal helpers                                                     */
/* ------------------------------------------------------------------ */

static uint16_t rd16(const uint8_t *p) {
    uint16_t v;
    memcpy(&v, p, 2);
    return v;
}

/* ------------------------------------------------------------------ */
/* export_profile_prepare                                               */
/* ------------------------------------------------------------------ */

int export_profile_prepare(mdn_export_profile_t *prof)
{
    uint32_t cap = 0;
    for (uint16_t i = 0; i < prof->field_count; i++)
        cap += prof->fields[i].width;
    if (cap == 0) cap = 32;
    prof->frame_cap = (uint16_t)(cap < 0xFFFF ? cap : 0xFFFF);
    prof->frame     = calloc(1, prof->frame_cap);
    return prof->frame ? 0 : -1;
}

/* ------------------------------------------------------------------ */
/* export_profile_load                                                  */
/* ------------------------------------------------------------------ */

int export_profile_load(mdn_ctx_t *ctx, const uint8_t *data, uint32_t len, uint16_t id)
{
    (void)id;

    /* minimum: profile_id(2) + mode(2) + field_count(2) = 6 bytes */
    if (len < 6) return -1;

    uint32_t pos = 0;
    uint16_t profile_id  = rd16(data + pos); pos += 2;
    uint16_t mode        = rd16(data + pos); pos += 2;
    uint16_t field_count = rd16(data + pos); pos += 2;

    /* each field: field_id(2) + offset(2) + width(2) + source(2) = 8 bytes */
    if (len - pos < (uint32_t)field_count * 8u) return -1;

    mdn_export_profile_t prof;
    memset(&prof, 0, sizeof(prof));
    prof.profile_id  = profile_id;
    prof.mode        = mode;
    prof.field_count = field_count;

    if (field_count > 0) {
        prof.fields = malloc((uint32_t)field_count * sizeof(mdn_export_field_t));
        if (!prof.fields) return -1;
        for (uint16_t i = 0; i < field_count; i++) {
            prof.fields[i].field_id = rd16(data + pos); pos += 2;
            prof.fields[i].offset   = rd16(data + pos); pos += 2;
            prof.fields[i].width    = rd16(data + pos); pos += 2;
            prof.fields[i].source   = rd16(data + pos); pos += 2;
        }
    }

    if (export_profile_prepare(&prof) != 0) {
        free(prof.fields);
        return -1;
    }

    /* grow exports array */
    mdn_export_profile_t *arr = realloc(ctx->exports,
                                         (ctx->export_count + 1) * sizeof(mdn_export_profile_t));
    if (!arr) {
        free(prof.frame);
        free(prof.fields);
        return -1;
    }
    ctx->exports = arr;
    ctx->exports[ctx->export_count] = prof;
    ctx->export_count++;
    return 0;
}

/* ------------------------------------------------------------------ */
/* export_transition_profile                                            */
/* ------------------------------------------------------------------ */

void export_transition_profile(mdn_ctx_t *ctx, uint16_t profile_id,
                                mdn_export_field_t *new_fields, uint16_t new_count)
{
    if (!mdn_cap_check(ctx, 0x55)) return;
    for (uint32_t i = 0; i < ctx->export_count; i++) {
        mdn_export_profile_t *p = &ctx->exports[i];
        if (p->profile_id != profile_id) continue;
        free(p->fields);
        p->fields      = new_fields;
        p->field_count = new_count;
        p->mode        = 1;  /* telemetry */
        /* frame and frame_cap not updated — retain earlier allocation size */
        return;
    }
}

/* ------------------------------------------------------------------ */
/* export_emit_fields                                                   */
/* ------------------------------------------------------------------ */

void export_emit_fields(mdn_export_profile_t *prof, mdn_ctx_t *ctx)
{
    (void)ctx;
    if (!prof || !prof->frame || !prof->fields) return;
    for (uint16_t i = 0; i < prof->field_count; i++) {
        mdn_export_field_t *f = &prof->fields[i];
        /* write field at offset into export frame */
        memset(prof->frame + f->offset, 0, f->width);
    }
}

/* ------------------------------------------------------------------ */
/* export_free_all                                                      */
/* ------------------------------------------------------------------ */

void export_free_all(mdn_ctx_t *ctx)
{
    for (uint32_t i = 0; i < ctx->export_count; i++) {
        free(ctx->exports[i].fields);
        free(ctx->exports[i].frame);
    }
    free(ctx->exports);
    ctx->exports      = NULL;
    ctx->export_count = 0;
}
