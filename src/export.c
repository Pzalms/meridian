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

    /* cap field_count at the compile-time maximum */
    if (field_count > MDN_EXPORT_FIELDS_MAX) return -1;

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

/* ------------------------------------------------------------------ */
/* export_find                                                          */
/* ------------------------------------------------------------------ */

/*
 * Scan ctx->exports for a profile whose profile_id matches the
 * requested id.  Returns a pointer into the live array, or NULL when
 * no matching profile is found.
 */
mdn_export_profile_t *export_find(mdn_ctx_t *ctx, uint16_t profile_id)
{
    if (!ctx || !ctx->exports)
        return NULL;
    for (uint32_t i = 0; i < ctx->export_count; i++) {
        if (ctx->exports[i].profile_id == profile_id)
            return &ctx->exports[i];
    }
    return NULL;
}

/* ------------------------------------------------------------------ */
/* export_field_encode_u32                                              */
/* ------------------------------------------------------------------ */

/*
 * Write a 32-bit unsigned integer in little-endian byte order into the
 * export frame at the byte offset specified by fields[field_idx].offset.
 * The field must have a width of at least 4 bytes.
 * Returns 0 on success, -1 on error.
 */
int export_field_encode_u32(mdn_export_profile_t *prof, uint16_t field_idx, uint32_t val)
{
    if (!prof || !prof->frame || !prof->fields)
        return -1;
    if (field_idx >= prof->field_count)
        return -1;

    mdn_export_field_t *f = &prof->fields[field_idx];
    if (f->width < 4u)
        return -1;

    uint32_t end = (uint32_t)f->offset + (uint32_t)f->width;
    if (end > (uint32_t)prof->frame_cap)
        return -1;

    uint8_t *p = prof->frame + f->offset;
    p[0] = (uint8_t)( val        & 0xFF);
    p[1] = (uint8_t)((val >>  8) & 0xFF);
    p[2] = (uint8_t)((val >> 16) & 0xFF);
    p[3] = (uint8_t)((val >> 24) & 0xFF);
    return 0;
}

/* ------------------------------------------------------------------ */
/* export_field_decode_u32                                              */
/* ------------------------------------------------------------------ */

/*
 * Read a 32-bit unsigned integer in little-endian byte order from the
 * export frame at the byte offset specified by fields[field_idx].offset.
 * The field must have a width of at least 4 bytes.
 * Returns 0 on success, -1 on error.
 */
int export_field_decode_u32(mdn_export_profile_t *prof, uint16_t field_idx,
                             uint32_t *val_out)
{
    if (!prof || !prof->frame || !prof->fields || !val_out)
        return -1;
    if (field_idx >= prof->field_count)
        return -1;

    mdn_export_field_t *f = &prof->fields[field_idx];
    if (f->width < 4u)
        return -1;

    uint32_t end = (uint32_t)f->offset + (uint32_t)f->width;
    if (end > (uint32_t)prof->frame_cap)
        return -1;

    const uint8_t *p = prof->frame + f->offset;
    *val_out = (uint32_t)p[0]
             | ((uint32_t)p[1] <<  8)
             | ((uint32_t)p[2] << 16)
             | ((uint32_t)p[3] << 24);
    return 0;
}

/* ------------------------------------------------------------------ */
/* export_profile_validate                                              */
/* ------------------------------------------------------------------ */

/*
 * Check internal consistency of an export profile:
 *   - frame must be non-NULL when frame_cap > 0
 *   - every field's offset + width must fit within frame_cap
 * Returns 0 when valid, -1 on any violation.
 */
int export_profile_validate(mdn_export_profile_t *prof)
{
    if (!prof)
        return -1;
    if (prof->frame_cap > 0 && !prof->frame)
        return -1;

    for (uint16_t i = 0; i < prof->field_count; i++) {
        mdn_export_field_t *f = &prof->fields[i];
        uint32_t end = (uint32_t)f->offset + (uint32_t)f->width;
        if (end > (uint32_t)prof->frame_cap)
            return -1;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* export_profile_serialize                                             */
/* ------------------------------------------------------------------ */

/*
 * Write the profile to a flat byte buffer in the same wire format that
 * export_profile_load() expects.  Layout (little-endian):
 *   profile_id  u16
 *   mode        u16
 *   field_count u16
 *   [field_count × { field_id(u16) offset(u16) width(u16) source(u16) }]
 *
 * Returns the number of bytes written on success, or -1 when cap is
 * too small.
 */
int export_profile_serialize(mdn_export_profile_t *prof, uint8_t *out, uint32_t cap)
{
    if (!prof || !out)
        return -1;

    uint32_t need = 6u + (uint32_t)prof->field_count * 8u;
    if (cap < need)
        return -1;

    uint32_t pos = 0;

    /* profile_id */
    out[pos++] = (uint8_t)(prof->profile_id & 0xFF);
    out[pos++] = (uint8_t)(prof->profile_id >> 8);
    /* mode */
    out[pos++] = (uint8_t)(prof->mode & 0xFF);
    out[pos++] = (uint8_t)(prof->mode >> 8);
    /* field_count */
    out[pos++] = (uint8_t)(prof->field_count & 0xFF);
    out[pos++] = (uint8_t)(prof->field_count >> 8);

    for (uint16_t i = 0; i < prof->field_count; i++) {
        mdn_export_field_t *f = &prof->fields[i];
        out[pos++] = (uint8_t)(f->field_id & 0xFF);
        out[pos++] = (uint8_t)(f->field_id >> 8);
        out[pos++] = (uint8_t)(f->offset & 0xFF);
        out[pos++] = (uint8_t)(f->offset >> 8);
        out[pos++] = (uint8_t)(f->width & 0xFF);
        out[pos++] = (uint8_t)(f->width >> 8);
        out[pos++] = (uint8_t)(f->source & 0xFF);
        out[pos++] = (uint8_t)(f->source >> 8);
    }
    return (int)pos;
}

/* ------------------------------------------------------------------ */
/* export_stats                                                         */
/* ------------------------------------------------------------------ */

/*
 * Aggregate counts across all export profiles in ctx.
 *   total_profiles — set to ctx->export_count
 *   total_fields   — set to the sum of field_count across all profiles
 */
void export_stats(mdn_ctx_t *ctx, uint32_t *total_profiles, uint32_t *total_fields)
{
    if (!ctx) {
        if (total_profiles) *total_profiles = 0;
        if (total_fields)   *total_fields   = 0;
        return;
    }

    uint32_t fields = 0;
    for (uint32_t i = 0; i < ctx->export_count; i++)
        fields += ctx->exports[i].field_count;

    if (total_profiles) *total_profiles = ctx->export_count;
    if (total_fields)   *total_fields   = fields;
}

/* ------------------------------------------------------------------ */
/* export_clone_profile                                                 */
/* ------------------------------------------------------------------ */

/*
 * Deep-copy the profile identified by src_id into a new slot identified
 * by dst_id.  Fields array and frame buffer are independently allocated
 * so each profile owns its own memory.
 * Returns 0 on success, -1 on error.
 */
int export_clone_profile(mdn_ctx_t *ctx, uint16_t src_id, uint16_t dst_id)
{
    if (!ctx)
        return -1;

    mdn_export_profile_t *src = export_find(ctx, src_id);
    if (!src)
        return -1;

    /* Grow the exports array */
    mdn_export_profile_t *arr = realloc(ctx->exports,
        (ctx->export_count + 1) * sizeof(mdn_export_profile_t));
    if (!arr)
        return -1;
    ctx->exports = arr;

    /* Re-derive src after potential realloc move */
    src = export_find(ctx, src_id);
    if (!src)
        return -1;

    mdn_export_profile_t *dst = &ctx->exports[ctx->export_count];
    memset(dst, 0, sizeof(*dst));

    dst->profile_id  = dst_id;
    dst->mode        = src->mode;
    dst->field_count = src->field_count;
    dst->frame_cap   = src->frame_cap;

    if (src->field_count > 0 && src->fields) {
        size_t fsz = (uint32_t)src->field_count * sizeof(mdn_export_field_t);
        dst->fields = malloc(fsz);
        if (!dst->fields)
            return -1;
        memcpy(dst->fields, src->fields, fsz);
    }

    if (src->frame_cap > 0 && src->frame) {
        dst->frame = malloc(src->frame_cap);
        if (!dst->frame) {
            free(dst->fields);
            return -1;
        }
        memcpy(dst->frame, src->frame, src->frame_cap);
    }

    ctx->export_count++;
    return 0;
}

/* ------------------------------------------------------------------ */
/* export_frame_checksum                                                */
/* ------------------------------------------------------------------ */

/*
 * Compute a 32-bit additive checksum over all bytes in prof->frame.
 * The result is stored in *csum_out.
 * Returns 0 on success, -1 when the profile or frame is not available.
 */
int export_frame_checksum(mdn_export_profile_t *prof, uint32_t *csum_out)
{
    if (!prof || !prof->frame || !csum_out)
        return -1;

    uint32_t acc = 0;
    for (uint16_t i = 0; i < prof->frame_cap; i++)
        acc += (uint32_t)prof->frame[i];

    *csum_out = acc;
    return 0;
}
