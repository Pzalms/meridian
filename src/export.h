#ifndef MDN_EXPORT_H
#define MDN_EXPORT_H

#include "mdn_internal.h"

int  export_profile_load(mdn_ctx_t *ctx, const uint8_t *data, uint32_t len, uint16_t id);
int  export_profile_prepare(mdn_export_profile_t *prof);
void export_transition_profile(mdn_ctx_t *ctx, uint16_t profile_id,
                                mdn_export_field_t *new_fields, uint16_t new_count);
void export_emit_fields(mdn_export_profile_t *prof, mdn_ctx_t *ctx);
void export_free_all(mdn_ctx_t *ctx);

/* Extended API */
mdn_export_profile_t *export_find(mdn_ctx_t *ctx, uint16_t profile_id);
int  export_field_encode_u32(mdn_export_profile_t *prof, uint16_t field_idx, uint32_t val);
int  export_field_decode_u32(mdn_export_profile_t *prof, uint16_t field_idx,
                              uint32_t *val_out);
int  export_profile_validate(mdn_export_profile_t *prof);
int  export_profile_serialize(mdn_export_profile_t *prof, uint8_t *out, uint32_t cap);
void export_stats(mdn_ctx_t *ctx, uint32_t *total_profiles, uint32_t *total_fields);
int  export_clone_profile(mdn_ctx_t *ctx, uint16_t src_id, uint16_t dst_id);
int  export_frame_checksum(mdn_export_profile_t *prof, uint32_t *csum_out);

#endif /* MDN_EXPORT_H */
