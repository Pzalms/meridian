#ifndef MDN_EXPORT_H
#define MDN_EXPORT_H

#include "mdn_internal.h"

int  export_profile_load(mdn_ctx_t *ctx, const uint8_t *data, uint32_t len, uint16_t id);
int  export_profile_prepare(mdn_export_profile_t *prof);
void export_transition_profile(mdn_ctx_t *ctx, uint16_t profile_id,
                                mdn_export_field_t *new_fields, uint16_t new_count);
void export_emit_fields(mdn_export_profile_t *prof, mdn_ctx_t *ctx);
void export_free_all(mdn_ctx_t *ctx);

#endif /* MDN_EXPORT_H */
