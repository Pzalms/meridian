#include "fragment.h"
#include "util.h"
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
