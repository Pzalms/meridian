#include "meridian.h"
#include "mdn_internal.h"
#include "parse.h"
#include "validate.h"
#include "query.h"
#include "zone.h"
#include "nat.h"
#include "session.h"
#include "template.h"
#include "audit.h"
#include "export.h"
#include "prefix.h"
#include <stdlib.h>

mdn_ctx_t *mdn_load(const uint8_t *buf, size_t len) {
    if (!buf || len == 0) return NULL;
    mdn_ctx_t *ctx = calloc(1, sizeof(mdn_ctx_t));
    if (!ctx) return NULL;
    if (mdn_parse(ctx, buf, len) != 0) { mdn_free(ctx); return NULL; }
    if (mdn_validate(ctx) != 0)        { mdn_free(ctx); return NULL; }
    return ctx;
}

int mdn_run(mdn_ctx_t *ctx) {
    if (!ctx) return -1;
    return query_run_all(ctx);
}

void mdn_free(mdn_ctx_t *ctx) {
    if (!ctx) return;
    zone_free_all(ctx);
    free(ctx->rules);
    for (int i = 0; i < MDN_MAX_PREFIX_PAGES; i++)
        prefix_page_free(ctx->prefix_pages[i]);
    nat_free_all(ctx);
    session_cursors_free(ctx);
    template_free_all(ctx);
    audit_free_all(ctx);
    export_free_all(ctx);
    free(ctx);
}

int mdn_fuzz(const uint8_t *data, size_t len) {
    mdn_ctx_t *ctx = mdn_load(data, len);
    if (!ctx) return 0;
    (void)mdn_run(ctx);
    mdn_free(ctx);
    return 0;
}
