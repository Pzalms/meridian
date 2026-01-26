#include "validate.h"

/*
 * mdn_validate — post-load integrity checks on a fully parsed context.
 *
 * Returns 0 if all checks pass, -1 on the first failed check.
 */
int mdn_validate(mdn_ctx_t *ctx)
{
    /* 1. Rule count must not exceed the compile-time limit */
    if (ctx->rule_count > MDN_MAX_RULES)
        return -1;

    /* 2. Every query's start rule index must be within the loaded rule set */
    if (ctx->rule_count > 0) {
        for (uint32_t i = 0; i < ctx->query_count; i++) {
            if (ctx->queries[i].start_rule >= ctx->rule_count)
                return -1;
        }
    }

    /* 3. Validate zone parent_id references — parent must be 0 or a loaded zone */
    for (uint32_t i = 0; i < MDN_MAX_ZONES; i++) {
        if (!ctx->zones[i]) continue;
        uint16_t pid = ctx->zones[i]->parent_id;
        if (pid == 0) continue; /* root zone; no parent required */
        /* parent must itself be present in the table */
        if (pid >= MDN_MAX_ZONES || !ctx->zones[pid % MDN_MAX_ZONES])
            return -1;
    }

    return 0;
}
