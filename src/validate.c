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

    /* 2. Every query's result rule index must be within the loaded rule set */
    if (ctx->rule_count > 0) {
        for (uint32_t i = 0; i < ctx->query_count; i++) {
            if (ctx->queries[i].result_rule_id >= ctx->rule_count)
                return -1;
        }
    }

    return 0;
}
