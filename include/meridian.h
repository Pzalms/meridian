#ifndef MERIDIAN_H
#define MERIDIAN_H
#include <stdint.h>
#include <stddef.h>
typedef struct mdn_ctx mdn_ctx_t;
mdn_ctx_t *mdn_load(const uint8_t *buf, size_t len);
int        mdn_run(mdn_ctx_t *ctx);
void       mdn_free(mdn_ctx_t *ctx);
int        mdn_fuzz(const uint8_t *data, size_t len);
#endif
