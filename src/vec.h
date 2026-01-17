#ifndef MDN_VEC_H
#define MDN_VEC_H

#include <stdint.h>
#include <stddef.h>

typedef struct {
    uint8_t *data;
    size_t   len;
    size_t   cap;
} vec_t;

void vec_init(vec_t *v);
int  vec_push(vec_t *v, uint8_t byte);
int  vec_append(vec_t *v, const uint8_t *buf, size_t n);
void vec_free(vec_t *v);

#endif /* MDN_VEC_H */
