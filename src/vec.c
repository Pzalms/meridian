#include "vec.h"
#include <stdlib.h>
#include <string.h>

#define VEC_INIT_CAP 64

void vec_init(vec_t *v)
{
    v->data = NULL;
    v->len  = 0;
    v->cap  = 0;
}

static int vec_grow(vec_t *v, size_t need)
{
    size_t new_cap = v->cap ? v->cap : VEC_INIT_CAP;
    while (new_cap < need)
        new_cap *= 2;

    uint8_t *p = realloc(v->data, new_cap);
    if (!p)
        return -1;
    v->data = p;
    v->cap  = new_cap;
    return 0;
}

int vec_push(vec_t *v, uint8_t byte)
{
    if (v->len == v->cap) {
        if (vec_grow(v, v->len + 1) != 0)
            return -1;
    }
    v->data[v->len++] = byte;
    return 0;
}

int vec_append(vec_t *v, const uint8_t *buf, size_t n)
{
    if (!n)
        return 0;
    if (v->len + n > v->cap) {
        if (vec_grow(v, v->len + n) != 0)
            return -1;
    }
    memcpy(v->data + v->len, buf, n);
    v->len += n;
    return 0;
}

void vec_free(vec_t *v)
{
    free(v->data);
    v->data = NULL;
    v->len  = 0;
    v->cap  = 0;
}
