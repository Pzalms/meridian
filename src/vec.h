#ifndef MDN_VEC_H
#define MDN_VEC_H

#include <stdint.h>
#include <stddef.h>

typedef struct {
    uint8_t *data;
    size_t   len;
    size_t   cap;
} vec_t;

void   vec_init(vec_t *v);
int    vec_push(vec_t *v, uint8_t byte);
int    vec_append(vec_t *v, const uint8_t *buf, size_t n);
void   vec_free(vec_t *v);
void   vec_clear(vec_t *v);
int    vec_contains(vec_t *v, const void *item, size_t item_size);
void   vec_reverse(vec_t *v, size_t item_size);
int    vec_remove_at(vec_t *v, size_t idx, size_t item_size);
int    vec_copy(vec_t *dst, vec_t *src, size_t item_size);
void  *vec_last(vec_t *v, size_t item_size);
void  *vec_at(vec_t *v, size_t idx, size_t item_size);
size_t vec_count(vec_t *v, size_t item_size);
int    vec_ensure_cap(vec_t *v, size_t n);

#endif /* MDN_VEC_H */
