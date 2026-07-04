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

/* ------------------------------------------------------------------ */
/* vec_clear                                                            */
/* Resets the element count to zero without freeing the backing        */
/* buffer. Subsequent pushes will reuse the allocated memory.          */
/* ------------------------------------------------------------------ */
void vec_clear(vec_t *v)
{
    if (!v) return;
    v->len = 0;
}

/* ------------------------------------------------------------------ */
/* vec_contains                                                         */
/* Scans the vec for an item matching the given byte pattern.          */
/* item_size specifies the stride (bytes per logical element).         */
/* Returns 1 if a byte-identical match is found, 0 otherwise.         */
/* ------------------------------------------------------------------ */
int vec_contains(vec_t *v, const void *item, size_t item_size)
{
    if (!v || !item || !item_size) return 0;
    size_t count = v->len / item_size;
    for (size_t i = 0; i < count; i++) {
        if (memcmp(v->data + i * item_size, item, item_size) == 0)
            return 1;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* vec_reverse                                                          */
/* Reverses the logical sequence of elements in-place.                 */
/* item_size must match the stride used when the data was written.     */
/* ------------------------------------------------------------------ */
void vec_reverse(vec_t *v, size_t item_size)
{
    if (!v || !item_size || v->len < item_size * 2) return;
    size_t count = v->len / item_size;
    uint8_t tmp[256];
    size_t lo = 0, hi = count - 1;
    /* cap swap buffer to max item_size we support in-stack */
    size_t swap_size = item_size <= sizeof(tmp) ? item_size : 0;
    if (!swap_size) return;

    while (lo < hi) {
        memcpy(tmp,                      v->data + lo * item_size, swap_size);
        memcpy(v->data + lo * item_size, v->data + hi * item_size, swap_size);
        memcpy(v->data + hi * item_size, tmp,                      swap_size);
        lo++;
        hi--;
    }
}

/* ------------------------------------------------------------------ */
/* vec_remove_at                                                        */
/* Removes the element at position idx by shifting subsequent          */
/* elements down by one position. item_size is the element stride.     */
/* Returns 0 on success, -1 if idx is out of range.                   */
/* ------------------------------------------------------------------ */
int vec_remove_at(vec_t *v, size_t idx, size_t item_size)
{
    if (!v || !item_size) return -1;
    size_t count = v->len / item_size;
    if (idx >= count) return -1;

    size_t tail = (count - idx - 1) * item_size;
    if (tail > 0)
        memmove(v->data + idx * item_size,
                v->data + (idx + 1) * item_size,
                tail);
    v->len -= item_size;
    return 0;
}

/* ------------------------------------------------------------------ */
/* vec_copy                                                             */
/* Deep-copies the byte contents of src into dst.                      */
/* dst is grown via realloc if its capacity is insufficient.           */
/* Returns 0 on success, -1 on allocation failure.                     */
/* ------------------------------------------------------------------ */
int vec_copy(vec_t *dst, vec_t *src, size_t item_size)
{
    if (!dst || !src || !item_size) return -1;
    if (src->len == 0) {
        dst->len = 0;
        return 0;
    }
    if (src->len > dst->cap) {
        uint8_t *p = realloc(dst->data, src->len);
        if (!p) return -1;
        dst->data = p;
        dst->cap  = src->len;
    }
    memcpy(dst->data, src->data, src->len);
    dst->len = src->len;
    (void)item_size; /* stride is implicit in byte length */
    return 0;
}

/* ------------------------------------------------------------------ */
/* vec_last                                                             */
/* Returns a pointer to the last logical element in the vec,           */
/* or NULL if the vec is empty. item_size is the element stride.       */
/* ------------------------------------------------------------------ */
void *vec_last(vec_t *v, size_t item_size)
{
    if (!v || !item_size || v->len < item_size) return NULL;
    size_t count = v->len / item_size;
    return (void *)(v->data + (count - 1) * item_size);
}

/* ------------------------------------------------------------------ */
/* vec_at                                                               */
/* Returns a pointer to the element at position idx, or NULL if idx   */
/* is out of range. item_size is the element stride.                   */
/* ------------------------------------------------------------------ */
void *vec_at(vec_t *v, size_t idx, size_t item_size)
{
    if (!v || !item_size) return NULL;
    size_t count = v->len / item_size;
    if (idx >= count) return NULL;
    return (void *)(v->data + idx * item_size);
}

/* ------------------------------------------------------------------ */
/* vec_count                                                            */
/* Returns the number of logical elements given a known item stride.   */
/* ------------------------------------------------------------------ */
size_t vec_count(vec_t *v, size_t item_size)
{
    if (!v || !item_size) return 0;
    return v->len / item_size;
}

/* ------------------------------------------------------------------ */
/* vec_ensure_cap                                                       */
/* Pre-allocates capacity for at least n bytes, avoiding repeated      */
/* realloc calls during bulk insertions. Returns 0 on success.         */
/* ------------------------------------------------------------------ */
int vec_ensure_cap(vec_t *v, size_t n)
{
    if (!v) return -1;
    if (v->cap >= n) return 0;
    return vec_grow(v, n);
}
