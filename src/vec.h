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

/* Callback types */
typedef int  (*vec_cmp_fn)(const void *a, const void *b);
typedef int  (*vec_pred_fn)(const void *elem, void *userdata);
typedef void (*vec_xform_fn)(const void *src, void *dst, void *userdata);

/* Sort / search */
void   vec_sort(vec_t *v, size_t item_size, vec_cmp_fn cmp);
int    vec_find(vec_t *v, size_t item_size, vec_pred_fn pred, void *userdata);
int    vec_binary_search(vec_t *v, size_t item_size, const void *key, vec_cmp_fn cmp);

/* Functional operations producing a new vec */
int    vec_filter(vec_t *src, size_t item_size, vec_pred_fn pred, void *userdata, vec_t *out);
int    vec_map(vec_t *src, size_t src_item, vec_xform_fn xform, void *userdata,
               vec_t *out, size_t dst_item);

/* Merge and dedup */
int    vec_merge_sorted(vec_t *a, vec_t *b, size_t item_size, vec_cmp_fn cmp, vec_t *out);
int    vec_dedup(vec_t *v, size_t item_size, vec_cmp_fn cmp);

/* Capacity management */
int    vec_reserve(vec_t *v, size_t n);
int    vec_shrink_to_fit(vec_t *v);

/* Aggregate */
void  *vec_min(vec_t *v, size_t item_size, vec_cmp_fn cmp);
void  *vec_max(vec_t *v, size_t item_size, vec_cmp_fn cmp);
int    vec_partition(vec_t *v, size_t item_size, vec_pred_fn pred, void *userdata, vec_t *yes, vec_t *no);

#endif /* MDN_VEC_H */
