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

/* ================================================================== */
/* Sort (heapsort) and search                                           */
/* ================================================================== */

/* Swap two items of item_size bytes using a stack buffer (max 256). */
static void vec_swap_items(uint8_t *a, uint8_t *b, size_t item_size)
{
    uint8_t tmp[256];
    size_t  rem = item_size;
    while (rem) {
        size_t chunk = rem < sizeof(tmp) ? rem : sizeof(tmp);
        memcpy(tmp, a, chunk);
        memcpy(a,   b, chunk);
        memcpy(b, tmp, chunk);
        a += chunk; b += chunk; rem -= chunk;
    }
}

static void heapify_down(uint8_t *base, size_t n, size_t i,
                         size_t item_size, vec_cmp_fn cmp)
{
    for (;;) {
        size_t largest = i;
        size_t l = 2 * i + 1;
        size_t r = 2 * i + 2;
        if (l < n && cmp(base + l * item_size, base + largest * item_size) > 0)
            largest = l;
        if (r < n && cmp(base + r * item_size, base + largest * item_size) > 0)
            largest = r;
        if (largest == i) break;
        vec_swap_items(base + i * item_size, base + largest * item_size, item_size);
        i = largest;
    }
}

void vec_sort(vec_t *v, size_t item_size, vec_cmp_fn cmp)
{
    if (!v || !item_size || !cmp) return;
    size_t n = v->len / item_size;
    if (n < 2) return;
    uint8_t *base = v->data;

    /* Build max-heap */
    for (size_t i = n / 2; i-- > 0; )
        heapify_down(base, n, i, item_size, cmp);

    /* Extract elements */
    for (size_t end = n - 1; end > 0; end--) {
        vec_swap_items(base, base + end * item_size, item_size);
        heapify_down(base, end, 0, item_size, cmp);
    }
}

int vec_find(vec_t *v, size_t item_size, vec_pred_fn pred, void *userdata)
{
    if (!v || !item_size || !pred) return -1;
    size_t n = v->len / item_size;
    for (size_t i = 0; i < n; i++) {
        if (pred(v->data + i * item_size, userdata))
            return (int)i;
    }
    return -1;
}

int vec_binary_search(vec_t *v, size_t item_size, const void *key, vec_cmp_fn cmp)
{
    if (!v || !item_size || !key || !cmp) return -1;
    size_t n = v->len / item_size;
    size_t lo = 0, hi = n;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        int r = cmp(key, v->data + mid * item_size);
        if (r == 0) return (int)mid;
        if (r < 0)  hi  = mid;
        else        lo  = mid + 1;
    }
    return -1;
}

/* ================================================================== */
/* Functional operations                                                */
/* ================================================================== */

int vec_filter(vec_t *src, size_t item_size, vec_pred_fn pred, void *userdata, vec_t *out)
{
    if (!src || !item_size || !pred || !out) return -1;
    vec_init(out);
    size_t n = src->len / item_size;
    for (size_t i = 0; i < n; i++) {
        uint8_t *elem = src->data + i * item_size;
        if (pred(elem, userdata)) {
            if (vec_append(out, elem, item_size) != 0) {
                vec_free(out);
                return -1;
            }
        }
    }
    return 0;
}

int vec_map(vec_t *src, size_t src_item, vec_xform_fn xform, void *userdata,
            vec_t *out, size_t dst_item)
{
    if (!src || !src_item || !xform || !out || !dst_item) return -1;
    vec_init(out);
    size_t n = src->len / src_item;
    if (vec_ensure_cap(out, n * dst_item) != 0) return -1;
    for (size_t i = 0; i < n; i++) {
        /* Reserve space for one output element, then transform into it. */
        size_t pos = out->len;
        if (vec_ensure_cap(out, pos + dst_item) != 0) { vec_free(out); return -1; }
        memset(out->data + pos, 0, dst_item);
        xform(src->data + i * src_item, out->data + pos, userdata);
        out->len += dst_item;
    }
    return 0;
}

/* ================================================================== */
/* Merge and dedup                                                      */
/* ================================================================== */

int vec_merge_sorted(vec_t *a, vec_t *b, size_t item_size, vec_cmp_fn cmp, vec_t *out)
{
    if (!a || !b || !item_size || !cmp || !out) return -1;
    vec_init(out);
    size_t na = a->len / item_size;
    size_t nb = b->len / item_size;
    if (vec_ensure_cap(out, (na + nb) * item_size) != 0) return -1;

    size_t i = 0, j = 0;
    while (i < na && j < nb) {
        uint8_t *ea = a->data + i * item_size;
        uint8_t *eb = b->data + j * item_size;
        if (cmp(ea, eb) <= 0) {
            vec_append(out, ea, item_size);
            i++;
        } else {
            vec_append(out, eb, item_size);
            j++;
        }
    }
    while (i < na) { vec_append(out, a->data + i++ * item_size, item_size); }
    while (j < nb) { vec_append(out, b->data + j++ * item_size, item_size); }
    return 0;
}

int vec_dedup(vec_t *v, size_t item_size, vec_cmp_fn cmp)
{
    if (!v || !item_size || !cmp) return -1;
    size_t n = v->len / item_size;
    if (n < 2) return 0;

    size_t write = 1; /* first element is always kept */
    for (size_t read = 1; read < n; read++) {
        uint8_t *prev = v->data + (write - 1) * item_size;
        uint8_t *curr = v->data + read * item_size;
        if (cmp(prev, curr) != 0) {
            if (write != read)
                memcpy(v->data + write * item_size, curr, item_size);
            write++;
        }
    }
    v->len = write * item_size;
    return 0;
}

/* ================================================================== */
/* Capacity management                                                  */
/* ================================================================== */

int vec_reserve(vec_t *v, size_t n)
{
    if (!v) return -1;
    if (v->cap >= n) return 0;
    uint8_t *p = realloc(v->data, n);
    if (!p) return -1;
    v->data = p;
    v->cap  = n;
    return 0;
}

int vec_shrink_to_fit(vec_t *v)
{
    if (!v || !v->len) return 0;
    if (v->cap == v->len) return 0;
    uint8_t *p = realloc(v->data, v->len);
    if (!p) return -1;
    v->data = p;
    v->cap  = v->len;
    return 0;
}

/* ================================================================== */
/* Aggregate                                                            */
/* ================================================================== */

void *vec_min(vec_t *v, size_t item_size, vec_cmp_fn cmp)
{
    if (!v || !item_size || !cmp || !v->len) return NULL;
    size_t n = v->len / item_size;
    uint8_t *best = v->data;
    for (size_t i = 1; i < n; i++) {
        uint8_t *e = v->data + i * item_size;
        if (cmp(e, best) < 0) best = e;
    }
    return best;
}

void *vec_max(vec_t *v, size_t item_size, vec_cmp_fn cmp)
{
    if (!v || !item_size || !cmp || !v->len) return NULL;
    size_t n = v->len / item_size;
    uint8_t *best = v->data;
    for (size_t i = 1; i < n; i++) {
        uint8_t *e = v->data + i * item_size;
        if (cmp(e, best) > 0) best = e;
    }
    return best;
}

int vec_partition(vec_t *v, size_t item_size, vec_pred_fn pred, void *userdata,
                  vec_t *yes, vec_t *no)
{
    if (!v || !item_size || !pred || !yes || !no) return -1;
    vec_init(yes);
    vec_init(no);
    size_t n = v->len / item_size;
    for (size_t i = 0; i < n; i++) {
        uint8_t *elem = v->data + i * item_size;
        vec_t *dest = pred(elem, userdata) ? yes : no;
        if (vec_append(dest, elem, item_size) != 0) {
            vec_free(yes); vec_free(no);
            return -1;
        }
    }
    return 0;
}
