#include "arena.h"
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#define ARENA_ALIGN 8

struct arena {
    uint8_t *buf;
    size_t   cap;
    size_t   pos;
};

arena_t *arena_new(size_t cap)
{
    arena_t *a = malloc(sizeof(arena_t));
    if (!a)
        return NULL;
    a->buf = malloc(cap);
    if (!a->buf) {
        free(a);
        return NULL;
    }
    a->cap = cap;
    a->pos = 0;
    return a;
}

void *arena_alloc(arena_t *a, size_t sz)
{
    if (!sz)
        sz = 1;

    /* align pos up to ARENA_ALIGN */
    size_t aligned = (a->pos + (ARENA_ALIGN - 1)) & ~(size_t)(ARENA_ALIGN - 1);
    if (aligned + sz > a->cap)
        return NULL;

    void *ptr = a->buf + aligned;
    a->pos = aligned + sz;
    return ptr;
}

void arena_reset(arena_t *a)
{
    if (!a) return;
    a->pos = 0;
}

void arena_free(arena_t *a)
{
    if (!a)
        return;
    free(a->buf);
    free(a);
}

/* ------------------------------------------------------------------ */
/* arena_used                                                           */
/* Returns the number of bytes currently consumed in the arena.        */
/* ------------------------------------------------------------------ */
size_t arena_used(arena_t *a)
{
    if (!a) return 0;
    return a->pos;
}

/* ------------------------------------------------------------------ */
/* arena_remaining                                                      */
/* Returns how many bytes can still be allocated from the arena.       */
/* Note: the actual usable space may be slightly less due to internal  */
/* alignment rounding on the next allocation.                          */
/* ------------------------------------------------------------------ */
size_t arena_remaining(arena_t *a)
{
    if (!a) return 0;
    if (a->pos >= a->cap) return 0;
    return a->cap - a->pos;
}

/* ------------------------------------------------------------------ */
/* arena_contains                                                       */
/* Returns 1 if ptr falls within the arena's buffer region, 0 if not. */
/* Useful to confirm that a pointer was allocated from this arena.     */
/* ------------------------------------------------------------------ */
int arena_contains(arena_t *a, const void *ptr)
{
    if (!a || !ptr) return 0;
    const uint8_t *p = (const uint8_t *)ptr;
    return (p >= a->buf && p < a->buf + a->cap) ? 1 : 0;
}

/* ------------------------------------------------------------------ */
/* arena_alloc_aligned                                                  */
/* Allocates sz bytes with a specific alignment requirement.           */
/* align must be a power of two (e.g., 1, 2, 4, 8, 16).              */
/* Returns NULL if there is insufficient space or align is invalid.    */
/* ------------------------------------------------------------------ */
void *arena_alloc_aligned(arena_t *a, size_t size, size_t align)
{
    if (!a || !size || !align) return NULL;

    /* Verify align is a power of two */
    if ((align & (align - 1)) != 0) return NULL;

    size_t mask    = align - 1;
    size_t aligned = (a->pos + mask) & ~mask;

    if (aligned + size > a->cap)
        return NULL;

    void *ptr = a->buf + aligned;
    a->pos    = aligned + size;
    return ptr;
}

/* ------------------------------------------------------------------ */
/* arena_alloc_zero                                                     */
/* Like arena_alloc but zeroes the returned region.                    */
/* ------------------------------------------------------------------ */
void *arena_alloc_zero(arena_t *a, size_t sz)
{
    void *ptr = arena_alloc(a, sz);
    if (ptr)
        memset(ptr, 0, sz);
    return ptr;
}

/* ------------------------------------------------------------------ */
/* arena_capacity                                                       */
/* Returns the total capacity of the arena buffer.                     */
/* ------------------------------------------------------------------ */
size_t arena_capacity(arena_t *a)
{
    if (!a) return 0;
    return a->cap;
}

/* ------------------------------------------------------------------ */
/* arena_resize                                                         */
/* Attempts to extend the arena's backing buffer to new_cap bytes.    */
/* The existing contents are preserved. Returns 0 on success, -1 if   */
/* new_cap is smaller than the current position or realloc fails.      */
/* ------------------------------------------------------------------ */
int arena_resize(arena_t *a, size_t new_cap)
{
    if (!a) return -1;
    if (new_cap < a->pos) return -1;

    uint8_t *nb = realloc(a->buf, new_cap);
    if (!nb) return -1;

    a->buf = nb;
    a->cap = new_cap;
    return 0;
}

/* ------------------------------------------------------------------ */
/* arena_copy                                                           */
/* Allocates sz bytes in a and copies the contents of src into them.  */
/* Returns a pointer to the copied region, or NULL on failure.         */
/* ------------------------------------------------------------------ */
void *arena_copy(arena_t *a, const void *src, size_t sz)
{
    if (!src || !sz) return NULL;
    void *dst = arena_alloc(a, sz);
    if (!dst) return NULL;
    memcpy(dst, src, sz);
    return dst;
}
