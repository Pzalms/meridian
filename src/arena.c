#include "arena.h"
#include <stdlib.h>
#include <stdint.h>

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
    a->pos = 0;
}

void arena_free(arena_t *a)
{
    if (!a)
        return;
    free(a->buf);
    free(a);
}
