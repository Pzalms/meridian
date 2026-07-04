#ifndef MDN_ARENA_H
#define MDN_ARENA_H

#include <stddef.h>

typedef struct arena arena_t;

arena_t *arena_new(size_t cap);
void    *arena_alloc(arena_t *a, size_t sz);
void    *arena_alloc_zero(arena_t *a, size_t sz);
void    *arena_alloc_aligned(arena_t *a, size_t size, size_t align);
void    *arena_copy(arena_t *a, const void *src, size_t sz);
void     arena_reset(arena_t *a);
void     arena_free(arena_t *a);
size_t   arena_used(arena_t *a);
size_t   arena_remaining(arena_t *a);
size_t   arena_capacity(arena_t *a);
int      arena_contains(arena_t *a, const void *ptr);
int      arena_resize(arena_t *a, size_t new_cap);

#endif /* MDN_ARENA_H */
