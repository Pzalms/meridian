#ifndef MDN_ARENA_H
#define MDN_ARENA_H

#include <stddef.h>

typedef struct arena arena_t;

arena_t *arena_new(size_t cap);
void    *arena_alloc(arena_t *a, size_t sz);
void     arena_reset(arena_t *a);
void     arena_free(arena_t *a);

#endif /* MDN_ARENA_H */
