#ifndef MDN_ARENA_H
#define MDN_ARENA_H

#include <stddef.h>
#include <stdint.h>

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

/* ------------------------------------------------------------------ */
/* Slab allocator — fixed-size object pool per size class              */
/* ------------------------------------------------------------------ */
#define ARENA_SLAB_CLASSES 8
#define ARENA_SLAB_OBJS    64

typedef struct arena_slab arena_slab_t;
struct arena_slab {
    uint8_t       *pool;          /* backing storage for ARENA_SLAB_OBJS objects */
    size_t         obj_size;      /* bytes per object in this slab               */
    uint64_t       free_bitmap;   /* bit i = 1 means slot i is free              */
    uint32_t       free_count;
    arena_slab_t  *next;          /* linked list of slabs for same size class    */
};

typedef struct {
    arena_slab_t *heads[ARENA_SLAB_CLASSES]; /* one chain per size class */
    size_t        class_sizes[ARENA_SLAB_CLASSES];
    uint32_t      total_allocs;
    uint32_t      total_frees;
} arena_slab_pool_t;

arena_slab_pool_t *slab_pool_create(void);
void               slab_pool_destroy(arena_slab_pool_t *sp);
void              *slab_alloc(arena_slab_pool_t *sp, size_t sz);
int                slab_free(arena_slab_pool_t *sp, void *ptr, size_t sz);
uint32_t           slab_pool_live_count(const arena_slab_pool_t *sp);

/* ------------------------------------------------------------------ */
/* Buddy allocator — power-of-2 block split/merge                      */
/* ------------------------------------------------------------------ */
#define BUDDY_MAX_ORDER   12
#define BUDDY_MIN_BLOCK   16   /* bytes in a smallest block */

typedef struct buddy_block {
    size_t           size;
    int              free;
    struct buddy_block *prev;
    struct buddy_block *next;
} buddy_block_t;

typedef struct {
    uint8_t        *base;
    size_t          total;
    buddy_block_t  *free_lists[BUDDY_MAX_ORDER + 1];
    uint32_t        alloc_count;
    uint32_t        merge_count;
} arena_buddy_t;

arena_buddy_t *buddy_create(size_t total_bytes);
void           buddy_destroy(arena_buddy_t *b);
void          *buddy_alloc(arena_buddy_t *b, size_t sz);
void           buddy_free(arena_buddy_t *b, void *ptr);
size_t         buddy_free_bytes(const arena_buddy_t *b);

/* ------------------------------------------------------------------ */
/* Arena GC helpers                                                     */
/* ------------------------------------------------------------------ */
#define ARENA_GC_MAX_ROOTS 256

typedef struct {
    void    **roots[ARENA_GC_MAX_ROOTS];
    uint32_t  root_count;
    uint8_t  *mark_bits;   /* one bit per ARENA_ALIGN-aligned slot */
    uint32_t  mark_count;
} arena_gc_t;

arena_gc_t *arena_gc_create(arena_t *a);
void        arena_gc_destroy(arena_gc_t *gc);
void        arena_gc_add_root(arena_gc_t *gc, void **root);
void        arena_gc_mark(arena_gc_t *gc, arena_t *a);
uint32_t    arena_gc_sweep(arena_gc_t *gc, arena_t *a);

/* ------------------------------------------------------------------ */
/* Arena allocation statistics                                          */
/* ------------------------------------------------------------------ */
typedef struct {
    size_t   capacity;
    size_t   used;
    size_t   peak;
    uint32_t alloc_calls;
    uint32_t reset_calls;
} arena_stats_t;

void arena_stats_collect(arena_t *a, arena_stats_t *out);
void arena_dump_blocks(arena_t *a, char *buf, size_t buf_cap);

#endif /* MDN_ARENA_H */
