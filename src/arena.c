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

/* ================================================================== */
/* Slab allocator                                                       */
/* ================================================================== */

#include <stdio.h>

/* Default size classes: 8, 16, 32, 64, 128, 256, 512, 1024 bytes */
static const size_t SLAB_CLASS_SIZES[ARENA_SLAB_CLASSES] = {
    8, 16, 32, 64, 128, 256, 512, 1024
};

static int slab_class_for(size_t sz)
{
    for (int c = 0; c < ARENA_SLAB_CLASSES; c++) {
        if (sz <= SLAB_CLASS_SIZES[c])
            return c;
    }
    return -1;
}

arena_slab_pool_t *slab_pool_create(void)
{
    arena_slab_pool_t *sp = calloc(1, sizeof(arena_slab_pool_t));
    if (!sp) return NULL;
    for (int c = 0; c < ARENA_SLAB_CLASSES; c++)
        sp->class_sizes[c] = SLAB_CLASS_SIZES[c];
    return sp;
}

static arena_slab_t *slab_new(size_t obj_size)
{
    arena_slab_t *s = calloc(1, sizeof(arena_slab_t));
    if (!s) return NULL;
    s->pool = malloc(obj_size * ARENA_SLAB_OBJS);
    if (!s->pool) { free(s); return NULL; }
    s->obj_size   = obj_size;
    s->free_bitmap = (ARENA_SLAB_OBJS < 64)
                     ? ((uint64_t)1 << ARENA_SLAB_OBJS) - 1u
                     : ~(uint64_t)0;
    s->free_count = ARENA_SLAB_OBJS;
    s->next = NULL;
    return s;
}

/* Find the lowest set bit (index of a free slot). */
static int slab_lowest_set(uint64_t bitmap)
{
    if (!bitmap) return -1;
    int idx = 0;
    uint64_t b = bitmap;
    if (!(b & 0xFFFFFFFFu)) { idx += 32; b >>= 32; }
    if (!(b & 0x0000FFFFu)) { idx += 16; b >>= 16; }
    if (!(b & 0x000000FFu)) { idx +=  8; b >>=  8; }
    if (!(b & 0x0000000Fu)) { idx +=  4; b >>=  4; }
    if (!(b & 0x00000003u)) { idx +=  2; b >>=  2; }
    if (!(b & 0x00000001u)) { idx +=  1; }
    return idx;
}

void *slab_alloc(arena_slab_pool_t *sp, size_t sz)
{
    if (!sp || !sz) return NULL;
    int cls = slab_class_for(sz);
    if (cls < 0) return NULL;

    size_t obj_size = sp->class_sizes[cls];

    /* Walk the chain looking for a slab with free slots. */
    arena_slab_t *s = sp->heads[cls];
    while (s && s->free_count == 0)
        s = s->next;

    /* No free slab — allocate a new one and prepend it. */
    if (!s) {
        s = slab_new(obj_size);
        if (!s) return NULL;
        s->next        = sp->heads[cls];
        sp->heads[cls] = s;
    }

    int slot = slab_lowest_set(s->free_bitmap);
    if (slot < 0) return NULL;

    s->free_bitmap &= ~((uint64_t)1 << slot);
    s->free_count--;
    sp->total_allocs++;

    return s->pool + (size_t)slot * obj_size;
}

int slab_free(arena_slab_pool_t *sp, void *ptr, size_t sz)
{
    if (!sp || !ptr || !sz) return -1;
    int cls = slab_class_for(sz);
    if (cls < 0) return -1;

    size_t obj_size = sp->class_sizes[cls];

    for (arena_slab_t *s = sp->heads[cls]; s; s = s->next) {
        uint8_t *pool_end = s->pool + obj_size * ARENA_SLAB_OBJS;
        if ((uint8_t *)ptr >= s->pool && (uint8_t *)ptr < pool_end) {
            size_t offset = (size_t)((uint8_t *)ptr - s->pool);
            if (offset % obj_size != 0) return -1; /* misaligned */
            int slot = (int)(offset / obj_size);
            s->free_bitmap |= (uint64_t)1 << slot;
            s->free_count++;
            sp->total_frees++;
            memset(ptr, 0, obj_size);
            return 0;
        }
    }
    return -1; /* ptr not found in any slab for this class */
}

uint32_t slab_pool_live_count(const arena_slab_pool_t *sp)
{
    if (!sp) return 0;
    return sp->total_allocs - sp->total_frees;
}

void slab_pool_destroy(arena_slab_pool_t *sp)
{
    if (!sp) return;
    for (int c = 0; c < ARENA_SLAB_CLASSES; c++) {
        arena_slab_t *s = sp->heads[c];
        while (s) {
            arena_slab_t *nxt = s->next;
            free(s->pool);
            free(s);
            s = nxt;
        }
    }
    free(sp);
}

/* ================================================================== */
/* Buddy allocator                                                      */
/* ================================================================== */

/* Round up sz to the nearest power of two >= BUDDY_MIN_BLOCK. */
static size_t buddy_round_up(size_t sz)
{
    if (sz < BUDDY_MIN_BLOCK) sz = BUDDY_MIN_BLOCK;
    size_t p = 1;
    while (p < sz) p <<= 1;
    return p;
}

static int buddy_order(size_t sz)
{
    int ord = 0;
    size_t b = BUDDY_MIN_BLOCK;
    while (b < sz) { b <<= 1; ord++; }
    return ord;
}

arena_buddy_t *buddy_create(size_t total_bytes)
{
    if (!total_bytes) return NULL;
    /* Round total up to a power of two. */
    size_t rounded = buddy_round_up(total_bytes);

    arena_buddy_t *b = calloc(1, sizeof(arena_buddy_t));
    if (!b) return NULL;

    b->base = malloc(rounded);
    if (!b->base) { free(b); return NULL; }
    b->total = rounded;

    /* Place an initial free block covering the whole region.
     * The block header lives in the buffer itself. */
    buddy_block_t *blk = (buddy_block_t *)b->base;
    blk->size = rounded;
    blk->free = 1;
    blk->prev = NULL;
    blk->next = NULL;

    int ord = buddy_order(rounded);
    if (ord > BUDDY_MAX_ORDER) ord = BUDDY_MAX_ORDER;
    b->free_lists[ord] = blk;

    return b;
}

static void buddy_list_remove(arena_buddy_t *b, buddy_block_t *blk)
{
    int ord = buddy_order(blk->size);
    if (ord > BUDDY_MAX_ORDER) ord = BUDDY_MAX_ORDER;
    if (blk->prev) blk->prev->next = blk->next;
    else           b->free_lists[ord] = blk->next;
    if (blk->next) blk->next->prev = blk->prev;
    blk->prev = blk->next = NULL;
}

static void buddy_list_push(arena_buddy_t *b, buddy_block_t *blk)
{
    int ord = buddy_order(blk->size);
    if (ord > BUDDY_MAX_ORDER) ord = BUDDY_MAX_ORDER;
    blk->next = b->free_lists[ord];
    blk->prev = NULL;
    if (b->free_lists[ord]) b->free_lists[ord]->prev = blk;
    b->free_lists[ord] = blk;
}

void *buddy_alloc(arena_buddy_t *b, size_t sz)
{
    if (!b || !sz) return NULL;
    size_t need = buddy_round_up(sz + sizeof(buddy_block_t));
    int ord = buddy_order(need);
    if (ord > BUDDY_MAX_ORDER) return NULL;

    /* Search upward for a free block of sufficient order. */
    int found = -1;
    for (int o = ord; o <= BUDDY_MAX_ORDER; o++) {
        if (b->free_lists[o]) { found = o; break; }
    }
    if (found < 0) return NULL;

    buddy_block_t *blk = b->free_lists[found];
    buddy_list_remove(b, blk);

    /* Split down to the required order. */
    while (buddy_order(blk->size) > ord) {
        size_t half = blk->size / 2;
        buddy_block_t *buddy_blk = (buddy_block_t *)((uint8_t *)blk + half);
        buddy_blk->size = half;
        buddy_blk->free = 1;
        buddy_blk->prev = NULL;
        buddy_blk->next = NULL;
        buddy_list_push(b, buddy_blk);
        blk->size = half;
    }

    blk->free = 0;
    b->alloc_count++;
    return (void *)((uint8_t *)blk + sizeof(buddy_block_t));
}

void buddy_free(arena_buddy_t *b, void *ptr)
{
    if (!b || !ptr) return;
    buddy_block_t *blk = (buddy_block_t *)((uint8_t *)ptr - sizeof(buddy_block_t));
    blk->free = 1;

    /* Attempt to merge with buddy. */
    int merged = 1;
    while (merged && buddy_order(blk->size) < BUDDY_MAX_ORDER) {
        merged = 0;
        size_t offset = (size_t)((uint8_t *)blk - b->base);
        size_t buddy_off = offset ^ blk->size;
        if (buddy_off + blk->size > b->total) break;

        buddy_block_t *buddy_blk = (buddy_block_t *)(b->base + buddy_off);
        if (!buddy_blk->free || buddy_blk->size != blk->size) break;

        /* Merge: the lower-address block absorbs the higher. */
        buddy_list_remove(b, buddy_blk);
        if ((uint8_t *)buddy_blk < (uint8_t *)blk)
            blk = buddy_blk;
        blk->size *= 2;
        b->merge_count++;
        merged = 1;
    }

    buddy_list_push(b, blk);
}

size_t buddy_free_bytes(const arena_buddy_t *b)
{
    if (!b) return 0;
    size_t total_free = 0;
    for (int o = 0; o <= BUDDY_MAX_ORDER; o++) {
        const buddy_block_t *blk = b->free_lists[o];
        while (blk) {
            total_free += blk->size;
            blk = blk->next;
        }
    }
    return total_free;
}

void buddy_destroy(arena_buddy_t *b)
{
    if (!b) return;
    free(b->base);
    free(b);
}

/* ================================================================== */
/* Arena GC helpers                                                     */
/* ================================================================== */

arena_gc_t *arena_gc_create(arena_t *a)
{
    if (!a) return NULL;
    arena_gc_t *gc = calloc(1, sizeof(arena_gc_t));
    if (!gc) return NULL;

    /* One mark bit per ARENA_ALIGN-aligned slot in the arena. */
    size_t slots = (arena_capacity(a) + ARENA_ALIGN - 1) / ARENA_ALIGN;
    size_t mark_bytes = (slots + 7) / 8;
    gc->mark_bits = calloc(1, mark_bytes);
    if (!gc->mark_bits) { free(gc); return NULL; }
    return gc;
}

void arena_gc_destroy(arena_gc_t *gc)
{
    if (!gc) return;
    free(gc->mark_bits);
    free(gc);
}

void arena_gc_add_root(arena_gc_t *gc, void **root)
{
    if (!gc || !root) return;
    if (gc->root_count >= ARENA_GC_MAX_ROOTS) return;
    gc->roots[gc->root_count++] = root;
}

void arena_gc_mark(arena_gc_t *gc, arena_t *a)
{
    if (!gc || !a) return;
    gc->mark_count = 0;

    /* For each root, if the pointer falls within the arena, mark it. */
    for (uint32_t i = 0; i < gc->root_count; i++) {
        void *ptr = *(gc->roots[i]);
        if (!arena_contains(a, ptr)) continue;
        gc->mark_count++;
    }
}

uint32_t arena_gc_sweep(arena_gc_t *gc, arena_t *a)
{
    /* Sweep: zero all mark bits and report how many were set. */
    if (!gc || !a) return 0;
    uint32_t swept = gc->mark_count;
    size_t slots = (arena_capacity(a) + ARENA_ALIGN - 1) / ARENA_ALIGN;
    size_t mark_bytes = (slots + 7) / 8;
    memset(gc->mark_bits, 0, mark_bytes);
    gc->mark_count = 0;
    return swept;
}

/* ================================================================== */
/* Arena allocation statistics                                          */
/* ================================================================== */

/* Internal tracking: we keep a small static table keyed by arena pointer. */
#define ARENA_STAT_SLOTS 32

static struct {
    arena_t *a;
    size_t   peak;
    uint32_t alloc_calls;
    uint32_t reset_calls;
} g_arena_stat[ARENA_STAT_SLOTS];

static int arena_stat_slot(arena_t *a)
{
    for (int i = 0; i < ARENA_STAT_SLOTS; i++)
        if (g_arena_stat[i].a == a) return i;
    return -1;
}

static int arena_stat_slot_alloc(arena_t *a)
{
    int slot = arena_stat_slot(a);
    if (slot >= 0) return slot;
    for (int i = 0; i < ARENA_STAT_SLOTS; i++) {
        if (!g_arena_stat[i].a) {
            g_arena_stat[i].a = a;
            return i;
        }
    }
    return -1;
}

void arena_stats_collect(arena_t *a, arena_stats_t *out)
{
    if (!a || !out) return;
    memset(out, 0, sizeof(*out));
    out->capacity = arena_capacity(a);
    out->used     = arena_used(a);

    int slot = arena_stat_slot(a);
    if (slot >= 0) {
        if (out->used > g_arena_stat[slot].peak)
            g_arena_stat[slot].peak = out->used;
        out->peak        = g_arena_stat[slot].peak;
        out->alloc_calls = g_arena_stat[slot].alloc_calls;
        out->reset_calls = g_arena_stat[slot].reset_calls;
    } else {
        out->peak = out->used;
    }
}

void arena_dump_blocks(arena_t *a, char *buf, size_t buf_cap)
{
    if (!a || !buf || !buf_cap) return;
    size_t used  = arena_used(a);
    size_t cap   = arena_capacity(a);
    size_t rem   = arena_remaining(a);

    int n = snprintf(buf, buf_cap,
        "arena: cap=%zu used=%zu remaining=%zu fill_pct=%u%%\n",
        cap, used, rem,
        cap ? (unsigned)(used * 100 / cap) : 0u);
    if (n <= 0 || (size_t)n >= buf_cap) return;
    buf     += n;
    buf_cap -= (size_t)n;

    /* Print a simple ASCII fill bar (40 chars wide). */
    if (buf_cap < 50) return;
    size_t fill = cap ? (used * 40 / cap) : 0;
    *buf++ = '['; buf_cap--;
    for (size_t i = 0; i < 40 && buf_cap > 1; i++, buf_cap--) {
        *buf++ = (i < fill) ? '#' : '.';
    }
    if (buf_cap > 3) {
        *buf++ = ']'; *buf++ = '\n'; *buf = '\0';
    }

    /* Register stat slot so future calls record peak. */
    int slot = arena_stat_slot_alloc(a);
    if (slot >= 0 && used > g_arena_stat[slot].peak)
        g_arena_stat[slot].peak = used;
}
