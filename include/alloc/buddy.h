#pragma once

#ifdef __BPF__
#include <scx/bpf_arena_common.bpf.h>
#include <scx/bpf_arena_spin_lock.h>
#else  /* __BPF__ */
#include <scx/bpf_arena_common.h>
#endif /* __BPF__ */

#include <alloc/stack.h>

/* Buddy allocator-related structs. */

struct scx_buddy_chunk;
typedef struct scx_buddy_chunk __arena scx_buddy_chunk_t;

struct scx_buddy_header;
typedef struct scx_buddy_header __arena scx_buddy_header_t;

enum scx_buddy_consts {
	SCX_BUDDY_MIN_ALLOC_SHIFT	= 4,
	SCX_BUDDY_MIN_ALLOC_BYTES	= 1 << SCX_BUDDY_MIN_ALLOC_SHIFT,
	SCX_BUDDY_CHUNK_MAX_ORDER	= 15,	/* Maximum _valid_ allocation order */
	SCX_BUDDY_CHUNK_PAGES		= (SCX_BUDDY_MIN_ALLOC_BYTES << SCX_BUDDY_CHUNK_MAX_ORDER) / PAGE_SIZE,
	SCX_BUDDY_CHUNK_ITEMS		= SCX_BUDDY_CHUNK_PAGES * PAGE_SIZE / SCX_BUDDY_MIN_ALLOC_BYTES,
	SCX_BUDDY_CHUNK_OFFSET_MASK	= (SCX_BUDDY_CHUNK_PAGES * PAGE_SIZE) - 1,
};

struct scx_buddy_header {
	u32 prev_index;	/* "Pointer" to the previous available allocation of the same size. */
	u32 next_index; /* Same for the next allocation. */
};

/*
 * We bring memory into the allocator 1MiB at a time.
 */
struct scx_buddy_chunk {
	/* The order of the current allocation for a item. 4 bits per order. */
	u8			orders[SCX_BUDDY_CHUNK_ITEMS / 2];
	u64			order_indices[SCX_BUDDY_CHUNK_MAX_ORDER];
	scx_buddy_chunk_t	*prev;
	scx_buddy_chunk_t	*next;
};

struct scx_buddy {
	scx_buddy_chunk_t *first_chunk;		/* Pointer to the chunk linked list. */
	size_t min_alloc_bytes;			/* Minimum allocation in bytes */
	arena_spinlock_t __arena *lock;		/* Allocator lock */

	/* XXXETSAL: Track used pages, used to drain the underlying page stack. */
};

#ifdef __BPF__

int scx_buddy_init(struct scx_buddy *buddy, size_t size, arena_spinlock_t __arena *lock);
int scx_buddy_destroy(struct scx_buddy *buddy, size_t size);
int scx_buddy_free_internal(struct scx_buddy *buddy, u64 free);
#define scx_buddy_free(buddy, ptr) do { scx_buddy_free_internal((buddy), (u64)(ptr)); } while (0)
u64 scx_buddy_alloc_internal(struct scx_buddy *buddy, size_t size);
#define scx_buddy_alloc(alloc, size) ((void __arena *)scx_buddy_alloc_internal((alloc), (size)))
int scx_buddy_destroy(struct scx_buddy *buddy, size_t size);


#endif /* __BPF__  */
