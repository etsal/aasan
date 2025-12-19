/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2024-2025 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2024-2025 Emil Tsalapatis <etsal@meta.com>
 */

#include <scx/common.bpf.h>
#include <lib/arena_map.h>
#include <lib/sdt_task.h>
#include <alloc/common.h>

enum {
	BUDDY_POISONED 		= (s8)0xef,
};

static
u64 scx_next_pow2(__u64 n)
{
	n--;
	n |= n >> 1;
	n |= n >> 2;
	n |= n >> 4;
	n |= n >> 8;
	n |= n >> 16;
	n |= n >> 32;
	n++;

	return n;
}

static
int header_set_order(scx_buddy_chunk_t *chunk, u64 offset, u8 order)
{
	u8 prev_order;

	if (order > SCX_BUDDY_CHUNK_MAX_ORDER) {
		arena_stderr("setting invalid order\n", order);
		arena_bug_trigger(__func__, __LINE__);
		return -EINVAL;
	}

	if (offset >= SCX_BUDDY_CHUNK_ITEMS) {
		arena_stderr("setting order of invalid offset (%d, max %d)\n", offset, SCX_BUDDY_CHUNK_ITEMS);
		arena_bug_trigger(__func__, __LINE__);
		return -EINVAL;
	}

	/* 
	 * We store two order instances per byte, one per nibble.
	 * Retain the existing nibble.
	 */
	prev_order = chunk->orders[offset / 2];
	if (offset & 0x1) {
		order &= 0xf;
		order |= (prev_order & 0xf0);
	} else {
		order <<= 4;
		order |= (prev_order & 0xf);
	}

	chunk->orders[offset / 2] = order;

	return 0;
}

static
u8 header_get_order(scx_buddy_chunk_t *chunk, u64 offset)
{
	u8 result;

	_Static_assert(SCX_BUDDY_CHUNK_MAX_ORDER < 16, "order must fit in 4 bits");

	if (offset >= SCX_BUDDY_CHUNK_ITEMS) {
		arena_stderr("setting order of invalid offset\n");
		return SCX_BUDDY_CHUNK_MAX_ORDER;
	}

	result = chunk->orders[offset / 2];

	return (offset & 0x1) ? (result & 0xf) : (result >> 4);
}

static
u64 size_to_order(size_t size)
{
	u64 order;

	if (unlikely(!size)) {
		arena_stderr("size 0 has no order\n");
		return 64;
	}

	/*
	 * To find the order of the allocation we find the first power of two
	 * >= the requested size, take the log2, then adjust it for the minimum
	 * allocation size by removing the minimum shift from it. Requests
	 * smaller than the minimum allocation size are rounded up.
	 */
	order = scx_ffs(scx_next_pow2(size));
	if (order < SCX_BUDDY_MIN_ALLOC_SHIFT)
		return 0;

	return order - SCX_BUDDY_MIN_ALLOC_SHIFT;
}

static
void __arena *chunk_idx_to_mem(scx_buddy_chunk_t *chunk, size_t idx)
{
	u64 address;

	/*
	 * The data blocks start in the chunk after the metadata block.
	 * We find the actual address by indexing into the region at an
	 * SCX_BUDDY_MIN_ALLOC_BYTES granularity, the minimum allowed.
	 * The index number already accounts for the fact that the first
	 * blocks in the chunk are occupied by the metadata, so we do
	 * not need to offset it.
	 */

	address = (u64)chunk + (idx * SCX_BUDDY_MIN_ALLOC_BYTES);

	return (void __arena *)address;
}

static
scx_buddy_header_t *chunk_get_header(scx_buddy_chunk_t *chunk, size_t idx)
{
	return (scx_buddy_header_t *)chunk_idx_to_mem(chunk, idx);
}

static
scx_buddy_chunk_t *scx_buddy_chunk_get(struct scx_buddy *buddy, bool locked)
{
	scx_buddy_header_t *header, *buddy_header;
	u64 order, ord, last_order;
	scx_buddy_chunk_t *chunk;
	u32 idx, cur_idx;
	int i, power2;
	size_t left;
	int ret;

	if (locked)
		arena_spin_unlock(buddy->lock);

	chunk = bpf_arena_alloc_pages(&arena, NULL, SCX_BUDDY_CHUNK_PAGES, NUMA_NO_NODE, 0);
	if (!chunk)
		return NULL;

	if (locked && (ret = arena_spin_lock(buddy->lock)))
		return NULL;

	/* Unpoison the chunk itself. */
	asan_unpoison(chunk, sizeof(*chunk));

	/*
	 * Initialize the chunk by carving out the first page to hold the metadata struct above,
	 * then dumping the rest of the pages into the allocator.
	 */

	bpf_for (i, 0, SCX_BUDDY_CHUNK_ITEMS) {
		header = chunk_get_header(chunk, i);
		asan_unpoison(header, sizeof(*header));

		header->prev_index = SCX_BUDDY_CHUNK_ITEMS;
		header->next_index = SCX_BUDDY_CHUNK_ITEMS;
		if (header_set_order(chunk, i, SCX_BUDDY_CHUNK_MAX_ORDER))
			goto error;
	}

	_Static_assert(SCX_BUDDY_CHUNK_PAGES * PAGE_SIZE >= SCX_BUDDY_MIN_ALLOC_BYTES * SCX_BUDDY_CHUNK_ITEMS,
		"chunk must fit within the allocation");

	/*
	 * This reserves a chunk for the chunk metadata, then breaks
	 * the rest of the full allocation into the different buckets.
	 * We allocating the memory by grabbing blocks of progressively
	 * smaller sizes from the allocator, which are guaranteed to be
	 * continuous.
	 *
	 * This operation also populates the allocator.
	 */
	last_order = SCX_BUDDY_CHUNK_MAX_ORDER;
	left = sizeof(*chunk);
	cur_idx = 0;
	while(left && can_loop) {
		power2 = scx_ffs(left);
		if (unlikely(power2 >= SCX_BUDDY_CHUNK_MAX_ORDER)) {
			arena_stderr("buddy chunk metadata require allocation of order %d\n", power2);
			goto error;
		}

		/* Round up allocations that are too small. */
		if (power2 < SCX_BUDDY_MIN_ALLOC_SHIFT) {
			order = 0;
			left = 0;
		} else {
			order = power2 - SCX_BUDDY_MIN_ALLOC_SHIFT;
			left -= 1 << power2;
		}

		idx = cur_idx;
		bpf_for (ord, order, last_order) {
			/* Skip to the buddy. */
			idx += 1 << ord;

			/* Mark it as unpoisoned. */
			buddy_header = chunk_get_header(chunk, idx);
			asan_unpoison(buddy_header, sizeof(*buddy_header));

			/* Mark it free. */
			arena_stdout("setting idx %lx to ord [%d]\n", idx, ord);
			chunk->order_indices[ord] = idx;
			if (header_set_order(chunk, idx, ord))
				goto error;
		}

		/* Adjust the index. */
		cur_idx += 1 << order;
	}

	return chunk;

error:
	if (locked)
		arena_spin_unlock(buddy->lock);

	return NULL;
}

static inline int
scx_buddy_lock(struct scx_buddy *buddy)
{
	return arena_spin_lock(buddy->lock);
}

static inline void
scx_buddy_unlock(struct scx_buddy *buddy)
{
	arena_spin_unlock(buddy->lock);
}

__hidden
int scx_buddy_init(struct scx_buddy *buddy, size_t size, arena_spinlock_t __arg_arena __arena *lock)
{
	scx_buddy_chunk_t *chunk;

	/* Set a minimum allocation size. */
	if (size < SCX_BUDDY_MIN_ALLOC_BYTES)
		return -EINVAL;

	/* Check if already initialized. */
	if (buddy->min_alloc_bytes)
		return -EALREADY;

	buddy->min_alloc_bytes = size;
	buddy->lock = lock;

	_Static_assert(SCX_BUDDY_CHUNK_PAGES > 0, "chunk must use one or more pages");

	/* Chunk is already properly unpoisoned if allocated. */
	chunk = scx_buddy_chunk_get(buddy, false);

	if (chunk) {
		/* Put the chunk at the beginning of the list. */
		chunk->next = buddy->first_chunk;
		chunk->prev = NULL;
		buddy->first_chunk = chunk;
	} else {
		/* Mark as uninitialized. */
		buddy->min_alloc_bytes = 0;
		buddy->first_chunk = NULL;
	}

	return chunk ? 0 : -ENOMEM;
}

/*
 * Destroy the allocator. This does not check whether there are any allocations
 * currently in use, so any pages being accessed will start taking arena faults.
 * We do not take a lock because we are freeing arena pages, and nobody should
 * be using the allocator at that point in the execution.
 */
__weak
int scx_buddy_destroy(struct scx_buddy *buddy, size_t size)
{
	scx_buddy_chunk_t *chunk, *next;

	if (!buddy)
		return -EINVAL;

	/*
	 * Traverse all buddy chunks and free them back to the arena
	 * with the same granularity they were allocated with.
	 */
	for (chunk = buddy->first_chunk; chunk && can_loop; chunk = next) {
		next = chunk->next;

		/* Wholesale poison the entire block. */
		asan_poison(chunk, BUDDY_POISONED, SCX_BUDDY_CHUNK_PAGES * PAGE_SIZE);
		bpf_arena_free_pages(&arena, chunk, SCX_BUDDY_CHUNK_PAGES);
	}

	/* Clear all fields. */
	buddy->first_chunk = NULL;
	buddy->min_alloc_bytes = 0;

	return 0;
}

__weak
u64 scx_buddy_chunk_alloc(scx_buddy_chunk_t __arg_arena *chunk, int order_req)
{
	scx_buddy_header_t *header, *tmp_header;
	u64 address;
	u64 order = 0;
	u32 idx, tmpidx;
	u64 i;

	bpf_for(order, order_req, SCX_BUDDY_CHUNK_MAX_ORDER + 1) {
		if (chunk->order_indices[order] != SCX_BUDDY_CHUNK_ITEMS)
			break;
	}

	if (order > SCX_BUDDY_CHUNK_MAX_ORDER)
		return (u64)NULL;


	idx = chunk->order_indices[order];
	if (idx > chunk->order_indices[order]) {
		arena_stdout("impossible index %lx", idx);
	}
	header = chunk_get_header(chunk, idx);
	chunk->order_indices[order] = header->next_index;
	arena_stdout("setting order indices to %lx->%lx\n", idx, header->next_index);

	header->prev_index = SCX_BUDDY_CHUNK_ITEMS;
	header->next_index = SCX_BUDDY_CHUNK_ITEMS;
	arena_stderr("%s:%d %u %d\n", __func__, __LINE__, idx, idx);
	if (header_set_order(chunk, idx, order_req))
		return (u64)NULL;

	/* 
	 * Do not unpoison the address yet, will be done by the caller
	 * because the caller has the exact allocation size requested.
	 */
	address = (u64)chunk_idx_to_mem(chunk, idx);

	/* If we allocated from a larger-order chunk, split the buddies. */
	bpf_for(i, order_req, order) {
		/* Flip the bit for the current order. */
		idx ^= 1 << i;

		/* Add the buddy of the allocation to the free list. */
		header = chunk_get_header(chunk, idx);
		/* Unpoison the buddy header */
		asan_unpoison(header, sizeof(*header));

		if (header_set_order(chunk, idx, i))
			return (u64)NULL;

		/* Push the header to the beginning of the order_indices list. */
		tmpidx = chunk->order_indices[i];

		header->prev_index = SCX_BUDDY_CHUNK_ITEMS;
		header->next_index = tmpidx;

		if (tmpidx != SCX_BUDDY_CHUNK_ITEMS) {
			tmp_header = chunk_get_header(chunk, tmpidx);
			tmp_header->prev_index = idx;
		}

		chunk->order_indices[i] = idx;
	}

	return address;
}

__weak
u64 scx_buddy_alloc_internal(struct scx_buddy *buddy, size_t size)
{
	scx_buddy_chunk_t *chunk;
	u64 address;
	int order;

	arena_stdout("allocation request of size %ld\n", size);

	if (!buddy)
		return (u64)NULL;

	order = size_to_order(size);
	if (order > SCX_BUDDY_CHUNK_MAX_ORDER || order < 0) {
		arena_stderr("invalid order %d (sz %lu)\n", order, size);
		return (u64)NULL;
	}

	if (scx_buddy_lock(buddy))
		return (u64)NULL;

	for (chunk = buddy->first_chunk; chunk != NULL && can_loop; chunk = chunk->next) {
		address = scx_buddy_chunk_alloc(chunk, order);
		if (address)
			goto done;
	}

	/* Get a new chunk. */
	chunk = scx_buddy_chunk_get(buddy, true);
	if (!chunk)
		return (u64)NULL;

	/* Add the chunk into the allocator and retry. */
	chunk->next = buddy->first_chunk;
	chunk->prev = NULL;
	buddy->first_chunk = chunk;

	address = scx_buddy_chunk_alloc(buddy->first_chunk, order);

done:
	scx_buddy_unlock(buddy);
	if (!address)
		return address;

	/* 
	 * Unpoison exactly the amount of bytes requested. If the
	 * data is smaller than the header, we must poison any
	 * unused bytes that were part of the header.
	 */

	if (size < sizeof(scx_buddy_header_t))
		asan_poison((u8 __arena *)address, BUDDY_POISONED, sizeof(scx_buddy_header_t));
	asan_unpoison((u8 __arena *)address, size);

	return address;
}

static
int scx_buddy_free_unlocked(struct scx_buddy *buddy, u64 addr)
{
	scx_buddy_header_t *header, *buddy_header, *tmp_header;
	scx_buddy_chunk_t *chunk, *target_chunk;
	u64 idx, buddy_idx;
	u8 order;

	if (!buddy)
		return -EINVAL;

	if (addr & (SCX_BUDDY_MIN_ALLOC_BYTES - 1)) {
		arena_stderr("Freeing unaligned address %llx\n", addr);
		return 0;
	}

	/* Align to the chunk boundary. */
	target_chunk = (void __arena *)(addr & ~SCX_BUDDY_CHUNK_OFFSET_MASK);

	/* XXX Only necessary for debugging. */
	for (chunk = buddy->first_chunk; chunk != NULL && can_loop; chunk = chunk->next) {
		if (chunk == target_chunk)
			break;
	}

	if (chunk == NULL)
		return 0;

	/* Get the page idx. */
	idx = (addr & SCX_BUDDY_CHUNK_OFFSET_MASK) / SCX_BUDDY_MIN_ALLOC_BYTES;
	header = chunk_get_header(chunk, idx);

	order = header_get_order(chunk, idx);

	/* We have placed the header into the block itself, keep it unpoisoned. */
	asan_poison((u8 __arena *)addr, BUDDY_POISONED, SCX_BUDDY_MIN_ALLOC_BYTES << order);
	asan_unpoison(header, sizeof(*header));

	bpf_for(order, order, SCX_BUDDY_CHUNK_MAX_ORDER + 1) {
		buddy_idx = idx ^ (1 << order);
		buddy_header = chunk_get_header(chunk, buddy_idx);

		/* Check if the buddy is not in the free list. */
		if (chunk->order_indices[order] != buddy_idx &&
		    buddy_header->prev_index == SCX_BUDDY_CHUNK_ITEMS &&
		    buddy_header->next_index == SCX_BUDDY_CHUNK_ITEMS)
			break;

		/* Pop off the list head if necessary. */
		if (chunk->order_indices[order] == buddy_idx)
			chunk->order_indices[order] = buddy_header->next_index;

		if (buddy_header->prev_index != SCX_BUDDY_CHUNK_ITEMS) {
			tmp_header = chunk_get_header(chunk, buddy_header->prev_index);
			tmp_header->next_index = buddy_header->next_index;
		}

		if (buddy_header->next_index != SCX_BUDDY_CHUNK_ITEMS) {
			tmp_header = chunk_get_header(chunk, buddy_header->next_index);
			tmp_header->prev_index = buddy_header->prev_index;
		}
			
		buddy_header->prev_index = SCX_BUDDY_CHUNK_ITEMS;
		buddy_header->next_index = SCX_BUDDY_CHUNK_ITEMS;

		if (header_set_order(chunk, buddy_idx, SCX_BUDDY_CHUNK_MAX_ORDER))
			return 0;

		idx = idx < buddy_idx ? idx : buddy_idx;

		/* Poison the buddy header now that it's unused. */
		buddy_header = chunk_get_header(chunk, buddy_idx);
		asan_poison(buddy_header, BUDDY_POISONED, sizeof(*buddy_header));

		header = chunk_get_header(chunk, idx);
		if (header_set_order(chunk, idx, order + 1))
			return 0;
	}

	order = header_get_order(chunk, idx);
	header->next_index = chunk->order_indices[order];
	header->prev_index = SCX_BUDDY_CHUNK_ITEMS;

	if (header->next_index != SCX_BUDDY_CHUNK_ITEMS) {
		tmp_header = chunk_get_header(chunk, header->next_index);
		tmp_header->prev_index = idx;
	}

	chunk->order_indices[order] = idx;

	return 0;
}

__weak
int scx_buddy_free_internal(struct scx_buddy *buddy, u64 addr)
{
	int ret;

	if (!buddy)
		return -EINVAL;

	if ((ret = scx_buddy_lock(buddy)))
		return ret;

	scx_buddy_free_unlocked(buddy, addr);

	scx_buddy_unlock(buddy);

	return 0;
}
