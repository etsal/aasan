/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2024-2025 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2024-2025 Emil Tsalapatis <etsal@meta.com>
 */

#include <scx/common.bpf.h>
#include <lib/arena_map.h>
#include <lib/sdt_task.h>

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
	if (order >= SCX_BUDDY_CHUNK_MAX_ORDER) {
		bpf_printk("setting invalid order");
		return -EINVAL;
	}

	if (offset >= SCX_BUDDY_CHUNK_ITEMS) {
		bpf_printk("setting order of invalid offset");
		return -EINVAL;
	}

	if (offset & 0x1)
		order &= 0xf;
	else
		order <<= 4;

	chunk->orders[offset / 2] |= order;

	return 0;
}

static
u8 header_get_order(scx_buddy_chunk_t *chunk, u64 offset)
{
	u8 result;

	_Static_assert(SCX_BUDDY_CHUNK_MAX_ORDER <= 16, "order must fit in 4 bits");

	if (offset >= SCX_BUDDY_CHUNK_ITEMS) {
		bpf_printk("setting order of invalid offset");
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
		bpf_printk("size 0 has no order");
		bpf_printk("size 0 has no order");
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
scx_buddy_chunk_t *scx_buddy_chunk_get(struct scx_stk *stk)
{
	u64 order, ord, last_order;
	scx_buddy_header_t *header;
	scx_buddy_chunk_t *chunk;
	u32 idx, cur_idx;
	int i, power2;
	size_t left;

	chunk = (scx_buddy_chunk_t *)scx_stk_alloc(stk);
	if (!chunk)
		return NULL;

	/*
	 * Initialize the chunk by carving out the first page to hold the metadata struct above,
	 * then dumping the rest of the pages into the allocator.
	 */

	bpf_for (i, 0, SCX_BUDDY_CHUNK_ITEMS) {
		header = chunk_get_header(chunk, i);
		header->prev_index = SCX_BUDDY_CHUNK_ITEMS;
		header->next_index = SCX_BUDDY_CHUNK_ITEMS;
		if (header_set_order(chunk, i, SCX_BUDDY_CHUNK_MAX_ORDER))
			return NULL;
	}

	_Static_assert(SCX_BUDDY_CHUNK_PAGES * PAGE_SIZE >= SCX_BUDDY_MIN_ALLOC_BYTES * SCX_BUDDY_CHUNK_ITEMS,
		"chunk must fit within the stack allocation");

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
			bpf_printk("buddy chunk metadata require allocation of order %d", power2);
			return NULL;
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

			/* Mark it free. */
			chunk->order_indices[ord] = idx;
			if (header_set_order(chunk, idx, ord))
				return NULL;
		}

		/* Adjust the index. */
		cur_idx += 1 << order;
	}

	return chunk;
}

__hidden
int scx_buddy_init(struct scx_buddy *buddy, size_t size)
{
	scx_buddy_chunk_t *chunk;
	int ret;

	/* Set a minimum allocation size. */
	if (size < SCX_BUDDY_MIN_ALLOC_BYTES)
		return -EINVAL;

	/* Check if already initialized. */
	if (buddy->min_alloc_bytes)
		return -EALREADY;

	buddy->min_alloc_bytes = size;

	_Static_assert(SCX_BUDDY_CHUNK_PAGES > 0, "chunk must use one or more pages");

	/* One allocation per chunk. */
	ret = scx_stk_init(&buddy->stack, SCX_BUDDY_CHUNK_PAGES * PAGE_SIZE, SCX_BUDDY_CHUNK_PAGES);
	if (ret) {
		buddy->min_alloc_bytes = 0;
		return ret;
	}

	chunk = scx_buddy_chunk_get(&buddy->stack);

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
		bpf_arena_free_pages(&arena, chunk, SCX_BUDDY_CHUNK_PAGES);
	}

	/* Destroy the underlying stack allocator. */
	scx_stk_destroy(&buddy->stack);

	/* Clear all fields. */
	buddy->first_chunk = NULL;
	buddy->min_alloc_bytes = 0;

	return 0;
}

__weak
u64 scx_buddy_chunk_alloc(scx_buddy_chunk_t *chunk, int order_req)
{
	scx_buddy_header_t *header;
	u64 address;
	u64 order = 0;
	u32 idx;

	bpf_for(order, order_req, SCX_BUDDY_CHUNK_MAX_ORDER) {
		if (chunk->order_indices[order] != SCX_BUDDY_CHUNK_ITEMS)
			break;
	}

	if (order == SCX_BUDDY_CHUNK_MAX_ORDER)
		return (u64)NULL;

	idx = chunk->order_indices[order];
	header = chunk_get_header(chunk, idx);
	chunk->order_indices[order] = header->next_index;

	header->prev_index = SCX_BUDDY_CHUNK_ITEMS;
	header->next_index = SCX_BUDDY_CHUNK_ITEMS;
	if (header_set_order(chunk, idx, order_req))
		return (u64)NULL;

	address = (u64)chunk_idx_to_mem(chunk, idx);

	/* If we allocated from a larger-order chunk, split the buddies. */
	bpf_for(order, order_req, order) {
		/* Flip the bit for the current order. */
		idx ^= 1 << order;

		/* Add the buddy of the allocation to the free list. */
		header = chunk_get_header(chunk, idx);
		if (header_set_order(chunk, idx, order))
			return (u64)NULL;
		header->prev_index = SCX_BUDDY_CHUNK_ITEMS;

		header->next_index = chunk->order_indices[order];
		chunk->order_indices[order] = idx;
	}

	return address;
}

__weak
u64 scx_buddy_alloc_internal(struct scx_buddy *buddy, size_t size)
{
	scx_buddy_chunk_t *chunk;
	u64 address;
	int order;

	order = size_to_order(size);
	if (order >= SCX_BUDDY_CHUNK_MAX_ORDER - 1) {
		bpf_printk("Allocation size %lu too large", size);
		return (u64)NULL;
	}

	bpf_spin_lock(&buddy->lock);
	chunk = buddy->first_chunk;
	do {
		address = scx_buddy_chunk_alloc(chunk, order);
		chunk = chunk->next;
	} while (address == (u64)NULL && can_loop);
	bpf_spin_unlock(&buddy->lock);

	if (address)
		return address;

	/* Get a new chunk. */
	chunk = scx_buddy_chunk_get(&buddy->stack);
	if (!chunk)
		return (u64)NULL;

	bpf_spin_lock(&buddy->lock);

	/* Add the chunk into the allocator and retry. */
	chunk->next = buddy->first_chunk;
	chunk->prev = NULL;
	buddy->first_chunk = chunk;

	address = scx_buddy_chunk_alloc(buddy->first_chunk, order);

	bpf_spin_unlock(&buddy->lock);

	return address;
}

__weak
void scx_buddy_free_internal(struct scx_buddy *buddy, u64 addr)
{
	scx_buddy_header_t *header, *buddy_header, *tmp_header;
	scx_buddy_chunk_t *chunk, *target_chunk;
	u64 idx, buddy_idx;
	u8 order;

	if (addr & (SCX_BUDDY_MIN_ALLOC_BYTES - 1)) {
		bpf_printk("Freeing unaligned address %llx", addr);
		return;
	}

	bpf_spin_lock(&buddy->lock);

	/* Align to the chunk boundary. */
	target_chunk = (void __arena *)(addr & ~SCX_BUDDY_CHUNK_OFFSET_MASK);

	/* XXX Only necessary for debugging. */
	for (chunk = buddy->first_chunk; chunk != NULL && can_loop; chunk = chunk->next) {
		if (chunk == target_chunk)
			break;
	}

	if (chunk == NULL) {
		bpf_spin_unlock(&buddy->lock);
		bpf_printk("could not find chunk for address %llx", addr);
		return;
	}

	/* Get the page idx. */
	idx = (addr & SCX_BUDDY_CHUNK_OFFSET_MASK) / SCX_BUDDY_MIN_ALLOC_BYTES;
	header = chunk_get_header(chunk, idx);

	bpf_for(order, header_get_order(chunk, idx), SCX_BUDDY_CHUNK_MAX_ORDER) {
		buddy_idx = idx ^= 1 << order;
		buddy_header = chunk_get_header(chunk, buddy_idx);

		/* Check if the buddy is not in the free list. */
		if (chunk->order_indices[order] != buddy_idx &&
		    buddy_header->prev_index == SCX_BUDDY_CHUNK_ITEMS &&
		    buddy_header->next_index == SCX_BUDDY_CHUNK_ITEMS)
			break;

		/* Pop off the list head if necessary. */
		if (chunk->order_indices[order] == buddy_idx)
			chunk->order_indices[order] = buddy_header->next_index;

		/* Pop */
		if (buddy_header->prev_index != SCX_BUDDY_CHUNK_ITEMS) {
			tmp_header = chunk_get_header(chunk, buddy_header->prev_index);
			tmp_header->next_index = buddy_header->next_index;
			buddy_header->next_index = SCX_BUDDY_CHUNK_ITEMS;
		}

		if (buddy_header->next_index != SCX_BUDDY_CHUNK_ITEMS) {
			tmp_header = chunk_get_header(chunk, buddy_header->next_index);
			tmp_header->prev_index = buddy_header->prev_index;
			buddy_header->prev_index = SCX_BUDDY_CHUNK_ITEMS;
		}

		if (header_set_order(chunk, buddy_idx, SCX_BUDDY_CHUNK_MAX_ORDER))
			return;

		idx = idx < buddy_idx ? idx : buddy_idx;

		header = chunk_get_header(chunk, idx);
		if (header_set_order(chunk, idx, order + 1))
			return;
	}

	order = header_get_order(chunk, idx);
	header->next_index = chunk->order_indices[order];
	chunk->order_indices[order] = idx;

	bpf_spin_unlock(&buddy->lock);
}
