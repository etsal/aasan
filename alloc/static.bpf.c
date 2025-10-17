/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2024-2025 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2024-2025 Tejun Heo <tj@kernel.org>
 * Copyright (c) 2024-2025 Emil Tsalapatis <etsal@meta.com>
 */

/*
 * Static allocation module used to allocate arena memory for
 * whose lifetime is that of the BPF program. Data is rarely
 * allocated, mostly at program init, and never freed. The
 * memory returned by this code is typeless so it avoids us
 * having to define an allocator for each type.
 */

#include <scx/common.bpf.h>
#include <lib/arena_map.h>

#include <alloc/static.h>

private(STATIC_ALLOC) struct bpf_spin_lock static_lock;

struct scx_static scx_static;

__weak
u64 scx_static_alloc_internal(size_t bytes, size_t alignment)
{
	void __arena *memory, *old;
	size_t alloc_bytes;
	void __arena *ptr;
	size_t padding;
	u64 addr;

	bpf_spin_lock(&static_lock);

	/* Round up the current offset. */
	addr = (__u64) scx_static.memory + scx_static.off;

	padding = round_up(addr, alignment) - addr;
	alloc_bytes = bytes + padding;

	if (alloc_bytes > scx_static.max_alloc_bytes) {
		bpf_spin_unlock(&static_lock);
		bpf_printk("invalid request %ld, max is %ld\n", alloc_bytes,
			      scx_static.max_alloc_bytes);
		return (u64)NULL;
	}

	/*
	 * The code assumes that the maximum static allocation
	 * size is significantly larger than the typical allocation
	 * size, so it does not attempt to alleviate memory
	 * fragmentation.
	 */
	if (scx_static.off + alloc_bytes > scx_static.max_alloc_bytes) {
		old = scx_static.memory;

		bpf_spin_unlock(&static_lock);

		/*
		 * No free operation so just forget about the previous
		 * allocation memory.
		 */

		memory = bpf_arena_alloc_pages(&arena, NULL,
					       scx_static.max_alloc_bytes / PAGE_SIZE,
					       NUMA_NO_NODE, 0);
		if (!memory)
			return (u64)NULL;

		bpf_spin_lock(&static_lock);

		/* Error out if we raced with another allocation. */
		if (scx_static.memory != old) {
			bpf_spin_unlock(&static_lock);
			bpf_arena_free_pages(&arena, memory, scx_static.max_alloc_bytes);

			bpf_printk("concurrent static memory allocations unsupported");
			return (u64)NULL;
		}

		/*
		 * Switch to new memory block, reset offset,
		 * and recalculate base address.
		 */
		scx_static.memory = memory;
		scx_static.off = 0;
		addr = (__u64) scx_static.memory + scx_static.off;

		/*
		 * We changed the base address. Recompute the padding.
		 */
		padding = round_up(addr, alignment) - addr;
		alloc_bytes = bytes + padding;
	}

	ptr = (void __arena *)(addr + padding);
	scx_static.off += alloc_bytes;

	bpf_spin_unlock(&static_lock);

	return (u64)ptr;
}

__weak
int scx_static_init(size_t alloc_pages)
{
	size_t max_bytes = alloc_pages * PAGE_SIZE;
	void __arena *memory;

	memory = bpf_arena_alloc_pages(&arena, NULL, alloc_pages, NUMA_NO_NODE, 0);
	if (!memory)
		return -ENOMEM;

	bpf_spin_lock(&static_lock);
	scx_static = (struct scx_static) {
		.max_alloc_bytes = max_bytes,
		.off = 0,
		.memory = memory,
	};
	bpf_spin_unlock(&static_lock);

	return 0;
}
