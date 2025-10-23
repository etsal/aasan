/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2025 Meta Platforms, Inc. and affiliates.
 */
#include <scx/common.bpf.h>
#include <lib/sdt_task.h>
#include <lib/arena_map.h>

/* How many pages do we reserve at the beginning of the arena segment? */
#define RESERVE_ALLOC (16)

SEC("syscall")
int arena_alloc_reserve(void)
{
	void __arena *start;

	/*
	 * Allocate and free a page to initialize the range tree.
	 * This way we also find the first address in the arena.
	 */

	start = bpf_arena_alloc_pages(&arena, NULL, 1, NUMA_NO_NODE, 0);
	if (!start)
		return -ENOMEM;

	bpf_arena_free_pages(&arena, start, 1);

	/* Reserve the arena's starting region. */

	return (bpf_arena_reserve_pages(&arena, start, RESERVE_ALLOC));
}
