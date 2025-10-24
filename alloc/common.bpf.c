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
	return bpf_arena_reserve_pages(&arena, NULL, RESERVE_ALLOC);
}
