/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2025 Meta Platforms, Inc. and affiliates.
 */
#include <scx/common.bpf.h>
#include <lib/sdt_task.h>
#include <lib/arena_map.h>

/* How many pages do we reserve at the beginning of the arena segment? */
#define RESERVE_ALLOC (16)

bool arena_bug_supported = false;

SEC("syscall")
int arena_alloc_reserve(void)
{
	int ret;

	ret = bpf_arena_reserve_pages(&arena, NULL, RESERVE_ALLOC);
	if (!ret)
		return ret;

	arena_bug_supported = true;

	return 0;
}

/*
 * Bug reporting mechanism based on BPF Streams. Piggyback on the stack
 * trace reporting done for arena page faults to report buggy conditions
 * akin to the kernel's BUG() mechanism: Invoking this function guarantees
 * a page fault by touching the arena's guard region, which in turn emits
 * the trace to the BPF Stream.
 *
 * This approach works right now for >= 6.16 kernels and uses minimal
 * code. We do have two limitations:
 * 	a) Representing bugs as arena page faults. The BPF Streams message
 * 	can be confusing, and the user must determine whether a stack is
 * 	from an actual page fault or from arena_bug() by examining the stack.
 * 	b) No custom user messages. We can't communicate custom messages to
 * 	BPF Streams, only backtraces.
 *
 * A possible future kfunc that lets us print to stdout from BPF will remove
 * these limitations.
 */
__weak
int arena_backtrace(void)
{
	if (!arena_bug_supported) {
		bpf_printk("[ERROR]: Bug triggered, but backtrace generation not supported");
		return -EOPNOTSUPP;
	}

	*(u8 __arena *)0x0 = 5;

	return 0;
}
