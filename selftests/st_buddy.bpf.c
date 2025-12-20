/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2025 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2025 Emil Tsalapatis <etsal@meta.com>
 */

#include <scx/common.bpf.h>
#include <lib/sdt_task.h>

#include <alloc/buddy.h>

#include "selftest.h"

private(ST_BUDDY) struct scx_buddy st_buddy;
u64 __arena st_buddy_lock;

static
int scx_selftest_buddy_create()
{
	const int iters = 10;
	int ret, i;

	for (i = 0; i < iters && can_loop; i++) {
		ret = scx_buddy_init(&st_buddy, SCX_BUDDY_MIN_ALLOC_BYTES,
				     (arena_spinlock_t __arena *)&st_buddy_lock);
		if (ret)
			return ret;

		ret = scx_buddy_destroy(&st_buddy, 0);
		if (ret)
			return ret;
	}

	return 0;
}

static
int scx_selftest_buddy_alloc()
{
	size_t sizes[] = { 3, 17, 64, 129, 256, 333, 512, 517 };
	void __arena *mem;
	int ret, i;

	for (i = 0; i < 8 && can_loop; i++) {
		ret = scx_buddy_init(&st_buddy, SCX_BUDDY_MIN_ALLOC_BYTES,
				     (arena_spinlock_t __arena *)&st_buddy_lock);
		if (ret)
			return ret;

		mem = scx_buddy_alloc(&st_buddy, sizes[i]);
		if (!mem) {
			scx_buddy_destroy(&st_buddy, 0);
			return -ENOMEM;
		}

		scx_buddy_destroy(&st_buddy, 0);
	}

	return 0;
}

static
int scx_selftest_buddy_alloc_free()
{
	size_t sizes[] = { 3, 17, 64, 129, 256, 333, 512, 517 };
	const int iters = 800;
	void __arena *mem;
	int ret, i;

	ret = scx_buddy_init(&st_buddy, SCX_BUDDY_MIN_ALLOC_BYTES,
			     (arena_spinlock_t __arena *)&st_buddy_lock);
	if (ret)
		return ret;

	bpf_for(i, 0, iters) {
		mem = scx_buddy_alloc(&st_buddy, sizes[(i * 5) % 8]);
		if (!mem) {
			scx_buddy_destroy(&st_buddy, 0);
			return -ENOMEM;
		}

		scx_buddy_free(&st_buddy, mem);
	}

	scx_buddy_destroy(&st_buddy, 0);

	return 0;
}

static
int scx_selftest_buddy_alloc_multiple()
{
	return -EOPNOTSUPP;
}

static
int scx_selftest_buddy_fragmentation()
{
	return -EOPNOTSUPP;
}

static
int scx_selftest_buddy_exhaustion()
{
	return -EOPNOTSUPP;
}

#define SCX_BUDDY_SELFTEST(suffix) SCX_SELFTEST(scx_selftest_buddy_ ## suffix)

__weak
int scx_selftest_buddy(void)
{
	SCX_BUDDY_SELFTEST(create);
	SCX_BUDDY_SELFTEST(alloc);
	SCX_BUDDY_SELFTEST(alloc_free);
	SCX_BUDDY_SELFTEST(alloc_multiple);
	SCX_BUDDY_SELFTEST(fragmentation);
	SCX_BUDDY_SELFTEST(exhaustion);

	return 0;
}
