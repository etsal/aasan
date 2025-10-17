/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2025 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2025 Emil Tsalapatis <etsal@meta.com>
 */

#include <scx/common.bpf.h>
#include <lib/sdt_task.h>

#include "selftest.h"

static
int scx_selftest_buddy_create()
{
	return -EOPNOTSUPP;
}

static
int scx_selftest_buddy_alloc()
{
	return -EOPNOTSUPP;
}

static
int scx_selftest_buddy_free()
{
	return -EOPNOTSUPP;
}

static
int scx_selftest_buddy_alloc_free()
{
	return -EOPNOTSUPP;
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
	SCX_BUDDY_SELFTEST(free);
	SCX_BUDDY_SELFTEST(alloc_free);
	SCX_BUDDY_SELFTEST(alloc_multiple);
	SCX_BUDDY_SELFTEST(fragmentation);
	SCX_BUDDY_SELFTEST(exhaustion);

	return 0;
}
