/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2025 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2025 Emil Tsalapatis <etsal@meta.com>
 */

#include <scx/common.bpf.h>
#include <lib/sdt_task.h>

#include <alloc/stack.h>

#include "selftest.h"

static
int scx_selftest_stack_init()
{
	return -EOPNOTSUPP;
}

static
int scx_selftest_stack_alloc()
{
	return -EOPNOTSUPP;
}

static
int scx_selftest_stack_free()
{
	return -EOPNOTSUPP;
}

static
int scx_selftest_stack_alloc_free()
{
	return -EOPNOTSUPP;
}

static
int scx_selftest_stack_alloc_multiple()
{
	return -EOPNOTSUPP;
}

static
int scx_selftest_stack_exhaustion()
{
	return -EOPNOTSUPP;
}

static
int scx_selftest_stack_push_pop()
{
	return -EOPNOTSUPP;
}

#define SCX_STACK_SELFTEST(suffix) SCX_SELFTEST(scx_selftest_stack_ ## suffix)

__weak
int scx_selftest_stack(void)
{
	SCX_STACK_SELFTEST(init);
	SCX_STACK_SELFTEST(alloc);
	SCX_STACK_SELFTEST(free);
	SCX_STACK_SELFTEST(alloc_free);
	SCX_STACK_SELFTEST(alloc_multiple);
	SCX_STACK_SELFTEST(exhaustion);
	SCX_STACK_SELFTEST(push_pop);

	return 0;
}
