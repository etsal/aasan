/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2025 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2025 Emil Tsalapatis <etsal@meta.com>
 */

#include <scx/common.bpf.h>
#include <lib/sdt_task.h>

#include <alloc/static.h>

#include "selftest.h"

static
int scx_selftest_static_alloc()
{
	return -EOPNOTSUPP;
}

static
int scx_selftest_static_alloc_multiple()
{
	return -EOPNOTSUPP;
}

static
int scx_selftest_static_alloc_aligned()
{
	return -EOPNOTSUPP;
}

static
int scx_selftest_static_alloc_exhaustion()
{
	return -EOPNOTSUPP;
}

static
int scx_selftest_static_alloc_wraparound()
{
	return -EOPNOTSUPP;
}

#define SCX_STATIC_SELFTEST(suffix) SCX_SELFTEST(scx_selftest_static_ ## suffix)

__weak
int scx_selftest_static(void)
{
	int ret;

	/* Initialize the static allocator with a small number of pages for testing */
	ret = scx_static_init(16);
	if (ret) {
		bpf_printk("scx_static_init failed with %d", ret);
		return ret;
	}

	SCX_STATIC_SELFTEST(alloc);
	SCX_STATIC_SELFTEST(alloc_multiple);
	SCX_STATIC_SELFTEST(alloc_aligned);
	SCX_STATIC_SELFTEST(alloc_exhaustion);
	SCX_STATIC_SELFTEST(alloc_wraparound);

	return 0;
}
