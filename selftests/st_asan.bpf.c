/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2025 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2025 Emil Tsalapatis <etsal@meta.com>
 */

#include <scx/common.bpf.h>
#include <lib/sdt_task.h>

#include <alloc/asan.h>
#include <alloc/static.h>

#include "selftest.h"

#define ST_PAGES		64

#define ASAN_MAP_STATE(addr)						\
do {									\
	bpf_printk("%s:%d ASAN %lx -> (val: %x gran: %x set: [%s])", 	\
			__func__, __LINE__, addr, 			\
			asan_shadow_value((addr)), ASAN_GRANULE(addr), 	\
			asan_shadow_set((addr)) ? "yes" : "no"); 	\
} while (0)

/*
 * Emit an error and force the current function to exit if the ASAN
 * violation state is unexpected. Reset the violation state after.
 */
#define ASAN_VALIDATE_ADDR(cond, addr) 		\
do { 						\
	if ((asan_violated != 0) != (cond)) { 	\
		ASAN_MAP_STATE((addr)); 	\
		return -EINVAL;			\
	}					\
	asan_violated = 0;			\
} while (0)

#define ASAN_VALIDATE() 						\
do { 									\
	if ((asan_violated)) { 						\
		bpf_printk("%s:%d Found ASAN violation at %lx", 	\
				__func__, __LINE__, asan_violated); 	\
		return -EINVAL;						\
	}								\
} while (0)

struct blob {
	volatile u8 mem[59];
	u8 oob;
};

int asan_test_static_blob_one(void)
{
	volatile struct blob __arena *blob;
	const size_t alignment = 1;

	blob = scx_static_alloc(sizeof(blob) - 1, alignment);
	if (!blob)
		return -ENOMEM;

	blob->mem[0] = 0xba;
	ASAN_VALIDATE_ADDR(false, &blob->mem[0]);

	blob->oob = 0;
	ASAN_VALIDATE_ADDR(true, &blob->oob);

	blob = (volatile struct blob __arena *)&blob->oob;
	blob->mem[0] = 0xba;
	ASAN_VALIDATE_ADDR(true, &blob->mem[0]);

	blob->oob = 4;
	ASAN_VALIDATE_ADDR(true, &blob->oob);

	blob = (volatile struct blob __arena *)&blob->oob;
	blob->oob = 5;
	ASAN_VALIDATE_ADDR(true, &blob->oob);

	return 0;
}

int asan_test_static_blob(void)
{
	const int iters = 20;
	int ret, i;

	ret = scx_static_init(ST_PAGES);
	if (ret) {
		bpf_printk("scx_static_init failed with %d", ret);
		return ret;
	}

	for (i = 0; i < iters && can_loop; i++) {
		ret = asan_test_static_blob_one();
		if (ret) {
			bpf_printk("%s:%d Failed on iteration %d", __func__, __LINE__, i);
			return ret;
		}
	}

	scx_static_destroy();

	ASAN_VALIDATE();

	return 0;
}

int asan_test_static_array_one(void)
{
	size_t bytes = 37;
	size_t overrun = 13;
	size_t alignment = 1;
	char __arena *mem;
	int i;

	mem = scx_static_alloc(sizeof(*mem) * bytes, alignment);
	if (!mem)
		return -ENOMEM;

	for (i = 0; i < bytes + overrun && can_loop; i++) {
		mem[i] = 0xba;
		ASAN_VALIDATE_ADDR(i >= bytes, &mem[i]);
	}

	ASAN_VALIDATE();

	return 0;
}

int asan_test_static_array(void)
{
	const size_t iters = 20;
	int ret, i;

	ret = scx_static_init(ST_PAGES);
	if (ret) {
		bpf_printk("scx_static_init failed with %d", ret);
		return ret;
	}

	for (i = 0; i < iters && can_loop; i++) {
		ret = asan_test_static_array_one();
		if (ret) {
			bpf_printk("%s:%d Failed on iteration %d", __func__, __LINE__, i);
			return ret;
		}
	}

	scx_static_destroy();

	return 0;
}

int asan_test_static_all(void)
{
	const int iters = 50;
	int ret, i;

	ret = scx_static_init(ST_PAGES);
	if (ret) {
		bpf_printk("scx_static_init failed with %d", ret);
		return ret;
	}

	for (i = 0; i < iters && can_loop; i++) {
		ret = asan_test_static_array_one();
		if (ret) {
			bpf_printk("%s:%d Failed on iteration %d", __func__, __LINE__, i);
			return ret;
		}

		ret = asan_test_static_blob_one();
		if (ret) {
			bpf_printk("%s:%d Failed on iteration %d", __func__, __LINE__, i);
			return ret;
		}
	}

	scx_static_destroy();

	return 0;
}

SEC("syscall")
int asan_test_static(void)
{
	int ret;

	ret = asan_test_static_blob();
	if (ret) {
		bpf_printk("%s:%d test failed", __func__, __LINE__);
		return ret;
	}

	ret = asan_test_static_array();
	if (ret) {
		bpf_printk("%s:%d test failed", __func__, __LINE__);
		return ret;
	}

	ret = asan_test_static_all();
	if (ret) {
		bpf_printk("%s:%d test failed", __func__, __LINE__);
		return ret;
	}

	bpf_printk("ASAN tests successful.");

	return 0;
}
