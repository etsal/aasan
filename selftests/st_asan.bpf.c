/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2025 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2025 Emil Tsalapatis <etsal@meta.com>
 */

#include <scx/common.bpf.h>
#include <lib/sdt_task.h>

#include <alloc/asan.h>
#include <alloc/stack.h>
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

#define STACK_PAGES_PER_ALLOC (4)
#define STACK_ALLOCS (4)

private(ST_STACK) struct scx_stk st_stack;

int asan_test_stack_uaf_oob_single(char __arena __arg_arena *alloced, char __arena __arg_arena *freed)
{
	const size_t overshoot = 5;
	int i;

	/* Use after free check. */
	scx_stk_free(&st_stack, freed);

	i = PAGE_SIZE;
//	for (i = 0; i < PAGE_SIZE && can_loop; i++) {
		freed[i] = 0xba;
//		ASAN_VALIDATE_ADDR(true, &freed[i]);
//	}

	/* 
	 * Out of bounds check. Assuming the blocks before were
	 * allocated consecutively, past the end of the block
	 * the memory is guaranteed to be freed.
	 */
//	for (i = 0; i < PAGE_SIZE + overshoot && can_loop; i++) {
		alloced[i] = 0xba;
		ASAN_VALIDATE_ADDR(i >= PAGE_SIZE, &alloced[i]);
//	}

	return 0;
}

int asan_test_stack_uaf_oob(void)
{
	char __arena *blocks[STACK_ALLOCS];
	int ret, i;

	ret = scx_stk_init(&st_stack, 1, STACK_PAGES_PER_ALLOC);
	if (ret) {
		bpf_printk("scx_stk_init failed with %d", ret);
		return ret;
	}

	bpf_for(i, 0, STACK_ALLOCS) {
		if (i > 0 && blocks[i] != blocks[i - 1] + PAGE_SIZE) {
			bpf_printk("allocations not consecutive");
			return -EINVAL;
		}

		blocks[i] = (void __arena *)scx_stk_alloc(&st_stack);
		if (!blocks[i]) {
			bpf_printk("allocation %d failed", i);
			return -ENOMEM;
		}
	}

	for (i = 0; i < STACK_ALLOCS && can_loop; i += 2) {
		if (i + 1 >= STACK_ALLOCS)
			break;

		asan_test_stack_uaf_oob_single(blocks[i], blocks[i + 1]);
	}

	scx_stk_destroy(&st_stack);

	return 0;
}

int asan_test_stack(void)
{
	int ret;

	ret = asan_test_stack_uaf_oob();
	if (ret) {
		bpf_printk("%s:%d test failed", __func__, __LINE__);
		return ret;
	}

	return 0;
}

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

	return 0;
}

SEC("syscall")
int asan_test(void)
{
	int ret;

	ret = asan_test_static();
	if (ret)
		return ret;

	ret = asan_test_stack();
	if (ret)
		return ret;

	bpf_printk("ASAN tests successful.");

	return 0;
}
