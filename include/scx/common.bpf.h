/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2022 Tejun Heo <tj@kernel.org>
 * Copyright (c) 2022 David Vernet <dvernet@meta.com>
 */
#ifndef __SCX_COMMON_BPF_H
#define __SCX_COMMON_BPF_H

/*
 * The generated kfunc prototypes in vmlinux.h are missing address space
 * attributes which cause build failures. For now, suppress the generated
 * prototypes. See https://github.com/sched-ext/scx/issues/1111.
 */
#define BPF_NO_KFUNC_PROTOTYPES

#ifdef LSP
#define __bpf__
#include "../vmlinux.h"
#else
#include "vmlinux.h"
#endif

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <asm-generic/errno.h>

/* useful compiler attributes */
#ifndef likely
#define likely(x) __builtin_expect(!!(x), 1)
#endif
#ifndef unlikely
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif
#ifndef __maybe_unused
#define __maybe_unused __attribute__((__unused__))
#endif

/*
 * READ/WRITE_ONCE() are from kernel (include/asm-generic/rwonce.h). They
 * prevent compiler from caching, redoing or reordering reads or writes.
 */
typedef __u8  __attribute__((__may_alias__))  __u8_alias_t;
typedef __u16 __attribute__((__may_alias__)) __u16_alias_t;
typedef __u32 __attribute__((__may_alias__)) __u32_alias_t;
typedef __u64 __attribute__((__may_alias__)) __u64_alias_t;

static __always_inline void __read_once_size(const volatile void *p, void *res, int size)
{
	switch (size) {
	case 1: *(__u8_alias_t  *) res = *(volatile __u8_alias_t  *) p; break;
	case 2: *(__u16_alias_t *) res = *(volatile __u16_alias_t *) p; break;
	case 4: *(__u32_alias_t *) res = *(volatile __u32_alias_t *) p; break;
	case 8: *(__u64_alias_t *) res = *(volatile __u64_alias_t *) p; break;
	default:
		barrier();
		__builtin_memcpy((void *)res, (const void *)p, size);
		barrier();
	}
}

static __always_inline void __write_once_size(volatile void *p, void *res, int size)
{
	switch (size) {
	case 1: *(volatile  __u8_alias_t *) p = *(__u8_alias_t  *) res; break;
	case 2: *(volatile __u16_alias_t *) p = *(__u16_alias_t *) res; break;
	case 4: *(volatile __u32_alias_t *) p = *(__u32_alias_t *) res; break;
	case 8: *(volatile __u64_alias_t *) p = *(__u64_alias_t *) res; break;
	default:
		barrier();
		__builtin_memcpy((void *)p, (const void *)res, size);
		barrier();
	}
}

/*
 * __unqual_typeof(x) - Declare an unqualified scalar type, leaving
 *			non-scalar types unchanged,
 *
 * Prefer C11 _Generic for better compile-times and simpler code. Note: 'char'
 * is not type-compatible with 'signed char', and we define a separate case.
 *
 * This is copied verbatim from kernel's include/linux/compiler_types.h, but
 * with default expression (for pointers) changed from (x) to (typeof(x)0).
 *
 * This is because LLVM has a bug where for lvalue (x), it does not get rid of
 * an extra address_space qualifier, but does in case of rvalue (typeof(x)0).
 * Hence, for pointers, we need to create an rvalue expression to get the
 * desired type. See https://github.com/llvm/llvm-project/issues/53400.
 */
#define __scalar_type_to_expr_cases(type) \
	unsigned type : (unsigned type)0, signed type : (signed type)0

#define __unqual_typeof(x)                              \
	typeof(_Generic((x),                            \
		char: (char)0,                          \
		__scalar_type_to_expr_cases(char),      \
		__scalar_type_to_expr_cases(short),     \
		__scalar_type_to_expr_cases(int),       \
		__scalar_type_to_expr_cases(long),      \
		__scalar_type_to_expr_cases(long long), \
		default: (typeof(x))0))

#define READ_ONCE(x)								\
({										\
	union { __unqual_typeof(x) __val; char __c[1]; } __u =			\
		{ .__c = { 0 } };						\
	__read_once_size((__unqual_typeof(x) *)&(x), __u.__c, sizeof(x));	\
	__u.__val;								\
})

#define WRITE_ONCE(x, val)							\
({										\
	union { __unqual_typeof(x) __val; char __c[1]; } __u =			\
		{ .__val = (val) }; 						\
	__write_once_size((__unqual_typeof(x) *)&(x), __u.__c, sizeof(x));	\
	__u.__val;								\
})

/*
 * __calc_avg - Calculate exponential weighted moving average (EWMA) with
 * @old and @new values. @decay represents how large the @old value remains.
 * With a larger @decay value, the moving average changes slowly, exhibiting
 * fewer fluctuations.
 */
#define __calc_avg(old, new, decay) ({						\
	typeof(decay) thr = 1 << (decay);					\
	typeof(old) ret;							\
	if (((old) < thr) || ((new) < thr)) {					\
		if (((old) == 1) && ((new) == 0))				\
			ret = 0;						\
		else								\
			ret = ((old) - ((old) >> 1)) + ((new) >> 1);		\
	} else {								\
		ret = ((old) - ((old) >> (decay))) + ((new) >> (decay));	\
	}									\
	ret;									\
})

/*
 * log2_u32 - Compute the base 2 logarithm of a 32-bit exponential value.
 * @v: The value for which we're computing the base 2 logarithm.
 */
static inline u32 log2_u32(u32 v)
{
        u32 r;
        u32 shift;

        r = (v > 0xFFFF) << 4; v >>= r;
        shift = (v > 0xFF) << 3; v >>= shift; r |= shift;
        shift = (v > 0xF) << 2; v >>= shift; r |= shift;
        shift = (v > 0x3) << 1; v >>= shift; r |= shift;
        r |= (v >> 1);
        return r;
}

/*
 * log2_u64 - Compute the base 2 logarithm of a 64-bit exponential value.
 * @v: The value for which we're computing the base 2 logarithm.
 */
static inline u32 log2_u64(u64 v)
{
        u32 hi = v >> 32;
        if (hi)
                return log2_u32(hi) + 32 + 1;
        else
                return log2_u32(v) + 1;
}

/*
 * sqrt_u64 - Calculate the square root of value @x using Newton's method.
 */
static inline u64 __sqrt_u64(u64 x)
{
	if (x == 0 || x == 1)
		return x;

	u64 r = ((1ULL << 32) > x) ? x : (1ULL << 32);

	for (int i = 0; i < 8; ++i) {
		u64 q = x / r;
		if (r <= q)
			break;
		r = (r + q) >> 1;
	}
	return r;
}

/*
 * Return a value proportionally scaled to the task's weight.
 */
static inline u64 scale_by_task_weight(const struct task_struct *p, u64 value)
{
	return (value * p->scx.weight) / 100;
}

/*
 * Return a value inversely proportional to the task's weight.
 */
static inline u64 scale_by_task_weight_inverse(const struct task_struct *p, u64 value)
{
	return value * 100 / p->scx.weight;
}

/*
 * Get a random u64 from the kernel's pseudo-random generator.
 */
static inline u64 get_prandom_u64()
{
	return ((u64)bpf_get_prandom_u32() << 32) | bpf_get_prandom_u32();
}

#define NUMA_NO_NODE (-1)
#define private(name) SEC(".data." #name) __hidden __attribute__((aligned(8)))
#ifndef NR_CPUS
#define NR_CPUS 1024
#endif

struct bpf_cpumask *bpf_cpumask_create(void) __ksym;
struct bpf_cpumask *bpf_cpumask_acquire(struct bpf_cpumask *cpumask) __ksym;
void bpf_cpumask_release(struct bpf_cpumask *cpumask) __ksym;
u32 bpf_cpumask_first(const struct cpumask *cpumask) __ksym;
u32 bpf_cpumask_first_zero(const struct cpumask *cpumask) __ksym;
void bpf_cpumask_set_cpu(u32 cpu, struct bpf_cpumask *cpumask) __ksym;
void bpf_cpumask_clear_cpu(u32 cpu, struct bpf_cpumask *cpumask) __ksym;
bool bpf_cpumask_test_cpu(u32 cpu, const struct cpumask *cpumask) __ksym;
bool bpf_cpumask_test_and_set_cpu(u32 cpu, struct bpf_cpumask *cpumask) __ksym;
bool bpf_cpumask_test_and_clear_cpu(u32 cpu, struct bpf_cpumask *cpumask) __ksym;
void bpf_cpumask_setall(struct bpf_cpumask *cpumask) __ksym;
void bpf_cpumask_clear(struct bpf_cpumask *cpumask) __ksym;
bool bpf_cpumask_and(struct bpf_cpumask *dst, const struct cpumask *src1,
                    const struct cpumask *src2) __ksym;
void bpf_cpumask_or(struct bpf_cpumask *dst, const struct cpumask *src1,
                   const struct cpumask *src2) __ksym;
void bpf_cpumask_xor(struct bpf_cpumask *dst, const struct cpumask *src1,
                    const struct cpumask *src2) __ksym;
bool bpf_cpumask_equal(const struct cpumask *src1, const struct cpumask *src2) __ksym;
bool bpf_cpumask_intersects(const struct cpumask *src1, const struct cpumask *src2) __ksym;
bool bpf_cpumask_subset(const struct cpumask *src1, const struct cpumask *src2) __ksym;
bool bpf_cpumask_empty(const struct cpumask *cpumask) __ksym;
bool bpf_cpumask_full(const struct cpumask *cpumask) __ksym;
void bpf_cpumask_copy(struct bpf_cpumask *dst, const struct cpumask *src) __ksym;
u32 bpf_cpumask_any_distribute(const struct cpumask *cpumask) __ksym;
u32 bpf_cpumask_any_and_distribute(const struct cpumask *src1,
                                  const struct cpumask *src2) __ksym;
u32 bpf_cpumask_weight(const struct cpumask *cpumask) __ksym;

static __always_inline const struct cpumask *cast_mask(struct bpf_cpumask *mask)
{
       return (const struct cpumask *)mask;
}

#endif	/* __SCX_COMMON_BPF_H */
