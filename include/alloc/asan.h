#pragma once

#define KASAN_SHADOW_SCALE 8
#define KASAN_GRANULE_MASK ((1ULL << KASAN_SHADOW_SCALE) - 1)

#define KASAN_GRANULE(expr) (((u64)expr) & KASAN_GRANULE_MASK)

int asan_init(void);
int asan_poison(void __arena *addr, size_t size);
int asan_unpoison(void __arena *addr, size_t size);

/*
 * Dummy calls to ensure the ASAN runtime's BTF information is present
 * in every object file when compiling the runtime and local BPF code
 * separately. The runtime calls are injected into the LLVM IR file 
 */
#define DECLARE_ASAN_LOAD_STORE_SIZE(size)				\
	void __asan_store##size(void *addr);				\
	void __asan_store##size##_noabort(void *addr);	\
	void __asan_load##size(void *addr);				\
	void __asan_load##size##_noabort(void *addr);	\
	void __asan_report_store##size(void *addr);			\
	void __asan_report_store##size##_noabort(void *addr);		\
	void __asan_report_load##size(void *addr);			\
	void __asan_report_load##size##_noabort(void *addr);		

DECLARE_ASAN_LOAD_STORE_SIZE(1);
DECLARE_ASAN_LOAD_STORE_SIZE(2);
DECLARE_ASAN_LOAD_STORE_SIZE(4);
DECLARE_ASAN_LOAD_STORE_SIZE(8);

#define DECLARE_ASAN_LOAD_STORE(size)				\
	void __asan_store##size(void *addr);			\
	void __asan_store##size##_noabort(void *addr);		\
	void __asan_load##size(void *addr);			\
	void __asan_load##size##_noabort(void *addr);		\
	void __asan_report_store##size(void *addr);		\
	void __asan_report_store##size##_noabort(void *addr);	\
	void __asan_report_load##size(void *addr);		\
	void __asan_report_load##size##_noabort(void *addr);		

#define ASAN_DUMMY_CALLS_SIZE(size, arg)		\
do {							\
	__asan_store##size((arg));			\
	__asan_store##size##_noabort((arg));		\
	__asan_load##size((arg));			\
	__asan_load##size##_noabort((arg));		\
	__asan_report_store##size((arg));		\
	__asan_report_store##size##_noabort((arg));	\
	__asan_report_load##size((arg));		\
	__asan_report_load##size##_noabort((arg));	\
} while (0)	

#define ASAN_DUMMY_CALLS_ALL(arg)	\
do { 					\
	ASAN_DUMMY_CALLS_SIZE(1, (arg));	\
	ASAN_DUMMY_CALLS_SIZE(2, (arg));	\
	ASAN_DUMMY_CALLS_SIZE(4, (arg));	\
	ASAN_DUMMY_CALLS_SIZE(8, (arg));	\
} while (0)

extern u64 __asan_shadow_memory_dynamic_address;

__weak __attribute__((no_sanitize_address))
int asan_dummy_call() {
	/* Use the shadow map base to prevent it from being optimized out. */
	if (__asan_shadow_memory_dynamic_address) 
		ASAN_DUMMY_CALLS_ALL((void*)__asan_shadow_memory_dynamic_address);

	return 0;
}
