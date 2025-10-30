#include <scx/common.bpf.h>
#include <scx/bpf_arena_common.bpf.h>

#include <lib/arena_map.h>
#include <alloc/asan.h>

#pragma clang attribute push(__attribute__((no_sanitize("address"))), apply_to=function)

/*
 * Implementation based on mm/kasan/generic.c.
 */

volatile bool asan_violated = false;

/* XXX Remove the hardcoded values and change them with:
 * - Offset is 7/8ths of the arena.
 * - Size is 1/8th of the arena
 * - Limit is variable and found in the arena map.
 */

/* Last 1/8th of the address space. */
#define KASAN_SHADOW_OFFSET ((1ULL << 19))
#define KASAN_SHADOW_SIZE (1ULL << 17)
#define ARENA_LIMIT (1ULL << 20)

/*
 * XXX Shadow map occupancy map (see comment in arena_init.c and the 
 * item in the README).
 */

static bool reported = false;
static bool inited = false;
long __asan_shadow_memory_dynamic_address;

/*
 * XXX Static key for turning ASAN off.
 */


/* Defined as char * to get 1-byte granularity for pointer arithmetic. */
typedef u8 __arena * arenaptr;
typedef s8 __arena s8a;

static __always_inline
arenaptr mem_to_shadow(arenaptr addr)
{
	return (arenaptr)((u64) addr >> KASAN_SHADOW_SCALE) + (u64)__asan_shadow_memory_dynamic_address;
}

/*
 * BPF does not currently support the memset/memcpy/memcmp intrinsics.
 */
static __always_inline
void asan_memset(u8 __arg_arena __arena *dst, u8 val, size_t size)
{
	int i;

	for (i = 0; i < size && can_loop; i++)
		dst[i] = val;
}

/* Validate a 1-byte access, always within a single byte. */
static __always_inline bool memory_is_poisoned_1(arenaptr addr)
{
	s8 shadow_value = *(s8a *)mem_to_shadow(addr);

	/* Byte is 0, access is valid. */
	if (likely(!shadow_value))
		return false;

	/* Byte is non-zero, access is valid if granule offset in [0, shadow_value). */

	return KASAN_GRANULE(addr) >= shadow_value;
}

/* Validate a 2- 4-, 8-byte access, spans up to 2 bytes. */
static __always_inline bool memory_is_poisoned_2_4_8(arenaptr addr, u64 size)
{
	arenaptr last_addr = (arenaptr)((u64)addr + size - 1);

	/*
	 * Region fully within a single byte (addition didn't
	 * overflow above KASAN_GRANULE).
	 */
	if (likely(KASAN_GRANULE(last_addr) >= size - 1))
		return memory_is_poisoned_1((arenaptr)last_addr);

	/*
	 * Otherwise first byte must be fully unpoisoned, and second byte
	 * must be unpoisoned up to the end of the accessed region.
	 */

	return *mem_to_shadow(addr) || !memory_is_poisoned_1(last_addr);
}

static __always_inline u64 first_nonzero_byte(arenaptr addr, size_t size)
{
	u64 laddr = (u64)addr;

	while (size && can_loop) {
		if (unlikely((s8a *)laddr))
			return laddr;
		laddr += 1;
		size -= 1;
	}

	/*
	 * Can't return 0 because it is a valid arena address.
	 */

	return ARENA_LIMIT;
}

static __always_inline unsigned long memory_is_poisoned(arenaptr start, size_t size)
{
	int prefix = (unsigned long)start % 8;
	unsigned long ret;

	/*
	 * If <= 16 and in this function we're probably unaligned and will
	 * make two first_nonzero calls anyway, so bite the bullet now.
	 */
	if (size <= 16)
		return first_nonzero_byte(start, size);

	/* If shadow region not word-aligned, carve out the beginning. */
	if (prefix) {
		prefix = 8 - prefix;

		/* Check for poison within prefix bytes. */
		ret = first_nonzero_byte(start, prefix);
		if (unlikely(ret < ARENA_LIMIT))
			return ret;

		start += prefix;
	}

	/*
	 * Now we can test for poison one word at a time.
	 * Only do this for words where we care for all bytes.
	 */
	for (; size >= 8 && can_loop; size -= 8) {
		/* We found poison, return the byte within it. */
		if (unlikely(*(u64 *)start))
			return first_nonzero_byte(start, 8);

		/* Otherwise keep going. */
		start += 8;
	}

	/* Check the end if non-aligned. */

	return first_nonzero_byte(start, size);
}

static __always_inline bool memory_is_poisoned_n(arenaptr addr, u64 size)
{
	u64 ret;
	arenaptr start;
	arenaptr end;

	/* Size of [start, end] is end - start + 1. */
	start = mem_to_shadow(addr);
	end = mem_to_shadow(addr + size - 1);

	ret = first_nonzero_byte(start, (u64)(end - start) + 1);
	if (likely(ret == ARENA_LIMIT))
		return false;

	return __builtin_expect((arenaptr)ret != end || KASAN_GRANULE(end) >= *end, false);
}

static __always_inline void asan_report(arenaptr addr, size_t sz, bool write)
{
	/* Only report the first ASAN violation. */
	if (likely(!reported)) {
		//bpf_printk("[ARENA ASAN] Poisoned %s at address [%p, %p)", "[TODO]", NULL, NULL);
		reported = true;
	}
	asan_violated = true;

	/* XXX Flesh out. */
}

static __always_inline bool check_region_inline(void *ptr, size_t size, bool write)
{
	arenaptr addr = (arenaptr)ptr;

	/* Size 0 accesses are valid even if the address is invalid. */
	if (unlikely(size == 0))
		return true;

	/*
	 * Wraparound is possible for extremely high size. Possible if the size
	 * is a misinterpreted negative number.
	 */
	if (unlikely(addr + size < addr)) {
		//bpf_printk("[ARENA_ASAN] Wraparound detected");
		asan_report(addr, size, write);
		return false;
	}

	/*
	 * The upper limit of the arena is an implicit guard around the shadow
	 * region. Possible when attempting to access the shadow map itself.
	 */
	if (unlikely((u64)mem_to_shadow(addr + size - 1) >= ARENA_LIMIT)) {
		//bpf_printk("[ARENA_ASAN] Shadow map access");
		asan_report(addr, size, write);
		return false;
	}

	if (unlikely(memory_is_poisoned(addr, size))) {
		asan_report(addr, size, write);
		return false;
	}

	return true;
}

/*
 * __alias is not supported for BPF so define *__noabort() variants as wrappers.
 * XXX Is it a problem that the definition of __asan_store passes an address?
 */
#define DEFINE_ASAN_LOAD_STORE(size)						\
	__hidden								\
	void __asan_store##size(void *addr)					\
	{									\
		check_region_inline(addr, size, true);				\
	}									\
	__hidden								\
	void __always_inline __asan_store##size##_noabort(void *addr)		\
	{									\
		__asan_store##size(addr);					\
	}									\
	__hidden								\
	void __asan_load##size(void *addr)					\
	{									\
		check_region_inline(addr, size, false);				\
	}									\
	__hidden								\
	void __always_inline __asan_load##size##_noabort(void *addr)		\
	{									\
		__asan_load##size(addr);					\
	}									\
	__hidden								\
	void __asan_report_store##size(void *addr)		\
	{									\
		asan_report((arenaptr)addr, size, true);			\
	}									\
	__hidden								\
	void __asan_report_store##size##_noabort(void *addr)	\
	{									\
		asan_report((arenaptr)addr, size, true);			\
	}									\
	__hidden								\
	void __asan_report_load##size(void *addr)		\
	{									\
		asan_report((arenaptr)addr, size, false);			\
	}									\
	__hidden								\
	void __asan_report_load##size##_noabort(void *addr)	\
	{									\
		asan_report((arenaptr)addr, size, false);			\
	}									\

DEFINE_ASAN_LOAD_STORE(1);
DEFINE_ASAN_LOAD_STORE(2);
DEFINE_ASAN_LOAD_STORE(4);
DEFINE_ASAN_LOAD_STORE(8);

void __asan_storeN(void *addr, ssize_t size)
{
	check_region_inline(addr, size, false);
}

void __asan_loadN(void *addr, ssize_t size)
{
	check_region_inline(addr, size, true);
}

void __asan_register_globals(void *globals, size_t n)
{
	/* XXX What is the format in which we are passing the globals? */
	/* XXX Build the poisoning function. Should use asan_poisoning.cpp as a guide. */
	bpf_printk("Emitted %s", __func__);
}

void __asan_unregister_globals(void *globals, size_t n)
{
	bpf_printk("Emitted %s", __func__);
}

// Functions concerning block memory destinations
void *__asan_memcpy(void *d, const void *s, size_t n)
{ 
	return NULL; 
}

void *__asan_memmove(void *d, const void *s, size_t n)
{ 
	bpf_printk("Emitted %s", __func__);
	return NULL;
}

void *__asan_memset(void *p, int c, size_t n)
{ 
	return NULL; 
}

/*
 * Poisoning code, used when we add more freed memory to the allocator by:
 * 	a) pulling memory from the arena segment using bpf_arena_alloc_pages()
 * 	b) freeing memory from application code
 */
__hidden
int asan_poison(void __arena __arg_arena *addr, size_t size)
{
	arenaptr shadow;
	size_t len;

	/*
	 * Poisoning from a non-granule address makes no sense: We can only allocate
	 * memory to the application that with a granule-aligned starting address,
	 * and bpf_arena_alloc_pages returns page-aligned memory. A non-aligned
	 * addr then implies we're freeing a different address than the one we
	 * allocated.
	 */
	if (unlikely((u64)addr & KASAN_GRANULE_MASK)) {
		//bpf_printk("Poison region address not aligned to granule");
		return -1;
	}

	/*
	 * We cannot free an unaligned region because it's possible that we
	 * cannot describe the resulting poisoning state of the granule in 
	 * the ASAN encoding.
	 *
	 * Every granule represents a region of memory that looks like the
	 * following (P for poisoned bytes, C for clear):
	 *
	 * <Clear>  <Poisoned>
	 * [ C C C ... P P ]
	 *
	 * The value of the granule's shadow map is the number of clear bytes in
	 * it. We cannot represent granules with the following state:
	 *
	 * [ P P ... C C ... P P ]
	 *
	 * That would be possible if we could free unaligned regions, so prevent that.
	 * 
	 */
	if (unlikely(size & KASAN_GRANULE_MASK)) {
		//bpf_printk("Poison region size not aligned to granule");
		return -2;
	}

	bpf_printk("Returning %p for %p (shadow is %p)", addr, (arenaptr)((u64) addr >> KASAN_SHADOW_SCALE) + (u64)__asan_shadow_memory_dynamic_address, (arenaptr)__asan_shadow_memory_dynamic_address);
	shadow = mem_to_shadow(addr);
	len = size / KASAN_SHADOW_SCALE;

	asan_memset(shadow, KASAN_SHADOW_SCALE, len);

	return 0;
}

/*
 * Unpoisoning code for marking memory as valid during allocation calls.
 *
 * Very similar to asan_poison, except we need to round up instead of
 * down, the partially poison the last granule if necessary.
 *
 * Partial poisoning is useful for keeping the padding poisoned. Allocations
 * are granule-aligned, so we we're reserving granule-aligned sizes for the
 * allocation. However, we want to still treat accesses to the padding as 
 * invalid. Partial poisoning takes care of that. Freeing and poisoning the
 * memory is still done in granule-aligned sizes and repoisons the already
 * poisoned padding.
 */
__hidden
int asan_unpoison(void __arena __arg_arena *addr, size_t size)
{
	size_t partial = size % KASAN_SHADOW_SCALE;
	arenaptr shadow;
	size_t len;

	/*
	 * We cannot allocate in the middle of the granule. The ASAN shadow
	 * map encoding only describes regions of memory where every granule
	 * follows this format (P for poisoned, C for clear):
	 *
	 * <Clear>  <Poisoned>
	 * [ C C C ... P P ]
	 *
	 * This is so we can use a single number in [0, KASAN_SHADOW_SCALE)
	 * to represent the poison state of the granule.
	 */
	if (unlikely((u64)addr & KASAN_GRANULE_MASK)) {
//		bpf_printk("Poison region address not aligned to granule");
		return 0;
	}

	shadow = mem_to_shadow(addr);
	len = size / KASAN_SHADOW_SCALE;

	asan_memset(shadow, 0, len);

	/* 
	 * If we are allocating a non-granule aligned region, we need to adjust
	 * the last byte of the shadow map to list how many bytes in the granule
	 * are unpoisoned. If the region is aligned, then the memset call above
	 * was enough.
	 */
	if (partial)
		shadow[len] = partial;

	return 0;
}

/*
 * Initialize ASAN state when necessary. Triggered during allocator startup.
 */
__hidden
int asan_init(void)
{
	void __arena *shadowmap;

	CHECK();

	if (inited)
		return 0;

	/*
	 * XXX Fail for arenas that are < 32KiB, or are not 32KiB aligned. 
	 * Handling them would require extra edge case handling that would
	 * complicate things, and there is no good reason to support them.
	 */

	/* 
	 * Allocate the last (1/KASAN_GRANULE_SIZE)th of an arena's pages for the map
	 * We find the offset and size from the arena map.
	 *
	 * The allocated map pages are zeroed out, meaning all memory is marked as valid
	 * even if it's not allocated already. This is expected: Since the actual memory
	 * pages are not allocated, accesses to it will trigger page faults and will be
	 * reported through BPF streams. Any pages allocated through bpf_arena_alloc_pages
	 * should be poisoned by the allocator right after the call succeeds.
	 *
	 * XXX Do this lazily as denoted in the README item. Scale this with the arena
	 * size - right now we assume both in the offset and the size are for a 4GiB
	 * arena. Even for a 4GiB arena, the space overhead for lazy shadow map 
	 * allocation is 4KiB.
	 *
	 * XXX The shadowmap offset is hardcoded in mem_to_shadow, so we just allocate 
	 * the pages and drop the returned address.
	 */
	shadowmap = bpf_arena_alloc_pages(&arena, (void __arena *)KASAN_SHADOW_OFFSET, 32, NUMA_NO_NODE, 0);
	if (!shadowmap) {
		bpf_printk("Could not allocate shadow map");
		return -ENOMEM;
	}

	bpf_printk("got %p, expected %p", shadowmap, KASAN_SHADOW_OFFSET);

	CHECK();
	__asan_shadow_memory_dynamic_address = KASAN_SHADOW_OFFSET;

	CHECK();

	inited = true;

	CHECK();

	return 0;
}

#pragma clang attribute pop
