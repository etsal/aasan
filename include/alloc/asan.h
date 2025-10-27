#pragma once

#define KASAN_SHADOW_SCALE 8
#define KASAN_GRANULE_MASK ((1ULL << KASAN_SHADOW_SCALE) - 1)

#define KASAN_GRANULE(expr) (((u64)expr) & KASAN_GRANULE_MASK)

int asan_init(void);
int asan_poison(void __arena *addr, size_t size);
int asan_unpoison(void __arena *addr, size_t size);
