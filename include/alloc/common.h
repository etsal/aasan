#ifndef __ALLOC_COMMON_H__

#define arena_stdout(fmt, ...) bpf_stream_printk(1, (fmt), __VA_ARGS__)
#define arena_stderr(fmt, ...) bpf_stream_printk(2, (fmt), __VA_ARGS__)

#define DIAG() (arena_stderr("%s:%d\n", __func__, __LINE__))

static inline void
arena_bug_trigger(const char *func, const int line)
{
	volatile u8 __arena *nullptr = (u8 __arena *)0ULL;

	*nullptr = 0;
}

#endif /* __ALLOC_COMMON_H__ */
