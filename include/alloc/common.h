#ifndef __ALLOC_COMMON_H__

#define arena_stdout(fmt, ...) bpf_stream_printk(1, (fmt), __VA_ARGS__)
#define arena_stderr(fmt, ...) bpf_stream_printk(2, (fmt), __VA_ARGS__)

int arena_bug_trigger(const char *file, int line);

#endif /* __ALLOC_COMMON_H__ */
