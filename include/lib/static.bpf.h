#pragma once

struct scx_static {
	size_t max_alloc_bytes;
	void __arena *memory;
	size_t off;
};
