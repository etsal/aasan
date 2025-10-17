/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2023 Tejun Heo <tj@kernel.org>
 * Copyright (c) 2023 David Vernet <dvernet@meta.com>
 */
#ifndef __SCHED_EXT_COMMON_H
#define __SCHED_EXT_COMMON_H

#ifdef __KERNEL__
#error "Should not be included by BPF programs"
#endif

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int8_t s8;
typedef int16_t s16;
typedef int32_t s32;
typedef int64_t s64;

/* not available when building kernel tools/sched_ext */
#if __has_include(<lib/sdt_task_defs.h>)
#include "bpf_arena_common.h"
#include <lib/sdt_task_defs.h>
#endif

#endif	/* __SCHED_EXT_COMMON_H */
