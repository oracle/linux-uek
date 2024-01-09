/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * linux/arch/mips/include/asm/perf_event.h
 *
 * Copyright (C) 2010 MIPS Technologies, Inc.
 * Author: Deng-Cheng Zhu
 */

#ifndef __MIPS_PERF_EVENT_H__
#define __MIPS_PERF_EVENT_H__

#include <linux/notifier.h>

/* Allow CPU specific actions on PMU state changes. */
int mipspmu_notifier_register(struct notifier_block *nb);
int mipspmu_notifier_unregister(struct notifier_block *nb);
#define MIPSPMU_ACTIVE 0
#define MIPSPMU_INACTIVE 1

#endif /* __MIPS_PERF_EVENT_H__ */
