/*
 * linux/arch/mips/include/asm/perf_event.h
 *
 * Copyright (C) 2010 MIPS Technologies, Inc.
 * Author: Deng-Cheng Zhu
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef __MIPS_PERF_EVENT_H__
#define __MIPS_PERF_EVENT_H__

#include <linux/notifier.h>

/* Allow CPU specific actions on PMU state changes. */
int mipspmu_notifier_register(struct notifier_block *nb);
int mipspmu_notifier_unregister(struct notifier_block *nb);
#define MIPSPMU_ENABLE 0
#define MIPSPMU_DISABLE 1

#endif /* __MIPS_PERF_EVENT_H__ */
