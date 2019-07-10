// SPDX-License-Identifier: GPL-2.0
/*
 * cpuidle driver for halt polling.
 *
 * Copyright 2019 Red Hat, Inc. and/or its affiliates.
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 * Authors: Marcelo Tosatti <mtosatti@redhat.com>
 */

#include <linux/init.h>
#include <linux/cpuidle.h>
#include <linux/module.h>
#include <linux/sched/clock.h>
#include <linux/sched/idle.h>
#include <linux/cpuidle_haltpoll.h>
#include <linux/kvm_para.h>

static unsigned int guest_halt_poll_ns __read_mostly = 200000;
module_param(guest_halt_poll_ns, uint, 0644);

/* division factor to shrink halt_poll_ns */
static unsigned int guest_halt_poll_shrink __read_mostly = 2;
module_param(guest_halt_poll_shrink, uint, 0644);

/* multiplication factor to grow per-cpu halt_poll_ns */
static unsigned int guest_halt_poll_grow __read_mostly = 2;
module_param(guest_halt_poll_grow, uint, 0644);

/* value in ns to start growing per-cpu halt_poll_ns */
static unsigned int guest_halt_poll_grow_start __read_mostly = 10000;
module_param(guest_halt_poll_grow_start, uint, 0644);

/* value in ns to start growing per-cpu halt_poll_ns */
static bool guest_halt_poll_allow_shrink __read_mostly = true;
module_param(guest_halt_poll_allow_shrink, bool, 0644);

static DEFINE_PER_CPU(unsigned int, halt_poll_ns);

static void adjust_haltpoll_ns(unsigned int block_ns,
			       unsigned int *cpu_halt_poll_ns)
{
	unsigned int val;

	/* Grow cpu_halt_poll_ns if
	 * cpu_halt_poll_ns < block_ns < guest_halt_poll_ns
	 */
	if (block_ns > *cpu_halt_poll_ns && block_ns <= guest_halt_poll_ns) {
		val = *cpu_halt_poll_ns * guest_halt_poll_grow;

		if (val < guest_halt_poll_grow_start)
			val = guest_halt_poll_grow_start;
		if (val > guest_halt_poll_ns)
			val = guest_halt_poll_ns;

		*cpu_halt_poll_ns = val;
	} else if (block_ns > guest_halt_poll_ns &&
		   guest_halt_poll_allow_shrink) {
		unsigned int shrink = guest_halt_poll_shrink;

		val = *cpu_halt_poll_ns;
		if (shrink == 0)
			val = 0;
		else
			val /= shrink;
		*cpu_halt_poll_ns = val;
	}
}

static int haltpoll_enter_idle(struct cpuidle_device *dev,
			       struct cpuidle_driver *drv, int index)
{
	unsigned int *cpu_halt_poll_ns;
	unsigned long long start, now, block_ns;
	int cpu = smp_processor_id();

	cpu_halt_poll_ns = per_cpu_ptr(&halt_poll_ns, cpu);

	if (current_set_polling_and_test()) {
		local_irq_enable();
		goto out;
	}

	start = sched_clock();
	local_irq_enable();
	for (;;) {
		if (need_resched()) {
			current_clr_polling();
			goto out;
		}

		now = sched_clock();
		if (now - start > *cpu_halt_poll_ns)
			break;

		cpu_relax();
	}

	local_irq_disable();
	if (current_clr_polling_and_test()) {
		local_irq_enable();
		goto out;
	}

	default_idle();
	block_ns = sched_clock() - start;
	adjust_haltpoll_ns(block_ns, cpu_halt_poll_ns);

out:
	return index;
}

static struct cpuidle_driver haltpoll_driver = {
	.name = "haltpoll_idle",
	.owner = THIS_MODULE,
	.states = {
		{ /* entry 0 is for polling */ },
		{
			.enter			= haltpoll_enter_idle,
			.exit_latency		= 0,
			.target_residency	= 0,
			.power_usage		= -1,
			.name			= "Halt poll",
			.desc			= "Halt poll idle",
		},
	},
	.safe_state_index = 0,
	.state_count = 2,
};

static int __init haltpoll_init(void)
{
	struct cpuidle_driver *drv = &haltpoll_driver;
	int ret;

	if (!kvm_para_available())
		return 0;

	cpuidle_poll_state_init(drv);

	ret = cpuidle_register(drv, NULL);

 	if (ret == 0)
 		arch_haltpoll_enable();
 
 	return ret;
}

static void __exit haltpoll_exit(void)
{
	arch_haltpoll_disable();
	cpuidle_unregister(&haltpoll_driver);
}

module_init(haltpoll_init);
module_exit(haltpoll_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Marcelo Tosatti <mtosatti@redhat.com>");

