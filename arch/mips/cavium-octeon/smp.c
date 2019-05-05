/*
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (C) 2004 - 2014 Cavium, Inc.
 */
#include <linux/cpu.h>
#include <linux/delay.h>
#include <linux/smp.h>
#include <linux/interrupt.h>
#include <linux/sched.h>
#include <linux/sched/hotplug.h>
#include <linux/sched/task_stack.h>
#include <linux/init.h>
#include <linux/export.h>
#include <linux/kexec.h>

#include <asm/time.h>
#include <asm/setup.h>
#include <asm/cacheflush.h>
#include <asm/tlbflush.h>

#include <asm/octeon/octeon.h>
#include <asm/octeon/cvmx-boot-vector.h>

unsigned long octeon_processor_boot = ~0ul;
unsigned long octeon_processor_sp;
unsigned long octeon_processor_gp;
#ifdef CONFIG_RELOCATABLE
volatile unsigned long octeon_processor_relocated_kernel_entry;
#endif /* CONFIG_RELOCATABLE */

#ifdef CONFIG_HOTPLUG_CPU
static struct cvmx_boot_vector_element *octeon_bootvector;
static void *octeon_hotplug_entry_raw;
extern asmlinkage void octeon_hotplug_entry(void);
#endif

/* State of each CPU. */
DEFINE_PER_CPU(int, cpu_state);

extern void kernel_entry(unsigned long arg1, ...);

static void octeon_icache_flush(void)
{
	asm volatile ("synci 0($0)\n");
}

static void (*octeon_message_functions[8])(void) = {
	scheduler_ipi,
	generic_smp_call_function_interrupt,
	octeon_icache_flush,
};

static  int octeon_message_free_mask = IS_ENABLED(CONFIG_KEXEC) ? 0xf0 : 0xf8;
static DEFINE_SPINLOCK(octeon_message_functions_lock);

int octeon_request_ipi_handler(octeon_message_fn_t fn)
{
	int i;
	int message;

	spin_lock(&octeon_message_functions_lock);

	for (i = 0; i < ARRAY_SIZE(octeon_message_functions); i++) {
		message = (1 << i);
		if (message & octeon_message_free_mask) {
			/* found a slot. */
			octeon_message_free_mask ^= message;
			octeon_message_functions[i] = fn;
			goto out;
		}
	}
	message = -ENOMEM;
out:
	spin_unlock(&octeon_message_functions_lock);
	return message;
}
EXPORT_SYMBOL(octeon_request_ipi_handler);

void octeon_release_ipi_handler(int action)
{
	int i;
	int message;

	spin_lock(&octeon_message_functions_lock);

	for (i = 0; i < ARRAY_SIZE(octeon_message_functions); i++) {
		message = (1 << i);
		if (message == action) {
			octeon_message_functions[i] = NULL;
			octeon_message_free_mask |= message;
			goto out;
		}
	}
	pr_err("octeon_release_ipi_handler: Unknown action: %x\n", action);
out:
	spin_unlock(&octeon_message_functions_lock);
}
EXPORT_SYMBOL(octeon_release_ipi_handler);

static irqreturn_t mailbox_interrupt(int irq, void *dev_id)
{
	u64 mbox_clrx = CVMX_CIU_MBOX_CLRX(cvmx_get_core_num());
	u64 action;
	int i;

	/*
	 * Make sure the function array initialization remains
	 * correct.
	 */
	BUILD_BUG_ON(SMP_RESCHEDULE_YOURSELF != (1 << 0));
	BUILD_BUG_ON(SMP_CALL_FUNCTION       != (1 << 1));
	BUILD_BUG_ON(SMP_ICACHE_FLUSH        != (1 << 2));

	/*
	 * Load the mailbox register to figure out what we're supposed
	 * to do.
	 */
	action = cvmx_read_csr(mbox_clrx);

	if (OCTEON_IS_MODEL(OCTEON_CN68XX))
		action &= 0xff;
	else
		action &= 0xffff;

	/* Clear the mailbox to clear the interrupt */
	cvmx_write_csr(mbox_clrx, action);

	for (i = 0; i < ARRAY_SIZE(octeon_message_functions) && action;) {
		if (action & 1) {
			void (*fn)(void) = octeon_message_functions[i];

			if (fn)
				fn();
		}
		action >>= 1;
		i++;
	}
	return IRQ_HANDLED;
}

/**
 * Cause the function described by call_data to be executed on the passed
 * cpu.	 When the function has finished, increment the finished field of
 * call_data.
 */
void octeon_send_ipi_single(int cpu, unsigned int action)
{
	int coreid = cpu_logical_map(cpu);
	cvmx_write_csr(CVMX_CIU_MBOX_SETX(coreid), action);
}
EXPORT_SYMBOL(octeon_send_ipi_single);

static inline void octeon_send_ipi_mask(const struct cpumask *mask,
					unsigned int action)
{
	int cpu;

	for_each_cpu(cpu, mask)
		octeon_send_ipi_single(cpu, action);
}

static void octeon_smp_setup(void)
{
	const int coreid = cvmx_get_core_num();
	int cpus;
	int id;
#ifdef CONFIG_HOTPLUG_CPU
	unsigned int num_cores = cvmx_octeon_num_cores();
	unsigned long t;
#endif
	struct cvmx_sysinfo *sysinfo = cvmx_sysinfo_get();

	/* The present CPUs are initially just the boot cpu (CPU 0). */
	for (id = 0; id < NR_CPUS; id++) {
		set_cpu_possible(id, id == 0);
		set_cpu_present(id, id == 0);
	}

	__cpu_number_map[coreid] = 0;
	__cpu_logical_map[0] = coreid;

	/* The present CPUs get the lowest CPU numbers. */
	cpus = 1;
	for (id = 0; id < CONFIG_MIPS_NR_CPU_NR_MAP; id++) {
		if ((id != coreid) && cvmx_coremask_is_core_set(&sysinfo->core_mask, id)) {
			set_cpu_possible(cpus, true);
			set_cpu_present(cpus, true);
			__cpu_number_map[id] = cpus;
			__cpu_logical_map[cpus] = id;
			cpus++;
		}
	}

#ifdef CONFIG_HOTPLUG_CPU

	octeon_bootvector = cvmx_boot_vector_get();
	if (!octeon_bootvector) {
		pr_err("Error: Cannot allocate boot vector.\n");
		return;
	}
	t = __pa_symbol(octeon_hotplug_entry);
	octeon_hotplug_entry_raw = phys_to_virt(t);

	/*
	 * The possible CPUs are all those present on the chip.	 We
	 * will assign CPU numbers for possible cores as well.	Cores
	 * are always consecutively numberd from 0.
	 */
	for (id = 0; id < num_cores && id < NR_CPUS; id++) {
		if (!(cvmx_coremask_is_core_set(&sysinfo->core_mask, id))) {
			set_cpu_possible(cpus, true);
			__cpu_number_map[id] = cpus;
			__cpu_logical_map[cpus] = id;
			cpus++;
		}
	}
#endif
}


#ifdef CONFIG_RELOCATABLE
int plat_post_relocation(long offset)
{
	unsigned long entry = (unsigned long)kernel_entry;

	/* Send secondaries into relocated kernel */
	octeon_processor_relocated_kernel_entry = entry + offset;

	return 0;
}
#endif /* CONFIG_RELOCATABLE */

/**
 * Firmware CPU startup hook
 *
 */
static int octeon_boot_secondary(int cpu, struct task_struct *idle)
{
	int count;
	int ret = 0;

	pr_info("SMP: Booting CPU%02d (CoreId %2d)...\n", cpu,
		cpu_logical_map(cpu));

	octeon_processor_sp = __KSTK_TOS(idle);
	octeon_processor_gp = (unsigned long)(task_thread_info(idle));
	/* This barrier is needed to guarangee the following is done last */
	mb();

	/* Indicate which core is being brought up out of pan */
	octeon_processor_boot = cpu_logical_map(cpu);

	/* Push the last update out before polling */
	mb();

	count = 10000;
	while (octeon_processor_sp && count) {
		/* Waiting for processor to get the SP and GP */
		udelay(1);
		count--;
		mb();
	}
	if (count == 0) {
		pr_err("Secondary boot timeout\n");
		ret = -ETIMEDOUT;
	}

	octeon_processor_boot = ~0ul;
	mb();
	return ret;
}

/**
 * After we've done initial boot, this function is called to allow the
 * board code to clean up state, if needed
 */
static void octeon_init_secondary(void)
{
	unsigned int sr;

	sr = set_c0_status(ST0_BEV);
	write_c0_ebase((u32)ebase);
	write_c0_status(sr);

	octeon_check_cpu_bist();
	octeon_init_cvmcount();

	octeon_irq_setup_secondary();
}

static irqreturn_t octeon_78xx_smp_dump_interrupt(int irq, void *dev_id)
{
#ifdef CONFIG_KEXEC
	octeon_crash_dump();
#endif
	return IRQ_HANDLED;
}

/**
 * Callout to firmware before smp_init
 *
 */
static void __init octeon_prepare_cpus(unsigned int max_cpus)
{
	u64 mask;
	u64 coreid;

	/*
	 * Only the low order mailbox bits are used for IPIs, leave
	 * the other bits alone.
	 */
	if (OCTEON_IS_MODEL(OCTEON_CN68XX))
		mask = 0xff;
	else
		mask = 0xffff;

	coreid = cvmx_get_core_num();

	/* Clear pending mailbox interrupts */
	cvmx_write_csr(CVMX_CIU_MBOX_CLRX(coreid), mask);

	/* Attach mailbox interrupt handler */
	if (request_irq(OCTEON_IRQ_MBOX0, mailbox_interrupt,
			IRQF_PERCPU | IRQF_NO_THREAD, "SMP-IPI",
			mailbox_interrupt)) {
		panic("Cannot request_irq(OCTEON_IRQ_MBOX0)");
	}
}

/**
 * Last chance for the board code to finish SMP initialization before
 * the CPU is "online".
 */
static void octeon_smp_finish(void)
{
	octeon_user_io_init();
	per_cpu(cpu_state, smp_processor_id()) = CPU_ONLINE;
	mb();
	octeon_numa_cpu_online();

	/* to generate the first CPU timer interrupt */
	write_c0_compare(read_c0_count() + mips_hpt_frequency / HZ);
	local_irq_enable();
}

#ifdef CONFIG_HOTPLUG_CPU

static int octeon_cpu_disable(void)
{
	unsigned int cpu = smp_processor_id();

	if (cpu == 0)
		return -EBUSY;

	set_cpu_online(cpu, false);
	calculate_cpu_foreign_map();
	octeon_fixup_irqs();

	__flush_cache_all();
	local_flush_tlb_all();

	return 0;
}

static void octeon_cpu_die(unsigned int cpu)
{
	while (per_cpu(cpu_state, cpu) != CPU_DEAD)
		cpu_relax();
}

void play_dead(void)
{
	int cpu = cpu_number_map(cvmx_get_core_num());
	idle_task_exit();
	per_cpu(cpu_state, cpu) = CPU_DEAD;
	mb();
	local_irq_disable();
	while (1) {	/* core will be reset here */
		asm volatile ("nop\n"
			      "	wait\n"
			      "	nop\n");
	}
}

static int octeon_up_prepare(unsigned int cpu)
{
	int coreid = cpu_logical_map(cpu);
	int node;

	per_cpu(cpu_state, cpu) = CPU_UP_PREPARE;
	octeon_bootvector[coreid].target_ptr = (uint64_t)octeon_hotplug_entry_raw;
	mb();
	/* Convert coreid to node,core spair and send NMI to target core */
	node = cvmx_coremask_core_to_node(coreid);
	coreid = cvmx_coremask_core_on_node(coreid);
	if (octeon_has_feature(OCTEON_FEATURE_CIU3))
		cvmx_write_csr_node(node, CVMX_CIU3_NMI, (1ull << coreid));
	else
		cvmx_write_csr(CVMX_CIU_NMI, (1ull << coreid));
	return 0;
}

static int octeon_cpu_callback(struct notifier_block *nfb,
	unsigned long action, void *hcpu)
{
	unsigned int cpu = (unsigned long)hcpu;
	int ret = 0;

	switch (action) {
	case CPU_UP_PREPARE_FROZEN:
	case CPU_UP_PREPARE:
		ret = octeon_up_prepare(cpu);
		if (ret)
			return notifier_from_errno(ret);
		break;
	case CPU_ONLINE_FROZEN:
	case CPU_ONLINE:
		pr_info("Cpu %d online\n", cpu);
		break;
	case CPU_DEAD_FROZEN:
	case CPU_DEAD:
		pr_info("Cpu %d offline\n", cpu);
		break;
	default:
		/* No action required for other events */
		break;
	}

	return NOTIFY_OK;
}

static struct notifier_block octeon_cpu_notifer = {
	.notifier_call = octeon_cpu_callback,
};

static int register_cavium_notifier(void)
{
	return register_cpu_notifier(&octeon_cpu_notifer);
}

early_initcall(register_cavium_notifier);

#endif	/* CONFIG_HOTPLUG_CPU */

static const struct plat_smp_ops octeon_smp_ops = {
	.send_ipi_single	= octeon_send_ipi_single,
	.send_ipi_mask		= octeon_send_ipi_mask,
	.init_secondary		= octeon_init_secondary,
	.smp_finish		= octeon_smp_finish,
	.boot_secondary		= octeon_boot_secondary,
	.smp_setup		= octeon_smp_setup,
	.prepare_cpus		= octeon_prepare_cpus,
#ifdef CONFIG_HOTPLUG_CPU
	.cpu_disable		= octeon_cpu_disable,
	.cpu_die		= octeon_cpu_die,
#endif
#ifdef CONFIG_KEXEC
	.kexec_nonboot_cpu	= kexec_nonboot_cpu_jump,
#endif
};

static irqreturn_t octeon_78xx_reched_interrupt(int irq, void *dev_id)
{
	scheduler_ipi();
	return IRQ_HANDLED;
}

static irqreturn_t octeon_78xx_call_function_interrupt(int irq, void *dev_id)
{
	generic_smp_call_function_interrupt();
	return IRQ_HANDLED;
}

static irqreturn_t octeon_78xx_icache_flush_interrupt(int irq, void *dev_id)
{
	octeon_icache_flush();
	return IRQ_HANDLED;
}

/*
 * Callout to firmware before smp_init
 */
static void octeon_78xx_prepare_cpus(unsigned int max_cpus)
{
	if (request_irq(OCTEON_IRQ_MBOX0 + 0,
			octeon_78xx_reched_interrupt,
			IRQF_PERCPU | IRQF_NO_THREAD, "Scheduler",
			octeon_78xx_reched_interrupt)) {
		panic("Cannot request_irq for SchedulerIPI");
	}
	if (request_irq(OCTEON_IRQ_MBOX0 + 1,
			octeon_78xx_call_function_interrupt,
			IRQF_PERCPU | IRQF_NO_THREAD, "SMP-Call",
			octeon_78xx_call_function_interrupt)) {
		panic("Cannot request_irq for SMP-Call");
	}
	if (request_irq(OCTEON_IRQ_MBOX0 + 2,
			octeon_78xx_icache_flush_interrupt,
			IRQF_PERCPU | IRQF_NO_THREAD, "ICache-Flush",
			octeon_78xx_icache_flush_interrupt)) {
		panic("Cannot request_irq for ICache-Flush");
	}
	if (request_irq(OCTEON_IRQ_MBOX0 + 3, octeon_78xx_smp_dump_interrupt,
			IRQF_PERCPU | IRQF_NO_THREAD, "SMP-Dump",
			octeon_78xx_smp_dump_interrupt)) {
		panic("Cannot request_irq for SMP-Dump");
	}
}

static void octeon_78xx_send_ipi_single(int cpu, unsigned int action)
{
	int i;

	for (i = 0; i < 8; i++) {
		if (action & 1)
			octeon_ciu3_mbox_send(cpu, i);
		action >>= 1;
	}
}

static void octeon_78xx_send_ipi_mask(const struct cpumask *mask,
				      unsigned int action)
{
	unsigned int cpu;

	for_each_cpu(cpu, mask)
		octeon_78xx_send_ipi_single(cpu, action);
}

static const struct plat_smp_ops octeon_78xx_smp_ops = {
	.send_ipi_single	= octeon_78xx_send_ipi_single,
	.send_ipi_mask		= octeon_78xx_send_ipi_mask,
	.init_secondary		= octeon_init_secondary,
	.smp_finish		= octeon_smp_finish,
	.boot_secondary		= octeon_boot_secondary,
	.smp_setup		= octeon_smp_setup,
	.prepare_cpus		= octeon_78xx_prepare_cpus,
#ifdef CONFIG_HOTPLUG_CPU
	.cpu_disable		= octeon_cpu_disable,
	.cpu_die		= octeon_cpu_die,
#endif
#ifdef CONFIG_KEXEC
	.kexec_nonboot_cpu	= kexec_nonboot_cpu_jump,
#endif
};

void __init octeon_setup_smp(void)
{
	const struct plat_smp_ops *ops;

	if (octeon_has_feature(OCTEON_FEATURE_CIU3))
		ops = &octeon_78xx_smp_ops;
	else
		ops = &octeon_smp_ops;

	register_smp_ops(ops);
}
