// SPDX-License-Identifier: GPL-2.0-only
#include <linux/fs.h>
#include <linux/interrupt.h>
#include <asm/octeon/octeon.h>
#include <asm/octeon/cvmx-ciu-defs.h>
#include <asm/octeon/cvmx-ciu3-defs.h>
#include <asm/octeon/cvmx.h>
#include <linux/debugfs.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/seq_file.h>

#define TIMER_NUM 3

static int oct_ilm_irq;
static u64 ciu_timx_reg;

static bool reset_stats;

struct latency_info {
	u64 io_interval;
	u64 cpu_interval;
	u64 timer_start1;
	u64 timer_start2;
	u64 max_latency;
	u64 min_latency;
	u64 latency_sum;
	u64 average_latency;
	u64 interrupt_cnt;
};

static struct latency_info li;
static struct dentry *dir;

static int show_latency(struct seq_file *m, void *v)
{
	u64 cpuclk, avg, max, min;
	struct latency_info curr_li = li;

	cpuclk = octeon_get_clock_rate();

	max = (curr_li.max_latency * 1000000000) / cpuclk;
	min = (curr_li.min_latency * 1000000000) / cpuclk;
	avg = (curr_li.latency_sum * 1000000000) / (cpuclk * curr_li.interrupt_cnt);

	seq_printf(m, "cnt: %10lld, avg: %7lld ns, max: %7lld ns, min: %7lld ns\n",
		   curr_li.interrupt_cnt, avg, max, min);
	return 0;
}

static int oct_ilm_open(struct inode *inode, struct file *file)
{
	return single_open(file, show_latency, NULL);
}

static const struct file_operations oct_ilm_ops = {
	.open = oct_ilm_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

static int reset_statistics(void *data, u64 value)
{
	reset_stats = true;
	return 0;
}

DEFINE_SIMPLE_ATTRIBUTE(reset_statistics_ops, NULL, reset_statistics, "%llu\n");

static void init_debugfs(void)
{
	dir = debugfs_create_dir("oct_ilm", 0);
	debugfs_create_file("statistics", 0444, dir, NULL, &oct_ilm_ops);
	debugfs_create_file("reset", 0220, dir, NULL, &reset_statistics_ops);
}

static void init_latency_info(struct latency_info *li, int startup)
{
	/* interval in milli seconds after which the interrupt will
	 * be triggered
	 */
	int interval = 1;

	if (startup) {
		/* Calculating by the amounts io clock and cpu clock would
		 *  increment in interval amount of ms
		 */
		li->io_interval = (octeon_get_io_clock_rate() * interval) / 1000;
		li->cpu_interval = (octeon_get_clock_rate() * interval) / 1000;
	}
	li->timer_start1 = 0;
	li->timer_start2 = 0;
	li->max_latency = 0;
	li->min_latency = (u64)-1;
	li->latency_sum = 0;
	li->interrupt_cnt = 0;
}


static void start_timer(u64 interval)
{
	union cvmx_ciu_timx timx;
	unsigned long flags;

	timx.u64 = 0;
	timx.s.one_shot = 1;
	timx.s.len = interval;
	raw_local_irq_save(flags);
	li.timer_start1 = read_c0_cvmcount();
	cvmx_write_csr(ciu_timx_reg, timx.u64);
	/* Read it back to force wait until register is written. */
	timx.u64 = cvmx_read_csr(ciu_timx_reg);
	li.timer_start2 = read_c0_cvmcount();
	raw_local_irq_restore(flags);
}


static irqreturn_t cvm_oct_ciu_timer_interrupt(int cpl, void *dev_id)
{
	u64 last_latency;
	u64 last_int_cnt;

	if (reset_stats) {
		init_latency_info(&li, 0);
		reset_stats = false;
	} else {
		last_int_cnt = read_c0_cvmcount();
		last_latency = last_int_cnt - (li.timer_start1 + li.cpu_interval);
		li.interrupt_cnt++;
		li.latency_sum += last_latency;
		if (last_latency > li.max_latency)
			li.max_latency = last_latency;
		if (last_latency < li.min_latency)
			li.min_latency = last_latency;
	}
	start_timer(li.io_interval);
	return IRQ_HANDLED;
}

static void disable_timer(void)
{
	union cvmx_ciu_timx timx;

	timx.s.one_shot = 0;
	timx.s.len = 0;
	cvmx_write_csr(ciu_timx_reg, timx.u64);
	/* Read it back to force immediate write of timer register*/
	timx.u64 = cvmx_read_csr(ciu_timx_reg);
}

static __init int oct_ilm_module_init(void)
{
	int rc;

	if (octeon_has_feature(OCTEON_FEATURE_CIU3)) {
		int intsn = 0x2000 + 0x80 * TIMER_NUM;
		struct irq_domain *d = octeon_irq_get_block_domain(0, intsn >> 12);

		oct_ilm_irq = irq_create_mapping(d, intsn);
		irqd_set_trigger_type(irq_get_irq_data(oct_ilm_irq),
				      IRQ_TYPE_EDGE_RISING);

		ciu_timx_reg = CVMX_CIU3_TIMX(TIMER_NUM);
	} else {
		oct_ilm_irq = OCTEON_IRQ_TIMER0 + TIMER_NUM;
		ciu_timx_reg = CVMX_CIU_TIMX(TIMER_NUM);
	}

	init_debugfs();

	rc = request_irq(oct_ilm_irq, cvm_oct_ciu_timer_interrupt, IRQF_NO_THREAD,
			 "oct_ilm", 0);
	if (rc) {
		WARN(1, "Could not acquire IRQ %d", oct_ilm_irq);
		goto err_irq;
	}

	init_latency_info(&li, 1);
	start_timer(li.io_interval);

	return 0;
err_irq:
	debugfs_remove_recursive(dir);
	return rc;
}

static __exit void oct_ilm_module_exit(void)
{
	disable_timer();
	debugfs_remove_recursive(dir);
	free_irq(oct_ilm_irq, 0);
}

module_exit(oct_ilm_module_exit);
module_init(oct_ilm_module_init);
MODULE_AUTHOR("Venkat Subbiah, Cavium");
MODULE_DESCRIPTION("Measures interrupt latency on Octeon chips.");
MODULE_LICENSE("GPL");
