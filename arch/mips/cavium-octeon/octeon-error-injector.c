/*
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (C) 2013 Cavium, Inc.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/gpio.h>
#include <linux/interrupt.h>

#include <asm/octeon/octeon.h>
#include <asm/octeon/cvmx-fpa.h>

int test_number;
module_param(test_number, int, 0444);
MODULE_PARM_DESC(test_number, "Which test case to run.");

int test_param;
module_param(test_param, int, 0444);
MODULE_PARM_DESC(test_param, "Parameter used in the test case.");

volatile int octeon_error_injector_foo;

static void octeon_error_injector_l1_icache_parity(void)
{
	unsigned long coreid = cvmx_get_core_num();
	if (OCTEON_IS_OCTEON3() || OCTEON_IS_OCTEON2()) {
		u64 icache;

		icache = read_octeon_c0_icacheerr();
		icache |= (1ull << 31);
		write_octeon_c0_icacheerr(icache);
		asm volatile("synci	0($0)" ::: "memory");
		pr_err("Wrote CacheErr(ICache): %016llx on core %lu\n", (unsigned long long)icache, coreid);
	}
}

static void octeon_error_injector_l1_dcache_parity(void)
{
	unsigned long coreid = cvmx_get_core_num();
	if (OCTEON_IS_OCTEON3()) {
		u64 errctl;
		int i;

		errctl = read_octeon_c0_errctl();
		errctl |= (1ull << 11);
		write_octeon_c0_errctl(errctl);
		asm volatile("cache	1, 0($0)" ::: "memory");
		i = octeon_error_injector_foo;
		pr_err("Wrote ErrCtl: %016llx on core %lu\n", (unsigned long long)errctl, coreid);
	} else if (OCTEON_IS_OCTEON2()) {
		write_octeon_c0_dcacheerr(1ull<<3);
		pr_err("Wrote DCacheErr: %016llx on core %lu\n", 1ull<<3, coreid);
	}
}

static void octeon_error_injector_tlb_parity(void)
{
	if (OCTEON_IS_OCTEON3()) {
		u64 errctl = read_octeon_c0_errctl();
		errctl |= (1ull << 15);
		write_octeon_c0_errctl(errctl);
	} else if (OCTEON_IS_OCTEON2())
		write_octeon_c0_dcacheerr(1ull<<6);
}

static void octeon_error_injector_memory_read(void)
{
	u8 val;
	/* Parameter is in GB and we add 256MB for the hole. */
	u64 addr = (((u64)test_param) << 30) + (1ull << 28) + (1ull << 63);
	u8 *ptr = (u8 *)addr;

	val = *ptr;
	pr_err("Load from %p -> 0x%02x\n", ptr, val);
}

static void octeon_error_injector_fpa1(void)
{
	/* Trigger an FPA threshold indication in pool 7*/
	char *mem;
	u64 old_threshold;

	cvmx_fpa1_enable();

	mem = kmalloc(1024, GFP_KERNEL);
	if (!mem)
		return;

	/* Add two blocks. */
	cvmx_fpa_free(mem + 128, 7, 0);
	cvmx_fpa_free(mem + 256, 7, 0);

	old_threshold = cvmx_read_csr(CVMX_FPA_POOLX_THRESHOLD(7));
	/* Set the threshold to 1 */
	cvmx_write_csr(CVMX_FPA_POOLX_THRESHOLD(7), 1);

	/* Remove the blocks */
	cvmx_fpa_alloc(7);
	cvmx_fpa_alloc(7);

	kfree(mem);
	pr_err("Expecting FPA Pool 7 threshold indication.\n");
	cvmx_write_csr(CVMX_FPA_POOLX_THRESHOLD(7), old_threshold);
}

static irqreturn_t octeon_error_injector_gpio_handler(int irq, void *arg)
{
	disable_irq_nosync(irq);
	return IRQ_HANDLED;
}

static int octeon_error_injector_irq;

static void octeon_error_injector_gpio_irq(void)
{
	int rv;
	int irq = gpio_to_irq(test_param);

	pr_err("gpio_to_irq(%d) -> %d\n", test_param, irq);

	if (irq) {
		rv = request_irq(irq, octeon_error_injector_gpio_handler, 0,
				 "octeon_error_injector",
				 octeon_error_injector_gpio_handler);
		if (rv)
			pr_err("request_irq failed: %d\n", rv);
		else
			octeon_error_injector_irq = irq;
	}
}

static int __init octeon_error_injector_init(void)
{
	/* We are injecting errors, so mark the kernel as tainted.*/
	add_taint(TAINT_CRAP, LOCKDEP_STILL_OK);

	switch (test_number) {
	case 1:
		octeon_error_injector_memory_read();
		break;
	case 2:
		octeon_error_injector_fpa1();
		break;
	case 3:
		octeon_error_injector_l1_dcache_parity();
		break;
	case 4:
		octeon_error_injector_tlb_parity();
		break;
	case 5:
		octeon_error_injector_l1_icache_parity();
		break;
	case 6:
		octeon_error_injector_gpio_irq();
		break;
	default:
		pr_err("Error: Unrecognized test number: %d\n",  test_number);
		break;
	}

	return 0;
}
module_init(octeon_error_injector_init);

static void __exit octeon_error_injector_exit(void)
{
	if (octeon_error_injector_irq)
		free_irq(octeon_error_injector_irq,
			 octeon_error_injector_gpio_handler);
}
module_exit(octeon_error_injector_exit);

MODULE_LICENSE("GPL");
