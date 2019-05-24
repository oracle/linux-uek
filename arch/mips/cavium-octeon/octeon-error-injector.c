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

#include <asm/octeon/octeon.h>
#include <asm/octeon/cvmx-fpa.h>

int test_number;
module_param(test_number, int, 0444);
MODULE_PARM_DESC(test_number, "Which test case to run.");

int test_param;
module_param(test_param, int, 0444);
MODULE_PARM_DESC(test_param, "Parameter used in the test case.");

static void octeon_error_injector_l1_dcache_parity(void)
{
	if (OCTEON_IS_OCTEON3())
		write_octeon_c0_errctl(1ull<<11);
	else if (OCTEON_IS_OCTEON2())
		write_octeon_c0_dcacheerr(1ull<<3);
}

static void octeon_error_injector_tlb_parity(void)
{
	if (OCTEON_IS_OCTEON3())
		write_octeon_c0_errctl(1ull<<15);
	else if (OCTEON_IS_OCTEON2())
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

	cvmx_fpa_enable();

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
	default:
		pr_err("Error: Unrecognized test number: %d\n",  test_number);
		break;
	}

	return 0;
}
module_init(octeon_error_injector_init);

static void __exit octeon_error_injector_exit(void)
{
}
module_exit(octeon_error_injector_exit);

MODULE_LICENSE("GPL");
