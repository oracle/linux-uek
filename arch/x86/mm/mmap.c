/*
 * Flexible mmap layout support
 *
 * Based on code by Ingo Molnar and Andi Kleen, copyrighted
 * as follows:
 *
 * Copyright 2003-2009 Red Hat Inc.
 * All Rights Reserved.
 * Copyright 2005 Andi Kleen, SUSE Labs.
 * Copyright 2007 Jiri Kosina, SUSE Labs.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <linux/personality.h>
#include <linux/mm.h>
#include <linux/random.h>
#include <linux/limits.h>
#include <linux/sched.h>
#include <asm/elf.h>

#include "physaddr.h"

struct va_alignment __read_mostly va_align = {
	.flags = -1,
};

static unsigned long stack_maxrandom_size(void)
{
	unsigned long max = 0;
	if ((current->flags & PF_RANDOMIZE) &&
		!(current->personality & ADDR_NO_RANDOMIZE)) {
		max = ((-1UL) & STACK_RND_MASK) << PAGE_SHIFT;
	}

	return max;
}

/*
 * Top of mmap area (just below the process stack).
 *
 * Leave an at least ~128 MB hole with possible stack randomization.
 */
#define MIN_GAP (128*1024*1024UL + stack_maxrandom_size())
#define MAX_GAP (TASK_SIZE/6*5)

static int mmap_is_legacy(void)
{
	if (current->personality & ADDR_COMPAT_LAYOUT)
		return 1;

	if (rlimit(RLIMIT_STACK) == RLIM_INFINITY)
		return 1;

	return sysctl_legacy_va_layout;
}

unsigned long arch_mmap_rnd(void)
{
	unsigned long rnd;

	/*
	 *  8 bits of randomness in 32bit mmaps, 20 address space bits
	 * 28 bits of randomness in 64bit mmaps, 40 address space bits
	 */
	if (mmap_is_ia32())
		rnd = (unsigned long)get_random_int() % (1<<8);
	else
		rnd = (unsigned long)get_random_int() % (1<<28);

	return rnd << PAGE_SHIFT;
}

static unsigned long mmap_base(unsigned long rnd)
{
	unsigned long gap = rlimit(RLIMIT_STACK);

	if (gap < MIN_GAP)
		gap = MIN_GAP;
	else if (gap > MAX_GAP)
		gap = MAX_GAP;

	return PAGE_ALIGN(TASK_SIZE - gap - rnd);
}

/*
 * This function, called very early during the creation of a new
 * process VM image, sets up which VM layout function to use:
 */
void arch_pick_mmap_layout(struct mm_struct *mm)
{
	unsigned long random_factor = 0UL;

	if (current->flags & PF_RANDOMIZE)
		random_factor = arch_mmap_rnd();

	mm->mmap_legacy_base = TASK_UNMAPPED_BASE + random_factor;

	if (mmap_is_legacy()) {
		mm->mmap_base = mm->mmap_legacy_base;
		mm->get_unmapped_area = arch_get_unmapped_area;
	} else {
		mm->mmap_base = mmap_base(random_factor);
		mm->get_unmapped_area = arch_get_unmapped_area_topdown;
	}
}

const char *arch_vma_name(struct vm_area_struct *vma)
{
	if (vma->vm_flags & VM_MPX)
		return "[mpx]";
	return NULL;
}

/**
 * mmap_address_hint_valid - Validate the address hint of mmap
 * @addr:	Address hint
 * @len:	Mapping length
 *
 * Check whether @addr and @addr + @len result in a valid mapping.
 *
 * On 32bit this only checks whether @addr + @len is <= TASK_SIZE.
 *
 * On 64bit with 5-level page tables another sanity check is required
 * because mappings requested by mmap(@addr, 0) which cross the 47-bit
 * virtual address boundary can cause the following theoretical issue:
 *
 *  An application calls mmap(addr, 0), i.e. without MAP_FIXED, where @addr
 *  is below the border of the 47-bit address space and @addr + @len is
 *  above the border.
 *
 *  With 4-level paging this request succeeds, but the resulting mapping
 *  address will always be within the 47-bit virtual address space, because
 *  the hint address does not result in a valid mapping and is
 *  ignored. Hence applications which are not prepared to handle virtual
 *  addresses above 47-bit work correctly.
 *
 *  With 5-level paging this request would be granted and result in a
 *  mapping which crosses the border of the 47-bit virtual address
 *  space. If the application cannot handle addresses above 47-bit this
 *  will lead to misbehaviour and hard to diagnose failures.
 *
 * Therefore ignore address hints which would result in a mapping crossing
 * the 47-bit virtual address boundary.
 *
 * Note, that in the same scenario with MAP_FIXED the behaviour is
 * different. The request with @addr < 47-bit and @addr + @len > 47-bit
 * fails on a 4-level paging machine but succeeds on a 5-level paging
 * machine. It is reasonable to expect that an application does not rely on
 * the failure of such a fixed mapping request, so the restriction is not
 * applied.
 */
bool mmap_address_hint_valid(unsigned long addr, unsigned long len)
{
	if (TASK_SIZE - len < addr)
		return false;

	return (addr > TASK_SIZE_MAX) == (addr + len > TASK_SIZE_MAX);
}

/* Can we access it for direct reading/writing? Must be RAM: */
int valid_phys_addr_range(phys_addr_t addr, size_t count)
{
	return addr + count <= __pa(high_memory);
}

/* Can we access it through mmap? Must be a valid physical address: */
int valid_mmap_phys_addr_range(unsigned long pfn, size_t count)
{
	phys_addr_t addr = (phys_addr_t)pfn << PAGE_SHIFT;

	return phys_addr_valid(addr + count - 1);
}

/*
 * Only allow root to set high MMIO mappings to PROT_NONE.
 * This prevents an unpriv. user to set them to PROT_NONE and invert
 * them, then pointing to valid memory for L1TF speculation.
 *
 * Note: for locked down kernels may want to disable the root override.
 */
bool pfn_modify_allowed(unsigned long pfn, pgprot_t prot)
{
	if (!boot_cpu_has_bug(X86_BUG_L1TF))
		return true;
	if (!__pte_needs_invert(pgprot_val(prot)))
		return true;
	/* If it's real memory always allow */
	if (pfn_valid(pfn))
		return true;
	if (pfn >= l1tf_pfn_limit() && !capable(CAP_SYS_ADMIN))
		return false;
	return true;
}
