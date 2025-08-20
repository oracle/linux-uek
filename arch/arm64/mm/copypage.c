// SPDX-License-Identifier: GPL-2.0-only
/*
 * Based on arch/arm/mm/copypage.c
 *
 * Copyright (C) 2002 Deep Blue Solutions Ltd, All Rights Reserved.
 * Copyright (C) 2012 ARM Ltd.
 */

#include <linux/bitops.h>
#include <linux/mm.h>

#include <asm/page.h>
#include <asm/cacheflush.h>
#include <asm/cpufeature.h>
#include <asm/mte.h>

void copy_highpage(struct page *to, struct page *from)
{
	void *kto = page_address(to);
	void *kfrom = page_address(from);
	unsigned int i, nr_pages;

	copy_page(kto, kfrom);

	page_kasan_tag_reset(to);

	if (!system_supports_mte())
		return;

	if (PageHuge(from) && test_bit(PG_mte_tagged, &compound_head(from)->flags)) {
		from = compound_head(from);
		to = compound_head(to);
		nr_pages = compound_nr(from);
		set_bit(PG_mte_tagged, &to->flags);
		/*
		 * See comment below
		 */
		smp_wmb();
		for (i = 0; i < nr_pages; from++, to++) {
			kfrom = page_address(from);
			kto = page_address(to);
			mte_copy_page_tags(kto, kfrom);
		}
	} else if (test_bit(PG_mte_tagged, &from->flags)) {
		set_bit(PG_mte_tagged, &to->flags);
		/*
		 * We need smp_wmb() in between setting the flags and clearing the
		 * tags because if another thread reads page->flags and builds a
		 * tagged address out of it, there is an actual dependency to the
		 * memory access, but on the current thread we do not guarantee that
		 * the new page->flags are visible before the tags were updated.
		 */
		smp_wmb();
		mte_copy_page_tags(kto, kfrom);
	}
}
EXPORT_SYMBOL(copy_highpage);

void copy_user_highpage(struct page *to, struct page *from,
			unsigned long vaddr, struct vm_area_struct *vma)
{
	copy_highpage(to, from);
	flush_dcache_page(to);
}
EXPORT_SYMBOL_GPL(copy_user_highpage);
