/*
 * SPARC64 Huge TLB page support.
 *
 * Copyright (C) 2002, 2003, 2006 David S. Miller (davem@davemloft.net)
 */

#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/hugetlb.h>
#include <linux/pagemap.h>
#include <linux/sysctl.h>
#include <asm/mman.h>
#include <asm/pgalloc.h>
#include <asm/tlb.h>
#include <asm/tlbflush.h>
#include <asm/cacheflush.h>
#include <asm/mmu_context.h>
#include <asm/pgtable.h>

/* Slightly simplified from the non-hugepage variant because by
 * definition we don't have to worry about any page coloring stuff
 */
static unsigned long hugetlb_get_unmapped_area_bottomup(struct file *file,
							unsigned long addr,
							unsigned long len,
							unsigned long pgoff,
							unsigned long flags)
{
	struct hstate *h = hstate_file(file);
	unsigned long task_size = TASK_SIZE;
	struct vm_unmapped_area_info info;

	if (test_thread_flag(TIF_32BIT))
		task_size = STACK_TOP32;

	info.flags = 0;
	info.length = len;
	info.low_limit = TASK_UNMAPPED_BASE;
	info.high_limit = min(task_size, VA_EXCLUDE_START);
	info.align_mask = PAGE_MASK & ~huge_page_mask(h);
	info.align_offset = 0;
	addr = vm_unmapped_area(&info);

	if ((addr & ~PAGE_MASK) && task_size > VA_EXCLUDE_END) {
		VM_BUG_ON(addr != -ENOMEM);
		info.low_limit = VA_EXCLUDE_END;
		info.high_limit = task_size;
		addr = vm_unmapped_area(&info);
	}

	return addr;
}

static unsigned long
hugetlb_get_unmapped_area_topdown(struct file *file,
				  const unsigned long addr0,
				  const unsigned long len,
				  const unsigned long pgoff,
				  const unsigned long flags)
{
	struct hstate *h = hstate_file(file);
	struct mm_struct *mm = current->mm;
	unsigned long addr = addr0;
	struct vm_unmapped_area_info info;

	/* This should only ever run for 32-bit processes.  */
	BUG_ON(!test_thread_flag(TIF_32BIT));

	info.flags = VM_UNMAPPED_AREA_TOPDOWN;
	info.length = len;
	info.low_limit = PAGE_SIZE;
	info.high_limit = mm->mmap_base;
	info.align_mask = PAGE_MASK & ~huge_page_mask(h);
	info.align_offset = 0;
	addr = vm_unmapped_area(&info);

	/*
	 * A failed mmap() very likely causes application failure,
	 * so fall back to the bottom-up function here. This scenario
	 * can happen with large stack limits and large mmap()
	 * allocations.
	 */
	if (addr & ~PAGE_MASK) {
		VM_BUG_ON(addr != -ENOMEM);
		info.flags = 0;
		info.low_limit = TASK_UNMAPPED_BASE;
		info.high_limit = STACK_TOP32;
		addr = vm_unmapped_area(&info);
	}

	return addr;
}

unsigned long hugetlb_get_unmapped_area(struct file *file, unsigned long addr,
					unsigned long len, unsigned long pgoff,
					unsigned long flags)
{
	struct hstate *h = hstate_file(file);
	unsigned long task_size = TASK_SIZE;
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma;

	if (test_thread_flag(TIF_32BIT))
		task_size = STACK_TOP32;

	if (len & ~huge_page_mask(h))
		return -EINVAL;
	if (len > task_size)
		return -ENOMEM;

	if (flags & MAP_FIXED) {
		if (prepare_hugepage_range(file, addr, len))
			return -EINVAL;
		return addr;
	}

	if (addr) {
		addr = ALIGN(addr, huge_page_size(h));
		vma = find_vma(mm, addr);
		if (task_size - len >= addr &&
		    (!vma || addr + len <= vma->vm_start))
			return addr;
	}
	if (mm->get_unmapped_area == arch_get_unmapped_area)
		return hugetlb_get_unmapped_area_bottomup(file, addr, len,
				pgoff, flags);
	else
		return hugetlb_get_unmapped_area_topdown(file, addr, len,
				pgoff, flags);
}

/* Since the hugepage could cover more than one pmd entry and more
 * than one pgd entry we must cover all possible conditions.
 */
static pmd_t *huge_pmd_alloc(struct mm_struct *mm, unsigned long addr)
{
	pgd_t *pgd = pgd_offset(mm, addr);
	pmd_t *pmd = NULL;
	pud_t *pud;

	if (pgd_none(*pgd)) {
		pud_t *pud = pud_alloc(mm, pgd, addr);

		if (pud == NULL)
			goto out;
	}
	pud = pud_offset(pgd, addr);
	if (pud_none(*pud)) {
		pmd = pmd_alloc(mm, pud, addr);

		if (pmd == NULL)
			goto out;
	}
	pmd = pmd_offset(pud, addr);
out:
	return pmd;
}

/* Note, should we fail leave behind the mm state
 * which will be cleaned up on exit.
 */
pte_t *huge_pte_alloc(struct mm_struct *mm, unsigned long addr,
		      unsigned long size)
{
	unsigned long start = addr & ~(size - 1);
	unsigned long end = start + size;
	pte_t *rpte = NULL;

	/* Our caller operates on start's pte which is rpte should we succeed.*/
	for (addr = start; addr < end; addr = addr + PMD_SIZE) {
		pmd_t *pmd = huge_pmd_alloc(mm, addr);
		pte_t *pte;

		if (!pmd)
			goto fail;
		if (size != (1UL << XLHPAGE_16GB_SHIFT)) {
			rpte = (pte_t *)pmd;
			break;
		}

		pte = pte_alloc_map(mm, NULL, pmd, addr);

		if (!pte)
			goto fail;
		else if (!rpte)
			rpte = pte;
	}

	return rpte;
fail:
	return NULL;
}

int huge_pmd_unshare(struct mm_struct *mm, unsigned long *addr, pte_t *ptep)
{
	return 0;
}

/* This function possibly needs to be moved. It will be different
 * for sun4u and even possibly for sun4v future cores. Though we have
 * no plans to support sun4u at this point.
 */
static unsigned int sun4v_tte_to_shift(pte_t entry)
{
	unsigned long hugepage_tte = pte_val(entry) & _PAGE_SZALL_4V;
	unsigned int hugepage_shift;

	switch (hugepage_tte) {
	case _PAGE_SZ16GB_4V:
		hugepage_shift = XLHPAGE_16GB_SHIFT;
		break;
	case _PAGE_SZ2GB_4V:
		hugepage_shift = XLHPAGE_2GB_SHIFT;
		break;
	case _PAGE_SZ4MB_4V:
		hugepage_shift = REAL_HPAGE_SHIFT;
		break;
	default:
		WARN_ONCE(1, "hugepage_shift: hugepage_tte=0x%lx\n",
			hugepage_tte);
		hugepage_shift = PAGE_SHIFT;
		break;
	}
	return hugepage_shift;
}

static unsigned int tte_to_shift(pte_t entry)
{
	unsigned int hugepage_shift;

	if (tlb_type == hypervisor)
		hugepage_shift = sun4v_tte_to_shift(entry);
	else
		hugepage_shift = REAL_HPAGE_SHIFT;

	return hugepage_shift;
}

static unsigned long tte_to_hugepage_size(pte_t pte)
{
	unsigned long hugepage_size = 1UL << tte_to_shift(pte);

	if (hugepage_size == REAL_HPAGE_SIZE)
		hugepage_size = HPAGE_SIZE;
	return hugepage_size;
}

static unsigned long tte_to_hugepage_mask(pte_t pte)
{
	unsigned int hugepage_shift = tte_to_shift(pte);
	unsigned long hugepage_mask;

	if (hugepage_shift == REAL_HPAGE_SHIFT)
		hugepage_shift = HPAGE_SHIFT;

	hugepage_mask = ~((1UL << hugepage_shift) - 1);

	return hugepage_mask;
}

/* This should also be moved and a noop for sun4u.
 * Only include hugepage sizes we plan to support.
 */
static pte_t hugepage_shift_to_tte(pte_t entry, unsigned int hugepage_shift)
{
	unsigned long sun4v_hugepage_size = _PAGE_SZ4MB_4V;

	pte_val(entry) = pte_val(entry) & ~_PAGE_SZALL_4V;

	switch (hugepage_shift) {
	/* 16Gb */
	case XLHPAGE_16GB_SHIFT:
		sun4v_hugepage_size = _PAGE_SZ16GB_4V;
		break;
	/* 2Gb */
	case XLHPAGE_2GB_SHIFT:
		sun4v_hugepage_size = _PAGE_SZ2GB_4V;
		pte_val(entry) |= _PAGE_PMD_HUGE;
		break;
	/* 8Mb */
	case HPAGE_SHIFT:
		pte_val(entry) |= _PAGE_PMD_HUGE;
		break;
	default:
		WARN_ONCE(hugepage_shift,
			"hugepage_shift_to_tte: unsupported "
			"hugepage_shift=%u.\n", hugepage_shift);
	}

	pte_val(entry) = pte_val(entry) | sun4v_hugepage_size;
	return entry;
}

pte_t arch_make_huge_pte(pte_t entry, struct vm_area_struct *vma,
			 struct page *page, int writeable)
{
	unsigned int hugepage_shift = huge_page_shift(hstate_vma(vma));

	return hugepage_shift_to_tte(entry, hugepage_shift);
}

static void huge_pte_at_flush_update(struct mm_struct *mm, unsigned long addr,
				     pte_t *pte, pte_t orig,
				     pte_t *sentinel_pte)
{
	if (pte_val(orig) & _PAGE_VALID) {
		if (!(pte_val(*sentinel_pte) & _PAGE_VALID)) {
			*sentinel_pte = orig;
			tlb_batch_add(mm, addr, pte, orig, false);
		}
	}
}

static void form_sentinel(pte_t *sentinel_pte, pte_t entry, pte_t *pte,
			  unsigned int hugepage_shift)
{
	pte_t sentinel = __pte(_PAGE_VALID | _PAGE_SPECIAL_4V |
		(pte_val(entry) & _PAGE_SZALL_4V) | __pa(pte));

	BUG_ON(__pa(pte) & _PAGE_SZALL_4V);
        if (hugepage_shift == 31U) /* 2G page */
		sentinel = __pte(pte_val(sentinel) | _PAGE_PMD_HUGE);

	*sentinel_pte = sentinel;
}

static bool huge_pte_at_handle_sentinel(pte_t *sentinel_pte, pte_t *pte,
					pte_t orig, pte_t entry,
					unsigned int hugepage_shift)
{
	bool rc = true;

	/* Should the original pte be marked valid then
	 * only update the sentinel.
	 */
	if (pte_val(orig) & _PAGE_VALID) {
		if ((pte_val(orig) & _PAGE_SPECIAL_4V) == 0UL)
			*pte = entry;
		rc = false;
	} else if (pte_val(*sentinel_pte) & _PAGE_VALID) {
		*pte = *sentinel_pte;
	} else {
		form_sentinel(sentinel_pte, entry, pte, hugepage_shift);
		*pte = entry;
	}

	return rc;
}

static bool __set_huge_pte_at(struct mm_struct *mm, unsigned long addr,
			      pte_t *pte, pte_t entry, pte_t *sentinel_pte,
			      unsigned int hugepage_shift)
{
	bool rc = true;

	if (hugepage_shift != REAL_HPAGE_SHIFT) {
		pte_t orig = *pte;

		rc = huge_pte_at_handle_sentinel(sentinel_pte, pte, orig,
						 entry, hugepage_shift);
		huge_pte_at_flush_update(mm, addr, pte, orig, sentinel_pte);
	} else
		*pte = entry;

	return rc;
}

static void __clear_huge_pte_at(struct mm_struct *mm, unsigned long addr,
				pte_t *pte, pte_t *sentinel_pte,
				unsigned int hugepage_shift)
{
	if (hugepage_shift != REAL_HPAGE_SHIFT) {
		pte_t orig = *pte;

		*pte = __pte(0UL);
		huge_pte_at_flush_update(mm, addr, pte, orig, sentinel_pte);
	} else
		*pte = __pte(0UL);
}

static bool set_huge_pte_range_at(struct mm_struct *mm, pmd_t *pmd,
				  unsigned long addr, pte_t *pentry,
				  pte_t *sentinel_pte, bool set_at)
{
	pte_t *pte = pte_offset_map(pmd, addr);
	pte_t *lpte = pte + PTRS_PER_PTE;
	pte_t entry = *pentry;
	pte_t orig = *(pte_t *)pte;
	bool rc = true;
	unsigned long orig_addr = addr;
	unsigned int hugepage_shift;

	if (set_at)
		hugepage_shift = tte_to_shift(entry);
	else
		hugepage_shift = tte_to_shift(*pte);

	for (; pte < lpte; pte++, addr = addr + PAGE_SIZE) {
		if (set_at) {
			rc = __set_huge_pte_at(mm, addr, pte, entry,
					sentinel_pte, hugepage_shift);
			if (!rc)
				break;
			pte_val(entry) = pte_val(entry) + PAGE_SIZE;
		} else
			__clear_huge_pte_at(mm, addr, pte, sentinel_pte,
					hugepage_shift);
	}
	if (set_at)
		*pentry = entry;

	if (hugepage_shift == REAL_HPAGE_SHIFT) {
		/* Issue TLB flush at REAL_HPAGE_SIZE boundaries */
		maybe_tlb_batch_add(mm, orig_addr, pte, orig, 0);
		maybe_tlb_batch_add(mm, orig_addr + REAL_HPAGE_SIZE,
					pte, orig, 0);
	}

	return rc;
}

static bool __set_huge_pmd_at(struct mm_struct *mm, pmd_t *pmd,
		unsigned long addr, unsigned long end, pte_t *pentry,
		pte_t *sentinel_pte, bool set_at)
{
	bool rc;
	pte_t orig;
	pte_t entry;
	unsigned long next;
	unsigned long hugepage_shift;

	rc = true;
	orig = *(pte_t *)pmd;
	entry = *pentry;

	if (set_at) {
		hugepage_shift = tte_to_shift(entry);
		if (hugepage_shift == REAL_HPAGE_SHIFT) {
			*pmd = __pmd(pte_val(entry));
		} else {
			do {
				next = pmd_addr_end(addr, end);
				rc = __set_huge_pte_at(mm, addr, (pte_t *)pmd,
					entry, sentinel_pte, hugepage_shift);
				if (!rc)
					break;
			} while (pmd++, addr = next, addr != end);
		}
		*pentry = entry;
	} else {
		hugepage_shift = tte_to_shift(orig);
		if (hugepage_shift == REAL_HPAGE_SHIFT) {
			*pmd = __pmd(0);
		} else {
			do {
				next = pmd_addr_end(addr, end);
				__clear_huge_pte_at(mm, addr, (pte_t *)pmd,
					sentinel_pte, hugepage_shift);
			} while (pmd++, addr = next, addr != end);
		}
	}

	if (hugepage_shift == REAL_HPAGE_SHIFT) {
		/* Issue TLB flush at REAL_HPAGE_SIZE boundaries */
		maybe_tlb_batch_add(mm, addr, (pte_t *)pmd, orig, 0);
		maybe_tlb_batch_add(mm, addr + REAL_HPAGE_SIZE,
					(pte_t *)pmd, orig, 0);
	}

	return rc;
}

static bool set_huge_pmd_at(struct mm_struct *mm, pud_t *pud,
			    unsigned long addr, unsigned long end,
			    pte_t *pentry, pte_t *sentinel_pte, bool set_at)
{
	pmd_t *pmd = pmd_offset(pud, addr);
	unsigned long next;
	bool rc;
	unsigned int is_huge_pmd;

	if (set_at)
		is_huge_pmd = is_hugetlb_pmd(__pmd(pte_val(*pentry)));
	else
		is_huge_pmd = is_hugetlb_pmd(*pmd);

	if (is_huge_pmd)
		return __set_huge_pmd_at(mm, pmd, addr, end, pentry,
					sentinel_pte, set_at);

	do {
		next = pmd_addr_end(addr, end);
		rc = set_huge_pte_range_at(mm, pmd, addr, pentry,
					sentinel_pte, set_at);
	} while (pmd++, addr = next, ((addr != end) && rc));
	return rc;
}

static bool set_huge_pud_at(struct mm_struct *mm, pgd_t *pgd,
			    unsigned long addr, unsigned long end,
			    pte_t *pentry, pte_t *sentinel_pte, bool set_at)
{
	pud_t *pud = pud_offset(pgd, addr);
	unsigned long next;
	bool rc;

	do {
		next = pud_addr_end(addr, end);
		rc = set_huge_pmd_at(mm, pud, addr, next, pentry,
				sentinel_pte, set_at);
	} while (pud++, addr = next, ((addr != end) && rc));
	return rc;
}

/* entry must be the first pte of the hugepage. Otherwise entry
 * must be adjusted before we enter the loop for set_pte_at and
 * aligned physically to match the hugepage_size. This is equally
 * true of other locations where HUGETLB_PAGE_ORDER is used within
 * this module for mainline as of 7/20/2014.
 */
void set_huge_pte_at(struct mm_struct *mm, unsigned long addr,
		     pte_t *ptep, pte_t entry)
{
	pte_t sentinel_pte = __pte(0UL);
	unsigned long hugepage_size = tte_to_hugepage_size(entry);
	unsigned long hugepage_mask = tte_to_hugepage_mask(entry);
	unsigned long start = addr & hugepage_mask;
	unsigned long end = start + hugepage_size;
	pgd_t *pgd = pgd_offset(mm, start);
	unsigned long next;
	bool rc;

	if (!pte_present(*ptep) && pte_present(entry)) {
		unsigned int pte_count_idx =
			hugepage_size_to_pte_count_idx(hugepage_size);

		mm->context.huge_pte_count[pte_count_idx]++;
	}

	do {
		next = pgd_addr_end(start, end);
		rc = set_huge_pud_at(mm, pgd, start, next, &entry,
						&sentinel_pte, true);
	} while (pgd++, start = next, ((start != end) && rc));
}

pte_t huge_ptep_get_and_clear(struct mm_struct *mm, unsigned long addr,
			      pte_t *ptep)
{
	pte_t sentinel_pte = __pte(0UL);
	pte_t entry = *ptep;
	unsigned long hugepage_size = tte_to_hugepage_size(entry);
	unsigned long hugepage_mask = tte_to_hugepage_mask(entry);
	unsigned long start = addr & hugepage_mask;
	unsigned long end = start + hugepage_size;
	pgd_t *pgd = pgd_offset(mm, start);
	unsigned long next;
	bool rc;

	if (pte_present(entry)) {
		unsigned int pte_count_idx =
			hugepage_size_to_pte_count_idx(hugepage_size);

		mm->context.huge_pte_count[pte_count_idx]--;
	}

	do {
		next = pgd_addr_end(start, end);
		rc = set_huge_pud_at(mm, pgd, start, next, &entry,
						&sentinel_pte, false);
	} while (pgd++, start = next, ((start != end) && rc));

	return entry;
}

pte_t *huge_pte_offset(struct mm_struct *mm, unsigned long addr)
{
	pte_t *pte = NULL;
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;

	pgd = pgd_offset(mm, addr);
	if (!pgd_none(*pgd)) {
		pud = pud_offset(pgd, addr);
		if (!pud_none(*pud)) {
			pmd = pmd_offset(pud, addr);
			if (xl_hugepage_shift != XLHPAGE_16GB_SHIFT)
				pte = (pte_t *)pmd;
			else if (!pmd_none(*pmd))
				pte = pte_offset_map(pmd, addr);
		}
	}

	return pte;
}

int pmd_huge(pmd_t pmd)
{
	return 0;
}

int pud_huge(pud_t pud)
{
	return 0;
}

static void hugetlb_free_pte_range(struct mmu_gather *tlb, pmd_t *pmd,
			   unsigned long addr)
{
	pgtable_t token = pmd_pgtable(*pmd);

	pmd_clear(pmd);
	pte_free_tlb(tlb, token, addr);
	atomic_long_dec(&tlb->mm->nr_ptes);
}

static void hugetlb_free_pmd_range(struct mmu_gather *tlb, pud_t *pud,
				   unsigned long addr, unsigned long end,
				   unsigned long floor, unsigned long ceiling)
{
	pmd_t *pmd;
	unsigned long next;
	unsigned long start;

	start = addr;
	pmd = pmd_offset(pud, addr);
	do {
		next = pmd_addr_end(addr, end);
		if (pmd_none(*pmd))
			continue;
		if (is_hugetlb_pmd(*pmd))
			pmd_clear(pmd);
		else
			hugetlb_free_pte_range(tlb, pmd, addr);
	} while (pmd++, addr = next, addr != end);

	start &= PUD_MASK;
	if (start < floor)
		return;
	if (ceiling) {
		ceiling &= PUD_MASK;
		if (!ceiling)
			return;
	}
	if (end - 1 > ceiling - 1)
		return;

	pmd = pmd_offset(pud, start);
	pud_clear(pud);
	pmd_free_tlb(tlb, pmd, start);
	mm_dec_nr_pmds(tlb->mm);
}

static void hugetlb_free_pud_range(struct mmu_gather *tlb, pgd_t *pgd,
				   unsigned long addr, unsigned long end,
				   unsigned long floor, unsigned long ceiling)
{
	pud_t *pud;
	unsigned long next;
	unsigned long start;

	start = addr;
	pud = pud_offset(pgd, addr);
	do {
		next = pud_addr_end(addr, end);
		if (pud_none_or_clear_bad(pud))
			continue;
		hugetlb_free_pmd_range(tlb, pud, addr, next, floor,
				       ceiling);
	} while (pud++, addr = next, addr != end);

	start &= PGDIR_MASK;
	if (start < floor)
		return;
	if (ceiling) {
		ceiling &= PGDIR_MASK;
		if (!ceiling)
			return;
	}
	if (end - 1 > ceiling - 1)
		return;

	pud = pud_offset(pgd, start);
	pgd_clear(pgd);
	pud_free_tlb(tlb, pud, start);
}

void hugetlb_free_pgd_range(struct mmu_gather *tlb,
			    unsigned long addr, unsigned long end,
			    unsigned long floor, unsigned long ceiling)
{
	pgd_t *pgd;
	unsigned long next;

	pgd = pgd_offset(tlb->mm, addr);
	do {
		next = pgd_addr_end(addr, end);
		if (pgd_none_or_clear_bad(pgd))
			continue;
		hugetlb_free_pud_range(tlb, pgd, addr, next, floor, ceiling);
	} while (pgd++, addr = next, addr != end);
}
