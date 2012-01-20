#ifndef _ASM_X86_HUGETLB_H
#define _ASM_X86_HUGETLB_H

#include <asm/page.h>


static inline int is_hugepage_only_range(struct mm_struct *mm,
					 unsigned long addr,
					 unsigned long len) {
	return 0;
}

/*
 * If the arch doesn't supply something else, assume that hugepage
 * size aligned regions are ok without further preparation.
 */
static inline int prepare_hugepage_range(struct file *file,
			unsigned long addr, unsigned long len)
{
	struct hstate *h = hstate_file(file);
	if (len & ~huge_page_mask(h))
		return -EINVAL;
	if (addr & ~huge_page_mask(h))
		return -EINVAL;
	return 0;
}

static inline void hugetlb_prefault_arch_hook(struct mm_struct *mm) {
}

static inline void hugetlb_free_pgd_range(struct mmu_gather *tlb,
					  unsigned long addr, unsigned long end,
					  unsigned long floor,
					  unsigned long ceiling)
{
	free_pgd_range(tlb, addr, end, floor, ceiling);
}

static inline pte_t huge_ptep_get(pte_t *ptep)
{
	return *ptep;
}

static inline void set_huge_pte_at(struct mm_struct *mm, unsigned long addr,
				   pte_t *ptep, pte_t pte)
{
	set_pmd((pmd_t *)ptep, native_make_pmd(native_pte_val(pte)));
}

static inline pte_t huge_ptep_get_and_clear(struct mm_struct *mm,
					    unsigned long addr, pte_t *ptep)
{
	pte_t pte = huge_ptep_get(ptep);

	set_huge_pte_at(mm, addr, ptep, __pte(0));
	return pte;
}

static inline void huge_ptep_clear_flush(struct vm_area_struct *vma,
					 unsigned long addr, pte_t *ptep)
{
}

static inline int huge_pte_none(pte_t pte)
{
	return pte_none(pte);
}

static inline pte_t huge_pte_wrprotect(pte_t pte)
{
	return pte_wrprotect(pte);
}

static inline void huge_ptep_set_wrprotect(struct mm_struct *mm,
					   unsigned long addr, pte_t *ptep)
{
	pte_t pte = huge_ptep_get(ptep);

	pte = pte_wrprotect(pte);
	set_huge_pte_at(mm, addr, ptep, pte);
}

static inline int huge_ptep_set_access_flags(struct vm_area_struct *vma,
					     unsigned long addr, pte_t *ptep,
					     pte_t pte, int dirty)
{
	pte_t oldpte = huge_ptep_get(ptep);
	int changed = !pte_same(oldpte, pte);

	if (changed && dirty) {
		set_huge_pte_at(vma->vm_mm, addr, ptep, pte);
		flush_tlb_page(vma, addr);
	}

	return changed;
}

#ifdef CONFIG_XEN
int xen_prepare_hugepage(struct page *page);
void xen_release_hugepage(struct page *page);
#endif
static inline int arch_prepare_hugepage(struct page *page)
{
#ifdef CONFIG_XEN
	return xen_prepare_hugepage(page);
#else
	return 0;
#endif
}

static inline void arch_release_hugepage(struct page *page)
{
#ifdef CONFIG_XEN
	return xen_release_hugepage(page);
#endif
}

#endif /* _ASM_X86_HUGETLB_H */
