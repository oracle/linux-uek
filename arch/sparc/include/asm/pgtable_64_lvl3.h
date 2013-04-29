#ifndef _SPARC64_PGTABLE_LVL3_H
#define _SPARC64_PGTABLE_LVL3_H
/* This is for a three level page table scheme.
 */

#include <asm-generic/pgtable-nopud.h>

/* PMD_SHIFT determines the size of the area a second-level page
 * table can map
 */
#define PMD_SHIFT	(PAGE_SHIFT + (PAGE_SHIFT-4))
#define PMD_SIZE	(_AC(1,UL) << PMD_SHIFT)
#define PMD_MASK	(~(PMD_SIZE-1))
#define PMD_BITS	(PAGE_SHIFT - 2)

/* PGDIR_SHIFT determines what a third-level page table entry can map */
#define PGDIR_SHIFT	(PAGE_SHIFT + (PAGE_SHIFT-4) + PMD_BITS)
#define PGDIR_SIZE	(_AC(1,UL) << PGDIR_SHIFT)
#define PGDIR_MASK	(~(PGDIR_SIZE-1))
#define PGDIR_BITS	(PAGE_SHIFT - 2)

#if (PGDIR_SHIFT + PGDIR_BITS) != 44
#error Page table parameters do not cover virtual address space properly.
#endif

/* PMDs point to PTE tables which are 4K aligned.  */
#define PMD_PADDR	_AC(0xfffffffe,UL)
#define PMD_PADDR_SHIFT	_AC(11,UL)

#define PMD_HUGE_PADDR		_AC(0xfffff800,UL)
/* PGDs point to PMD tables which are 8K aligned.  */
#define PGD_PADDR	_AC(0xfffffffc,UL)
#define PGD_PADDR_SHIFT	_AC(11,UL)

#ifndef __ASSEMBLY__

#include <linux/sched.h>

/* Entries per page directory level. */
#define PTRS_PER_PTE	(1UL << (PAGE_SHIFT-4))
#define PTRS_PER_PMD	(1UL << PMD_BITS)
#define PTRS_PER_PGD	(1UL << PGDIR_BITS)

static inline unsigned long pmd_pfn(pmd_t pmd)
{
	unsigned long val = pmd_val(pmd) & PMD_HUGE_PADDR;

	return val >> (PAGE_SHIFT - PMD_PADDR_SHIFT);
}

static inline int pmd_present(pmd_t pmd)
{
	return pmd_val(pmd) != 0U;
}

#define pmd_none(pmd)			(!pmd_val(pmd))

static inline void pmd_set(struct mm_struct *mm, pmd_t *pmdp, pte_t *ptep)
{
	unsigned long val = __pa((unsigned long) (ptep)) >> PMD_PADDR_SHIFT;

	pmd_val(*pmdp) = val;
}

#define pud_set(pudp, pmdp)	\
	(pud_val(*(pudp)) = (__pa((unsigned long) (pmdp)) >> PGD_PADDR_SHIFT))
static inline unsigned long __pmd_page(pmd_t pmd)
{
	unsigned long paddr = (unsigned long) pmd_val(pmd);
#ifdef CONFIG_TRANSPARENT_HUGEPAGE
	if (pmd_val(pmd) & PMD_ISHUGE)
		paddr &= PMD_HUGE_PADDR;
#endif
	paddr <<= PMD_PADDR_SHIFT;
	return ((unsigned long) __va(paddr));
}
#define pmd_page(pmd) 			virt_to_page((void *)__pmd_page(pmd))
#define pud_page_vaddr(pud)		\
	((unsigned long) __va((((unsigned long)pud_val(pud))<<PGD_PADDR_SHIFT)))
#define pud_page(pud) 			virt_to_page((void *)pud_page_vaddr(pud))
#define pmd_bad(pmd)			(0)
#define pmd_clear(pmdp)			(pmd_val(*(pmdp)) = 0U)
#define pud_none(pud)			(!pud_val(pud))
#define pud_bad(pud)			(0)
#define pud_present(pud)		(pud_val(pud) != 0U)
#define pud_clear(pudp)			(pud_val(*(pudp)) = 0U)

/* Same in both SUN4V and SUN4U.  */
#define pte_none(pte) 			(!pte_val(pte))

/* to find an entry in a page-table-directory. */
#define pgd_index(address)	(((address) >> PGDIR_SHIFT) & (PTRS_PER_PGD - 1))
#define pgd_offset(mm, address)	((mm)->pgd + pgd_index(address))

/* to find an entry in a kernel page-table-directory */
#define pgd_offset_k(address) pgd_offset(&init_mm, address)

/* Find an entry in the second-level page table.. */
#define pmd_offset(pudp, address)	\
	((pmd_t *) pud_page_vaddr(*(pudp)) + \
	 (((address) >> PMD_SHIFT) & (PTRS_PER_PMD-1)))

/* Find an entry in the third-level page table.. */
#define pte_index(dir, address)	\
	((pte_t *) __pmd_page(*(dir)) + \
	 ((address >> PAGE_SHIFT) & (PTRS_PER_PTE - 1)))
#define pte_offset_kernel		pte_index
#define pte_offset_map			pte_index
#define pte_unmap(pte)			do { } while (0)

#endif /* !(__ASSEMBLY__) */

#ifndef __ASSEMBLY__
extern pgd_t swapper_pg_dir[2048];
extern pmd_t swapper_low_pmd_dir[2048];
#endif /* !__ASSEMBLY__ */

#endif /* !_SPARC64_PGTABLE_LVL3_H */
