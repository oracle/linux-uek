/* This is for a four level sparc64 software pagetable scheme.
 * Large parts gratefully taken from x86.
 */

#ifndef _SPARC64_PGTABLE_LVL4_H
#define _SPARC64_PGTABLE_LVL4_H

/* Unlike the three level page table scheme for sparc64, the four level
 * scheme doesn't compress the page frame within an unsigned int. It leaves
 * the pfn in its pte (TTE data part) form. Though only the first level
 * is ever actually loaded into the TSB.
 */
#define PMD_PADDR_SHIFT _AC(0,UL)

/* PGDIR_SHIFT determines what a top-level page table entry can map
 */
#define PGDIR_SHIFT	42
#define PTRS_PER_PGD	1024

/* 3rd level page
 */
#define PUD_SHIFT	32
#define PTRS_PER_PUD	1024

/* PMD_SHIFT determines the size of the area a middle-level
 * page table can map
 */
#define PMD_SHIFT	22
#define PTRS_PER_PMD	1024

#define PMD_SIZE	(_AC(1, UL) << PMD_SHIFT)
#define PMD_MASK	(~(PMD_SIZE - 1))
#define PUD_SIZE	(_AC(1, UL) << PUD_SHIFT)
#define PUD_MASK	(~(PUD_SIZE - 1))
#define PGDIR_SIZE	(_AC(1, UL) << PGDIR_SHIFT)
#define PGDIR_MASK	(~(PGDIR_SIZE - 1))

#define PTRS_PER_PTE	(1UL << (PAGE_SHIFT-4))

#define pmd_set(mm, pmdp, ptep)				\
		(pmd_val(*(pmdp)) = __pa((unsigned long) (ptep)))
#define pmd_clear(pmdp)		(pmd_val(*(pmdp)) = 0UL)
#define pud_set(pudp, pmdp) (pud_val(*(pudp)) = __pa((unsigned long) (pmdp)))
#define pud_page(pud)	    pfn_to_page(pud_val(pud) >> PAGE_SHIFT)
#define pud_val(x)		((x).pud)
#define pud_ERROR		pgd_ERROR
#define pgd_set(pgdp, pudp) (pgd_val(*(pgdp)) = __pa((unsigned long) (pudp)))
#define	pgd_bad(pgd)		(0)
#define pgd_val(x)		((x).pgd)
#define pgd_index(address)  (((address) >> PGDIR_SHIFT) & (PTRS_PER_PGD - 1))
#define pgd_offset(mm, address)	((mm)->pgd + pgd_index((address)))
#define pgd_offset_k(address)	pgd_offset(&init_mm, address)
#define pte_offset_map(dir, address) pte_offset_kernel((dir), (address))
#define	pte_unmap(pte)		do { } while (0)

#ifndef __ASSEMBLY__
struct mm_struct;
#include <linux/sched.h>

/* This fills in the lds slot.
 */
extern unsigned int swapper_low_pmd_dir[2048];

extern pgd_t swapper_pg_dir[PTRS_PER_PGD];

static inline void pgd_clear(pgd_t *pgd)
{
	pgd_val(*(pgd)) = 0UL;
}

static inline void pud_clear(pud_t *pud)
{
	pud_val((*pud)) = 0UL;
}

static inline void pgd_populate(struct mm_struct *mm, pgd_t *pgd, pud_t *pud)
{
	pgd_set(pgd, pud);
}

static inline int pgd_present(pgd_t pgd)
{
	return pgd_val(pgd);
}

static inline unsigned long pud_page_vaddr(pud_t pud)
{
	return (unsigned long)__va((unsigned long)pud_val(pud));
}

static inline int pmd_present(pmd_t pmd)
{
	return pmd_val(pmd) != 0UL;
}

static inline int pmd_none(pmd_t pmd)
{
	return pmd_val(pmd) == 0;
}

static inline unsigned long pmd_index(unsigned long address)
{
	return (address >> PMD_SHIFT) & (PTRS_PER_PMD - 1);
}

static inline pmd_t *pmd_offset(pud_t *pud, unsigned long address)
{
	return (pmd_t *) pud_page_vaddr(*pud) + pmd_index(address);
}

static inline unsigned long pmd_page_vaddr(pmd_t pmd)
{
	return (unsigned long) __va(pmd_val(pmd));
}

static inline unsigned long __pmd_page(pmd_t pmd)
{
	unsigned long pmdaddr = pmd_val(pmd);

	pmdaddr &= ~PMD_HUGE_PROTBITS;

	return (unsigned long) __va(pmdaddr);
}

#define pmd_page(pmd)	virt_to_page((void *)__pmd_page(pmd))

static inline unsigned long pmd_pfn(pmd_t pmd)
{
	unsigned long pmdaddr = (unsigned long) pmd_val(pmd);

	pmdaddr &= PAGE_MASK;

	return pmdaddr >> PAGE_SHIFT;
}

static inline unsigned long pte_index(unsigned long address)
{
	return (address >> PAGE_SHIFT) & (PTRS_PER_PTE - 1);
}

static inline pte_t *pte_offset_kernel(pmd_t *pmd, unsigned long address)
{
	return (pte_t *)pmd_page_vaddr(*pmd) + pte_index(address);
}

static inline int pmd_bad(pmd_t pmd)
{
	return 0;
}

static inline int pud_present(pud_t pud)
{
	return pud_val(pud) != 0UL;
}

static inline unsigned long pgd_page_vaddr(pgd_t pgd)
{
	return (unsigned long)__va(pgd_val(pgd));
}

static inline unsigned long pud_index(unsigned long address)
{
	return (address >> PUD_SHIFT) & (PTRS_PER_PUD - 1);
}

static inline pud_t *pud_offset(pgd_t *pgd, unsigned long address)
{
	return (pud_t *) pgd_page_vaddr(*pgd) + pud_index(address);
}

static inline int pgd_none(pgd_t pgd)
{
	return !pgd_val(pgd);
}

static inline int pud_none(pud_t pud)
{
	return !pud_val(pud);
}

static inline int pud_bad(pud_t pud)
{
	return pud_val(pud) == 0UL;
}

static inline int pte_none(pte_t pte)
{
	return !pte_val(pte);
}
#endif /* !__ASSEMBLY__ */
#endif /* !_SPARC64_PGTABLE_LVL4_H */
