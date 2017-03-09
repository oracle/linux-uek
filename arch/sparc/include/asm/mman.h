#ifndef __SPARC_MMAN_H__
#define __SPARC_MMAN_H__

#include <uapi/asm/mman.h>

#ifndef __ASSEMBLY__
#define arch_mmap_check(addr,len,flags)	sparc_mmap_check(addr,len)
int sparc_mmap_check(unsigned long addr, unsigned long len);

#ifdef CONFIG_SPARC64
#include <asm/adi_64.h>

#define arch_calc_vm_prot_bits(prot) sparc_calc_vm_prot_bits(prot)
static inline unsigned long sparc_calc_vm_prot_bits(unsigned long prot)
{
	if (prot & PROT_ADI) {
		struct pt_regs *regs;

		if (!current->mm->context.adi) {
			regs = task_pt_regs(current);
			regs->tstate |= TSTATE_MCDE;
			current->mm->context.adi = true;
		}
		return VM_SPARC_ADI;
	} else {
		return 0;
	}
}

#define arch_vm_get_page_prot(vm_flags) sparc_vm_get_page_prot(vm_flags)
static inline pgprot_t sparc_vm_get_page_prot(unsigned long vm_flags)
{
	return (vm_flags & VM_SPARC_ADI) ? __pgprot(_PAGE_MCD_4V) : __pgprot(0);
}

#define arch_validate_prot(prot) sparc_validate_prot(prot)
static inline int sparc_validate_prot(unsigned long prot)
{
	if (prot & ~(PROT_READ | PROT_WRITE | PROT_EXEC | PROT_SEM | PROT_ADI))
		return 0;
	if ((prot & PROT_ADI) && !adi_capable())
		return 0;
	return 1;
}
#endif /* CONFIG_SPARC64 */

#endif /* __ASSEMBLY__ */
#endif /* __SPARC_MMAN_H__ */
