#ifndef _ASM_SPARC_KEXEC_H
#define _ASM_SPARC_KEXEC_H
#include <asm/hypervisor.h>
#include <asm/pgtable_64.h>

#define KEXEC_SOURCE_MEMORY_LIMIT	(-1UL)
#define KEXEC_DESTINATION_MEMORY_LIMIT	(-1UL)
#define KEXEC_CONTROL_MEMORY_LIMIT	(-1UL)
#define KEXEC_CONTROL_PAGE_SIZE		(8192)
#define KEXEC_ARCH			KEXEC_ARCH_SPARC64

/* This is the maximum size we support for the shim. */
#define KX_SHIM_SIZE		_AC(0x10000,UL)
#define NR_KEXEC_TTE	8

#ifndef __ASSEMBLY__
#ifdef CONFIG_KEXEC
#define ARCH_HAS_KIMAGE_ARCH

/* We have two kexec segments. One for vmlinuz and the other initrd.
 * The physical memory is contiguous for both segments. For kexec out of
 * the crash area, what kexec-tools patches for initrd within vmlinuz
 * is correct before the kernel copies the images into the crashkernel
 * region.
 * The kexec shim handles vmlinuz HV mapping.  The vmlinuz and initrd size
 * are each limited to 1UL << (3 + 22)UL in size - 32Mb. Note we never
 * really load kexec initrd TTEs.
 * Final note, we don't hold a reference to these compound pages. They
 * aren't used until machine_kexec time when transferring them to the shim.
 */
struct kexec_region {
	unsigned long nr_tte;
	unsigned long tte[NR_KEXEC_TTE];
};

struct kimage_arch {
	struct kexec_region ki_kernel;
	struct kexec_region ki_initrd;
};

extern unsigned int sparc_kexec;
static inline void sparc64_kexec_finished(void)
{
	sparc_kexec = 0U;
}
static inline int sparc64_kexec_kernel(void)
{
	return sparc_kexec;
}

extern unsigned long long sparc_crash_base;
extern unsigned long long sparc_crash_size;

extern unsigned int sparc64_kexec_trap_tl0, kexec_start;
/* This is what is contained at sparc64_kexec_trap_tl0 address.
 * Should you change the layout within kexec_shim.S then you must
 * change the layout below.
 */
/* T0 and T1 for TL 0 and 1. */
#define SPARC64_NR_TBA_SIZE	((0x200UL << 5UL) << 1UL)
/* The last element of the array must be NULLs. */
#define KEXEC_OBP_TRANSLATION	(128)
struct obp_trans {
	unsigned long va;
	unsigned long size;
	unsigned long tte;
};

struct sparc64_kexec_shim {
				/* instructions */
	unsigned int trap_table[SPARC64_NR_TBA_SIZE >> 2];
				/* hv fault status area, aka scratchpad */
	struct hv_fault_status hv_fault;
	unsigned long nr_tte;	/* current number of pinned tte */
				/* the vmlinuz to be launched */
	struct kexec_region kernel;
				/* the initrd for --load */
	struct kexec_region initrd;
	unsigned long obp_cif;	/* OBP CFI as in _start %o4 */
	unsigned long obp_sp;	/* OBP stack */
	struct obp_trans obp_translations[KEXEC_OBP_TRANSLATION];
};

static inline struct sparc64_kexec_shim *kexec_launched_shim(void)
{
	return (void *) KEXEC_BASE;
}

static inline struct sparc64_kexec_shim *kexec_shim(void)
{
	struct sparc64_kexec_shim *shimp;

	shimp = (struct sparc64_kexec_shim *) &sparc64_kexec_trap_tl0;
	return shimp;
}

static inline void crash_setup_regs(struct pt_regs *newregs,
	struct pt_regs *oldregs)
{
	if (oldregs)
		memcpy(newregs, oldregs, sizeof(*newregs));
	else {
		unsigned long tl = 1, tstate, tpc, tnpc, y;

		asm volatile("stx %%g0, %0" : "=m" (newregs->u_regs[0]));
		asm volatile("stx %%g1, %0" : "=m" (newregs->u_regs[1]));
		asm volatile("stx %%g2, %0" : "=m" (newregs->u_regs[2]));
		asm volatile("stx %%g3, %0" : "=m" (newregs->u_regs[3]));
		asm volatile("stx %%g4, %0" : "=m" (newregs->u_regs[4]));
		asm volatile("stx %%g5, %0" : "=m" (newregs->u_regs[5]));
		asm volatile("stx %%g6, %0" : "=m" (newregs->u_regs[6]));
		asm volatile("stx %%g7, %0" : "=m" (newregs->u_regs[7]));
		asm volatile("stx %%o0, %0" : "=m" (newregs->u_regs[8]));
		asm volatile("stx %%o1, %0" : "=m" (newregs->u_regs[9]));
		asm volatile("stx %%o2, %0" : "=m" (newregs->u_regs[10]));
		asm volatile("stx %%o3, %0" : "=m" (newregs->u_regs[11]));
		asm volatile("stx %%o4, %0" : "=m" (newregs->u_regs[12]));
		asm volatile("stx %%o5, %0" : "=m" (newregs->u_regs[13]));
		asm volatile("stx %%o6, %0" : "=m" (newregs->u_regs[14]));
		asm volatile("stx %%o7, %0" : "=m" (newregs->u_regs[15]));
		asm volatile("wrpr %0, %%tl" :: "r" (tl));
		asm volatile("rdpr %%tstate, %0" : "=r" (tstate));
		newregs->tstate = tstate;
		asm volatile("rdpr %%tpc, %0" : "=r" (tpc));
		newregs->tpc = tpc;
		asm volatile("rdpr %%tnpc, %0" : "=r" (tnpc));
		newregs->tnpc = tnpc;
		asm volatile("rd %%y, %0" : "=r" (y));
		newregs->y = y;
		newregs->magic = PT_REGS_MAGIC;
	}
}
#else
static inline int sparc64_kexec_kernel(void)
{
	return 0;
}
#define sparc_crash_base 0
#define sparc_crash_size 0

#endif /* CONFIG_KEXEC */
#endif /* !__ASSEMBLY__ */
#endif /* !_ASM_SPARC_KEXEC_H */
