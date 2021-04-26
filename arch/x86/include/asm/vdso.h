/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_VDSO_H
#define _ASM_X86_VDSO_H

#include <asm/page_types.h>
#include <linux/linkage.h>
#include <linux/init.h>

#ifndef __ASSEMBLER__

#include <linux/mm_types.h>

struct vdso_image {
	void *data;
	unsigned long size;   /* Always a multiple of PAGE_SIZE */

	unsigned long alt, alt_len;

	long sym_vvar_start;  /* Negative offset to the vvar area */

	long sym_vvar_page;
	long sym_pvclock_page;
	long sym_hvclock_page;
	long sym_VDSO32_NOTE_MASK;
	long sym___kernel_sigreturn;
	long sym___kernel_rt_sigreturn;
	long sym___kernel_vsyscall;
	long sym_int80_landing_pad;
};

/* extend the vdso_image to maintain a consistent kABI */
struct vdso_image_ext {
	unsigned long extable_base, extable_len;
	const void *extable;
};

/* for each vdso_image instance, add a read-only vdso_image_ext instance */
#ifdef CONFIG_X86_64
extern const struct vdso_image vdso_image_64;
extern const struct vdso_image_ext vdso_image_64_ext;
#endif

#ifdef CONFIG_X86_X32
extern const struct vdso_image vdso_image_x32;
extern const struct vdso_image_ext vdso_image_x32_ext;
#endif

#if defined CONFIG_X86_32 || defined CONFIG_COMPAT
extern const struct vdso_image vdso_image_32;
extern const struct vdso_image_ext vdso_image_32_ext;
#endif

extern void __init init_vdso_image(const struct vdso_image *image);

extern int map_vdso_once(const struct vdso_image *image, unsigned long addr);

extern bool fixup_vdso_exception(struct pt_regs *regs, int trapnr,
				 unsigned long error_code,
				 unsigned long fault_addr);
#endif /* __ASSEMBLER__ */

#endif /* _ASM_X86_VDSO_H */
