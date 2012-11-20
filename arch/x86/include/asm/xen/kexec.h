/*
 * Copyright (c) 2011 Daniel Kiper
 * Copyright (c) 2012 Daniel Kiper, Oracle Corporation
 *
 * kexec/kdump implementation for Xen was written by Daniel Kiper.
 * Initial work on it was sponsored by Google under Google Summer
 * of Code 2011 program and Citrix. Konrad Rzeszutek Wilk from Oracle
 * was the mentor for this project.
 *
 * Some ideas are taken from:
 *   - native kexec/kdump implementation,
 *   - kexec/kdump implementation for Xen Linux Kernel Ver. 2.6.18,
 *   - PV-GRUB.
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
 * You should have received a copy of the GNU General Public License along
 * with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _ASM_X86_XEN_KEXEC_H
#define _ASM_X86_XEN_KEXEC_H

#include <linux/init.h>

#define KEXEC_XEN_NO_PAGES	17

#define XK_MA_CONTROL_PAGE	0
#define XK_VA_CONTROL_PAGE	1
#define XK_MA_PGD_PAGE		2
#define XK_VA_PGD_PAGE		3
#define XK_MA_PUD0_PAGE		4
#define XK_VA_PUD0_PAGE		5
#define XK_MA_PUD1_PAGE		6
#define XK_VA_PUD1_PAGE		7
#define XK_MA_PMD0_PAGE		8
#define XK_VA_PMD0_PAGE		9
#define XK_MA_PMD1_PAGE		10
#define XK_VA_PMD1_PAGE		11
#define XK_MA_PTE0_PAGE		12
#define XK_VA_PTE0_PAGE		13
#define XK_MA_PTE1_PAGE		14
#define XK_VA_PTE1_PAGE		15
#define XK_MA_TABLE_PAGE	16

#ifndef __ASSEMBLY__
struct xen_kexec_image {
	unsigned long page_list[KEXEC_XEN_NO_PAGES];
	unsigned long indirection_page;
	unsigned long start_address;
};

struct xen_kexec_load {
	int type;
	struct xen_kexec_image image;
};

extern unsigned int xen_kexec_control_code_size;

extern void __init xen_init_kexec_ops(void);

#ifdef CONFIG_X86_32
extern void xen_relocate_kernel(unsigned long indirection_page,
				unsigned long *page_list,
				unsigned long start_address,
				unsigned int has_pae,
				unsigned int preserve_context);
#else
extern void xen_relocate_kernel(unsigned long indirection_page,
				unsigned long *page_list,
				unsigned long start_address,
				unsigned int preserve_context);
#endif
#endif
#endif /* _ASM_X86_XEN_KEXEC_H */
