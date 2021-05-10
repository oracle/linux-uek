/* SPDX-License-Identifier: GPL-2.0 */
#ifndef ___ASM_SPARC_IO_H
#define ___ASM_SPARC_IO_H

/*
 * On LEON PCI addresses below 64k are converted to IO accesses.
 * io_remap_xxx() returns a kernel virtual address in the PCI window so
 * inb() doesn't need to add an offset.
 */
#define PCI_IOBASE ((void __iomem *)0)

#if defined(__sparc__) && defined(__arch64__)
#include <asm/io_64.h>
#else
#include <asm/io_32.h>
#endif

/*
 * Defines used for both SPARC32 and SPARC64
 */

/* Big endian versions of memory read/write routines */
#define readb_be(__addr)	__raw_readb(__addr)
#define readw_be(__addr)	__raw_readw(__addr)
#define readl_be(__addr)	__raw_readl(__addr)
#define writeb_be(__b, __addr)	__raw_writeb(__b, __addr)
#define writel_be(__w, __addr)	__raw_writel(__w, __addr)
#define writew_be(__l, __addr)	__raw_writew(__l, __addr)

#endif
