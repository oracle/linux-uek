/* SPDX-License-Identifier: (GPL-2.0+ OR MIT) */

#ifndef _DT_BINDINGS_PENSANDO_CAPMEM_H
#define _DT_BINDINGS_PENSANDO_CAPMEM_H

/*
 * Memory range attrbutes passed in via the device-tree
 */
#define DSC_MEM_ATTR_NONCOHERENT	0x0	/* range is DMA noncoherent */
#define DSC_MEM_ATTR_COHERENT		0x1	/* range is DMA coherent */
#define DSC_MEM_ATTR_BYPASS		0x2	/* range is LLC bypass */
#define DSC_MEM_ATTR_DEVICE		0x4	/* range is device */

#endif /* _DT_BINDINGS_PENSANDO_CAPMEM_H */

