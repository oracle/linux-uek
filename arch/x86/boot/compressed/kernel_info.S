/* SPDX-License-Identifier: GPL-2.0 */

#include <linux/linkage.h>
#include <asm/bootparam.h>
#include "kernel_info.h"

/*
 * If a field needs to hold the offset of a symbol from the start
 * of the image, use the macro below, eg
 *	.long	rva(symbol)
 * This will avoid creating run-time relocations, which are not
 * allowed in the compressed kernel.
 */

#define rva(X) (((X) - kernel_info) + KERNEL_INFO_OFFSET)

	.section ".rodata.kernel_info", "a"

	.balign	16
SYM_DATA_START(kernel_info)
	/* Header, Linux top (structure). */
	.ascii	"LToP"
	/* Size. */
	.long	kernel_info_var_len_data - kernel_info
	/* Size total. */
	.long	kernel_info_end - kernel_info

	/* Maximal allowed type for setup_data and setup_indirect structs. */
	.long	SETUP_TYPE_MAX

kernel_info_var_len_data:
	/* Empty for time being... */
SYM_DATA_END_LABEL(kernel_info, SYM_L_LOCAL, kernel_info_end)
