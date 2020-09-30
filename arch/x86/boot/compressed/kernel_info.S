/* SPDX-License-Identifier: GPL-2.0 */

#include <linux/linkage.h>
#include <asm/bootparam.h>

/*
 * The kernel_info structure is not placed at a fixed offest in the
 * kernel image. So this macro and the support in the linker file
 * allow the relative offsets for the MLE header within the kernel
 * image to be configured at build time.
 */
#define roffset(X) ((X) - kernel_info)

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

	/* Offset to the MLE header structure */
#if IS_ENABLED(CONFIG_SECURE_LAUNCH)
	.long	roffset(mle_header_offset)
#else
	.long	0
#endif

kernel_info_var_len_data:
	/* Empty for time being... */
SYM_DATA_END_LABEL(kernel_info, SYM_L_LOCAL, kernel_info_end)

#if IS_ENABLED(CONFIG_SECURE_LAUNCH)
	/*
	 * The MLE Header per the TXT Specification, section 2.1
	 * MLE capabilities, see table 4. Capabilities set:
	 * bit 0: Support for GETSEC[WAKEUP] for RLP wakeup
	 * bit 1: Support for RLP wakeup using MONITOR address
	 * bit 2: The ECX register will contain the pointer to the MLE page table
	 * bit 5: TPM 1.2 family: Details/authorities PCR usage support
	 * bit 9: Supported format of TPM 2.0 event log - TCG compliant
	 */
SYM_DATA_START(mle_header)
	.long	0x9082ac5a  /* UUID0 */
	.long	0x74a7476f  /* UUID1 */
	.long	0xa2555c0f  /* UUID2 */
	.long	0x42b651cb  /* UUID3 */
	.long	0x00000034  /* MLE header size */
	.long	0x00020002  /* MLE version 2.2 */
	.long	roffset(sl_stub_entry_offset) /* Linear entry point of MLE (virt. address) */
	.long	0x00000000  /* First valid page of MLE */
	.long	0x00000000  /* Offset within binary of first byte of MLE */
	.long	roffset(_edata_offset) /* Offset within binary of last byte + 1 of MLE */
	.long	0x00000227  /* Bit vector of MLE-supported capabilities */
	.long	0x00000000  /* Starting linear address of command line (unused) */
	.long	0x00000000  /* Ending linear address of command line (unused) */
SYM_DATA_END(mle_header)
#endif
