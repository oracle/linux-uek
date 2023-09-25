/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Main Secure Launch header file.
 *
 * Copyright (c) 2021, Oracle and/or its affiliates.
 */

#ifndef _LINUX_SLAUNCH_H
#define _LINUX_SLAUNCH_H

/*
 * Secure Launch Defined State Flags
 */
#define SL_FLAG_ACTIVE		0x00000001
#define SL_FLAG_ARCH_SKINIT	0x00000002
#define SL_FLAG_ARCH_TXT	0x00000004

/*
 * Secure Launch CPU Type
 */
#define SL_CPU_AMD	1
#define SL_CPU_INTEL	2

#if IS_ENABLED(CONFIG_SECURE_LAUNCH)

#define __SL32_CS	0x0008
#define __SL32_DS	0x0010

/*
 * Intel Safer Mode Extensions (SMX)
 *
 * Intel SMX provides a programming interface to establish a Measured Launched
 * Environment (MLE). The measurement and protection mechanisms supported by the
 * capabilities of an Intel Trusted Execution Technology (TXT) platform. SMX is
 * the processor’s programming interface in an Intel TXT platform.
 *
 * See Intel SDM Volume 2 - 6.1 "Safer Mode Extensions Reference"
 */

/*
 * SMX GETSEC Leaf Functions
 */
#define SMX_X86_GETSEC_SEXIT	5
#define SMX_X86_GETSEC_SMCTRL	7
#define SMX_X86_GETSEC_WAKEUP	8

/*
 * Intel Trusted Execution Technology MMIO Registers Banks
 */
#define TXT_PUB_CONFIG_REGS_BASE	0xfed30000
#define TXT_PRIV_CONFIG_REGS_BASE	0xfed20000
#define TXT_NR_CONFIG_PAGES     ((TXT_PUB_CONFIG_REGS_BASE - \
				  TXT_PRIV_CONFIG_REGS_BASE) >> PAGE_SHIFT)

/*
 * Intel Trusted Execution Technology (TXT) Registers
 */
#define TXT_CR_STS			0x0000
#define TXT_CR_ESTS			0x0008
#define TXT_CR_ERRORCODE		0x0030
#define TXT_CR_CMD_RESET		0x0038
#define TXT_CR_CMD_CLOSE_PRIVATE	0x0048
#define TXT_CR_DIDVID			0x0110
#define TXT_CR_VER_EMIF			0x0200
#define TXT_CR_CMD_UNLOCK_MEM_CONFIG	0x0218
#define TXT_CR_SINIT_BASE		0x0270
#define TXT_CR_SINIT_SIZE		0x0278
#define TXT_CR_MLE_JOIN			0x0290
#define TXT_CR_HEAP_BASE		0x0300
#define TXT_CR_HEAP_SIZE		0x0308
#define TXT_CR_SCRATCHPAD		0x0378
#define TXT_CR_CMD_OPEN_LOCALITY1	0x0380
#define TXT_CR_CMD_CLOSE_LOCALITY1	0x0388
#define TXT_CR_CMD_OPEN_LOCALITY2	0x0390
#define TXT_CR_CMD_CLOSE_LOCALITY2	0x0398
#define TXT_CR_CMD_SECRETS		0x08e0
#define TXT_CR_CMD_NO_SECRETS		0x08e8
#define TXT_CR_E2STS			0x08f0

/* TXT default register value */
#define TXT_REGVALUE_ONE		0x1ULL

/* TXTCR_STS status bits */
#define TXT_SENTER_DONE_STS		(1<<0)
#define TXT_SEXIT_DONE_STS		(1<<1)

/*
 * SINIT/MLE Capabilities Field Bit Definitions
 */
#define TXT_SINIT_MLE_CAP_WAKE_GETSEC	0
#define TXT_SINIT_MLE_CAP_WAKE_MONITOR	1

/*
 * OS/MLE Secure Launch Specific Definitions
 */
#define TXT_OS_MLE_STRUCT_VERSION	1
#define TXT_OS_MLE_MAX_VARIABLE_MTRRS	32

/*
 * TXT Heap Table Enumeration
 */
#define TXT_BIOS_DATA_TABLE		1
#define TXT_OS_MLE_DATA_TABLE		2
#define TXT_OS_SINIT_DATA_TABLE		3
#define TXT_SINIT_MLE_DATA_TABLE	4
#define TXT_SINIT_TABLE_MAX		TXT_SINIT_MLE_DATA_TABLE

/*
 * Secure Launch Defined Error Codes used in MLE-initiated TXT resets.
 *
 * TXT Specification
 * Appendix I ACM Error Codes
 */
#define SL_ERROR_GENERIC		0xc0008001
#define SL_ERROR_TPM_INIT		0xc0008002
#define SL_ERROR_TPM_INVALID_LOG20	0xc0008003
#define SL_ERROR_TPM_LOGGING_FAILED	0xc0008004
#define SL_ERROR_REGION_STRADDLE_4GB	0xc0008005
#define SL_ERROR_TPM_EXTEND		0xc0008006
#define SL_ERROR_MTRR_INV_VCNT		0xc0008007
#define SL_ERROR_MTRR_INV_DEF_TYPE	0xc0008008
#define SL_ERROR_MTRR_INV_BASE		0xc0008009
#define SL_ERROR_MTRR_INV_MASK		0xc000800a
#define SL_ERROR_MSR_INV_MISC_EN	0xc000800b
#define SL_ERROR_INV_AP_INTERRUPT	0xc000800c
#define SL_ERROR_INTEGER_OVERFLOW	0xc000800d
#define SL_ERROR_HEAP_WALK		0xc000800e
#define SL_ERROR_HEAP_MAP		0xc000800f
#define SL_ERROR_REGION_ABOVE_4GB	0xc0008010
#define SL_ERROR_HEAP_INVALID_DMAR	0xc0008011
#define SL_ERROR_HEAP_DMAR_SIZE		0xc0008012
#define SL_ERROR_HEAP_DMAR_MAP		0xc0008013
#define SL_ERROR_HI_PMR_BASE		0xc0008014
#define SL_ERROR_HI_PMR_SIZE		0xc0008015
#define SL_ERROR_LO_PMR_BASE		0xc0008016
#define SL_ERROR_LO_PMR_MLE		0xc0008017
#define SL_ERROR_INITRD_TOO_BIG		0xc0008018
#define SL_ERROR_HEAP_ZERO_OFFSET	0xc0008019
#define SL_ERROR_WAKE_BLOCK_TOO_SMALL	0xc000801a
#define SL_ERROR_MLE_BUFFER_OVERLAP	0xc000801b
#define SL_ERROR_BUFFER_BEYOND_PMR	0xc000801c
#define SL_ERROR_OS_SINIT_BAD_VERSION	0xc000801d
#define SL_ERROR_EVENTLOG_MAP		0xc000801e
#define SL_ERROR_TPM_NUMBER_ALGS	0xc000801f
#define SL_ERROR_TPM_UNKNOWN_DIGEST	0xc0008020
#define SL_ERROR_TPM_INVALID_EVENT	0xc0008021
#define SL_ERROR_MISSING_EVENT_LOG	0xc0008022
#define SL_ERROR_MAP_SETUP_DATA		0xc0008023

/*
 * Secure Launch Defined Limits
 */
#define TXT_MAX_CPUS		512
#define TXT_BOOT_STACK_SIZE	24

/*
 * Secure Launch event log entry type. The TXT specification defines the
 * base event value as 0x400 for DRTM values.
 */
#define TXT_EVTYPE_BASE			0x400
#define TXT_EVTYPE_SLAUNCH		(TXT_EVTYPE_BASE + 0x102)
#define TXT_EVTYPE_SLAUNCH_START	(TXT_EVTYPE_BASE + 0x103)
#define TXT_EVTYPE_SLAUNCH_END		(TXT_EVTYPE_BASE + 0x104)

/*
 * Measured Launch PCRs
 */
#define SL_DEF_IMAGE_PCR17	17 /* TCG Details PCR */
#define SL_DEF_CONFIG_PCR18	18 /* TCG Authorities PCR */
#define SL_ALT_CONFIG_PCR19	19
#define SL_ALT_IMAGE_PCR20	20

/*
 * MLE scratch area offsets
 */
#define SL_SCRATCH_AP_EBX		0
#define SL_SCRATCH_AP_JMP_OFFSET	4
#define SL_SCRATCH_AP_PAUSE		8

#ifndef __ASSEMBLY__

#include <asm/bootparam.h>
#include <linux/io.h>
#include <linux/tpm.h>
#include <linux/tpm_eventlog.h>

/*
 * Secure Launch AP wakeup information fetched in SMP boot code.
 */
struct sl_ap_wake_info {
	u32 ap_wake_block;
	u32 ap_wake_block_size;
	u32 ap_jmp_offset;
};

/*
 * TXT heap extended data elements.
 */
struct txt_heap_ext_data_element {
	u32 type;
	u32 size;
	/* Data */
} __packed;

#define TXT_HEAP_EXTDATA_TYPE_END			0

struct txt_heap_end_element {
	u32 type;
	u32 size;
} __packed;

#define TXT_HEAP_EXTDATA_TYPE_TPM_EVENT_LOG_PTR		5

struct txt_heap_event_log_element {
	u64 event_log_phys_addr;
} __packed;

#define TXT_HEAP_EXTDATA_TYPE_EVENT_LOG_POINTER2_1	8

struct txt_heap_event_log_pointer2_1_element {
	u64 phys_addr;
	u32 allocated_event_container_size;
	u32 first_record_offset;
	u32 next_record_offset;
} __packed;

/*
 * Secure Launch defined MTRR saving structures
 */
struct txt_mtrr_pair {
	u64 mtrr_physbase;
	u64 mtrr_physmask;
} __packed;

struct txt_mtrr_state {
	u64 default_mem_type;
	u64 mtrr_vcnt;
	struct txt_mtrr_pair mtrr_pair[TXT_OS_MLE_MAX_VARIABLE_MTRRS];
} __packed;

/*
 * Secure Launch defined OS/MLE TXT Heap table
 */
struct txt_os_mle_data {
	u32 version;
	u32 boot_params_addr;
	u64 saved_misc_enable_msr;
	struct txt_mtrr_state saved_bsp_mtrrs;
	u32 ap_wake_block;
	u32 ap_wake_block_size;
	u64 evtlog_addr;
	u32 evtlog_size;
	u8 mle_scratch[64];
} __packed;

/*
 * TXT specification defined BIOS data TXT Heap table
 */
struct txt_bios_data {
	u32 version; /* Currently 5 for TPM 1.2 and 6 for TPM 2.0 */
	u32 bios_sinit_size;
	u64 reserved1;
	u64 reserved2;
	u32 num_logical_procs;
	/* Versions >= 5 with updates in version 6 */
	u32 sinit_flags;
	u32 mle_flags;
	/* Versions >= 4 */
	/* Ext Data Elements */
} __packed;

/*
 * TXT specification defined OS/SINIT TXT Heap table
 */
struct txt_os_sinit_data {
	u32 version; /* Currently 6 for TPM 1.2 and 7 for TPM 2.0 */
	u32 flags;
	u64 mle_ptab;
	u64 mle_size;
	u64 mle_hdr_base;
	u64 vtd_pmr_lo_base;
	u64 vtd_pmr_lo_size;
	u64 vtd_pmr_hi_base;
	u64 vtd_pmr_hi_size;
	u64 lcp_po_base;
	u64 lcp_po_size;
	u32 capabilities;
	/* Version = 5 */
	u64 efi_rsdt_ptr;
	/* Versions >= 6 */
	/* Ext Data Elements */
} __packed;

/*
 * TXT specification defined SINIT/MLE TXT Heap table
 */
struct txt_sinit_mle_data {
	u32 version;             /* Current values are 6 through 9 */
	/* Versions <= 8 */
	u8 bios_acm_id[20];
	u32 edx_senter_flags;
	u64 mseg_valid;
	u8 sinit_hash[20];
	u8 mle_hash[20];
	u8 stm_hash[20];
	u8 lcp_policy_hash[20];
	u32 lcp_policy_control;
	/* Versions >= 7 */
	u32 rlp_wakeup_addr;
	u32 reserved;
	u32 num_of_sinit_mdrs;
	u32 sinit_mdrs_table_offset;
	u32 sinit_vtd_dmar_table_size;
	u32 sinit_vtd_dmar_table_offset;
	/* Versions >= 8 */
	u32 processor_scrtm_status;
	/* Versions >= 9 */
	/* Ext Data Elements */
} __packed;

/*
 * TXT data reporting structure for memory types
 */
struct txt_sinit_memory_descriptor_record {
	u64 address;
	u64 length;
	u8 type;
	u8 reserved[7];
} __packed;

/*
 * TXT data structure used by a responsive local processor (RLP) to start
 * execution in response to a GETSEC[WAKEUP].
 */
struct smx_rlp_mle_join {
	u32 rlp_gdt_limit;
	u32 rlp_gdt_base;
	u32 rlp_seg_sel;     /* cs (ds, es, ss are seg_sel+8) */
	u32 rlp_entry_point; /* phys addr */
} __packed;

/* The TCG original Spec ID structure defined for TPM 1.2 */
#define TCG_SPECID_SIG00 "Spec ID Event00"

struct tpm12_tcg_specid_event_head {
	char signature[16];
	u32  platform_class;
	u8   spec_ver_minor;
	u8   spec_ver_major;
	u8   errata;
	u8   uintn_size;	/* reserved (must be 0) for 1.21 */
	u8   vendor_info_size;
	/* vendor_info[]; */
} __packed;

/*
 * TPM event log structures defined by the TXT specification derived
 * from the TCG documentation. For TXT this is setup as the conainter
 * header. On AMD this header is embedded in to vendor information
 * after the TCG spec ID header.
 */
#define TPM12_EVTLOG_SIGNATURE "TXT Event Container"

struct tpm12_event_log_header {
	char signature[20];
	char reserved[12];
	u8 container_ver_major;
	u8 container_ver_minor;
	u8 pcr_event_ver_major;
	u8 pcr_event_ver_minor;
	u32 container_size;
	u32 pcr_events_offset;
	u32 next_event_offset;
	/* PCREvents[] */
} __packed;

/* TPM Event Log Size Macros */
#define TCG_PCClientSpecIDEventStruct_SIZE 			\
		(sizeof(struct tpm12_tcg_specid_event_head))
#define TCG_EfiSpecIdEvent_SIZE(n) \
		((n) * sizeof(struct tcg_efi_specid_event_algs)	\
		 + sizeof(struct tcg_efi_specid_event_head)	\
		 + sizeof(u8) /* vendorInfoSize */)
#define TPM20_HASH_COUNT(base) (*((u32 *)(base)			\
		+ (offsetof(struct tcg_efi_specid_event_head, num_algs) >> 2)))

/* AMD Specific Structures and Definitions */
struct sl_header {
	u16 skl_entry_point;
	u8 reserved[64];
	u16 bootloader_data_offset;
	u16 skl_info_offset;
} __packed;

#define SKL_TAG_CLASS_MASK	0xF0

/* Tags with no particular class */
#define SKL_TAG_NO_CLAS		0x00
#define SKL_TAG_END		0x00
#define SKL_TAG_SETUP_INDIRECT	0x01
#define SKL_TAG_TAGS_SIZE	0x0F	/* Always first */

/* Tags specifying kernel type */
#define SKL_TAG_BOOT_CLASS	0x10
#define SKL_TAG_BOOT_LINUX	0x10
#define SKL_TAG_BOOT_MB2	0x11

/* Tags specific to TPM event log */
#define SKL_TAG_EVENT_LOG_CLASS	0x20
#define SKL_TAG_EVENT_LOG	0x20
#define SKL_TAG_SKL_HASH	0x21

struct skl_tag_hdr {
	u8 type;
	u8 len;
} __packed;

struct skl_tag_tags_size {
	struct skl_tag_hdr hdr;
	u16 size;
} __packed;

struct skl_tag_setup_indirect {
	struct skl_tag_hdr hdr;
	/* type = SETUP_INDIRECT */
	struct setup_data data;
	/* type = SETUP_INDIRECT | SETUP_SECURE_LAUNCH */
	struct setup_indirect indirect;
} __packed;

struct skl_tag_evtlog {
	struct skl_tag_hdr hdr;
	u32 address;
	u32 size;
} __packed;

/*
 * Functions to extract data from the Intel TXT Heap Memory. The layout
 * of the heap is as follows:
 *  +----------------------------+
 *  | Size Bios Data table (u64) |
 *  +----------------------------+
 *  | Bios Data table            |
 *  +----------------------------+
 *  | Size OS MLE table (u64)    |
 *  +----------------------------+
 *  | OS MLE table               |
 *  +--------------------------- +
 *  | Size OS SINIT table (u64)  |
 *  +----------------------------+
 *  | OS SINIT table             |
 *  +----------------------------+
 *  | Size SINIT MLE table (u64) |
 *  +----------------------------+
 *  | SINIT MLE table            |
 *  +----------------------------+
 *
 *  NOTE: the table size fields include the 8 byte size field itself.
 */
static inline u64 txt_bios_data_size(void *heap)
{
	return *((u64 *)heap);
}

static inline void *txt_bios_data_start(void *heap)
{
	return heap + sizeof(u64);
}

static inline u64 txt_os_mle_data_size(void *heap)
{
	return *((u64 *)(heap + txt_bios_data_size(heap)));
}

static inline void *txt_os_mle_data_start(void *heap)
{
	return heap + txt_bios_data_size(heap) + sizeof(u64);
}

static inline u64 txt_os_sinit_data_size(void *heap)
{
	return *((u64 *)(heap + txt_bios_data_size(heap) +
			txt_os_mle_data_size(heap)));
}

static inline void *txt_os_sinit_data_start(void *heap)
{
	return heap + txt_bios_data_size(heap) +
		txt_os_mle_data_size(heap) + sizeof(u64);
}

static inline u64 txt_sinit_mle_data_size(void *heap)
{
	return *((u64 *)(heap + txt_bios_data_size(heap) +
			txt_os_mle_data_size(heap) +
			txt_os_sinit_data_size(heap)));
}

static inline void *txt_sinit_mle_data_start(void *heap)
{
	return heap + txt_bios_data_size(heap) +
		txt_os_mle_data_size(heap) +
		txt_sinit_mle_data_size(heap) + sizeof(u64);
}

/*
 * SKINIT specific event logging.
 */
static inline u64 skinit_find_event_log(void *skl_base, u32 *evtlog_size)
{
	struct sl_header *sl_hdr = skl_base;
	struct skl_tag_tags_size *t = skl_base + sl_hdr->bootloader_data_offset;
	struct skl_tag_evtlog *t_log = (struct skl_tag_evtlog *)t;
	void *end = (void *)t + t->size;

	*evtlog_size = 0;

	while ((void *)t_log < end
	       && t_log->hdr.type != SKL_TAG_EVENT_LOG
	       && t_log->hdr.type != SKL_TAG_END) {
		t_log = (void *)t_log + t_log->hdr.len;
	}

	if (t_log->hdr.type != SKL_TAG_EVENT_LOG)
		return 0;

	*evtlog_size = t_log->size;

	 return (u64)t_log->address;
}

/*
 * TPM event logging functions.
 */
static inline struct txt_heap_event_log_pointer2_1_element*
tpm20_find_log2_1_element(struct txt_os_sinit_data *os_sinit_data)
{
	struct txt_heap_ext_data_element *ext_elem;

	/* The extended element array as at the end of this table */
	ext_elem = (struct txt_heap_ext_data_element *)
		((u8 *)os_sinit_data + sizeof(struct txt_os_sinit_data));

	while (ext_elem->type != TXT_HEAP_EXTDATA_TYPE_END) {
		if (ext_elem->type ==
		    TXT_HEAP_EXTDATA_TYPE_EVENT_LOG_POINTER2_1) {
			return (struct txt_heap_event_log_pointer2_1_element *)
				((u8 *)ext_elem +
					sizeof(struct txt_heap_ext_data_element));
		}
		ext_elem =
			(struct txt_heap_ext_data_element *)
			((u8 *)ext_elem + ext_elem->size);
	}

	return NULL;
}

static inline int tpm12_log_event(void *evtlog_base, u32 evtlog_size,
				  u32 event_size, void *event)
{
	struct tpm12_event_log_header *evtlog =
		(struct tpm12_event_log_header *)evtlog_base;

	if (memcmp(evtlog->signature, TPM12_EVTLOG_SIGNATURE,
		   sizeof(TPM12_EVTLOG_SIGNATURE)))
		return -EINVAL;

	if (evtlog->container_size > evtlog_size)
		return -EINVAL;

	if (evtlog->next_event_offset + event_size > evtlog->container_size)
		return -E2BIG;

	memcpy(evtlog_base + evtlog->next_event_offset, event, event_size);
	evtlog->next_event_offset += event_size;

	return 0;
}

static inline int tpm20_log_event(struct txt_heap_event_log_pointer2_1_element *elem,
				  void *evtlog_base, u32 evtlog_size,
				  u32 event_size, void *event)
{
	struct tcg_pcr_event *header =
		(struct tcg_pcr_event *)evtlog_base;

	/* Has to be at least big enough for the signature */
	if (header->event_size < sizeof(TCG_SPECID_SIG))
		return -EINVAL;

	if (memcmp((u8 *)header + sizeof(struct tcg_pcr_event),
		   TCG_SPECID_SIG, sizeof(TCG_SPECID_SIG)))
		return -EINVAL;

	if (elem->allocated_event_container_size > evtlog_size)
		return -EINVAL;

	if (elem->next_record_offset + event_size >
	    elem->allocated_event_container_size)
		return -E2BIG;

	memcpy(evtlog_base + elem->next_record_offset, event, event_size);
	elem->next_record_offset += event_size;

	return 0;
}

/*
 * External functions avalailable in compressed kernel.
 */
extern u32 slaunch_get_cpu_type(void);

/*
 * External functions avalailable in mainline kernel.
 */
extern void slaunch_setup_txt(void);
extern void slaunch_setup_skinit(void);
extern u32 slaunch_get_flags(void);
extern struct sl_ap_wake_info *slaunch_get_ap_wake_info(void);
extern struct acpi_table_header *slaunch_get_dmar_table(struct acpi_table_header *dmar);
extern void __noreturn slaunch_txt_reset(void __iomem *txt,
					 const char *msg, u64 error);
extern void __noreturn slaunch_skinit_reset(const char *msg, u64 error);
extern void slaunch_finalize(int do_sexit);

extern void slaunch_psp_setup(void);
extern void slaunch_psp_finalize(void);

#endif /* !__ASSEMBLY */

#else

#define slaunch_get_cpu_type()		0
#define slaunch_setup_txt()		do { } while (0)
#define slaunch_setup_skinit()		do { } while (0)
#define slaunch_get_flags()		0
#define slaunch_get_dmar_table(d)	(d)
#define slaunch_finalize(d)		do { } while (0)

#endif /* !IS_ENABLED(CONFIG_SECURE_LAUNCH) */

#endif /* _LINUX_SLAUNCH_H */
