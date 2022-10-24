/* SPDX-License-Identifier: GPL-2.0 */
/*
 * TrenchBoot Secure Launch Resource Table
 *
 * The Secure Launch Resource Table is TrenchBoot project defined
 * specfication to provide cross-architecture compatibility. See
 * TrenchBoot Secure Launch kernel documentation for details.
 *
 * Copyright (c) 2024 Apertus Solutions, LLC
 * Copyright (c) 2024, Oracle and/or its affiliates.
 */

#ifndef _LINUX_SLR_TABLE_H
#define _LINUX_SLR_TABLE_H

/* Put this in efi.h if it becomes a standard */
#define SLR_TABLE_GUID				EFI_GUID(0x877a9b2a, 0x0385, 0x45d1, 0xa0, 0x34, 0x9d, 0xac, 0x9c, 0x9e, 0x56, 0x5f)

/* SLR table header values */
#define SLR_TABLE_MAGIC		0x4452544d
#define SLR_TABLE_REVISION	1

/* Current revisions for the policy and UEFI config */
#define SLR_POLICY_REVISION		1
#define SLR_UEFI_CONFIG_REVISION	1

/* SLR defined architectures */
#define SLR_INTEL_TXT		1
#define SLR_AMD_SKINIT		2

/* SLR defined bootloaders */
#define SLR_BOOTLOADER_INVALID	0
#define SLR_BOOTLOADER_GRUB	1

/* Log formats */
#define SLR_DRTM_TPM12_LOG	1
#define SLR_DRTM_TPM20_LOG	2

/* DRTM Policy Entry Flags */
#define SLR_POLICY_FLAG_MEASURED	0x1
#define SLR_POLICY_IMPLICIT_SIZE	0x2

/* Array Lengths */
#define TPM_EVENT_INFO_LENGTH		32
#define TXT_VARIABLE_MTRRS_LENGTH	32

/* Tags */
#define SLR_ENTRY_INVALID	0x0000
#define SLR_ENTRY_DL_INFO	0x0001
#define SLR_ENTRY_LOG_INFO	0x0002
#define SLR_ENTRY_ENTRY_POLICY	0x0003
#define SLR_ENTRY_INTEL_INFO	0x0004
#define SLR_ENTRY_AMD_INFO	0x0005
#define SLR_ENTRY_ARM_INFO	0x0006
#define SLR_ENTRY_UEFI_INFO	0x0007
#define SLR_ENTRY_UEFI_CONFIG	0x0008
#define SLR_ENTRY_END		0xffff

/* Entity Types */
#define SLR_ET_UNSPECIFIED	0x0000
#define SLR_ET_SLRT		0x0001
#define SLR_ET_BOOT_PARAMS	0x0002
#define SLR_ET_SETUP_DATA	0x0003
#define SLR_ET_CMDLINE		0x0004
#define SLR_ET_UEFI_MEMMAP	0x0005
#define SLR_ET_RAMDISK		0x0006
#define SLR_ET_TXT_OS2MLE	0x0010
#define SLR_ET_UNUSED		0xffff

#ifndef __ASSEMBLY__

/*
 * Primary Secure Launch Resource Table Header
 */
struct slr_table {
	u32 magic;
	u16 revision;
	u16 architecture;
	u32 size;
	u32 max_size;
	/* table entries */
} __packed;

/*
 * Common SLRT Table Header
 */
struct slr_entry_hdr {
	u32 tag;
	u32 size;
} __packed;

/*
 * Boot loader context
 */
struct slr_bl_context {
	u16 bootloader;
	u16 reserved[3];
	u64 context;
} __packed;

/*
 * Dynamic Launch Callback Function type
 */
typedef void (*dl_handler_func)(struct slr_bl_context *bl_context);

/*
 * DRTM Dynamic Launch Configuration
 */
struct slr_entry_dl_info {
	struct slr_entry_hdr hdr;
	u64 dce_size;
	u64 dce_base;
	u64 dlme_size;
	u64 dlme_base;
	u64 dlme_entry;
	struct slr_bl_context bl_context;
	u64 dl_handler;
} __packed;

/*
 * TPM Log Information
 */
struct slr_entry_log_info {
	struct slr_entry_hdr hdr;
	u16 format;
	u16 reserved;
	u32 size;
	u64 addr;
} __packed;

/*
 * DRTM Measurement Entry
 */
struct slr_policy_entry {
	u16 pcr;
	u16 entity_type;
	u16 flags;
	u16 reserved;
	u64 size;
	u64 entity;
	char evt_info[TPM_EVENT_INFO_LENGTH];
} __packed;

/*
 * DRTM Measurement Policy
 */
struct slr_entry_policy {
	struct slr_entry_hdr hdr;
	u16 reserved[2];
	u16 revision;
	u16 nr_entries;
	struct slr_policy_entry policy_entries[];
} __packed;

/*
 * Secure Launch defined MTRR saving structures
 */
struct slr_txt_mtrr_pair {
	u64 mtrr_physbase;
	u64 mtrr_physmask;
} __packed;

struct slr_txt_mtrr_state {
	u64 default_mem_type;
	u64 mtrr_vcnt;
	struct slr_txt_mtrr_pair mtrr_pair[TXT_VARIABLE_MTRRS_LENGTH];
} __packed;

/*
 * Intel TXT Info table
 */
struct slr_entry_intel_info {
	struct slr_entry_hdr hdr;
	u64 txt_heap;
	u64 saved_misc_enable_msr;
	struct slr_txt_mtrr_state saved_bsp_mtrrs;
} __packed;

/*
 * UEFI config measurement entry
 */
struct slr_uefi_cfg_entry {
	u16 pcr;
	u16 reserved;
	u32 size;
	u64 cfg; /* address or value */
	char evt_info[TPM_EVENT_INFO_LENGTH];
} __packed;

/*
 * UEFI config measurements
 */
struct slr_entry_uefi_config {
	struct slr_entry_hdr hdr;
	u16 reserved[2];
	u16 revision;
	u16 nr_entries;
	struct slr_uefi_cfg_entry uefi_cfg_entries[];
} __packed;

static inline void *slr_end_of_entries(struct slr_table *table)
{
	return (void *)table + table->size;
}

static inline void *
slr_next_entry(struct slr_table *table,
	       struct slr_entry_hdr *curr)
{
	struct slr_entry_hdr *next = (struct slr_entry_hdr *)((u8 *)curr + curr->size);

	if ((void *)next >= slr_end_of_entries(table))
		return NULL;
	if (next->tag == SLR_ENTRY_END)
		return NULL;

	return next;
}

static inline void *
slr_next_entry_by_tag(struct slr_table *table,
		      struct slr_entry_hdr *entry,
		      u16 tag)
{
	if (!entry) /* Start from the beginning */
		entry = (struct slr_entry_hdr *)(((u8 *)table) + sizeof(*table));

	for ( ; ; ) {
		if (entry->tag == tag)
			return entry;

		entry = slr_next_entry(table, entry);
		if (!entry)
			return NULL;
	}

	return NULL;
}

static inline int
slr_add_entry(struct slr_table *table,
	      struct slr_entry_hdr *entry)
{
	struct slr_entry_hdr *end;

	if ((table->size + entry->size) > table->max_size)
		return -1;

	memcpy((u8 *)table + table->size - sizeof(*end), entry, entry->size);
	table->size += entry->size;

	end  = (struct slr_entry_hdr *)((u8 *)table + table->size - sizeof(*end));
	end->tag = SLR_ENTRY_END;
	end->size = sizeof(*end);

	return 0;
}

static inline void
slr_init_table(struct slr_table *slrt, u16 architecture, u32 max_size)
{
	struct slr_entry_hdr *end;

	slrt->magic = SLR_TABLE_MAGIC;
	slrt->revision = SLR_TABLE_REVISION;
	slrt->architecture = architecture;
	slrt->size = sizeof(*slrt) + sizeof(*end);
	slrt->max_size = max_size;
	end = (struct slr_entry_hdr *)((u8 *)slrt + sizeof(*slrt));
	end->tag = SLR_ENTRY_END;
	end->size = sizeof(*end);
}

#endif /* !__ASSEMBLY */

#endif /* _LINUX_SLR_TABLE_H */
