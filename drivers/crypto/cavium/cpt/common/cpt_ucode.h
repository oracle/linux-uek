/* SPDX-License-Identifier: GPL-2.0
 * Marvell CPT common code
 *
 * Copyright (C) 2018 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef __CPT_UCODE_H
#define __CPT_UCODE_H

#include "cpt_hw_types.h"

/* Name maximum length */
#define NAME_LENGTH		64

/* On 8x platform only one type of engines is allowed to be attached
 * to an engine group. On 9x platform we have one exception from this
 * rule because IPSec ucode can use both IE and SE engines therefore
 * IE and SE engines can be attached to the same engine group.
 */
#define MAX_ENGS_PER_GRP	2

/* CPT ucode alignment */
#define CPT_UCODE_ALIGNMENT	128

/* CPT ucode signature size */
#define CPT_UCODE_SIGN_LEN	256

/* Maximum number of supported engines/cores on 8X platform */
#define CPT_8X_MAX_ENGINES	64

/* Maximum number of supported engines/cores on 9X platform */
#define CPT_9X_MAX_ENGINES	128

#define CPT_MAX_ENGINES		CPT_9X_MAX_ENGINES

#define CPT_ENGS_BITMASK_LEN	(CPT_MAX_ENGINES/(BITS_PER_BYTE * \
				 sizeof(unsigned long)))

#define ROUNDUP16(val) ((((int) val) + 15) & 0xFFFFFFF0)

/* Microcode types */
enum cpt_ucode_type {
	AE_UC_TYPE =	1,  /* AE-MAIN */
	SE_UC_TYPE1 =	20, /* SE-MAIN - combination of 21 and 22 */
	SE_UC_TYPE2 =	21, /* Fast Path IPSec + AirCrypto */
	SE_UC_TYPE3 =	22, /* Hash + HMAC + FlexiCrypto + RNG + Full Feature
			     *  IPSec + AirCrypto + Kasumi
			     */
	IE_UC_TYPE1 =	30, /* IE-MAIN - combination of 31 and 32 */
	IE_UC_TYPE2 =	31, /* Fast Path IPSec */
	IE_UC_TYPE3 =	32, /* Hash + HMAC + FlexiCrypto + RNG + Full Future
			     * IPSec
			     */
};

/* Tar archive defines */
#define TAR_MAGIC		"ustar"
#define TAR_MAGIC_LEN		6
#define TAR_BLOCK_LEN		512
#define REGTYPE			'0'
#define AREGTYPE		'\0'

/* tar header as defined in POSIX 1003.1-1990.  */
struct tar_hdr_t {
	char name[100];
	char mode[8];
	char uid[8];
	char gid[8];
	char size[12];
	char mtime[12];
	char chksum[8];
	char typeflag;
	char linkname[100];
	char magic[6];
	char version[2];
	char uname[32];
	char gname[32];
	char devmajor[8];
	char devminor[8];
	char prefix[155];
};

struct tar_blk_t {
	union {
		struct tar_hdr_t hdr;
		char block[TAR_BLOCK_LEN];
	};
};

struct tar_arch_info_t {
	struct list_head ucodes;
	const struct firmware *fw;
};

struct bitmap {
	unsigned long bits[CPT_ENGS_BITMASK_LEN];
	int size;
};

struct engines {
	int type;
	int count;
};

/* Microcode version number */
struct microcode_ver_num {
	u8 nn;
	u8 xx;
	u8 yy;
	u8 zz;
};

/* Microcode header size should be 48 bytes according to CNT8x-MC-IPSEC-0002 */
struct microcode_hdr {
	struct microcode_ver_num ver_num;
	u8 ver_str[CPT_UCODE_VER_STR_SZ];
	u32 code_length;
	u32 padding[3];
};

struct microcode {
	u8 ver_str[CPT_UCODE_VER_STR_SZ];/* ucode version in readable format */
	struct microcode_ver_num ver_num;/* ucode version number */
	char filename[NAME_LENGTH];	 /* ucode filename */
	dma_addr_t dma;		/* phys address of ucode image */
	dma_addr_t align_dma;	/* aligned phys address of ucode image */
	void *va;		/* virt address of ucode image */
	void *align_va;		/* aligned virt address of ucode image */
	u32 size;		/* ucode image size */
	int type;		/* ucode image type SE, IE, AE or SE+IE */
};

struct tar_ucode_info_t {
	struct list_head list;
	struct microcode ucode;	/* microcode information */
	const u8 *ucode_ptr;	/* pointer to microcode in tar archive */
};

/* Maximum and current number of engines available for all engine groups */
struct engines_available {
	int max_se_cnt;
	int max_ie_cnt;
	int max_ae_cnt;
	int se_cnt;
	int ie_cnt;
	int ae_cnt;
};

/* Engines reserved to an engine group */
struct engines_reserved {
	int type;	/* engine type */
	int count;	/* number of engines attached */
	int offset;     /* constant offset of engine type in the bitmap */
	unsigned long *bmap;		/* attached engines bitmap */
	struct microcode *ucode;	/* ucode used by these engines */
};

struct mirror_info {
	int is_ena;	/* is mirroring enabled, it is set only for engine
			 * group which mirrors another engine group
			 */
	int idx;	/* index of engine group which is mirrored by this
			 * group, set only for engine group which mirrors
			 * another group
			 */
	int ref_count;	/* number of times this engine group is mirrored by
			 * other groups, this is set only for engine group
			 * which is mirrored by other group(s)
			 */
};

struct engine_group_info {
	struct engine_groups *g; /* pointer to engine_groups structure */
	struct device_attribute info_attr; /* group info entry attr */
	struct engines_reserved engs[MAX_ENGS_PER_GRP];	/* engines attached */
	struct microcode ucode[MAX_ENGS_PER_GRP]; /* ucodes information */
	char sysfs_info_name[NAME_LENGTH]; /* sysfs info entry name */
	struct mirror_info mirror; /* engine group mirroring information */
	int idx;	 /* engine group index */
	bool is_enabled; /* is engine group enabled, engine group is enabled
			  * when it has engines attached and ucode loaded
			  */
};

struct ucode_ops {
	int (*detach_and_disable_cores)(struct engine_group_info *eng_grp,
					void *obj);
	int (*attach_and_enable_cores)(struct engine_group_info *eng_grp,
				       void *obj);
	int (*set_ucode_base)(struct engine_group_info *eng_grp, void *obj);
	void (*print_engines_mask)(struct engine_group_info *eng_grp,
				   void *obj, char *buf, int size);
	int (*discover_eng_capabilities)(void *obj);
};

struct engine_groups {
	struct engine_group_info grp[CPT_MAX_ENGINE_GROUPS];
	struct device_attribute ucode_load_attr;	/* ucode load attr */
	struct engines_available avail;
	struct mutex lock;
	struct ucode_ops ops;		/* 8x/9x microcode operations */
	void *obj;			/* 8x/9x platform specific data */
	int engs_num;			/* total number of engines supported */
	int eng_types_supported;	/* engine types supported SE, IE, AE */
	u8 eng_ref_cnt[CPT_MAX_ENGINES];/* engines reference count */
	bool is_ucode_load_created;	/* is ucode_load sysfs entry created */
	bool is_first_try; /* is this first try to create kcrypto engine grp */
	bool is_rdonly;	/* do engine groups configuration can be modified */
};

int cpt_init_eng_grps(struct pci_dev *pdev, struct engine_groups *eng_grps,
		      struct ucode_ops ops, int pf_type);
void cpt_cleanup_eng_grps(struct pci_dev *pdev,
			  struct engine_groups *eng_grps);
int cpt_try_create_default_eng_grps(struct pci_dev *pdev,
				    struct engine_groups *eng_grps);
int cpt_create_eng_caps_discovery_grps(struct pci_dev *pdev,
				       struct engine_groups *eng_grps);
int cpt_delete_eng_caps_discovery_grps(struct pci_dev *pdev,
				       struct engine_groups *eng_grps);
int cpt_get_eng_caps_discovery_grp(struct engine_groups *eng_grps, u8 eng_type);
void cpt_set_eng_grps_is_rdonly(struct engine_groups *eng_grps, bool is_rdonly);
int cpt_uc_supports_eng_type(struct microcode *ucode, int eng_type);
int cpt_eng_grp_has_eng_type(struct engine_group_info *eng_grp, int eng_type);

#endif /* __CPT_UCODE_H */
