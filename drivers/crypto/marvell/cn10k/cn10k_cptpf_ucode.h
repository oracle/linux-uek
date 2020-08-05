/* SPDX-License-Identifier: GPL-2.0-only
 * Copyright (C) 2020 Marvell.
 */

#ifndef __CN10K_CPTPF_UCODE_H
#define __CN10K_CPTPF_UCODE_H

#include <linux/pci.h>
#include <linux/types.h>
#include <linux/module.h>
#include "cn10k_cpt_hw_types.h"
#include "cn10k_cpt_common.h"

/*
 * On OcteonTX2 platform IPSec ucode can use both IE and SE engines therefore
 * IE and SE engines can be attached to the same engine group.
 */
#define CN10K_CPT_MAX_ETYPES_PER_GRP 2

/* CPT ucode alignment */
#define CN10K_CPT_UCODE_ALIGNMENT    128

/* CPT ucode signature size */
#define CN10K_CPT_UCODE_SIGN_LEN     256

/* Microcode version string length */
#define CN10K_CPT_UCODE_VER_STR_SZ   44

/* Maximum number of supported engines/cores on OcteonTX3 platform */
#define CN10K_CPT_MAX_ENGINES        144

#define CN10K_CPT_ENGS_BITMASK_LEN   BITS_TO_LONGS(CN10K_CPT_MAX_ENGINES)

/* Microcode types */
enum cn10k_cpt_ucode_type {
	CN10K_CPT_AE_UC_TYPE = 1,  /* AE-MAIN */
	CN10K_CPT_SE_UC_TYPE1 = 20,/* SE-MAIN - combination of 21 and 22 */
	CN10K_CPT_SE_UC_TYPE2 = 21,/* Fast Path IPSec + AirCrypto */
	CN10K_CPT_SE_UC_TYPE3 = 22,/*
				    * Hash + HMAC + FlexiCrypto + RNG +
				    * Full Feature IPSec + AirCrypto + Kasumi
				    */
	CN10K_CPT_IE_UC_TYPE1 = 30, /* IE-MAIN - combination of 31 and 32 */
	CN10K_CPT_IE_UC_TYPE2 = 31, /* Fast Path IPSec */
	CN10K_CPT_IE_UC_TYPE3 = 32, /*
				     * Hash + HMAC + FlexiCrypto + RNG +
				     * Full Future IPSec
				     */
};

struct cn10k_cpt_bitmap {
	unsigned long bits[CN10K_CPT_ENGS_BITMASK_LEN];
	int size;
};

struct cn10k_cpt_engines {
	int type;
	int count;
};

/* Microcode version number */
struct cn10k_cpt_ucode_ver_num {
	u8 nn;
	u8 xx;
	u8 yy;
	u8 zz;
};

struct cn10k_cpt_ucode_hdr {
	struct cn10k_cpt_ucode_ver_num ver_num;
	u8 ver_str[CN10K_CPT_UCODE_VER_STR_SZ];
	u32 code_length;
	u32 padding[3];
};

struct cn10k_cpt_ucode {
	u8 ver_str[CN10K_CPT_UCODE_VER_STR_SZ];/*
						* ucode version in readable
						* format
						*/
	struct cn10k_cpt_ucode_ver_num ver_num;/* ucode version number */
	char filename[CN10K_CPT_NAME_LENGTH];  /* ucode filename */
	dma_addr_t dma;		/* phys address of ucode image */
	dma_addr_t align_dma;	/* aligned phys address of ucode image */
	void *va;		/* virt address of ucode image */
	void *align_va;		/* aligned virt address of ucode image */
	u32 size;		/* ucode image size */
	int type;		/* ucode image type SE, IE, AE or SE+IE */
};

struct tar_ucode_info_t {
	struct list_head list;
	struct cn10k_cpt_ucode ucode;/* microcode information */
	const u8 *ucode_ptr;	/* pointer to microcode in tar archive */
};

/* Maximum and current number of engines available for all engine groups */
struct cn10k_cpt_engs_available {
	int max_se_cnt;
	int max_ie_cnt;
	int max_ae_cnt;
	int se_cnt;
	int ie_cnt;
	int ae_cnt;
};

/* Engines reserved to an engine group */
struct cn10k_cpt_engs_rsvd {
	int type;	/* engine type */
	int count;	/* number of engines attached */
	int offset;     /* constant offset of engine type in the bitmap */
	unsigned long *bmap;		/* attached engines bitmap */
	struct cn10k_cpt_ucode *ucode;	/* ucode used by these engines */
};

struct cn10k_cpt_mirror_info {
	int is_ena;	/*
			 * is mirroring enabled, it is set only for engine
			 * group which mirrors another engine group
			 */
	int idx;	/*
			 * index of engine group which is mirrored by this
			 * group, set only for engine group which mirrors
			 * another group
			 */
	int ref_count;	/*
			 * number of times this engine group is mirrored by
			 * other groups, this is set only for engine group
			 * which is mirrored by other group(s)
			 */
};

struct cn10k_cpt_eng_grp_info {
	struct cn10k_cpt_eng_grps *g; /* pointer to engine_groups structure */
	struct device_attribute info_attr; /* group info entry attr */
	/* engines attached */
	struct cn10k_cpt_engs_rsvd engs[CN10K_CPT_MAX_ETYPES_PER_GRP];
	/* ucodes information */
	struct cn10k_cpt_ucode ucode[CN10K_CPT_MAX_ETYPES_PER_GRP];
	/* sysfs info entry name */
	char sysfs_info_name[CN10K_CPT_NAME_LENGTH];
	/* engine group mirroring information */
	struct cn10k_cpt_mirror_info mirror;
	int idx;	 /* engine group index */
	bool is_enabled; /*
			  * is engine group enabled, engine group is enabled
			  * when it has engines attached and ucode loaded
			  */
};

struct cn10k_cpt_eng_grps {
	struct cn10k_cpt_eng_grp_info grp[CN10K_CPT_MAX_ENGINE_GROUPS];
	struct device_attribute ucode_load_attr;/* ucode load attr */
	struct cn10k_cpt_engs_available avail;
	struct mutex lock;
	void *obj;			/* device specific data */
	int engs_num;			/* total number of engines supported */
	int eng_types_supported;	/* engine types supported SE, IE, AE */
	u8 eng_ref_cnt[CN10K_CPT_MAX_ENGINES];/* engines reference count */
	bool is_ucode_load_created;	/* is ucode_load sysfs entry created */
	bool is_first_try; /* is this first try to create kcrypto engine grp */
	bool is_rdonly;	/* do engine groups configuration can be modified */
};
struct cn10k_cptpf_dev;
int cn10k_cpt_init_eng_grps(struct pci_dev *pdev,
			    struct cn10k_cpt_eng_grps *eng_grps);
void cn10k_cpt_cleanup_eng_grps(struct pci_dev *pdev,
				struct cn10k_cpt_eng_grps *eng_grps);
int cn10k_cpt_try_create_default_eng_grps(struct pci_dev *pdev,
					  struct cn10k_cpt_eng_grps *eng_grps);
void cn10k_cpt_set_eng_grps_is_rdonly(struct cn10k_cpt_eng_grps *eng_grps,
				      bool is_rdonly);
int cn10k_cpt_uc_supports_eng_type(struct cn10k_cpt_ucode *ucode, int eng_type);
int cn10k_cpt_eng_grp_has_eng_type(struct cn10k_cpt_eng_grp_info *eng_grp,
				   int eng_type);
int cn10k_cpt_disable_all_cores(struct cn10k_cptpf_dev *cptpf);
int cn10k_cpt_discover_eng_capabilities(void *obj);

#endif /* __CN10K_CPTPF_UCODE_H */
