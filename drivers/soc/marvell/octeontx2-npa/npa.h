/* SPDX-License-Identifier: GPL-2.0
 * Marvell OcteonTx2 NPA driver
 *
 * Copyright (C) 2020 Marvell.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

/* PCI Config offsets */
#define REG_BAR_NUM 2
#define MBOX_BAR_NUM 4

#define NPA_MAX_PFS	16
#define NPA_MAX_AURAS	128
#define NPA_AURA_AVG_LVL	255
#define NAME_SIZE               32

#define RVU_PFVF_PF_SHIFT       10
#define RVU_PFVF_PF_MASK        0x3F
#define RVU_PFVF_FUNC_SHIFT     0
#define RVU_PFVF_FUNC_MASK      0x3FF

#define RVU_FUNC_BLKADDR_SHIFT          20
#define RVU_FUNC_BLKADDR_MASK           0x1FULL

/* NPA LF registers */
#define NPA_LFBASE                      (BLKTYPE_NPA << RVU_FUNC_BLKADDR_SHIFT)
#define NPA_LF_AURA_OP_ALLOCX(a)        (NPA_LFBASE | 0x10 | (a) << 3)
#define NPA_LF_AURA_OP_FREE0            (NPA_LFBASE | 0x20)
#define NPA_LF_AURA_OP_FREE1            (NPA_LFBASE | 0x28)

#if defined(CONFIG_ARM64)
static inline void otx2_write128(u64 lo, u64 hi, void __iomem *addr)
{
	__asm__ volatile("stp %x[x0], %x[x1], [%x[p1],#0]!"
			 ::[x0]"r"(lo), [x1]"r"(hi), [p1]"r"(addr));
}

static inline u64 otx2_atomic64_add(u64 incr, u64 *ptr)
{
	u64 result;

	__asm__ volatile(".cpu   generic+lse\n"
			 "ldadd %x[i], %x[r], [%[b]]"
			 : [r]"=r"(result), "+m"(*ptr)
			 : [i]"r"(incr), [b]"r"(ptr)
			 : "memory");
	return result;
}
#else
#define otx2_write128(lo, hi, addr)
#define otx2_atomic64_add(incr, ptr)		({ *(ptr) += incr; })
#endif

enum {
	NPA_REG_BASE,
	AFPF_MBOX_BASE,
	PFVF_MBOX_BASE,
	NPA_MEM_REGIONS,
};

struct ptr_pair {
	struct page *page;
	dma_addr_t iova;
};

struct otx2_npa_pool {
	struct qmem *stack;
	struct qmem *fc_addr;
	u8 rbpage_order;
	u16 rbsize;
	u32 page_offset;
	u16 pageref;
	struct page *page;

	/* Metadata of pointers */
	u16 ptr_pairs_in_page;
	u16 ptr_pairs_per_page;
	u16 ptr_pair_cnt;
	u8 *ptr_list;
	struct page *ptr_list_start;
};

struct otx2_mmio {
  /** PCI address to which the BAR is mapped. */
	unsigned long start;
  /** Length of this PCI address space. */
	unsigned long len;
  /** Length that has been mapped to phys. address space. */
	unsigned long mapped_len;
  /** The physical address to which the PCI address space is mapped. */
	void __iomem *hw_addr;
  /** Flag indicating the mapping was successful. */
	int done;
};

struct npa_dev_t;
struct rvu_vf {
	struct work_struct mbox_wrk;
	struct work_struct mbox_wrk_up;
	struct work_struct pfvf_flr_work;
	struct device_attribute in_use_attr;
	struct pci_dev *pdev;
	struct kobject *limits_kobj;
	/* pointer to PF struct this PF belongs to */
	struct npa_dev_t *npa;
	int vf_id;
	int intr_idx;		/* vf_id%64 actually */
	bool in_use;
	bool got_flr;
};

struct npa_dev_t {
	struct mutex lock;
	struct pci_dev *pdev;
	u64 *alloc_reg_ptr;
	void __iomem *free_reg_addr;
	u16 pcifunc;
	u16 npa_msixoff;
	u16 pf_id;
	u16 num_vfs;
	u16 num_vec;
	u32 stack_pg_ptrs;	/* No of ptrs per stack page */
	u32 stack_pg_bytes;	/* Size of stack page */
	DECLARE_BITMAP(aura_bmp, NPA_MAX_AURAS);
	char *irq_names;
	struct workqueue_struct *afpf_mbox_wq;
	struct workqueue_struct *pfvf_mbox_wq;
	struct otx2_mbox pfvf_mbox;	/* MBOXes for VF => PF channel */
	struct otx2_mbox pfvf_mbox_up;	/* MBOXes for PF => VF channel */
	struct otx2_mbox afpf_mbox;	/* MBOX for PF => AF channel */
	struct otx2_mbox afpf_mbox_up;	/* MBOX for AF => PF channel */
	struct work_struct mbox_wrk;
	struct work_struct mbox_wrk_up;
	struct rvu_vf *vf_info;
	struct otx2_npa_pool *pools[NPA_MAX_AURAS];
	struct otx2_mmio mmio[NPA_MEM_REGIONS];
};

union aura_handle {
	struct {
		u32 aura:16;
		u32 pf_id:16;
	} s;
	u32 handle;
};

#define M(_name, _id, _fn_name, _req_type, _rsp_type)                   \
static struct _req_type __maybe_unused					\
*otx2_af_mbox_alloc_msg_ ## _fn_name(struct otx2_mbox *mbox)            \
{									\
	struct _req_type *req;						\
									\
	req = (struct _req_type *)otx2_mbox_alloc_msg_rsp(		\
		mbox, 0, sizeof(struct _req_type),			\
		sizeof(struct _rsp_type));				\
	if (!req)							\
		return NULL;						\
	req->hdr.sig = OTX2_MBOX_REQ_SIG;				\
	req->hdr.id = _id;						\
	return req;							\
}

MBOX_MESSAGES
#undef M
