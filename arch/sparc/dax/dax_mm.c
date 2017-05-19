/*
 * Copyright (c) 2017, Oracle and/or its affiliates. All rights reserved.
 *
 * This work is licensed under the terms of the GNU GPL, version 2.
 */

#include "dax_impl.h"

const struct vm_operations_struct dax_vm_ops = {
	.open  = dax_vm_open,
	.close = dax_vm_close,
};

int dax_at_to_ccb_idx[AT_MAX] = {
	QUERY_DWORD_OUTPUT,
	QUERY_DWORD_INPUT,
	QUERY_DWORD_SEC_INPUT,
	QUERY_DWORD_TBL,
};

char *dax_at_to_str[AT_MAX] = {
	"dst",
	"src0",
	"src1",
	"tbl"
};

static void dax_vm_print(char *prefix, struct dax_vma *dv)
{
	dax_map_dbg("%s : vma %p, kva=%p, uva=0x%lx, pa=0x%lx",
		  prefix, dv->vma, dv->kva,
		  dv->vma ? dv->vma->vm_start : 0, dv->pa);
	dax_map_dbg("%s: req length=0x%lx", prefix, dv->length);
}

static int dax_alloc_ram(struct file *filp, struct vm_area_struct *vma)
{
	unsigned long pa, pfn;
	char *kva;
	struct dax_vma *dv;
	size_t len;
	int ret = -ENOMEM;
	struct dax_ctx *dax_ctx = (struct dax_ctx *) filp->private_data;

	if (dax_no_ra_pgsz) {
		ret = -ENODEV;
		goto done;
	}

	len = vma->vm_end - vma->vm_start;
	if (len & (PAGE_SIZE - 1)) {
		dax_err("request (0x%lx) not a multiple of page size", len);
		goto done;
	}

	if (dax_no_flow_ctl && len != DAX_SYN_LARGE_PAGE_SIZE) {
		dax_map_dbg("unsupported length 0x%lx != 0x%lx virtual page size",
			    len, DAX_SYN_LARGE_PAGE_SIZE);
		ret = -EOVERFLOW;
		goto done;
	}

	dax_map_dbg("requested length=0x%lx", len);

	if (dax_ctx->dax_mm == NULL) {
		dax_err("no dax_mm for ctx %p!", dax_ctx);
		goto done;
	}

	kva = kzalloc(len, GFP_KERNEL);
	if (kva == NULL)
		goto done;

	if ((unsigned long)kva & (PAGE_SIZE - 1)) {
		dax_err("kmalloc returned unaligned (%ld) addr %p",
			PAGE_SIZE, kva);
		goto kva_error;
	}

	if (dax_no_flow_ctl && ((unsigned long)kva & (len - 1))) {
		dax_err("kmalloc returned unaligned (%ldk) addr %p",
			len/1024, kva);
		goto kva_error;
	}

	dv = kzalloc(sizeof(*dv), GFP_KERNEL);
	if (dv == NULL)
		goto kva_error;

	pa = virt_to_phys((void *)kva);
	pfn = pa >> PAGE_SHIFT;
	ret = remap_pfn_range(vma, vma->vm_start, pfn, len,
			      vma->vm_page_prot);
	if (ret != 0) {
		dax_err("remap failed with error %d for uva 0x%lx, len 0x%lx",
			ret, vma->vm_start, len);
		goto dv_error;
	}

	dax_map_dbg("mapped kva 0x%lx = uva 0x%lx to pa 0x%lx",
		    (unsigned long) kva, vma->vm_start, pa);

	dv->vma = vma;
	dv->kva = kva;
	dv->pa = pa;
	dv->length = len;
	dv->dax_mm = dax_ctx->dax_mm;

	spin_lock(&dax_ctx->dax_mm->lock);
	dax_ctx->dax_mm->vma_count++;
	spin_unlock(&dax_ctx->dax_mm->lock);
	atomic_inc(&dax_alloc_counter);
	atomic_add(dv->length / 1024, &dax_requested_mem);
	vma->vm_ops = &dax_vm_ops;
	vma->vm_private_data = dv;


	dax_vm_print("mapped", dv);
	ret = 0;

	goto done;

dv_error:
	kfree(dv);
kva_error:
	kfree(kva);
done:
	return ret;
}

/*
 * Maps two types of memory based on the PROT_READ or PROT_WRITE flag
 * set in the 'prot' argument of mmap user call
 *	1. When PROT_READ is set this function allocates DAX completion area
 *	2. When PROT_WRITE is set this function allocates memory using kmalloc
 *		and maps it to the userspace address.
 */
int dax_devmap(struct file *f, struct vm_area_struct *vma)
{
	unsigned long pfn;
	struct dax_ctx *dax_ctx = (struct dax_ctx *) f->private_data;
	size_t len = vma->vm_end - vma->vm_start;

	dax_dbg("len=0x%lx, flags=0x%lx", len, vma->vm_flags);

	if (dax_ctx == NULL) {
		dax_err("CCB_INIT ioctl not previously called");
		return -EINVAL;
	}
	if (dax_ctx->owner != current) {
		dax_err("devmap called from wrong thread");
		return -EINVAL;
	}

	if (vma->vm_flags & VM_WRITE)
		return dax_alloc_ram(f, vma);

	/* map completion area */

	if (len != dax_ctx->ca_buflen) {
		dax_err("len(%lu) != dax_ctx->ca_buflen(%u)",
			len, dax_ctx->ca_buflen);
		return -EINVAL;
	}

	pfn = virt_to_phys(dax_ctx->ca_buf) >> PAGE_SHIFT;
	if (remap_pfn_range(vma, vma->vm_start, pfn, len, vma->vm_page_prot))
		return -EAGAIN;
	dax_map_dbg("mmapped completion area at uva 0x%lx",  vma->vm_start);
	return 0;
}

int dax_map_segment_common(u32 *ccb_addr_type, enum dax_at at,
			   u32 addr_sel, union ccb *ccbp,
			   struct dax_ctx *dax_ctx)
{
	struct dax_vma *dv = NULL;
	struct vm_area_struct *vma;
	unsigned long virtp = ccbp->dwords[addr_sel];
	int ret, idx, tmp;
	struct page *page;

	*ccb_addr_type = CCB_AT_VA_ALT;
	dax_map_dbg("%s uva 0x%lx", dax_at_to_str[at], virtp);
	vma = find_vma(dax_ctx->dax_mm->this_mm, virtp);

	if (vma == NULL)
		return 0;

	dv = vma->vm_private_data;

	/* Only memory allocated by dax_alloc_ram has dax_vm_ops set */
	if (dv == NULL || vma->vm_ops != &dax_vm_ops) {
		idx = ccbp - dax_ctx->ccb_buf;

		if (is_vm_hugetlb_page(vma)) {
			dax_dbg("virtp=0x%lx backed by huge page. No need to lock",
				virtp);
		} else {
			ret = get_user_pages_fast(virtp, 1, 1, &page);

			if (ret == 1) {
				dax_ctx->pages[at][idx] = page;
				dax_dbg("locked page %p, for VA 0x%lx",
					page, virtp);
			} else {
				dax_err("get_user_pages for 1 page failed, virtp=0x%lx, ret=%d",
					virtp, ret);
				return -1;
			}
		}

		/*
		 * Hypervisor does the TLB or TSB walk
		 * and expects the translation to be present
		 * in either of them.
		 */
		if (copy_from_user(&tmp, (void __user *)
				   ccbp->dwords[addr_sel], 1)) {
			dax_dbg("ccb=0x%p, idx=%d", ccbp, idx);
			dax_dbg("bad %s address 0x%llx",
				dax_at_to_str[at], ccbp->dwords[addr_sel]);
		}
		return 0;
	}

	dax_vm_print("matched", dv);
	*ccb_addr_type = CCB_AT_RA;

	if (dax_no_flow_ctl) {
		ccbp->dwords[addr_sel] = CHECK_4MB_PAGE_RANGE |
			(dv->pa + (virtp - vma->vm_start));
		dax_map_dbg("changed %s to RA 0x%llx", dax_at_to_str[at],
			    ccbp->dwords[addr_sel]);
	} else {
		ccbp->dwords[addr_sel] = NO_PAGE_RANGE_CHECK |
			(dv->pa + (virtp - vma->vm_start));
		dax_map_dbg("changed %s to RA 0x%llx", dax_at_to_str[at],
			    ccbp->dwords[addr_sel]);
	}

	return 0;
}

/*
 * Look for use of special dax contiguous segment and
 * set it up for physical access
 */
int dax_map_segment(struct dax_ctx *dax_ctx, union ccb *ccb, size_t ccb_len)
{
	int i;
	int nelem = CCB_BYTE_TO_NCCB(ccb_len);
	u32 ccb_addr_type;

	for (i = 0; i < nelem; i++) {
		union ccb *ccbp = &ccb[i];
		struct ccb_hdr *hdr = CCB_HDR(ccbp);
		u32 idx;

		/* index into ccb_buf */
		idx = &ccb[i] - dax_ctx->ccb_buf;

		dax_dbg("ccb[%d]=0x%p, idx=%d, at_dst=%d",
			i, ccbp, idx, hdr->at_dst);
		if (hdr->at_dst == CCB_AT_VA_ALT) {
			if (dax_map_segment_common(&ccb_addr_type, AT_DST,
						   QUERY_DWORD_OUTPUT, ccbp,
						   dax_ctx) != 0)
				goto error;
			hdr->at_dst = ccb_addr_type;
		}

		if (hdr->at_src0 == CCB_AT_VA_ALT) {
			if (dax_map_segment_common(&ccb_addr_type, AT_SRC0,
						   QUERY_DWORD_INPUT, ccbp,
						   dax_ctx) != 0)
				goto error;
			hdr->at_src0 = ccb_addr_type;
		}

		if (hdr->at_src1 == CCB_AT_VA_ALT) {
			if (dax_map_segment_common(&ccb_addr_type, AT_SRC1,
						   QUERY_DWORD_SEC_INPUT, ccbp,
						   dax_ctx) != 0)
				goto error;
			hdr->at_src1 = ccb_addr_type;
		}

		if (hdr->at_tbl == CCB_AT_VA_ALT) {
			if (dax_map_segment_common(&ccb_addr_type, AT_TBL,
						   QUERY_DWORD_TBL, ccbp,
						   dax_ctx) != 0)
				goto error;
			hdr->at_tbl = ccb_addr_type;
		}

		/* skip over 2nd 64 bytes of long CCB */
		if (IS_LONG_CCB(ccbp))
			i++;
	}
	return 0;
error:
	/*
	 * On error this unlocks all the pages locked by
	 * dax_map_segment_common(...)
	 */
	dax_unlock_pages(dax_ctx, ccb, ccb_len);
	return -1;
}

int dax_alloc_page_arrays(struct dax_ctx *ctx)
{
	int i;

	for (i = 0; i < AT_MAX ; i++) {
		ctx->pages[i] = vzalloc(DAX_CCB_BUF_NELEMS *
					sizeof(struct page *));
		if (ctx->pages[i] == NULL) {
			dax_dealloc_page_arrays(ctx);
			return -ENOMEM;
		}
	}

	return 0;
}

void dax_dealloc_page_arrays(struct dax_ctx *ctx)
{
	int i;

	for (i = 0; i < AT_MAX ; i++) {
		if (ctx->pages[i] != NULL)
			vfree(ctx->pages[i]);
		ctx->pages[i] = NULL;
	}
}


void dax_unlock_pages_ccb(struct dax_ctx *ctx, int ccb_num, union ccb *ccbp)
{
	int i;

	for (i = 0; i < AT_MAX ; i++) {
		if (ctx->pages[i][ccb_num]) {
			set_page_dirty(ctx->pages[i][ccb_num]);
			put_page(ctx->pages[i][ccb_num]);
			dax_dbg("freeing page %p", ctx->pages[i][ccb_num]);
			ctx->pages[i][ccb_num] = NULL;
		}
	}
}

/*
 * Unlock user pages. Called during dequeue or device close.
 */
void dax_unlock_pages(struct dax_ctx *dax_ctx, union ccb *ccb, size_t ccb_len)
{
	int i;
	int nelem = CCB_BYTE_TO_NCCB(ccb_len);

	for (i = 0; i < nelem; i++) {
		u32 idx;

		/* index into ccb_buf */
		idx = &ccb[i] - dax_ctx->ccb_buf;
		dax_unlock_pages_ccb(dax_ctx, idx, ccb);
	}
}

int dax_address_in_use(struct dax_vma *dv, u32 addr_type,
			      unsigned long addr)
{
	if (addr_type == CCB_AT_VA) {
		unsigned long virtp = addr;

		if (virtp >= (unsigned long)dv->kva &&
		    virtp < (unsigned long)dv->kva + dv->length)
			return 1;
	} else if (addr_type == CCB_AT_RA) {
		unsigned long physp = addr;

		if (physp >= dv->pa && physp < dv->pa + dv->length)
			return 1;
	}

	return 0;
}


/*
 * open function called if the vma is split;
 * usually happens in response to a partial munmap()
 */
void dax_vm_open(struct vm_area_struct *vma)
{
	dax_map_dbg("call with va=0x%lx, len=0x%lx",
		    vma->vm_start, vma->vm_end - vma->vm_start);
	dax_map_dbg("prot=0x%lx, flags=0x%lx",
		    pgprot_val(vma->vm_page_prot), vma->vm_flags);
}

static void dax_vma_drain(struct dax_vma *dv)
{
	struct dax_mm *dax_mm;
	struct dax_ctx *ctx;
	struct list_head *p;

	/* iterate over all threads in this process and drain all */
	dax_mm = dv->dax_mm;
	list_for_each(p, &dax_mm->ctx_list) {
		ctx = list_entry(p, struct dax_ctx, ctx_list);
		dax_ccbs_drain(ctx, dv);
	}
}

void dax_vm_close(struct vm_area_struct *vma)
{
	struct dax_vma *dv;
	struct dax_mm  *dm;

	dv = vma->vm_private_data;
	dax_map_dbg("vma=%p, dv=%p", vma, dv);
	if (dv == NULL) {
		dax_alert("dv NULL in dax_vm_close");
		return;
	}
	if (dv->vma != vma) {
		dax_map_dbg("munmap(0x%lx, 0x%lx) differs from mmap length 0x%lx",
			     vma->vm_start, vma->vm_end - vma->vm_start,
			     dv->length);
		return;
	}

	dm = dv->dax_mm;
	if (dm == NULL) {
		dax_alert("dv->dax_mm NULL in dax_vm_close");
		return;
	}

	dax_vm_print("freeing", dv);
	spin_lock(&dm->lock);
	vma->vm_private_data = NULL;

	/* signifies no mapping exists and prevents new transactions */
	dv->vma = NULL;
	dax_vma_drain(dv);

	kfree(dv->kva);
	atomic_sub(dv->length / 1024, &dax_requested_mem);
	kfree(dv);
	dm->vma_count--;
	atomic_dec(&dax_alloc_counter);

	if (dax_clean_dm(dm))
		spin_unlock(&dm->lock);
}

int dax_clean_dm(struct dax_mm *dm)
{
	/* if ctx list is empty, clean up this struct dax_mm */
	if (list_empty(&dm->ctx_list) && (dm->vma_count == 0)) {
		spin_lock(&dm_list_lock);
		list_del(&dm->mm_list);
		dax_list_dbg("freeing dm with vma_count=%d, ctx_count=%d",
			      dm->vma_count, dm->ctx_count);
		kfree(dm);
		spin_unlock(&dm_list_lock);
		return 0;
	}

	return -1;
}

