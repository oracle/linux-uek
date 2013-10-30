/*
 * Copyright (c) 2006-2012 Xsigo Systems Inc.  All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *	Redistribution and use in source and binary forms, with or
 *	without modification, are permitted provided that the following
 *	conditions are met:
 *
 *	 - Redistributions of source code must retain the above
 *	   copyright notice, this list of conditions and the following
 *	   disclaimer.
 *
 *	 - Redistributions in binary form must reproduce the above
 *	   copyright notice, this list of conditions and the following
 *	   disclaimer in the documentation and/or other materials
 *	   provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

 /* File which houses logig to align cmd->request_buffer sg lists
  * to make them work with the IB FMR frames
  * Bugs: This code uses PAGE_SIZE as HCA Page size.  This is a horribly
  * incorrect assumption.
  */
#include <linux/version.h>
#include <linux/blkdev.h>

#include <linux/highmem.h>

#include "xs_compat.h"
#include "vhba_align.h"
#include "vhba_os_def.h"

static size_t sg_copy_buffer(struct scatterlist *sgl, unsigned int nents,
			     void *buf, size_t buflen, int to_buffer)
{
	struct scatterlist *sg;
	size_t buf_off = 0;
	int i;

	for (i = 0, sg = sgl; i < nents; i++, sg++) {
		struct page *page;
		int n = 0;
		unsigned int sg_off = sg->offset;
		unsigned int sg_copy = sg->length;

		if (sg_copy > buflen)
			sg_copy = buflen;
		buflen -= sg_copy;

		while (sg_copy > 0) {
			unsigned int page_copy;
			void *p;

			page_copy = PAGE_SIZE - sg_off;
			if (page_copy > sg_copy)
				page_copy = sg_copy;

			page = nth_page(sg_page(sg), n);
			p = kmap_atomic(page);

			if (to_buffer)
				memcpy(buf + buf_off, p + sg_off, page_copy);
			else {
				memcpy(p + sg_off, buf + buf_off, page_copy);
				flush_kernel_dcache_page(page);
			}

			kunmap_atomic(p);

			buf_off += page_copy;
			sg_off += page_copy;
			if (sg_off == PAGE_SIZE) {
				sg_off = 0;
				n++;
			}
			sg_copy -= page_copy;
		}

		if (!buflen)
			break;
	}

	return buf_off;
}

size_t sg_copy_from_buffer(struct scatterlist *sgl, unsigned int nents,
			   void *buf, size_t buflen)
{
	return sg_copy_buffer(sgl, nents, buf, buflen, 0);
}

size_t sg_copy_to_buffer(struct scatterlist *sgl, unsigned int nents,
			 void *buf, size_t buflen)
{
	return sg_copy_buffer(sgl, nents, buf, buflen, 1);
}

struct scatterlist *vhba_setup_bounce_buffer(struct srb *sp)
{
	struct scatterlist *scat;
	int nents;
	int total_len = 0;
	void *memp;
	struct scatterlist *orig_sg = scsi_sglist(sp->cmd);

	nents = scsi_sg_count(sp->cmd);
	scat = scsi_sglist(sp->cmd);
	total_len = scsi_bufflen(sp->cmd);

	memp = (void *)__get_free_pages(GFP_ATOMIC,
					max(2, get_order(total_len)));

	if (!memp)
		return NULL;

	if (sp->cmd->sc_data_direction == DMA_TO_DEVICE)
		sg_copy_to_buffer(scat, nents, memp, total_len);

	/*
	 * Sajid check here, we should not be mucking around with use_sg here
	 */
	sp->use_sg_orig = scsi_sg_count(sp->cmd);
	scsi_set_buffer(sp->cmd, memp);
	sp->bounce_buffer = memp;
	set_scsi_sg_count(sp->cmd, 0);
	sp->bounce_buf_len = total_len;

	return orig_sg;
}

void vhba_tear_bounce_buffer(struct srb *sp)
{
	int total_len;
	void *memp;
	int nents;
	struct scatterlist *scat;

	scsi_set_buffer(sp->cmd, sp->unaligned_sg);
	set_scsi_sg_count(sp->cmd, sp->use_sg_orig);

	nents = scsi_sg_count(sp->cmd);
	scat = scsi_sglist(sp->cmd);
	memp = sp->bounce_buffer;
	total_len = sp->bounce_buf_len;

	if (sp->cmd->sc_data_direction == DMA_FROM_DEVICE)
		sg_copy_from_buffer(scat, nents, memp, total_len);

	sp->bounce_buffer = NULL;
	sp->bounce_buf_len = 0;
	sp->unaligned_sg = NULL;

	free_pages((unsigned long)memp, max(2, get_order(total_len)));
}

int check_sg_alignment(struct srb *sp, struct scatterlist *sg)
{
	int i;
	int ret = 0;
	unsigned int sg_offset = SG_OFFSET(sg);

	/*
	 * check for 8 byte alignment only for sg entry
	 * as we can handle an offset for the first entry alone
	 * rest of the entries should be 4k (and thus also 8 byte)
	 * aligned
	 */
	if ((sg_offset + SG_LENGTH(sg)) % PAGE_SIZE) {
		dprintk(TRC_UNALIGNED, NULL,
			"Need to copy. SG_LENGTH:%d/scsi_sg_count:%d\n",
			SG_LENGTH(sg), scsi_sg_count(sp->cmd));
		ret = 1;
		goto out;
	}
	SG_NEXT(sg);

	/* Check from second entry */
	for (i = 1; i < scsi_sg_count(sp->cmd); i++, SG_NEXT(sg)) {
		sg_offset = SG_OFFSET(sg);
		/* All intermediate sg ptrs should be page (4k) aligned */
		if (sg_offset) {
			dprintk(TRC_UNALIGNED, NULL,
				"ptr %d in sg list needs copy len %d addr "
				"align %llu\n", i, SG_LENGTH(sg),
				(long long unsigned int)
				(sg_offset & (PAGE_SIZE - 1)));
			ret = 1;
			goto out;
		}

		if ((i != (scsi_sg_count(sp->cmd) - 1))
		    && (SG_LENGTH(sg) % PAGE_SIZE)) {
			dprintk(TRC_UNALIGNED, NULL,
				"ptr %d in sg list needs copy len %d\n", i,
				SG_LENGTH(sg));
			ret = 1;
			goto out;
		}

	}
out:
	SG_RESET(sg);
	return ret;
}
