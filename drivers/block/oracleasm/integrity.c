/* -*- mode: c; c-basic-offset: 8; -*-
 * vim: noexpandtab sw=8 ts=8 sts=0:
 *
 * NAME
 *	integrity.c - ASM block layer data integrity support.
 *
 * AUTHOR
 * 	Martin K. Petersen <martin.petersen@oracle.com>
 *
 * MODIFIED   (YYYY/MM/DD)
 *	2010/04/07 Martin K. Petersen <martin.petersen@oracle.com>
 *		App tag checking
 *	2009/11/04 - Martin K. Petersen <martin.petersen@oracle.com>
 *		Support for 4KB/4KB and 512/4KB formats.
 *	2009/01/06 - Martin K. Petersen <martin.petersen@oracle.com>
 *		Moved into a separate file so we can compile on older
 * 		kernels.
 *	2008/09/01 - Martin K. Petersen <martin.petersen@oracle.com>
 *		Data integrity changes.
 *
 * Copyright (c) 2008-2010 Oracle.  All rights reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License, version 2 as published by the Free Software Foundation.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 */

#include <linux/pagemap.h>
#include <linux/bio.h>
#include <linux/blkdev.h>
#include <linux/compat.h>

#include "linux/oracleasm/compat32.h"
#include "linux/oracleasm/kernel.h"
#include "linux/oracleasm/abi.h"
#include "linux/oracleasm/disk.h"
#include "linux/oracleasm/error.h"

#include "request.h"
#include "masklog.h"
#include "integrity.h"

u32 asm_integrity_format(struct block_device *bdev)
{
	struct blk_integrity *bi = bdev_get_integrity(bdev);
	unsigned int lbs = bdev_logical_block_size(bdev);
	unsigned int pbs = bdev_physical_block_size(bdev);
	unsigned int format = 0;

	if (!bi)
		return 0;

	if (lbs == 512 && pbs == 512)
		format = ASM_IMODE_512_512;
	else if (lbs == 512 && pbs == 4096)
		format = ASM_IMODE_512_4K;
	else if (lbs == 4096 && pbs == 4096)
		format = ASM_IMODE_4K_4K;
	else
		return 0;

	if (!strcmp(bi->name, "T10-DIF-TYPE1-CRC"))
		return format;

	if (!strcmp(bi->name, "T10-DIF-TYPE1-IP"))
		return format | ASM_IFMT_IP_CHECKSUM;

	return 0;
} /* asm_integrity_format */


int asm_integrity_check(struct oracleasm_integrity_v2 *it, struct block_device *bdev)
{
	unsigned int dev_format;

	/* Strip feature flags */
	dev_format = asm_integrity_format(bdev) & ASM_INTEGRITY_HANDLE_MASK;

	if (!dev_format)
		return 0;

	if (it->it_magic != ASM_INTEGRITY_MAGIC) {
		mlog(ML_ERROR|ML_IOC, "IOC integrity: Bad magic...\n");
		return -EINVAL;
	}

	if (it->it_format != dev_format) {
		mlog(ML_ERROR|ML_IOC,
		     "IOC integrity: incorrect format for %s (%u != %u)\n",
		     bdev->bd_disk->disk_name, it->it_format, dev_format);
		return -EINVAL;
	}

	if (it->it_bytes == 0) {
		mlog(ML_ERROR|ML_IOC,
		     "IOC integrity: zero integrity buffer length\n");
		return -EINVAL;
	}

	if (it->it_buf == 0) {
		mlog(ML_ERROR|ML_IOC,
		     "IOC integrity: NULL integrity buffer\n");
		return -EINVAL;
	}

	return 0;
} /* asm_integrity_check */


int asm_integrity_map(struct oracleasm_integrity_v2 *it, struct asm_request *r, int write_to_vm)
{
	int len = it->it_bytes;
	unsigned long uaddr = (unsigned long)it->it_buf;
	unsigned long end = (uaddr + len + PAGE_SIZE - 1) >> PAGE_SHIFT;
	unsigned long start = uaddr >> PAGE_SHIFT;
	unsigned int nr_pages = end - start;
	unsigned int offset;
	int i, ret;
	struct bio *bio = r->r_bio;
	struct bio_integrity_payload *bip;
	struct page **pages;

	ret = 0;

	if (nr_pages < 1) {
		mlog(ML_ERROR, "%s: nr_pages < 1\n", __func__);
		return -EINVAL;
	}

	bip = bio_integrity_alloc(bio, GFP_NOIO, nr_pages);
	if (!bip) {
		mlog(ML_ERROR, "%s: could not allocate bip\n", __func__);
		return -ENOMEM;
	}

	bip->bip_size = len;
	bip->bip_sector = bio->bi_sector;
	bio->bi_flags |= (1 << BIO_FS_INTEGRITY);

	/* This is a retry. Prevent reference tag from being remapped again */
	if (it->it_flags & ASM_IFLAG_REMAPPED)
		bio->bi_flags |= 1 << BIO_MAPPED_INTEGRITY;

	pages = kcalloc(nr_pages, sizeof(struct page *), GFP_KERNEL);
	if (!pages) {
		mlog(ML_ERROR, "%s: could not allocate page array\n", __func__);
		return -ENOMEM;
	}

	ret = get_user_pages_fast(uaddr, nr_pages, write_to_vm, &pages[0]);
	if (ret < nr_pages) {
		mlog(ML_ERROR, "%s: could not get user pages\n", __func__);
		kfree(pages);
		return -EFAULT;
	}

	offset = offset_in_page(it->it_buf);
	ret = 0;

	for (i = 0 ; i < nr_pages ; i++) {
		unsigned int bytes = PAGE_SIZE - offset;
		unsigned int added;

		if (len <= 0)
			break;

		if (bytes > len)
			bytes = len;

		added = bio_integrity_add_page(bio, pages[i], bytes, offset);

		if (added < bytes) {
			ret = -1;
			mlog(ML_ERROR, "%s: bio %p added %u bytes, wanted %u\n",
			     __func__, bio, added, bytes);
			break;
		}

		len -= bytes;
		offset = 0;
	}

	while (i < nr_pages)
		page_cache_release(pages[i++]);

	kfree(pages);

	if (bio->bi_integrity->bip_vcnt == 0)
		ret = -EINVAL;

	return ret;
} /* asm_integrity_map */


void asm_integrity_unmap(struct bio *bio)
{
	struct bio_vec *iv;
	unsigned int i;

	if (!bio_flagged(bio, BIO_FS_INTEGRITY))
		return;

	bip_for_each_vec(iv, bio->bi_integrity, i) {
		if (bio_data_dir(bio) == READ)
			set_page_dirty_lock(iv->bv_page);

		page_cache_release(iv->bv_page);
	}
} /* asm_integrity_unmap */


unsigned int asm_integrity_error(struct asm_request *r)
{
	return ASM_ERR_INTEGRITY;
}
