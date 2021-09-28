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
#include "integrity.h"
#include "trace.h"

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

	if (bi->flags & BLK_INTEGRITY_DEVICE_CAPABLE)
		format |= ASM_IFMT_DISK;

	if (bi->tag_size)
		format |= ASM_IFMT_DISK | ASM_IFMT_ATO;

	if (!strcmp(bi->profile->name, "T10-DIF-TYPE1-CRC"))
		return format;

	if (!strcmp(bi->profile->name, "T10-DIF-TYPE1-IP"))
		return format | ASM_IFMT_IP_CHECKSUM;

	return 0;
} /* asm_integrity_format */


int asm_integrity_check(struct oracleasm_integrity_v2 *it, struct block_device *bdev)
{
	unsigned int dev_format;

	if (unlikely(it->it_magic != ASM_INTEGRITY_MAGIC)) {
		pr_err("%s: Bad integrity magic %x!\n", __func__, it->it_magic);
		return -EINVAL;
	}

	if (unlikely(it->it_bytes == 0)) {
		pr_err("%s: zero length integrity buffer\n", __func__);
		return -EINVAL;
	}

	if (unlikely(it->it_buf == 0)) {
		pr_err("%s: NULL integrity buffer\n", __func__);
		return -EINVAL;
	}

	if (it->it_flags & ASM_IFLAG_FORMAT_NOCHECK)
		return 0;

	dev_format = asm_integrity_format(bdev) & ASM_INTEGRITY_HANDLE_MASK;

	if (!dev_format)
		return -EINVAL;

	if (unlikely(it->it_format != dev_format)) {
		pr_err("%s: incorrect format for %s (%u != %u)\n", __func__,
		       bdev->bd_disk->disk_name, it->it_format, dev_format);
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

	if (unlikely(nr_pages < 1)) {
		pr_err("%s: nr_pages < 1\n", __func__);
		return -EINVAL;
	}

	bip = bio_integrity_alloc(bio, GFP_NOIO, nr_pages);
	if (unlikely(!bip)) {
		pr_err("%s: could not allocate bip\n", __func__);
		return -ENOMEM;
	}

	bip->bip_iter.bi_size = len;
	bip->bip_iter.bi_sector = bio->bi_iter.bi_sector;
	bip->bip_flags |= BIP_USER_MAPPED;

	/* This is a retry. Prevent reference tag from being remapped again */
	if (it->it_flags & ASM_IFLAG_REMAPPED)
		bip->bip_flags |= BIP_MAPPED_INTEGRITY;

	if (it->it_flags & ASM_IFLAG_IP_CHECKSUM)
		bip->bip_flags |= BIP_IP_CHECKSUM;

	if (it->it_flags & ASM_IFLAG_CTRL_NOCHECK)
		bip->bip_flags |= BIP_CTRL_NOCHECK;

	if (it->it_flags & ASM_IFLAG_DISK_NOCHECK)
		bip->bip_flags |= BIP_DISK_NOCHECK;

	pages = kcalloc(nr_pages, sizeof(struct page *), GFP_KERNEL);
	if (unlikely(!pages)) {
		pr_err("%s: could not allocate page array\n", __func__);
		return -ENOMEM;
	}

	ret = get_user_pages_fast(uaddr, nr_pages, write_to_vm, &pages[0]);
	if (unlikely(ret < nr_pages)) {
		pr_err("%s: could not get user pages\n", __func__);
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

		if (unlikely(added < bytes)) {
			ret = -1;
			pr_err("%s: bio %p added %u bytes, wanted %u\n",
			       __func__, bio, added, bytes);
			break;
		}

		len -= bytes;
		offset = 0;
	}

	trace_integrity(it, r, i);

	while (i < nr_pages)
		put_page(pages[i++]);

	kfree(pages);

	if (bip->bip_vcnt == 0)
		ret = -EINVAL;

	return ret;
} /* asm_integrity_map */
