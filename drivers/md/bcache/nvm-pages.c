// SPDX-License-Identifier: GPL-2.0-only
/*
 * Nvdimm page-buddy allocator
 *
 * Copyright (c) 2021, Intel Corporation.
 * Copyright (c) 2021, Qiaowei Ren <qiaowei.ren@intel.com>.
 * Copyright (c) 2021, Jianpeng Ma <jianpeng.ma@intel.com>.
 */

#ifdef CONFIG_BCACHE_NVM_PAGES

#include "bcache.h"
#include "nvm-pages.h"

#include <linux/slab.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/dax.h>
#include <linux/pfn_t.h>
#include <linux/libnvdimm.h>
#include <linux/mm_types.h>
#include <linux/err.h>
#include <linux/pagemap.h>
#include <linux/bitmap.h>
#include <linux/blkdev.h>

struct bch_nvm_set *only_set;

static void release_nvm_namespaces(struct bch_nvm_set *nvm_set)
{
	int i;
	struct bch_nvm_namespace *ns;

	for (i = 0; i < nvm_set->total_namespaces_nr; i++) {
		ns = nvm_set->nss[i];
		if (ns) {
			blkdev_put(ns->bdev, FMODE_READ|FMODE_WRITE|FMODE_EXEC);
			kfree(ns);
		}
	}

	kfree(nvm_set->nss);
}

static void release_nvm_set(struct bch_nvm_set *nvm_set)
{
	release_nvm_namespaces(nvm_set);
	kfree(nvm_set);
}

static int init_owner_info(struct bch_nvm_namespace *ns)
{
	struct bch_owner_list_head *owner_list_head = ns->sb->owner_list_head;

	mutex_lock(&only_set->lock);
	only_set->owner_list_head = owner_list_head;
	only_set->owner_list_size = owner_list_head->size;
	only_set->owner_list_used = owner_list_head->used;
	mutex_unlock(&only_set->lock);

	return 0;
}

static bool attach_nvm_set(struct bch_nvm_namespace *ns)
{
	bool rc = true;

	mutex_lock(&only_set->lock);
	if (only_set->nss) {
		if (memcmp(ns->sb->set_uuid, only_set->set_uuid, 16)) {
			pr_info("namespace id doesn't match nvm set\n");
			rc = false;
			goto unlock;
		}

		if (only_set->nss[ns->sb->this_namespace_nr]) {
			pr_info("already has the same position(%d) nvm\n",
					ns->sb->this_namespace_nr);
			rc = false;
			goto unlock;
		}
	} else {
		memcpy(only_set->set_uuid, ns->sb->set_uuid, 16);
		only_set->total_namespaces_nr = ns->sb->total_namespaces_nr;
		only_set->nss = kcalloc(only_set->total_namespaces_nr,
				sizeof(struct bch_nvm_namespace *), GFP_KERNEL);
		if (!only_set->nss) {
			rc = false;
			goto unlock;
		}
	}

	only_set->nss[ns->sb->this_namespace_nr] = ns;

unlock:
	mutex_unlock(&only_set->lock);
	return rc;
}

static int read_nvdimm_meta_super(struct block_device *bdev,
			      struct bch_nvm_namespace *ns)
{
	struct page *page;
	struct bch_nvm_pages_sb *sb;

	page = read_cache_page_gfp(bdev->bd_inode->i_mapping,
			BCH_NVM_PAGES_SB_OFFSET >> PAGE_SHIFT, GFP_KERNEL);

	if (IS_ERR(page))
		return -EIO;

	sb = page_address(page) + offset_in_page(BCH_NVM_PAGES_SB_OFFSET);

	/* temporary use for DAX API */
	ns->page_size = sb->page_size;
	ns->pages_total = sb->pages_total;

	put_page(page);

	return 0;
}

struct bch_nvm_namespace *bch_register_namespace(const char *dev_path)
{
	struct bch_nvm_namespace *ns;
	int err;
	pgoff_t pgoff;
	char buf[BDEVNAME_SIZE];
	struct block_device *bdev;
	uint64_t expected_csum;
	int id;
	char *path = NULL;

	path = kstrndup(dev_path, 512, GFP_KERNEL);
	if (!path) {
		pr_err("kstrndup failed\n");
		return ERR_PTR(-ENOMEM);
	}

	bdev = blkdev_get_by_path(strim(path),
				  FMODE_READ|FMODE_WRITE|FMODE_EXEC,
				  only_set);
	if (IS_ERR(bdev)) {
		pr_info("get %s error: %ld\n", dev_path, PTR_ERR(bdev));
		kfree(path);
		return ERR_PTR(PTR_ERR(bdev));
	}

	ns = kzalloc(sizeof(struct bch_nvm_namespace), GFP_KERNEL);
	if (!ns)
		goto bdput;

	err = -EIO;
	if (read_nvdimm_meta_super(bdev, ns)) {
		pr_info("%s read nvdimm meta super block failed.\n",
			bdevname(bdev, buf));
		goto free_ns;
	}

	err = -EOPNOTSUPP;
	if (!bdev_dax_supported(bdev, ns->page_size)) {
		pr_info("%s don't support DAX\n", bdevname(bdev, buf));
		goto free_ns;
	}

	err = -EINVAL;
	if (bdev_dax_pgoff(bdev, 0, ns->page_size, &pgoff)) {
		pr_info("invalid offset of %s\n", bdevname(bdev, buf));
		goto free_ns;
	}

	err = -ENOMEM;
	ns->dax_dev = fs_dax_get_by_bdev(bdev);
	if (!ns->dax_dev) {
		pr_info("can't by dax device by %s\n", bdevname(bdev, buf));
		goto free_ns;
	}

	err = -EINVAL;
	id = dax_read_lock();
	if (dax_direct_access(ns->dax_dev, pgoff, ns->pages_total,
			      &ns->kaddr, &ns->start_pfn) <= 0) {
		pr_info("dax_direct_access error\n");
		dax_read_unlock(id);
		goto free_ns;
	}
	dax_read_unlock(id);

	ns->sb = ns->kaddr + BCH_NVM_PAGES_SB_OFFSET;

	if (memcmp(ns->sb->magic, bch_nvm_pages_magic, 16)) {
		pr_info("invalid bch_nvm_pages_magic\n");
		goto free_ns;
	}

	if (ns->sb->sb_offset != BCH_NVM_PAGES_SB_OFFSET) {
		pr_info("invalid superblock offset\n");
		goto free_ns;
	}

	if (ns->sb->total_namespaces_nr != 1) {
		pr_info("only one nvm device\n");
		goto free_ns;
	}

	expected_csum = csum_set(ns->sb);
	if (expected_csum != ns->sb->csum) {
		pr_info("csum is not match with expected one\n");
		goto free_ns;
	}

	err = -EEXIST;
	if (!attach_nvm_set(ns))
		goto free_ns;

	/* Firstly attach */
	if ((unsigned long)ns->sb->owner_list_head == BCH_NVM_PAGES_OWNER_LIST_HEAD_OFFSET) {
		struct bch_nvm_pages_owner_head *sys_owner_head;
		struct bch_nvm_pgalloc_recs *sys_pgalloc_recs;

		ns->sb->owner_list_head = ns->kaddr + BCH_NVM_PAGES_OWNER_LIST_HEAD_OFFSET;
		sys_pgalloc_recs = ns->kaddr + BCH_NVM_PAGES_SYS_RECS_HEAD_OFFSET;

		sys_owner_head = &(ns->sb->owner_list_head->heads[0]);
		sys_owner_head->recs[0] = sys_pgalloc_recs;
		ns->sb->csum = csum_set(ns->sb);

		sys_pgalloc_recs->owner = sys_owner_head;
	} else
		BUG_ON(ns->sb->owner_list_head !=
			(ns->kaddr + BCH_NVM_PAGES_OWNER_LIST_HEAD_OFFSET));

	ns->page_size = ns->sb->page_size;
	ns->pages_offset = ns->sb->pages_offset;
	ns->pages_total = ns->sb->pages_total;
	ns->free = 0;
	ns->bdev = bdev;
	ns->nvm_set = only_set;
	mutex_init(&ns->lock);

	if (ns->sb->this_namespace_nr == 0) {
		pr_info("only first namespace contain owner info\n");
		err = init_owner_info(ns);
		if (err < 0) {
			pr_info("init_owner_info met error %d\n", err);
			only_set->nss[ns->sb->this_namespace_nr] = NULL;
			goto free_ns;
		}
	}

	kfree(path);
	return ns;
free_ns:
	kfree(ns);
bdput:
	blkdev_put(bdev, FMODE_READ|FMODE_WRITE|FMODE_EXEC);
	kfree(path);
	return ERR_PTR(err);
}
EXPORT_SYMBOL_GPL(bch_register_namespace);

int __init bch_nvm_init(void)
{
	only_set = kzalloc(sizeof(*only_set), GFP_KERNEL);
	if (!only_set)
		return -ENOMEM;

	only_set->total_namespaces_nr = 0;
	only_set->owner_list_head = NULL;
	only_set->nss = NULL;

	mutex_init(&only_set->lock);

	pr_info("bcache nvm init\n");
	return 0;
}

void bch_nvm_exit(void)
{
	release_nvm_set(only_set);
	pr_info("bcache nvm exit\n");
}

#endif /* CONFIG_BCACHE_NVM_PAGES */
