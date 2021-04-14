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
#include <linux/bcache-nvm.h>

struct bch_nvm_set *only_set;

static void release_nvm_namespaces(struct bch_nvm_set *nvm_set)
{
	int i;
	struct bch_nvm_namespace *ns;

	for (i = 0; i < nvm_set->total_namespaces_nr; i++) {
		ns = nvm_set->nss[i];
		if (ns) {
			kvfree(ns->pages_bitmap);
			if (ns->pgalloc_recs_bitmap)
				bitmap_free(ns->pgalloc_recs_bitmap);

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

static struct page *nvm_vaddr_to_page(struct bch_nvm_namespace *ns, void *addr)
{
	return virt_to_page(addr);
}

static void *nvm_pgoff_to_vaddr(struct bch_nvm_namespace *ns, pgoff_t pgoff)
{
	return ns->kaddr + (pgoff << PAGE_SHIFT);
}

static inline void remove_owner_space(struct bch_nvm_namespace *ns,
					pgoff_t pgoff, u32 nr)
{
	bitmap_set(ns->pages_bitmap, pgoff, nr);
}

/* If not found, it will create if create == true */
static struct bch_nvm_pages_owner_head *find_owner_head(const char *owner_uuid, bool create)
{
	struct bch_owner_list_head *owner_list_head = only_set->owner_list_head;
	struct bch_nvm_pages_owner_head *owner_head = NULL;
	int i;

	if (owner_list_head == NULL)
		goto out;

	for (i = 0; i < only_set->owner_list_used; i++) {
		if (!memcmp(owner_uuid, owner_list_head->heads[i].uuid, 16)) {
			owner_head = &(owner_list_head->heads[i]);
			break;
		}
	}

	if (!owner_head && create) {
		int used = only_set->owner_list_used;

		BUG_ON((used > 0) && (only_set->owner_list_size == used));
		memcpy_flushcache(owner_list_head->heads[used].uuid, owner_uuid, 16);
		only_set->owner_list_used++;

		owner_list_head->used++;
		owner_head = &(owner_list_head->heads[used]);
	}

out:
	return owner_head;
}

static struct bch_nvm_pgalloc_recs *find_empty_pgalloc_recs(void)
{
	unsigned int start;
	struct bch_nvm_namespace *ns = only_set->nss[0];
	struct bch_nvm_pgalloc_recs *recs;

	start = bitmap_find_next_zero_area(ns->pgalloc_recs_bitmap, BCH_MAX_PGALLOC_RECS, 0, 1, 0);
	if (start > BCH_MAX_PGALLOC_RECS) {
		pr_info("no free struct bch_nvm_pgalloc_recs\n");
		return NULL;
	}

	bitmap_set(ns->pgalloc_recs_bitmap, start, 1);
	recs = (struct bch_nvm_pgalloc_recs *)(ns->kaddr + BCH_NVM_PAGES_SYS_RECS_HEAD_OFFSET)
		+ start;
	return recs;
}

static struct bch_nvm_pgalloc_recs *find_nvm_pgalloc_recs(struct bch_nvm_namespace *ns,
		struct bch_nvm_pages_owner_head *owner_head, bool create)
{
	int ns_nr = ns->sb->this_namespace_nr;
	struct bch_nvm_pgalloc_recs *prev_recs = NULL, *recs = owner_head->recs[ns_nr];

	/* If create=false, we return recs[nr] */
	if (!create)
		return recs;

	/*
	 * If create=true, it mean we need a empty struct bch_pgalloc_rec
	 * So we should find non-empty struct bch_nvm_pgalloc_recs or alloc
	 * new struct bch_nvm_pgalloc_recs. And return this bch_nvm_pgalloc_recs
	 */
	while (recs && (recs->used == recs->size)) {
		prev_recs = recs;
		recs = recs->next;
	}

	/* Found empty struct bch_nvm_pgalloc_recs */
	if (recs)
		return recs;
	/* Need alloc new struct bch_nvm_galloc_recs */
	recs = find_empty_pgalloc_recs();
	if (recs) {
		recs->next = NULL;
		recs->owner = owner_head;
		strncpy(recs->magic, bch_nvm_pages_pgalloc_magic, 16);
		strncpy(recs->owner_uuid, owner_head->uuid, 16);
		recs->size = BCH_MAX_RECS;
		recs->used = 0;

		if (prev_recs)
			prev_recs->next = recs;
		else
			owner_head->recs[ns_nr] = recs;
	}

	return recs;
}

static void add_pgalloc_rec(struct bch_nvm_pgalloc_recs *recs, void *kaddr, int order)
{
	int i;

	for (i = 0; i < recs->size; i++) {
		if (recs->recs[i].pgoff == 0) {
			recs->recs[i].pgoff = (unsigned long)kaddr >> PAGE_SHIFT;
			recs->recs[i].order = order;
			recs->used++;
			break;
		}
	}
	BUG_ON(i == recs->size);
}

static inline void *nvm_end_addr(struct bch_nvm_namespace *ns)
{
	return ns->kaddr + (ns->pages_total << PAGE_SHIFT);
}

static inline bool in_nvm_range(struct bch_nvm_namespace *ns,
		void *start_addr, void *end_addr)
{
	return (start_addr >= ns->kaddr) && (end_addr <= nvm_end_addr(ns));
}

static struct bch_nvm_namespace *find_nvm_by_addr(void *addr, int order)
{
	int i;
	struct bch_nvm_namespace *ns;

	for (i = 0; i < only_set->total_namespaces_nr; i++) {
		ns = only_set->nss[i];
		if (ns && in_nvm_range(ns, addr, addr + (1 << order)))
			return ns;
	}
	return NULL;
}

static int remove_pgalloc_rec(struct bch_nvm_pgalloc_recs *pgalloc_recs, int ns_nr,
				void *kaddr, int order)
{
	struct bch_nvm_pages_owner_head *owner_head = pgalloc_recs->owner;
	struct bch_nvm_pgalloc_recs *prev_recs, *sys_recs;
	u64 pgoff = (unsigned long)kaddr >> PAGE_SHIFT;
	struct bch_nvm_namespace *ns = only_set->nss[0];
	int i;

	prev_recs = pgalloc_recs;
	sys_recs = ns->kaddr + BCH_NVM_PAGES_SYS_RECS_HEAD_OFFSET;
	while (pgalloc_recs) {
		for (i = 0; i < pgalloc_recs->size; i++) {
			struct bch_pgalloc_rec *rec = &(pgalloc_recs->recs[i]);

			if (rec->pgoff == pgoff) {
				WARN_ON(rec->order != order);
				rec->pgoff = 0;
				rec->order = 0;
				pgalloc_recs->used--;

				if (pgalloc_recs->used == 0) {
					int recs_pos = pgalloc_recs - sys_recs;

					if (pgalloc_recs == prev_recs)
						owner_head->recs[ns_nr] = pgalloc_recs->next;
					else
						prev_recs->next = pgalloc_recs->next;

					pgalloc_recs->next = NULL;
					pgalloc_recs->owner = NULL;

					bitmap_clear(ns->pgalloc_recs_bitmap, recs_pos, 1);
				}
				goto exit;
			}
		}
		prev_recs = pgalloc_recs;
		pgalloc_recs = pgalloc_recs->next;
	}
exit:
	return pgalloc_recs ? 0 : -ENOENT;
}

static void __free_space(struct bch_nvm_namespace *ns, void *addr, int order)
{
	unsigned int add_pages = (1 << order);
	pgoff_t pgoff;
	struct page *page;

	page = nvm_vaddr_to_page(ns, addr);
	WARN_ON((!page) || (page->private != order));
	pgoff = page->index;

	while (order < BCH_MAX_ORDER - 1) {
		struct page *buddy_page;

		pgoff_t buddy_pgoff = pgoff ^ (1 << order);
		pgoff_t parent_pgoff = pgoff & ~(1 << order);

		if ((parent_pgoff + (1 << (order + 1)) > ns->pages_total))
			break;

		buddy_page = nvm_vaddr_to_page(ns, nvm_pgoff_to_vaddr(ns, buddy_pgoff));
		WARN_ON(!buddy_page);

		if (PageBuddy(buddy_page) && (buddy_page->private == order)) {
			list_del((struct list_head *)&buddy_page->zone_device_data);
			__ClearPageBuddy(buddy_page);
			pgoff = parent_pgoff;
			order++;
			continue;
		}
		break;
	}

	page = nvm_vaddr_to_page(ns, nvm_pgoff_to_vaddr(ns, pgoff));
	WARN_ON(!page);
	list_add((struct list_head *)&page->zone_device_data, &ns->free_area[order]);
	page->index = pgoff;
	set_page_private(page, order);
	__SetPageBuddy(page);
	ns->free += add_pages;
}

void bch_nvm_free_pages(void *addr, int order, const char *owner_uuid)
{
	struct bch_nvm_namespace *ns;
	struct bch_nvm_pages_owner_head *owner_head;
	struct bch_nvm_pgalloc_recs *pgalloc_recs;
	int r;

	mutex_lock(&only_set->lock);

	ns = find_nvm_by_addr(addr, order);
	if (!ns) {
		pr_info("can't find nvm_dev by kaddr %p\n", addr);
		goto unlock;
	}

	owner_head = find_owner_head(owner_uuid, false);
	if (!owner_head) {
		pr_info("can't found bch_nvm_pages_owner_head by(uuid=%s)\n", owner_uuid);
		goto unlock;
	}

	pgalloc_recs = find_nvm_pgalloc_recs(ns, owner_head, false);
	if (!pgalloc_recs) {
		pr_info("can't find bch_nvm_pgalloc_recs by(uuid=%s)\n", owner_uuid);
		goto unlock;
	}

	r = remove_pgalloc_rec(pgalloc_recs, ns->sb->this_namespace_nr, addr, order);
	if (r < 0) {
		pr_info("can't find bch_pgalloc_rec\n");
		goto unlock;
	}

	__free_space(ns, addr, order);

unlock:
	mutex_unlock(&only_set->lock);
}
EXPORT_SYMBOL_GPL(bch_nvm_free_pages);

void *bch_nvm_alloc_pages(int order, const char *owner_uuid)
{
	void *kaddr = NULL;
	struct bch_nvm_pgalloc_recs *pgalloc_recs;
	struct bch_nvm_pages_owner_head *owner_head;
	int i, j;

	mutex_lock(&only_set->lock);
	owner_head = find_owner_head(owner_uuid, true);

	if (!owner_head) {
		pr_err("can't find bch_nvm_pgalloc_recs by(uuid=%s)\n", owner_uuid);
		goto unlock;
	}

	for (j = 0; j < only_set->total_namespaces_nr; j++) {
		struct bch_nvm_namespace *ns = only_set->nss[j];

		if (!ns || (ns->free < (1 << order)))
			continue;

		for (i = order; i < BCH_MAX_ORDER; i++) {
			struct list_head *list;
			struct page *page, *buddy_page;

			if (list_empty(&ns->free_area[i]))
				continue;

			list = ns->free_area[i].next;
			page = container_of((void *)list, struct page, zone_device_data);

			list_del(list);

			while (i != order) {
				buddy_page = nvm_vaddr_to_page(ns,
					nvm_pgoff_to_vaddr(ns, page->index + (1 << (i - 1))));
				set_page_private(buddy_page, i - 1);
				buddy_page->index = page->index + (1 << (i - 1));
				__SetPageBuddy(buddy_page);
				list_add((struct list_head *)&buddy_page->zone_device_data,
					&ns->free_area[i - 1]);
				i--;
			}

			set_page_private(page, order);
			__ClearPageBuddy(page);
			ns->free -= 1 << order;
			kaddr = nvm_pgoff_to_vaddr(ns, page->index);
			break;
		}

		if (i != BCH_MAX_ORDER) {
			pgalloc_recs = find_nvm_pgalloc_recs(ns, owner_head, true);
			/* ToDo: handle pgalloc_recs==NULL */
			add_pgalloc_rec(pgalloc_recs, kaddr, order);
			break;
		}
	}

unlock:
	mutex_unlock(&only_set->lock);
	return kaddr;
}
EXPORT_SYMBOL_GPL(bch_nvm_alloc_pages);

struct bch_nvm_pages_owner_head *bch_get_allocated_pages(const char *owner_uuid)
{
	return find_owner_head(owner_uuid, false);
}
EXPORT_SYMBOL_GPL(bch_get_allocated_pages);

static int init_owner_info(struct bch_nvm_namespace *ns)
{
	struct bch_owner_list_head *owner_list_head = ns->sb->owner_list_head;
	struct bch_nvm_pgalloc_recs *sys_recs;
	int i, j, k, rc = 0;

	mutex_lock(&only_set->lock);
	only_set->owner_list_head = owner_list_head;
	only_set->owner_list_size = owner_list_head->size;
	only_set->owner_list_used = owner_list_head->used;

	/* remove used space */
	remove_owner_space(ns, 0, div_u64(ns->pages_offset, ns->page_size));

	sys_recs = ns->kaddr + BCH_NVM_PAGES_SYS_RECS_HEAD_OFFSET;
	/* suppose no hole in array */
	for (i = 0; i < owner_list_head->used; i++) {
		struct bch_nvm_pages_owner_head *head = &owner_list_head->heads[i];

		for (j = 0; j < BCH_NVM_PAGES_NAMESPACES_MAX; j++) {
			struct bch_nvm_pgalloc_recs *pgalloc_recs = head->recs[j];
			unsigned long offset = (unsigned long)ns->kaddr >> PAGE_SHIFT;
			struct page *page;

			while (pgalloc_recs) {
				u32 pgalloc_recs_pos = (unsigned long)(pgalloc_recs - sys_recs);

				if (memcmp(pgalloc_recs->magic, bch_nvm_pages_pgalloc_magic, 16)) {
					pr_info("invalid bch_nvm_pages_pgalloc_magic\n");
					rc = -EINVAL;
					goto unlock;
				}
				if (memcmp(pgalloc_recs->owner_uuid, head->uuid, 16)) {
					pr_info("invalid owner_uuid in bch_nvm_pgalloc_recs\n");
					rc = -EINVAL;
					goto unlock;
				}
				if (pgalloc_recs->owner != head) {
					pr_info("invalid owner in bch_nvm_pgalloc_recs\n");
					rc = -EINVAL;
					goto unlock;
				}

				/* recs array can has hole */
				for (k = 0; k < pgalloc_recs->size; k++) {
					struct bch_pgalloc_rec *rec = &pgalloc_recs->recs[k];

					if (rec->pgoff) {
						BUG_ON(rec->pgoff <= offset);

						/* init struct page: index/private */
						page = nvm_vaddr_to_page(ns,
							BCH_PGOFF_TO_KVADDR(rec->pgoff));

						set_page_private(page, rec->order);
						page->index = rec->pgoff - offset;

						remove_owner_space(ns,
							rec->pgoff - offset,
							1 << rec->order);
					}
				}
				bitmap_set(ns->pgalloc_recs_bitmap, pgalloc_recs_pos, 1);
				pgalloc_recs = pgalloc_recs->next;
			}
		}
	}
unlock:
	mutex_unlock(&only_set->lock);

	return rc;
}

static void init_nvm_free_space(struct bch_nvm_namespace *ns)
{
	unsigned int start, end, i;
	struct page *page;
	u64 pages;
	pgoff_t pgoff_start;

	bitmap_for_each_clear_region(ns->pages_bitmap, start, end, 0, ns->pages_total) {
		pgoff_start = start;
		pages = end - start;

		while (pages) {
			for (i = BCH_MAX_ORDER - 1; i >= 0 ; i--) {
				if ((pgoff_start % (1 << i) == 0) && (pages >= (1 << i)))
					break;
			}

			page = nvm_vaddr_to_page(ns, nvm_pgoff_to_vaddr(ns, pgoff_start));
			page->index = pgoff_start;
			set_page_private(page, i);

			/* in order to update ns->free */
			__free_space(ns, nvm_pgoff_to_vaddr(ns, pgoff_start), i);

			pgoff_start += 1 << i;
			pages -= 1 << i;
		}
	}
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
	int i, err;
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
	ns->free = 0; /* increase by __free_space() */
	ns->bdev = bdev;
	ns->nvm_set = only_set;
	mutex_init(&ns->lock);

	ns->pages_bitmap = kvcalloc(BITS_TO_LONGS(ns->pages_total),
					sizeof(unsigned long), GFP_KERNEL);
	if (!ns->pages_bitmap) {
		err = -ENOMEM;
		goto clear_ns_nr;
	}

	if (ns->sb->this_namespace_nr == 0) {
		ns->pgalloc_recs_bitmap = bitmap_zalloc(BCH_MAX_PGALLOC_RECS, GFP_KERNEL);
		if (ns->pgalloc_recs_bitmap == NULL) {
			err = -ENOMEM;
			goto free_pages_bitmap;
		}
	}

	for (i = 0; i < BCH_MAX_ORDER; i++)
		INIT_LIST_HEAD(&ns->free_area[i]);

	if (ns->sb->this_namespace_nr == 0) {
		pr_info("only first namespace contain owner info\n");
		err = init_owner_info(ns);
		if (err < 0) {
			pr_info("init_owner_info met error %d\n", err);
			goto free_recs_bitmap;
		}
		/* init buddy allocator */
		init_nvm_free_space(ns);
	}

	kfree(path);
	return ns;
free_recs_bitmap:
	bitmap_free(ns->pgalloc_recs_bitmap);
free_pages_bitmap:
	kvfree(ns->pages_bitmap);
clear_ns_nr:
	only_set->nss[ns->sb->this_namespace_nr] = NULL;
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
