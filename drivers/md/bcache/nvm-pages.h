/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _BCACHE_NVM_PAGES_H
#define _BCACHE_NVM_PAGES_H

#ifdef CONFIG_BCACHE_NVM_PAGES
#include <linux/bcache-nvm.h>
#include <linux/libnvdimm.h>
#endif /* CONFIG_BCACHE_NVM_PAGES */

/*
 * Bcache NVDIMM in memory data structures
 */

/*
 * The following three structures in memory records which page(s) allocated
 * to which owner. After reboot from power failure, they will be initialized
 * based on nvm pages superblock in NVDIMM device.
 */
#define BCH_MAX_ORDER 20
struct bch_nvm_namespace {
	struct bch_nvm_pages_sb *sb;
	void *kaddr;

	u8 uuid[16];
	u64 free;
	u32 page_size;
	u64 pages_offset;
	u64 pages_total;
	pfn_t start_pfn;

	unsigned long *pages_bitmap;
	struct list_head free_area[BCH_MAX_ORDER];

	unsigned long *pgalloc_recs_bitmap;

	struct dax_device *dax_dev;
	struct block_device *bdev;
	struct bch_nvm_set *nvm_set;

	struct mutex lock;
};

/*
 * A set of namespaces. Currently only one set can be supported.
 */
struct bch_nvm_set {
	u8 set_uuid[16];
	u32 total_namespaces_nr;

	u32 owner_list_size;
	u32 owner_list_used;
	struct bch_owner_list_head *owner_list_head;

	struct bch_nvm_namespace **nss;

	struct mutex lock;
};
extern struct bch_nvm_set *only_set;

#ifdef CONFIG_BCACHE_NVM_PAGES

struct bch_nvm_namespace *bch_register_namespace(const char *dev_path);
int bch_nvm_init(void);
void bch_nvm_exit(void);
void *bch_nvm_alloc_pages(int order, const char *owner_uuid);
void bch_nvm_free_pages(void *addr, int order, const char *owner_uuid);
struct bch_nvm_pages_owner_head *bch_get_allocated_pages(const char *owner_uuid);

#else

static inline struct bch_nvm_namespace *bch_register_namespace(const char *dev_path)
{
	return NULL;
}
static inline int bch_nvm_init(void)
{
	return 0;
}
static inline void bch_nvm_exit(void) { }
static inline void *bch_nvm_alloc_pages(int order, const char *owner_uuid)
{
	return NULL;
}
static inline void bch_nvm_free_pages(void *addr, int order, const char *owner_uuid) { }
static inline struct bch_nvm_pages_owner_head *bch_get_allocated_pages(const char *owner_uuid)
{
	return NULL;
}

#endif /* CONFIG_BCACHE_NVM_PAGES */

#endif /* _BCACHE_NVM_PAGES_H */
