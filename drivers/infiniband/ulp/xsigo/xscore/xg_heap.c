/*
 * Copyright (c) 2006-2012 Xsigo Systems Inc.  All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 */
#include <linux/gfp.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/smp.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/radix-tree.h>
#include <linux/notifier.h>
#include <linux/string.h>
#include <linux/bitops.h>

#include "xg_heap.h"

#ifdef __KERNEL__
#define RADIX_TREE_MAP_SHIFT    6
#else
#define RADIX_TREE_MAP_SHIFT    3	/* For more stressful testing */
#endif
#define RADIX_TREE_TAGS         2

#define RADIX_TREE_MAP_SIZE     (1UL << RADIX_TREE_MAP_SHIFT)
#define RADIX_TREE_MAP_MASK     (RADIX_TREE_MAP_SIZE-1)

#define RADIX_TREE_TAG_LONGS    \
	((RADIX_TREE_MAP_SIZE + BITS_PER_LONG - 1) / BITS_PER_LONG)

struct radix_tree_node {
	unsigned int count;
	void *slots[RADIX_TREE_MAP_SIZE];
	unsigned long tags[RADIX_TREE_TAGS][RADIX_TREE_TAG_LONGS];
};

struct radix_tree_path {
	struct radix_tree_node *node;
	int offset;
};

#define RADIX_TREE_INDEX_BITS  (8 /* CHAR_BIT */ * sizeof(unsigned long))
#define RADIX_TREE_MAX_PATH (RADIX_TREE_INDEX_BITS/RADIX_TREE_MAP_SHIFT + 2)

static unsigned long height_to_maxindex[RADIX_TREE_MAX_PATH] __read_mostly;

/*
 * Radix tree node cache.
 */
static kmem_cache_t *radix_tree_node_cachep;

/*
 * Per-cpu pool of preloaded nodes
*/
struct radix_tree_preload {
	int nr;
	struct radix_tree_node *nodes[RADIX_TREE_MAX_PATH];
};

vmk_moduleid moduleid;
vmk_heapid heapid;

void memory_thread_init(void)
{
	moduleid = vmk_modulestacktop();
	pr_info("module id = %d\n", moduleid);
	heapid = vmk_modulegetheapid(moduleid);
}

void *ib_alloc_pages(unsigned int flags, unsigned int order)
{
	void *vaddr;
	unsigned long size = (VMK_PAGE_SIZE << order);
	vaddr = vmk_heapalign(heapid, size, PAGE_SIZE);
	if (vaddr == NULL)
		return 0;

	return vaddr;
}
EXPORT_SYMBOL(ib_alloc_pages);

void ib_free_pages(void *ptr, int order)
{
	vmk_heapfree(heapid, ptr);
}
EXPORT_SYMBOL(ib_free_pages);

void *ib_kmalloc(size_t size, gfp_t flags)
{
	return vmk_heapalloc(heapid, size);
}
EXPORT_SYMBOL(ib_kmalloc);

void ib_free(void *ptr)
{
	vmk_heapfree(heapid, ptr);
}
EXPORT_SYMBOL(ib_free);

static int __init ib_kompat_init(void)
{
	radix_tree_init();
	memory_thread_init();
	return 0;
}

static void __exit ib_kompat_cleanup(void)
{
	radix_tree_destroy();
}

int xg_vmk_kompat_init(void)
{
	return ib_kompat_init();
}

void xg_vmk_kompat_cleanup(void)
{
	return ib_kompat_cleanup();
}

/*
 * We added iowrite64_copy because it is a missing API
 */
void __iowrite64_copy(void __iomem *to, const void *from, size_t count)
{
	u64 __iomem *dst = to;
	const u64 *src = from;
	const u64 *end = src + count;

	while (src < end)
		__raw_writeq(*src++, dst++);
}
EXPORT_SYMBOL(__iowrite64_copy);

/*
 * memmove() implementation taken from vmklinux26/linux/lib/string.c
 */
void *memmove(void *dest, const void *src, size_t count)
{
	char *tmp;
	const char *s;

	if (dest <= src) {
		tmp = dest;
		s = src;
		while (count--)
			*tmp++ = *s++;
	} else {
		tmp = dest;
		tmp += count;
		s = src;
		s += count;
		while (count--)
			*--tmp = *--s;
	}
	return dest;
}
EXPORT_SYMBOL(memmove);

/* functions from radix-tree.c */
static void
radix_tree_node_ctor(void *node, kmem_cache_t *cachep, unsigned long flags)
{
	memset(node, 0, sizeof(struct radix_tree_node));
}

static __init unsigned long __maxindex(unsigned int height)
{
	unsigned int tmp = height * RADIX_TREE_MAP_SHIFT;
	unsigned long index = (~0UL >> (RADIX_TREE_INDEX_BITS - tmp - 1)) >> 1;

	if (tmp >= RADIX_TREE_INDEX_BITS)
		index = ~0UL;
	return index;
}

static __init void radix_tree_init_maxindex(void)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(height_to_maxindex); i++)
		height_to_maxindex[i] = __maxindex(i);
}

#ifdef CONFIG_HOTPLUG_CPU
static int radix_tree_callback(struct notifier_block *nfb,
			       unsigned long action, void *hcpu)
{
	int cpu = (long)hcpu;
	struct radix_tree_preload *rtp;
	return NOTIFY_OK;
}
#endif /* CONFIG_HOTPLUG_CPU */

void __init radix_tree_init(void)
{
	radix_tree_node_cachep = kmem_cache_create("radix_tree_node",
						   sizeof(struct
							  radix_tree_node), 0,
						   SLAB_PANIC,
						   radix_tree_node_ctor, NULL);
	radix_tree_init_maxindex();
}
