/* arch/sparc64/mm/tsb.c
 *
 * Copyright (C) 2006, 2008 David S. Miller <davem@davemloft.net>
 */

#include <linux/kernel.h>
#include <linux/preempt.h>
#include <linux/slab.h>
#include <asm/page.h>
#include <asm/pgtable.h>
#include <asm/mmu_context.h>
#include <asm/setup.h>
#include <asm/tsb.h>
#include <asm/tlb.h>
#include <asm/oplib.h>
#include <asm/mdesc.h>
#include <linux/ratelimit.h>

extern struct tsb swapper_tsb[KERNEL_TSB_NENTRIES];

static inline unsigned long tsb_hash(unsigned long vaddr, unsigned long hash_shift, unsigned long nentries)
{
	vaddr >>= hash_shift;
	return vaddr & (nentries - 1);
}

static inline int tag_compare(unsigned long tag, unsigned long vaddr)
{
	return (tag == (vaddr >> 22));
}

static void flush_tsb_kernel_range_scan(unsigned long start, unsigned long end)
{
	unsigned long idx;

	for (idx = 0; idx < KERNEL_TSB_NENTRIES; idx++) {
		struct tsb *ent = &swapper_tsb[idx];
		unsigned long match = idx << 13;

		match |= (ent->tag << 22);
		if (match >= start && match < end)
			ent->tag = (1UL << TSB_TAG_INVALID_BIT);
	}
}

/* TSB flushes need only occur on the processor initiating the address
 * space modification, not on each cpu the address space has run on.
 * Only the TLB flush needs that treatment.
 */

void flush_tsb_kernel_range(unsigned long start, unsigned long end)
{
	unsigned long v;

	if ((end - start) >> PAGE_SHIFT >= 2 * KERNEL_TSB_NENTRIES)
		return flush_tsb_kernel_range_scan(start, end);

	for (v = start; v < end; v += PAGE_SIZE) {
		unsigned long hash = tsb_hash(v, PAGE_SHIFT,
					      KERNEL_TSB_NENTRIES);
		struct tsb *ent = &swapper_tsb[hash];

		if (tag_compare(ent->tag, v))
			ent->tag = (1UL << TSB_TAG_INVALID_BIT);
	}
}

static void __flush_tsb_one_entry(unsigned long tsb, unsigned long v,
				  unsigned long hash_shift,
				  unsigned long nentries)
{
	unsigned long tag, ent, hash;

	v &= ~0x1UL;
	hash = tsb_hash(v, hash_shift, nentries);
	ent = tsb + (hash * sizeof(struct tsb));
	tag = (v >> 22UL);

	tsb_flush(ent, tag);
}

static void __flush_tsb_one(struct tlb_batch *tb, unsigned long hash_shift,
			    unsigned long tsb, unsigned long nentries)
{
	unsigned long i;

	for (i = 0; i < tb->tlb_nr; i++)
		__flush_tsb_one_entry(tsb, tb->vaddrs[i], hash_shift, nentries);
}

#if defined(CONFIG_HUGETLB_PAGE) || defined(CONFIG_TRANSPARENT_HUGEPAGE)
static void __flush_huge_tsb_one_entry(unsigned long tsb, unsigned long v,
				       unsigned long hash_shift,
				       unsigned long nentries,
				       unsigned int hugepage_shift)
{
	unsigned int hpage_entries;
	unsigned int i;

	hpage_entries = 1 << (hugepage_shift - hash_shift);
	for (i = 0; i < hpage_entries; i++)
		__flush_tsb_one_entry(tsb, v + (i << hash_shift), hash_shift,
				      nentries);
}

static void __flush_huge_tsb_one(struct tlb_batch *tb, unsigned long hash_shift,
				 unsigned long tsb, unsigned long nentries,
				 unsigned int hugepage_shift)
{
	unsigned long i;

	for (i = 0; i < tb->tlb_nr; i++)
		__flush_huge_tsb_one_entry(tsb, tb->vaddrs[i], hash_shift,
					   nentries, hugepage_shift);
}
#endif

void flush_tsb_user(struct tlb_batch *tb)
{
	struct mm_struct *mm = tb->mm;
	unsigned long nentries, base, flags;

	spin_lock_irqsave(&mm->context.lock, flags);

	if (tb->hugepage_shift < REAL_HPAGE_SHIFT) {
		base = (unsigned long) mm->context.tsb_block[MM_TSB_BASE].tsb;
		nentries = mm->context.tsb_block[MM_TSB_BASE].tsb_nentries;
		if (tlb_type == cheetah_plus || tlb_type == hypervisor)
			base = __pa(base);
		if (tb->hugepage_shift == PAGE_SHIFT)
			__flush_tsb_one(tb, PAGE_SHIFT, base, nentries);
#if defined(CONFIG_HUGETLB_PAGE)
		else
			__flush_huge_tsb_one(tb, PAGE_SHIFT, base, nentries,
					     tb->hugepage_shift);
#endif
	}
#if defined(CONFIG_HUGETLB_PAGE) || defined(CONFIG_TRANSPARENT_HUGEPAGE)
	else if (mm->context.tsb_block[MM_TSB_HUGE].tsb) {
		base = (unsigned long) mm->context.tsb_block[MM_TSB_HUGE].tsb;
		nentries = mm->context.tsb_block[MM_TSB_HUGE].tsb_nentries;
		if (tlb_type == cheetah_plus || tlb_type == hypervisor)
			base = __pa(base);
		__flush_huge_tsb_one(tb, REAL_HPAGE_SHIFT, base, nentries,
				     tb->hugepage_shift);
	}
#endif
	spin_unlock_irqrestore(&mm->context.lock, flags);
}

void flush_tsb_user_page(struct mm_struct *mm, unsigned long vaddr,
			 unsigned int hugepage_shift)
{
	unsigned long nentries, base, flags;

	spin_lock_irqsave(&mm->context.lock, flags);

	if (hugepage_shift < REAL_HPAGE_SHIFT) {
		base = (unsigned long) mm->context.tsb_block[MM_TSB_BASE].tsb;
		nentries = mm->context.tsb_block[MM_TSB_BASE].tsb_nentries;
		if (tlb_type == cheetah_plus || tlb_type == hypervisor)
			base = __pa(base);
		if (hugepage_shift == PAGE_SHIFT)
			__flush_tsb_one_entry(base, vaddr, PAGE_SHIFT,
					      nentries);
#if defined(CONFIG_HUGETLB_PAGE)
		else
			__flush_huge_tsb_one_entry(base, vaddr, PAGE_SHIFT,
						   nentries, hugepage_shift);
#endif
	}
#if defined(CONFIG_HUGETLB_PAGE) || defined(CONFIG_TRANSPARENT_HUGEPAGE)
	else if (mm->context.tsb_block[MM_TSB_HUGE].tsb) {
		base = (unsigned long) mm->context.tsb_block[MM_TSB_HUGE].tsb;
		nentries = mm->context.tsb_block[MM_TSB_HUGE].tsb_nentries;
		if (tlb_type == cheetah_plus || tlb_type == hypervisor)
			base = __pa(base);
		__flush_huge_tsb_one_entry(base, vaddr, REAL_HPAGE_SHIFT,
					   nentries, hugepage_shift);
	}
#endif
	spin_unlock_irqrestore(&mm->context.lock, flags);
}

#define HV_PGSZ_IDX_BASE	HV_PGSZ_IDX_8K
#define HV_PGSZ_MASK_BASE	HV_PGSZ_MASK_8K

#if defined(CONFIG_HUGETLB_PAGE) || defined(CONFIG_TRANSPARENT_HUGEPAGE)
#define HV_PGSZ_IDX_HUGE	HV_PGSZ_IDX_4MB
#define HV_PGSZ_MASK_HUGE	HV_PGSZ_MASK_4MB
#endif

static void setup_tsb_params(struct mm_struct *mm, unsigned long tsb_idx,
			     unsigned long tsb_bytes)
{
	unsigned long tsb_reg = get_order(tsb_bytes);
	unsigned long base, tsb_paddr;
	unsigned long page_sz, tte;

	mm->context.tsb_block[tsb_idx].tsb_nentries =
		tsb_bytes / sizeof(struct tsb);

	switch (tsb_idx) {
	case MM_TSB_BASE:
		base = TSBMAP_8K_BASE;
		break;
#if defined(CONFIG_HUGETLB_PAGE) || defined(CONFIG_TRANSPARENT_HUGEPAGE)
	case MM_TSB_HUGE:
		base = TSBMAP_4M_BASE;
		break;
#endif
	default:
		BUG();
	}

	tte = pgprot_val(PAGE_KERNEL_LOCKED);
	tsb_paddr = __pa(mm->context.tsb_block[tsb_idx].tsb);
	BUG_ON(tsb_paddr & (tsb_bytes - 1UL));

	/* Use the smallest page size that can map the whole TSB
	 * in one TLB entry.
	 */
	switch (tsb_reg) {
	case 0:
#ifdef DCACHE_ALIASING_POSSIBLE
		base += (tsb_paddr & 8192);
#endif
		page_sz = 8192;
		break;
	case 1 ... 3:
		page_sz = 64 * 1024;
		break;
	case 4 ... 6:
		page_sz = 512 * 1024;
		break;
	case 7:
		page_sz = 4 * 1024 * 1024;
		break;
	case 8 ... HV_TSB_SIZE_MASK:
		/* This case should only be selected by supported sun4v. */
		/* page_sz not used by sun4v but validly warned by gcc. */
		page_sz = PAGE_MASK;
		break;
	default:
		printk(KERN_ERR "TSB[%s:%d]: Impossible TSB size %lu, killing process.\n",
		       current->comm, current->pid, tsb_bytes);
		do_exit(SIGSEGV);
	}
	tte |= pte_sz_bits(page_sz);

	if (tlb_type == cheetah_plus || tlb_type == hypervisor) {
		/* Physical mapping, no locked TLB entry for TSB.  */
		tsb_reg |= tsb_paddr;

		mm->context.tsb_block[tsb_idx].tsb_reg_val = tsb_reg;
		mm->context.tsb_block[tsb_idx].tsb_map_vaddr = 0;
		mm->context.tsb_block[tsb_idx].tsb_map_pte = 0;
	} else {
		tsb_reg |= base;
		tsb_reg |= (tsb_paddr & (page_sz - 1UL));
		tte |= (tsb_paddr & ~(page_sz - 1UL));

		mm->context.tsb_block[tsb_idx].tsb_reg_val = tsb_reg;
		mm->context.tsb_block[tsb_idx].tsb_map_vaddr = base;
		mm->context.tsb_block[tsb_idx].tsb_map_pte = tte;
	}

	/* Setup the Hypervisor TSB descriptor.  */
	if (tlb_type == hypervisor) {
		struct hv_tsb_descr *hp = &mm->context.tsb_descr[tsb_idx];

		switch (tsb_idx) {
		case MM_TSB_BASE:
			hp->pgsz_idx = HV_PGSZ_IDX_BASE;
			break;
#if defined(CONFIG_HUGETLB_PAGE) || defined(CONFIG_TRANSPARENT_HUGEPAGE)
		case MM_TSB_HUGE:
			hp->pgsz_idx = HV_PGSZ_IDX_HUGE;
			break;
#endif
		default:
			BUG();
		}
		hp->assoc = 1;
		hp->num_ttes = tsb_bytes / 16;
		hp->ctx_idx = 0;
		switch (tsb_idx) {
		case MM_TSB_BASE:
			hp->pgsz_mask = HV_PGSZ_MASK_BASE;
			break;
#if defined(CONFIG_HUGETLB_PAGE) || defined(CONFIG_TRANSPARENT_HUGEPAGE)
		case MM_TSB_HUGE:
			hp->pgsz_mask = HV_PGSZ_MASK_HUGE;
			break;
#endif
		default:
			BUG();
		}
		hp->tsb_base = tsb_paddr;
		hp->resv = 0;
	}
}

struct kmem_cache *pgtable_cache __read_mostly;

#define	MAX_TSB_CACHES	(8)
static struct kmem_cache *tsb_caches[MAX_TSB_CACHES] __read_mostly;
static const char *tsb_cache_names[MAX_TSB_CACHES] = {
	"tsb_8KB",
	"tsb_16KB",
	"tsb_32KB",
	"tsb_64KB",
	"tsb_128KB",
	"tsb_256KB",
	"tsb_512KB",
	"tsb_1MB",
};

#define MAX_TSB_ORDER	(15)
#define	TSB_ALLOC_ORDER	(((MAX_ORDER - 1) < MAX_TSB_ORDER) ?		\
			   (MAX_ORDER - 1) : MAX_TSB_ORDER)
static const unsigned long tsb_size_max __initconst = 1UL <<
	(PAGE_SHIFT + TSB_ALLOC_ORDER);
static const unsigned long tsb_cache_size_max __initconst = 1UL <<
	(PAGE_SHIFT + MAX_TSB_CACHES - 1);
static const unsigned long encoded_tsb_size_max __initconst = 1UL <<
	(HV_TSB_SIZE_BASE_SHIFT + HV_TSB_TTE_SIZE_SHIFT + HV_TSB_SIZE_MASK);
static unsigned long tsb_size_limit;

static unsigned long __init mdesc_find_max_tsb(void)
{
	struct mdesc_handle *hp = mdesc_grab();
	unsigned long max_tsb_size = 0UL;
	u64 pn;

	pn = mdesc_node_by_name(hp, MDESC_NODE_NULL, "cpu");

	if (pn != MDESC_NODE_NULL) {
		u64 *val = (u64 *) mdesc_get_property(hp, pn,
						 "mmu-max-tsb-entries",
						  NULL);
		if (val) {
			unsigned long tsb_entries = *val;

			max_tsb_size = tsb_entries << HV_TSB_TTE_SIZE_SHIFT;
		}
	}

	mdesc_release(hp);

	return max_tsb_size;
}

static unsigned long __init chip_type_find_max_tsb(void)
{
	unsigned long max_size = tsb_cache_size_max;

	switch (sun4v_chip_type) {
	/* For any sun4v but those selected in case use kmem cache maximum. */
	case SUN4V_CHIP_NIAGARA4 ... SUN4V_CHIP_SPARC_M7:
		max_size = encoded_tsb_size_max;
		break;
	default:
		break;
	}

	return max_size;
}

/* This all seems a little complicated but there are: sun4u (no machine
 * description), sun4v (machine description but no property for tsb max entries)
 * and sun4v with property. Plus MAX_ORDER constrained at our limit.
 */
static unsigned long __init establish_max_tsb_size(void)
{
	unsigned long size = tsb_cache_size_max;
	unsigned long hv_size;

	BUILD_BUG_ON(MAX_TSB_ORDER > HV_TSB_SIZE_MASK);

	/* For not hypervisor keep the tsb within the kmem cache. */
	if (tlb_type != hypervisor)
		goto out;

	hv_size = mdesc_find_max_tsb();

	if (hv_size)
		size = hv_size;
	else
		size = chip_type_find_max_tsb();

	if (size > tsb_size_max)
		size = tsb_size_max;
out:
	return size;
}

void __init pgtable_cache_init(void)
{
	unsigned long i;

	pgtable_cache = kmem_cache_create("pgtable_cache",
					  PAGE_SIZE, PAGE_SIZE,
					  0,
					  _clear_page);
	if (!pgtable_cache) {
		prom_printf("pgtable_cache_init(): Could not create!\n");
		prom_halt();
	}

	for (i = 0; i < ARRAY_SIZE(tsb_cache_names); i++) {
		unsigned long size = 8192 << i;
		const char *name = tsb_cache_names[i];

		tsb_caches[i] = kmem_cache_create(name,
						  size, size,
						  0, NULL);
		if (!tsb_caches[i]) {
			prom_printf("Could not create %s cache\n", name);
			prom_halt();
		}
	}

	tsb_size_limit = establish_max_tsb_size();
}

static void *tsb_allocate(unsigned int tsb_order, gfp_t gfp)
{
	int nid = numa_node_id();
	void *tsb = NULL;

	if (tsb_order < MAX_TSB_CACHES)
		tsb = kmem_cache_alloc_node(tsb_caches[tsb_order], gfp, nid);
	else {
		struct page *page;

		page = alloc_pages_exact_node(nid, gfp, tsb_order);

		if (page)
			tsb = (void *) page_address(page);
	}

	return tsb;
}

static void tsb_free(void *tsb, unsigned int tsb_order)
{
	if (tsb_order < MAX_TSB_CACHES)
		kmem_cache_free(tsb_caches[tsb_order], tsb);
	else
		free_pages((unsigned long) tsb, tsb_order);
}

int sysctl_tsb_ratio = -2;

static unsigned long tsb_size_to_rss_limit(unsigned long new_size)
{
	unsigned long num_ents = (new_size / sizeof(struct tsb));

	if (sysctl_tsb_ratio < 0)
		return num_ents - (num_ents >> -sysctl_tsb_ratio);
	else
		return num_ents + (num_ents >> sysctl_tsb_ratio);
}

/* When the RSS of an address space exceeds tsb_rss_limit for a TSB,
 * do_sparc64_fault() invokes this routine to try and grow it.
 *
 * When we reach the maximum TSB size supported, we stick ~0UL into
 * tsb_rss_limit for that TSB so the grow checks in do_sparc64_fault()
 * will not trigger any longer.
 *
 * The TSB can be anywhere from 8K to (1ul << (PAGE_SHIFT + HV_TSB_SIZE_MASK)
 * in size, in increasing powers of two.  The TSB must be aligned to it's
 * size, so f.e. a 512K TSB must be 512K aligned. It also must be physically
 * contiguous, so we cannot use vmalloc(). Older sparc64 are limited
 * to kmem cache size of 1MB. A tsb larger than 1MB is not in kmem cache.
 *
 * The idea here is to grow the TSB when the RSS of the process approaches
 * the number of entries that the current TSB can hold at once.  Currently,
 * we trigger when the RSS hits 3/4 of the TSB capacity.
 */
void tsb_grow(struct mm_struct *mm, unsigned long tsb_index, unsigned long rss)
{
	unsigned long new_rss_limit = PAGE_SIZE / sizeof(struct tsb);
	unsigned long new_cache_index, old_cache_index;
	unsigned long max_tsb_size = tsb_size_limit;
	unsigned long new_size, old_size, flags;
	struct tsb *old_tsb, *new_tsb;
	gfp_t gfp_flags;

	new_cache_index = 0;
	for (new_size = PAGE_SIZE; new_size < max_tsb_size; new_size <<= 1UL) {
		new_rss_limit = tsb_size_to_rss_limit(new_size);
		if (new_rss_limit > rss)
			break;
		new_cache_index++;
	}

	if (new_size == max_tsb_size)
		new_rss_limit = ~0UL;

retry_tsb_alloc:
	gfp_flags = GFP_KERNEL;
	if (new_size > (PAGE_SIZE * 2))
		gfp_flags |= __GFP_NOWARN | __GFP_NORETRY;

	new_tsb = tsb_allocate(new_cache_index, gfp_flags);
	if (unlikely(!new_tsb)) {
		/* Not being able to fork due to a high-order TSB
		 * allocation failure is very bad behavior.  Just back
		 * down to a 0-order allocation and force no TSB
		 * growing for this address space.
		 */
		if (mm->context.tsb_block[tsb_index].tsb == NULL &&
		    new_cache_index > 0) {
			new_cache_index = 0;
			new_size = 8192;
			new_rss_limit = ~0UL;
			goto retry_tsb_alloc;
		}

		/* If we failed on a TSB grow, we are under serious
		 * memory pressure so don't try to grow any more.
		 */
		if (mm->context.tsb_block[tsb_index].tsb != NULL)
			mm->context.tsb_block[tsb_index].tsb_rss_limit = ~0UL;
		return;
	}

	/* Mark all tags as invalid.  */
	tsb_init(new_tsb, new_size);

	/* Ok, we are about to commit the changes.  If we are
	 * growing an existing TSB the locking is very tricky,
	 * so WATCH OUT!
	 *
	 * We have to hold mm->context.lock while committing to the
	 * new TSB, this synchronizes us with processors in
	 * flush_tsb_user() and switch_mm() for this address space.
	 *
	 * But even with that lock held, processors run asynchronously
	 * accessing the old TSB via TLB miss handling.  This is OK
	 * because those actions are just propagating state from the
	 * Linux page tables into the TSB, page table mappings are not
	 * being changed.  If a real fault occurs, the processor will
	 * synchronize with us when it hits flush_tsb_user(), this is
	 * also true for the case where vmscan is modifying the page
	 * tables.  The only thing we need to be careful with is to
	 * skip any locked TSB entries during copy_tsb().
	 *
	 * When we finish committing to the new TSB, we have to drop
	 * the lock and ask all other cpus running this address space
	 * to run tsb_context_switch() to see the new TSB table.
	 */
	spin_lock_irqsave(&mm->context.lock, flags);

	old_tsb = mm->context.tsb_block[tsb_index].tsb;
	old_cache_index = mm->context.tsb_block[tsb_index].tsb_reg_val &
			  HV_TSB_SIZE_MASK;
	old_size = (mm->context.tsb_block[tsb_index].tsb_nentries *
		    sizeof(struct tsb));


	/* Handle multiple threads trying to grow the TSB at the same time.
	 * One will get in here first, and bump the size and the RSS limit.
	 * The others will get in here next and hit this check.
	 */
	if (unlikely(old_tsb &&
		     (rss < mm->context.tsb_block[tsb_index].tsb_rss_limit))) {
		spin_unlock_irqrestore(&mm->context.lock, flags);

		tsb_free(new_tsb, new_cache_index);
		return;
	}

	mm->context.tsb_block[tsb_index].tsb_rss_limit = new_rss_limit;

	if (old_tsb) {
		extern void copy_tsb(unsigned long old_tsb_base,
				     unsigned long old_tsb_size,
				     unsigned long new_tsb_base,
				     unsigned long new_tsb_size,
				     unsigned long page_size_shift);
		unsigned long old_tsb_base = (unsigned long) old_tsb;
		unsigned long new_tsb_base = (unsigned long) new_tsb;

		if (tlb_type == cheetah_plus || tlb_type == hypervisor) {
			old_tsb_base = __pa(old_tsb_base);
			new_tsb_base = __pa(new_tsb_base);
		}
		copy_tsb(old_tsb_base, old_size, new_tsb_base, new_size,
			tsb_index == MM_TSB_BASE ?
			PAGE_SHIFT : REAL_HPAGE_SHIFT);
	}

	mm->context.tsb_block[tsb_index].tsb = new_tsb;
	setup_tsb_params(mm, tsb_index, new_size);

	spin_unlock_irqrestore(&mm->context.lock, flags);

	/* If old_tsb is NULL, we're being invoked for the first time
	 * from init_new_context().
	 */
	if (old_tsb) {
		/* Reload it on the local cpu.  */
		tsb_context_switch(mm);

		/* Now force other processors to do the same.  */
		preempt_disable();
		smp_tsb_sync(mm);
		preempt_enable();

		/* Now it is safe to free the old tsb.  */
		tsb_free(old_tsb, old_cache_index);
	}
}

static atomic_t nctxs = ATOMIC_INIT(0);

int init_new_context(struct task_struct *tsk, struct mm_struct *mm)
{
	unsigned long mm_rss = get_mm_rss(mm);
#if defined(CONFIG_HUGETLB_PAGE) || defined(CONFIG_TRANSPARENT_HUGEPAGE)
	unsigned long saved_hugetlb_pte_count;
	unsigned long saved_thp_pte_count;
#endif
	unsigned int i;
	int max_nctx = max_user_nctx;
	int ret = 0;
	int uid = current_cred()->uid.val;

	/*
	 * In the worst case, user(s) might use up all contexts and make the
	 * system unusable.  Give root extra 100 grace ctxs to recover the
	 * system. E.g by killing some user processes.
	 */
	if (uid != 0)
		max_nctx -= 100;

	if (unlikely(max_nctx <= atomic_inc_return(&nctxs))) {
		pr_warn_ratelimited("Reached max(%d) number of processes for %s\n",
				    max_nctx, uid ? "users" : "root");
		ret = -EAGAIN;
		goto error;
	}

	spin_lock_init(&mm->context.lock);

	mm->context.sparc64_ctx_val = 0UL;

#if defined(CONFIG_HUGETLB_PAGE) || defined(CONFIG_TRANSPARENT_HUGEPAGE)
	/* We reset them to zero because the fork() page copying
	 * will re-increment the counters as the parent PTEs are
	 * copied into the child address space.
	 */
	saved_hugetlb_pte_count = mm->context.hugetlb_pte_count;
	saved_thp_pte_count = mm->context.thp_pte_count;
	mm->context.hugetlb_pte_count = 0;
	mm->context.thp_pte_count = 0;

	mm_rss -= saved_thp_pte_count * (HPAGE_SIZE / PAGE_SIZE);
#endif

	/* copy_mm() copies over the parent's mm_struct before calling
	 * us, so we need to zero out the TSB pointer or else tsb_grow()
	 * will be confused and think there is an older TSB to free up.
	 */
	for (i = 0; i < MM_NUM_TSBS; i++)
		mm->context.tsb_block[i].tsb = NULL;

	/* If this is fork, inherit the parent's TSB size.  We would
	 * grow it to that size on the first page fault anyways.
	 */
	tsb_grow(mm, MM_TSB_BASE, mm_rss);

#if defined(CONFIG_HUGETLB_PAGE) || defined(CONFIG_TRANSPARENT_HUGEPAGE)
	if (unlikely(saved_hugetlb_pte_count + saved_thp_pte_count))
		tsb_grow(mm, MM_TSB_HUGE,
			 (saved_hugetlb_pte_count + saved_thp_pte_count) *
			 REAL_HPAGE_PER_HPAGE);
#endif

	if (unlikely(!mm->context.tsb_block[MM_TSB_BASE].tsb)) {
		ret = -ENOMEM;
		goto error;
	}

	return ret;
error:
	atomic_dec(&nctxs);
	return ret;
}

static void tsb_destroy_one(struct tsb_config *tp)
{
	unsigned long tsb_order;

	if (!tp->tsb)
		return;
	tsb_order = tp->tsb_reg_val & HV_TSB_SIZE_MASK;
	tsb_free(tp->tsb, tsb_order);
	tp->tsb = NULL;
	tp->tsb_reg_val = 0UL;
}

void destroy_context(struct mm_struct *mm)
{
	unsigned long flags, i;

	for (i = 0; i < MM_NUM_TSBS; i++)
		tsb_destroy_one(&mm->context.tsb_block[i]);

	atomic_dec(&nctxs);

	spin_lock_irqsave(&ctx_alloc_lock, flags);

	if (CTX_VALID(mm->context)) {
		unsigned long nr = CTX_NRBITS(mm->context);
		mmu_context_bmap[nr>>6] &= ~(1UL << (nr & 63));
	}

	spin_unlock_irqrestore(&ctx_alloc_lock, flags);
}
