#include <linux/module.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/uio.h>
#include <linux/hardirq.h>
#include <linux/highmem.h>
#include <linux/pagemap.h>
#include <linux/bio.h>

static size_t __iovec_copy_to_user(char *vaddr, const struct iovec *iov,
				   size_t base, size_t bytes, int atomic)
{
	size_t copied = 0, left = 0;

	while (bytes) {
		char __user *buf = iov->iov_base + base;
		int copy = min(bytes, iov->iov_len - base);

		base = 0;
		if (atomic)
			left = __copy_to_user_inatomic(buf, vaddr, copy);
		else
			left = __copy_to_user(buf, vaddr, copy);
		copied += copy;
		bytes -= copy;
		vaddr += copy;
		iov++;

		if (unlikely(left))
			break;
	}
	return copied - left;
}

/*
 * Copy as much as we can into the page and return the number of bytes which
 * were sucessfully copied.  If a fault is encountered then return the number of
 * bytes which were copied.
 */
static size_t ii_iovec_copy_to_user_atomic(struct page *page,
		struct iov_iter *i, unsigned long offset, size_t bytes)
{
	struct iovec *iov = (struct iovec *)i->data;
	char *kaddr;
	size_t copied;

	BUG_ON(!in_atomic());
	kaddr = kmap_atomic(page);
	if (likely(i->nr_segs == 1)) {
		int left;
		char __user *buf = iov->iov_base + i->iov_offset;
		left = __copy_to_user_inatomic(buf, kaddr + offset, bytes);
		copied = bytes - left;
	} else {
		copied = __iovec_copy_to_user(kaddr + offset, iov,
					      i->iov_offset, bytes, 1);
	}
	kunmap_atomic(kaddr);

	return copied;
}

/*
 * This has the same sideeffects and return value as
 * ii_iovec_copy_to_user_atomic().
 * The difference is that it attempts to resolve faults.
 * Page must not be locked.
 */
static size_t ii_iovec_copy_to_user(struct page *page,
		struct iov_iter *i, unsigned long offset, size_t bytes,
		int check_access)
{
	struct iovec *iov = (struct iovec *)i->data;
	char *kaddr;
	size_t copied;

	if (check_access) {
		might_sleep();
		if (generic_segment_checks(iov, &i->nr_segs, &bytes,
					   VERIFY_WRITE))
			return 0;
	}

	if (likely(i->nr_segs == 1)) {
		int left;
		char __user *buf = iov->iov_base + i->iov_offset;
		/*
		 * Faults on the destination of a read are common, so do it
		 * before taking the kmap.
		 */
		if (!fault_in_pages_writeable(buf, bytes)) {
			kaddr = kmap_atomic(page);
			left = __copy_to_user_inatomic(buf, kaddr + offset,
						     bytes);
			kunmap_atomic(kaddr);
			if (left == 0)
				goto success;
		}
		kaddr = kmap(page);
		left = copy_to_user(buf, kaddr + offset, bytes);
		kunmap(page);
success:
		copied = bytes - left;
	} else {
		kaddr = kmap(page);
		copied = __iovec_copy_to_user(kaddr + offset, iov,
					      i->iov_offset, bytes, 0);
		kunmap(page);
	}
	return copied;
}

#ifdef CONFIG_BLOCK
/*
 * As an easily verifiable first pass, we implement all the methods that
 * copy data to and from bvec pages with one function.  We implement it
 * all with kmap_atomic().
 */
static size_t bvec_copy_tofrom_page(struct iov_iter *iter, struct page *page,
				    unsigned long page_offset, size_t bytes,
				    int topage)
{
	struct bio_vec *bvec = (struct bio_vec *)iter->data;
	size_t bvec_offset = iter->iov_offset;
	size_t remaining = bytes;
	void *bvec_map;
	void *page_map;
	size_t copy;

	page_map = kmap_atomic(page);

	BUG_ON(bytes > iter->count);
	while (remaining) {
		BUG_ON(bvec->bv_len == 0);
		BUG_ON(bvec_offset >= bvec->bv_len);
		copy = min(remaining, bvec->bv_len - bvec_offset);
		bvec_map = kmap_atomic(bvec->bv_page);
		if (topage)
			memcpy(page_map + page_offset,
			       bvec_map + bvec->bv_offset + bvec_offset,
			       copy);
		else
			memcpy(bvec_map + bvec->bv_offset + bvec_offset,
			       page_map + page_offset,
			       copy);
		kunmap_atomic(bvec_map);
		remaining -= copy;
		bvec_offset += copy;
		page_offset += copy;
		if (bvec_offset == bvec->bv_len) {
			bvec_offset = 0;
			bvec++;
		}
	}

	kunmap_atomic(page_map);

	return bytes;
}

static size_t ii_bvec_copy_to_user_atomic(struct page *page, struct iov_iter *i,
					  unsigned long offset, size_t bytes)
{
	return bvec_copy_tofrom_page(i, page, offset, bytes, 0);
}
static size_t ii_bvec_copy_to_user(struct page *page, struct iov_iter *i,
				   unsigned long offset, size_t bytes,
				   int check_access)
{
	return bvec_copy_tofrom_page(i, page, offset, bytes, 0);
}
static size_t ii_bvec_copy_from_user_atomic(struct page *page,
					    struct iov_iter *i,
					    unsigned long offset, size_t bytes)
{
	return bvec_copy_tofrom_page(i, page, offset, bytes, 1);
}
static size_t ii_bvec_copy_from_user(struct page *page, struct iov_iter *i,
				     unsigned long offset, size_t bytes)
{
	return bvec_copy_tofrom_page(i, page, offset, bytes, 1);
}

/*
 * bio_vecs have a stricter structure than iovecs that might have
 * come from userspace.  There are no zero length bio_vec elements.
 */
static void ii_bvec_advance(struct iov_iter *i, size_t bytes)
{
	struct bio_vec *bvec = (struct bio_vec *)i->data;
	size_t offset = i->iov_offset;
	size_t delta;

	BUG_ON(i->count < bytes);
	while (bytes) {
		BUG_ON(bvec->bv_len == 0);
		BUG_ON(bvec->bv_len <= offset);
		delta = min(bytes, bvec->bv_len - offset);
		offset += delta;
		i->count -= delta;
		bytes -= delta;
		if (offset == bvec->bv_len) {
			bvec++;
			offset = 0;
		}
	}

	i->data = (unsigned long)bvec;
	i->iov_offset = offset;
}

/*
 * pages pointed to by bio_vecs are always pinned.
 */
static int ii_bvec_fault_in_readable(struct iov_iter *i, size_t bytes)
{
	return 0;
}

static size_t ii_bvec_single_seg_count(struct iov_iter *i)
{
	const struct bio_vec *bvec = (struct bio_vec *)i->data;
	if (i->nr_segs == 1)
		return i->count;
	else
		return min(i->count, bvec->bv_len - i->iov_offset);
}

static int ii_bvec_shorten(struct iov_iter *i, size_t count)
{
	return -EINVAL;
}

struct iov_iter_ops ii_bvec_ops = {
	.ii_copy_to_user_atomic = ii_bvec_copy_to_user_atomic,
	.ii_copy_to_user = ii_bvec_copy_to_user,
	.ii_copy_from_user_atomic = ii_bvec_copy_from_user_atomic,
	.ii_copy_from_user = ii_bvec_copy_from_user,
	.ii_advance = ii_bvec_advance,
	.ii_fault_in_readable = ii_bvec_fault_in_readable,
	.ii_single_seg_count = ii_bvec_single_seg_count,
	.ii_shorten = ii_bvec_shorten,
};
EXPORT_SYMBOL(ii_bvec_ops);
#endif	/* CONFIG_BLOCK */

static size_t __iovec_copy_from_user(char *vaddr, const struct iovec *iov,
				     size_t base, size_t bytes, int atomic)
{
	size_t copied = 0, left = 0;

	while (bytes) {
		char __user *buf = iov->iov_base + base;
		int copy = min(bytes, iov->iov_len - base);

		base = 0;
		if (atomic)
			left = __copy_from_user_inatomic(vaddr, buf, copy);
		else
			left = __copy_from_user(vaddr, buf, copy);
		copied += copy;
		bytes -= copy;
		vaddr += copy;
		iov++;

		if (unlikely(left))
			break;
	}
	return copied - left;
}

/*
 * Copy as much as we can into the page and return the number of bytes which
 * were successfully copied.  If a fault is encountered then return the number
 * of bytes which were copied.
 */
static size_t ii_iovec_copy_from_user_atomic(struct page *page,
		struct iov_iter *i, unsigned long offset, size_t bytes)
{
	struct iovec *iov = (struct iovec *)i->data;
	char *kaddr;
	size_t copied;

	BUG_ON(!in_atomic());
	kaddr = kmap_atomic(page);
	if (likely(i->nr_segs == 1)) {
		int left;
		char __user *buf = iov->iov_base + i->iov_offset;
		left = __copy_from_user_inatomic(kaddr + offset, buf, bytes);
		copied = bytes - left;
	} else {
		copied = __iovec_copy_from_user(kaddr + offset, iov,
						i->iov_offset, bytes, 1);
	}
	kunmap_atomic(kaddr);

	return copied;
}
EXPORT_SYMBOL(iov_iter_copy_from_user_atomic);

/*
 * This has the same sideeffects and return value as
 * ii_iovec_copy_from_user_atomic().
 * The difference is that it attempts to resolve faults.
 * Page must not be locked.
 */
static size_t ii_iovec_copy_from_user(struct page *page,
		struct iov_iter *i, unsigned long offset, size_t bytes)
{
	struct iovec *iov = (struct iovec *)i->data;
	char *kaddr;
	size_t copied;

	kaddr = kmap(page);
	if (likely(i->nr_segs == 1)) {
		int left;
		char __user *buf = iov->iov_base + i->iov_offset;
		left = __copy_from_user(kaddr + offset, buf, bytes);
		copied = bytes - left;
	} else {
		copied = __iovec_copy_from_user(kaddr + offset, iov,
						i->iov_offset, bytes, 0);
	}
	kunmap(page);
	return copied;
}

static void ii_iovec_advance(struct iov_iter *i, size_t bytes)
{
	BUG_ON(i->count < bytes);

	if (likely(i->nr_segs == 1)) {
		i->iov_offset += bytes;
		i->count -= bytes;
	} else {
		struct iovec *iov = (struct iovec *)i->data;
		size_t base = i->iov_offset;
		unsigned long nr_segs = i->nr_segs;

		/*
		 * The !iov->iov_len check ensures we skip over unlikely
		 * zero-length segments (without overruning the iovec).
		 */
		while (bytes || unlikely(i->count && !iov->iov_len)) {
			int copy;

			copy = min(bytes, iov->iov_len - base);
			BUG_ON(!i->count || i->count < copy);
			i->count -= copy;
			bytes -= copy;
			base += copy;
			if (iov->iov_len == base) {
				iov++;
				nr_segs--;
				base = 0;
			}
		}
		i->data = (unsigned long)iov;
		i->iov_offset = base;
		i->nr_segs = nr_segs;
	}
}

/*
 * Fault in the first iovec of the given iov_iter, to a maximum length
 * of bytes. Returns 0 on success, or non-zero if the memory could not be
 * accessed (ie. because it is an invalid address).
 *
 * writev-intensive code may want this to prefault several iovecs -- that
 * would be possible (callers must not rely on the fact that _only_ the
 * first iovec will be faulted with the current implementation).
 */
static int ii_iovec_fault_in_readable(struct iov_iter *i, size_t bytes)
{
	struct iovec *iov = (struct iovec *)i->data;
	char __user *buf = iov->iov_base + i->iov_offset;
	bytes = min(bytes, iov->iov_len - i->iov_offset);
	return fault_in_pages_readable(buf, bytes);
}

/*
 * Return the count of just the current iov_iter segment.
 */
static size_t ii_iovec_single_seg_count(struct iov_iter *i)
{
	struct iovec *iov = (struct iovec *)i->data;
	if (i->nr_segs == 1)
		return i->count;
	else
		return min(i->count, iov->iov_len - i->iov_offset);
}

static int ii_iovec_shorten(struct iov_iter *i, size_t count)
{
	struct iovec *iov = (struct iovec *)i->data;
	i->nr_segs = iov_shorten(iov, i->nr_segs, count);
	i->count = min(i->count, count);
	return 0;
}

struct iov_iter_ops ii_iovec_ops = {
	.ii_copy_to_user_atomic = ii_iovec_copy_to_user_atomic,
	.ii_copy_to_user = ii_iovec_copy_to_user,
	.ii_copy_from_user_atomic = ii_iovec_copy_from_user_atomic,
	.ii_copy_from_user = ii_iovec_copy_from_user,
	.ii_advance = ii_iovec_advance,
	.ii_fault_in_readable = ii_iovec_fault_in_readable,
	.ii_single_seg_count = ii_iovec_single_seg_count,
	.ii_shorten = ii_iovec_shorten,
};
EXPORT_SYMBOL(ii_iovec_ops);
