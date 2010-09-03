#include <linux/module.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/uio.h>
#include <linux/hardirq.h>
#include <linux/highmem.h>
#include <linux/pagemap.h>

static size_t __iovec_copy_to_user_inatomic(char *vaddr,
			const struct iovec *iov, size_t base, size_t bytes)
{
	size_t copied = 0, left = 0;

	while (bytes) {
		char __user *buf = iov->iov_base + base;
		int copy = min(bytes, iov->iov_len - base);

		base = 0;
		left = __copy_to_user_inatomic(buf, vaddr, copy);
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
size_t ii_iovec_copy_to_user_atomic(struct page *page,
		struct iov_iter *i, unsigned long offset, size_t bytes)
{
	struct iovec *iov = (struct iovec *)i->data;
	char *kaddr;
	size_t copied;

	BUG_ON(!in_atomic());
	kaddr = kmap_atomic(page, KM_USER0);
	if (likely(i->nr_segs == 1)) {
		int left;
		char __user *buf = iov->iov_base + i->iov_offset;
		left = __copy_to_user_inatomic(buf, kaddr + offset, bytes);
		copied = bytes - left;
	} else {
		copied = __iovec_copy_to_user_inatomic(kaddr + offset,
						iov, i->iov_offset, bytes);
	}
	kunmap_atomic(kaddr, KM_USER0);

	return copied;
}

/*
 * This has the same sideeffects and return value as
 * ii_iovec_copy_to_user_atomic().
 * The difference is that it attempts to resolve faults.
 * Page must not be locked.
 */
size_t ii_iovec_copy_to_user(struct page *page,
		struct iov_iter *i, unsigned long offset, size_t bytes)
{
	struct iovec *iov = (struct iovec *)i->data;
	char *kaddr;
	size_t copied;

	kaddr = kmap(page);
	if (likely(i->nr_segs == 1)) {
		int left;
		char __user *buf = iov->iov_base + i->iov_offset;
		left = copy_to_user(buf, kaddr + offset, bytes);
		copied = bytes - left;
	} else {
		copied = __iovec_copy_to_user_inatomic(kaddr + offset,
						iov, i->iov_offset, bytes);
	}
	kunmap(page);
	return copied;
}


static size_t __iovec_copy_from_user_inatomic(char *vaddr,
			const struct iovec *iov, size_t base, size_t bytes)
{
	size_t copied = 0, left = 0;

	while (bytes) {
		char __user *buf = iov->iov_base + base;
		int copy = min(bytes, iov->iov_len - base);

		base = 0;
		left = __copy_from_user_inatomic(vaddr, buf, copy);
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
 * were successfully copied.  If a fault is encountered then return the number of
 * bytes which were copied.
 */
size_t ii_iovec_copy_from_user_atomic(struct page *page,
		struct iov_iter *i, unsigned long offset, size_t bytes)
{
	struct iovec *iov = (struct iovec *)i->data;
	char *kaddr;
	size_t copied;

	BUG_ON(!in_atomic());
	kaddr = kmap_atomic(page, KM_USER0);
	if (likely(i->nr_segs == 1)) {
		int left;
		char __user *buf = iov->iov_base + i->iov_offset;
		left = __copy_from_user_inatomic(kaddr + offset, buf, bytes);
		copied = bytes - left;
	} else {
		copied = __iovec_copy_from_user_inatomic(kaddr + offset,
						iov, i->iov_offset, bytes);
	}
	kunmap_atomic(kaddr, KM_USER0);

	return copied;
}
EXPORT_SYMBOL(iov_iter_copy_from_user_atomic);

/*
 * This has the same sideeffects and return value as
 * ii_iovec_copy_from_user_atomic().
 * The difference is that it attempts to resolve faults.
 * Page must not be locked.
 */
size_t ii_iovec_copy_from_user(struct page *page,
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
		copied = __iovec_copy_from_user_inatomic(kaddr + offset,
						iov, i->iov_offset, bytes);
	}
	kunmap(page);
	return copied;
}

void ii_iovec_advance(struct iov_iter *i, size_t bytes)
{
	BUG_ON(i->count < bytes);

	if (likely(i->nr_segs == 1)) {
		i->iov_offset += bytes;
		i->count -= bytes;
	} else {
		struct iovec *iov = (struct iovec *)i->data;
		size_t base = i->iov_offset;

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
				base = 0;
			}
		}
		i->data = (unsigned long)iov;
		i->iov_offset = base;
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
int ii_iovec_fault_in_readable(struct iov_iter *i, size_t bytes)
{
	struct iovec *iov = (struct iovec *)i->data;
	char __user *buf = iov->iov_base + i->iov_offset;
	bytes = min(bytes, iov->iov_len - i->iov_offset);
	return fault_in_pages_readable(buf, bytes);
}

/*
 * Return the count of just the current iov_iter segment.
 */
size_t ii_iovec_single_seg_count(struct iov_iter *i)
{
	struct iovec *iov = (struct iovec *)i->data;
	if (i->nr_segs == 1)
		return i->count;
	else
		return min(i->count, iov->iov_len - i->iov_offset);
}

struct iov_iter_ops ii_iovec_ops = {
	.ii_copy_to_user_atomic = ii_iovec_copy_to_user_atomic,
	.ii_copy_to_user = ii_iovec_copy_to_user,
	.ii_copy_from_user_atomic = ii_iovec_copy_from_user_atomic,
	.ii_copy_from_user = ii_iovec_copy_from_user,
	.ii_advance = ii_iovec_advance,
	.ii_fault_in_readable = ii_iovec_fault_in_readable,
	.ii_single_seg_count = ii_iovec_single_seg_count,
};
EXPORT_SYMBOL(ii_iovec_ops);
