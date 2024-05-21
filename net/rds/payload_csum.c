// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2006, 2024, Oracle and/or its affiliates.
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
#include <linux/tracepoint-defs.h>

#include "rds.h"
#include "trace.h"

/* RDS checksum version of copy_page_from_iter()
 *
 * This code is largely a functional copy of copy_page_from_iter() as found in
 * lib/iov_iter.c, as that code does not have a provision for calculating a
 * checksum but otherwise has the functionality needed.
 */
size_t rds_csum_and_copy_page_from_iter(struct page *page, size_t offset,
					size_t bytes, __wsum *sum,
					struct iov_iter *i)
{
	size_t res = 0;

	page += offset / PAGE_SIZE;	/* first subpage */
	offset %= PAGE_SIZE;

	while (1) {
		__wsum sum_iter = 0;
		void *kaddr = kmap_local_page(page);
		size_t n = min(bytes, (size_t)PAGE_SIZE - offset);
		bool status = csum_and_copy_from_iter_full(kaddr + offset, n, &sum_iter, i);

		kunmap_local(kaddr);

		/* If the returned status is false, the full copy did not occur
		 * so return a count less than (bytes) to signify an error.
		 */
		if (!status) {
			*sum = 0;
			break;
		}

		*sum = csum_block_add(*sum, sum_iter, res);
		res += n;
		bytes -= n;

		if (!bytes)
			break;

		offset += n;

		if (offset == PAGE_SIZE) {
			page++;
			offset = 0;
		}
	}

	return res;
}
EXPORT_SYMBOL_GPL(rds_csum_and_copy_page_from_iter);

/* Below are local versions of csum_and_copy_to_iter() and ancillary routines
 * from net/core/datagram.c as they are no longer callable outside of core
 * networking due to changes in the upstream kernel.
 *
 * The upstream kernel also no longer exports arch-specific versions of
 * csum_and_copy_to_user(), so the code must use an architecture-agnostic
 * version.
 *
 * As payload checksums are a diagnostic tool ONLY that must specifically be
 * enabled, a slight performance impact isn't of concern.
 */
static inline
__wsum rds_csum_and_copy_to_user(const void *src, void __user *dst, int len)
{
	__wsum sum = csum_partial(src, len, ~0U);

	if (copy_to_user(dst, src, len) == 0)
		return sum;
	return 0;
}

/* Copy to destination address mapped into user space:
 * iovec ITER_UBUF || ITER_IOVEC
 */
static inline
size_t rds_copy_to_user_iter_csum(void __user *iter_to, size_t progress,
				  size_t len, void *from, void *priv2)
{
	__wsum next, *csum = priv2;

	next = rds_csum_and_copy_to_user(from + progress, iter_to, len);
	*csum = csum_block_add(*csum, next, progress);
	return next ? 0 : len;
}

/* Copy to destination address mapped into kernel space:
 * iovec ITER_BVEC || ITER_KVEC || ITER_XARRAY
 */
static inline
size_t rds_memcpy_to_iter_csum(void *iter_to, size_t progress,
			       size_t len, void *from, void *priv2)
{
	__wsum *csum = priv2;
	__wsum next = csum_partial_copy_nocheck(from + progress, iter_to, len);

	*csum = csum_block_add(*csum, next, progress);
	return 0;
}

/* Local version of csum_and_copy_to_iter() as it is now declared as a static in
 * upstream code.
 */
size_t rds_csum_and_copy_to_iter(const void *addr, size_t bytes, void *_csstate,
				 struct iov_iter *i)
{
	struct rds_csum_state *csstate = _csstate;
	__wsum sum;

	if (WARN_ON_ONCE(i->data_source))
		return 0;
	if (unlikely(iov_iter_is_discard(i))) {
		// can't use csum_memcpy() for that one - data is not copied
		csstate->csum = csum_block_add(csstate->csum,
					       csum_partial(addr, bytes, 0),
					       csstate->off);
		csstate->off += bytes;
		return bytes;
	}

	sum = csum_shift(csstate->csum, csstate->off);

	/* iterate_and_advance2:
	 *	iter = i				[destination iov]
	 *	len = bytes				[copy length]
	 *	priv = (void *)addr			[source address]
	 *	priv2 = &sum				[loop checksum value]
	 *	ustep = rds_copy_to_user_iter_csum	[userspace dest copy routine]
	 *	step = rds_memcpy_to_iter_csum		[kernel dest copy routine]
	 */
	bytes = iterate_and_advance2(i, bytes, (void *)addr, &sum,
				     rds_copy_to_user_iter_csum,
				     rds_memcpy_to_iter_csum);

	csstate->csum = csum_shift(sum, csstate->off);
	csstate->off += bytes;
	return bytes;
}
EXPORT_SYMBOL_GPL(rds_csum_and_copy_to_iter);

/* Local version of copy_page_to_iter() from lib/iov_iter.c modified to
 * accommodate checksums.
 */
size_t rds_csum_and_copy_page_to_iter(struct page *page, size_t offset,
				      size_t bytes, __wsum *sum,
				      struct iov_iter *i)
{
	size_t res = 0;

	if (WARN_ON_ONCE(i->data_source))
		return 0;

	page += offset / PAGE_SIZE;	/* first subpage */
	offset %= PAGE_SIZE;

	while (1) {
		struct rds_csum_state csdata = { .csum = 0 };
		void *kaddr = kmap_local_page(page);
		size_t n = min(bytes, (size_t)PAGE_SIZE - offset);

		n = rds_csum_and_copy_to_iter(kaddr + offset, n, &csdata, i);
		kunmap_local(kaddr);

		if (!n) {
			*sum = 0;
			break;
		}

		*sum = csum_block_add(*sum, csdata.csum, res);
		res += n;
		bytes -= n;

		if (!bytes)
			break;

		offset += n;

		if (offset == PAGE_SIZE) {
			page++;
			offset = 0;
		}
	}

	return res;
}
EXPORT_SYMBOL_GPL(rds_csum_and_copy_page_to_iter);

/* end of routines based upon upstream generic code */

void rds_check_csum(struct rds_incoming *inc)
{
	if (unlikely(inc->i_payload_csum.csum != inc->i_usercopy_csum)) {
		rds_stats_inc(inc->i_conn->c_stats,
			      s_recv_payload_csum_bad);

		trace_rds_receive_csum_err(inc, inc->i_conn, inc->i_conn_path,
					   &inc->i_saddr,
					   inc->i_conn ?  &inc->i_conn->c_faddr : NULL);
	}
}
EXPORT_SYMBOL_GPL(rds_check_csum);
