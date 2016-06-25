/*
 * Copyright (c) 2006 Oracle.  All rights reserved.
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
#include <linux/kernel.h>

#include "rds.h"

static unsigned int	rds_exthdr_size[__RDS_EXTHDR_MAX] = {
[RDS_EXTHDR_NONE]	= 0,
[RDS_EXTHDR_VERSION]	= sizeof(struct rds_ext_header_version),
[RDS_EXTHDR_RDMA]	= sizeof(struct rds_ext_header_rdma),
[RDS_EXTHDR_RDMA_DEST]	= sizeof(struct rds_ext_header_rdma_dest),
[RDS_EXTHDR_RDMA_BYTES] = sizeof(struct rds_ext_header_rdma_bytes),
};


void rds_message_addref(struct rds_message *rm)
{
	rdsdebug("addref rm %p ref %d\n", rm, atomic_read(&rm->m_refcount));
	atomic_inc(&rm->m_refcount);
}
EXPORT_SYMBOL_GPL(rds_message_addref);

/*
 * This relies on dma_map_sg() not touching sg[].page during merging.
 */
static void rds_message_purge(struct rds_message *rm)
{
	unsigned long i;

	if (unlikely(test_bit(RDS_MSG_PAGEVEC, &rm->m_flags)))
		return;

	for (i = 0; i < rm->data.op_nents; i++) {
		rdsdebug("putting data page %p\n", (void *)sg_page(&rm->data.op_sg[i]));
		/* XXX will have to put_page for page refs */
		(rm->data.op_sg[i].length <= PAGE_SIZE) ?
			__free_page(sg_page(&rm->data.op_sg[i])) :
			__free_pages(sg_page(&rm->data.op_sg[i]),
				     get_order(rm->data.op_sg[i].length));
	}
	rm->data.op_nents = 0;

	if (rm->rdma.op_active)
		rds_rdma_free_op(&rm->rdma);
	if (rm->rdma.op_rdma_mr)
		rds_mr_put(rm->rdma.op_rdma_mr);

	if (rm->atomic.op_active)
		rds_atomic_free_op(&rm->atomic);
	if (rm->atomic.op_rdma_mr)
		rds_mr_put(rm->atomic.op_rdma_mr);
}

void rds_message_put(struct rds_message *rm)
{
	rdsdebug("put rm %p ref %d\n", rm, atomic_read(&rm->m_refcount));
	if (atomic_read(&rm->m_refcount) == 0) {
		printk(KERN_CRIT "danger refcount zero on %p\n", rm);
		WARN_ON(1);
	}
	if (atomic_dec_and_test(&rm->m_refcount)) {
		BUG_ON(!list_empty(&rm->m_sock_item));
		BUG_ON(!list_empty(&rm->m_conn_item));
		rds_message_purge(rm);

		kfree(rm);
	}
}
EXPORT_SYMBOL_GPL(rds_message_put);

void rds_message_populate_header(struct rds_header *hdr, __be16 sport,
				 __be16 dport, u64 seq)
{
	hdr->h_flags = 0;
	hdr->h_sport = sport;
	hdr->h_dport = dport;
	hdr->h_sequence = cpu_to_be64(seq);
	/* see rds_find_next_ext_space for reason why we memset the
	 * ext header
	 */
	memset(hdr->h_exthdr, RDS_EXTHDR_NONE, RDS_HEADER_EXT_SPACE);
}
EXPORT_SYMBOL_GPL(rds_message_populate_header);

/*
 * Find the next place we can add rds header extension with specific lenght.
 * Extension headers are pushed one after the other as follow:
 * [ [ ext #1 ] RDS_EXTHDR_NONE [ ext #2 ] RDS_EXTHDR_NONE ... ]
 * Last extension is detected as follow:
 * [ [ ext #n ] RDS_EXTHDR_NONE RDS_EXTHDR_NONE ]
 * See Orabug: 18468180 - NEW EXTENSION HEADER TYPE RDSV3_EXTHDR_RDMA_BYTES
 */
static int rds_find_next_ext_space(struct rds_header *hdr, unsigned int len,
	u8 **ext_start)
{
	int ind;

	for (ind = 0; ind < RDS_HEADER_EXT_SPACE - 1; ind++) {
		if (hdr->h_exthdr[ind] != RDS_EXTHDR_NONE ||
			hdr->h_exthdr[ind + 1] != RDS_EXTHDR_NONE)
			continue;
		/* found free space in ext header  */
		/* skip the RDS_EXTHDR_NONE only if not on first ext */
		if (ind > 0)
			ind++;
		if (RDS_HEADER_EXT_SPACE - ind < len)
			return 1;
		/* extension can fit to header */
		*ext_start = hdr->h_exthdr + ind;
		return 0;
	}
	/* no room for extension */
	return 1;
}

int rds_message_add_extension(struct rds_header *hdr,
		unsigned int type, const void *data, unsigned int len)
{
	unsigned int ext_len = sizeof(u8) + len;
	unsigned char *dst;

	if (rds_find_next_ext_space(hdr, ext_len, &dst))
		return 0;

	if (type >= __RDS_EXTHDR_MAX
	 || len != rds_exthdr_size[type])
		return 0;

	if (ext_len >= RDS_HEADER_EXT_SPACE)
		return 0;

	*dst++ = type;
	memcpy(dst, data, len);

	dst[len] = RDS_EXTHDR_NONE;
	return 1;
}
EXPORT_SYMBOL_GPL(rds_message_add_extension);

/*
 * If a message has extension headers, retrieve them here.
 * Call like this:
 *
 * unsigned int pos = 0;
 *
 * while (1) {
 *	buflen = sizeof(buffer);
 *	type = rds_message_next_extension(hdr, &pos, buffer, &buflen);
 *	if (type == RDS_EXTHDR_NONE)
 *		break;
 *	...
 * }
 */
int rds_message_next_extension(struct rds_header *hdr,
		unsigned int *pos, void *buf, unsigned int *buflen)
{
	unsigned int offset, ext_type, ext_len;
	u8 *src = hdr->h_exthdr;

	offset = *pos;
	if (offset >= RDS_HEADER_EXT_SPACE)
		goto none;

	/* Get the extension type and length. For now, the
	 * length is implied by the extension type. */
	ext_type = src[offset++];

	if (ext_type == RDS_EXTHDR_NONE || ext_type >= __RDS_EXTHDR_MAX)
		goto none;
	ext_len = rds_exthdr_size[ext_type];
	if (offset + ext_len > RDS_HEADER_EXT_SPACE)
		goto none;

	*pos = offset + ext_len;
	if (ext_len < *buflen)
		*buflen = ext_len;
	memcpy(buf, src + offset, *buflen);
	return ext_type;

none:
	*pos = RDS_HEADER_EXT_SPACE;
	*buflen = 0;
	return RDS_EXTHDR_NONE;
}

int rds_message_add_version_extension(struct rds_header *hdr, unsigned int version)
{
	struct rds_ext_header_version ext_hdr;

	ext_hdr.h_version = cpu_to_be32(version);
	return rds_message_add_extension(hdr, RDS_EXTHDR_VERSION, &ext_hdr, sizeof(ext_hdr));
}

int rds_message_get_version_extension(struct rds_header *hdr, unsigned int *version)
{
	struct rds_ext_header_version ext_hdr;
	unsigned int pos = 0, len = sizeof(ext_hdr);

	/* We assume the version extension is the only one present */
	if (rds_message_next_extension(hdr, &pos, &ext_hdr, &len) != RDS_EXTHDR_VERSION)
		return 0;
	*version = be32_to_cpu(ext_hdr.h_version);
	return 1;
}

int rds_message_add_rdma_dest_extension(struct rds_header *hdr, u32 r_key, u32 offset)
{
	struct rds_ext_header_rdma_dest ext_hdr;

	ext_hdr.h_rdma_rkey = cpu_to_be32(r_key);
	ext_hdr.h_rdma_offset = cpu_to_be32(offset);
	return rds_message_add_extension(hdr, RDS_EXTHDR_RDMA_DEST, &ext_hdr, sizeof(ext_hdr));
}
EXPORT_SYMBOL_GPL(rds_message_add_rdma_dest_extension);

/*
 * Each rds_message is allocated with extra space for the scatterlist entries
 * rds ops will need. This is to minimize memory allocation count. Then, each rds op
 * can grab SGs when initializing its part of the rds_message.
 */
struct rds_message *rds_message_alloc(unsigned int extra_len, gfp_t gfp)
{
	struct rds_message *rm;

	if (extra_len > KMALLOC_MAX_SIZE - sizeof(struct rds_message))
		return NULL;

	rm = kzalloc(sizeof(struct rds_message) + extra_len, gfp);
	if (!rm)
		goto out;

	rm->m_used_sgs = 0;
	rm->m_total_sgs = extra_len / sizeof(struct scatterlist);

	atomic_set(&rm->m_refcount, 1);
	INIT_LIST_HEAD(&rm->m_sock_item);
	INIT_LIST_HEAD(&rm->m_conn_item);
	spin_lock_init(&rm->m_rs_lock);
	init_waitqueue_head(&rm->m_flush_wait);

out:
	return rm;
}

/*
 * RDS ops use this to grab SG entries from the rm's sg pool.
 */
struct scatterlist *rds_message_alloc_sgs(struct rds_message *rm, int nents)
{
	struct scatterlist *sg_first = (struct scatterlist *) &rm[1];
	struct scatterlist *sg_ret;

	WARN_ON(rm->m_used_sgs + nents > rm->m_total_sgs);
	WARN_ON(!nents);

	sg_ret = &sg_first[rm->m_used_sgs];
	sg_init_table(sg_ret, nents);
	rm->m_used_sgs += nents;

	return sg_ret;
}

int rds_message_copy_from_user(struct rds_message *rm, struct iov_iter *from,
			       gfp_t gfp, bool large_page)
{
	unsigned long to_copy, nbytes;
	unsigned long sg_off;
	struct scatterlist *sg;
	int ret = 0;

	rm->m_inc.i_hdr.h_len = cpu_to_be32(iov_iter_count(from));

	/*
	 * now allocate and copy in the data payload.
	 */
	sg = rm->data.op_sg;
	sg_off = 0; /* Dear gcc, sg->page will be null from kzalloc. */

	while (iov_iter_count(from)) {
		if (!sg_page(sg)) {
			ret = rds_page_remainder_alloc(sg, iov_iter_count(from),
						       GFP_ATOMIC == gfp ?
						       gfp : GFP_HIGHUSER,
						       large_page);

			if (ret)
				return ret;
			rm->data.op_nents++;
			sg_off = 0;
		}

		to_copy = min_t(unsigned long, iov_iter_count(from),
				sg->length - sg_off);

		rds_stats_add(s_copy_from_user, to_copy);
		nbytes = copy_page_from_iter(sg_page(sg), sg->offset + sg_off,
					     to_copy, from);
		if (nbytes != to_copy)
			return -EFAULT;

		sg_off += to_copy;

		if (sg_off == sg->length)
			sg++;
	}

	return ret;
}

int rds_message_inc_copy_to_user(struct rds_incoming *inc, struct iov_iter *to)
{
	struct rds_message *rm;
	struct scatterlist *sg;
	unsigned long to_copy;
	unsigned long vec_off;
	int copied;
	int ret;
	u32 len;

	rm = container_of(inc, struct rds_message, m_inc);
	len = be32_to_cpu(rm->m_inc.i_hdr.h_len);

	sg = rm->data.op_sg;
	vec_off = 0;
	copied = 0;

	while (iov_iter_count(to) && copied < len) {
		to_copy = min_t(unsigned long, iov_iter_count(to),
				sg->length - vec_off);
		to_copy = min_t(unsigned long, to_copy, len - copied);

		rds_stats_add(s_copy_to_user, to_copy);
		ret = copy_page_to_iter(sg_page(sg), sg->offset + vec_off,
					to_copy, to);
		if (ret != to_copy)
			return -EFAULT;

		vec_off += to_copy;
		copied += to_copy;

		if (vec_off == sg->length) {
			vec_off = 0;
			sg++;
		}
	}

	return copied;
}

/*
 * If the message is still on the send queue, wait until the transport
 * is done with it. This is particularly important for RDMA operations.
 */
void rds_message_wait(struct rds_message *rm)
{
	wait_event_interruptible(rm->m_flush_wait,
			!test_bit(RDS_MSG_MAPPED, &rm->m_flags));
}

void rds_message_unmapped(struct rds_message *rm)
{
	clear_bit(RDS_MSG_MAPPED, &rm->m_flags);
	wake_up_interruptible(&rm->m_flush_wait);
}
EXPORT_SYMBOL_GPL(rds_message_unmapped);

int rds_message_inc_to_skb(struct rds_incoming *inc, struct sk_buff *skb)
{
	struct rds_message *rm;
	struct scatterlist *sg;
	skb_frag_t *frag;
	int ret = 0;
	u32 len;
	int i;

	rm  = container_of(inc, struct rds_message, m_inc);
	len = be32_to_cpu(rm->m_inc.i_hdr.h_len);
	i   = 0;

	/* for now we will only have a single chain of fragments in the skb */
	if (rm->data.op_nents >= MAX_SKB_FRAGS) {
		rdsdebug("too many fragments in op %u > max %u, rm %p",
			 rm->data.op_nents, (int)MAX_SKB_FRAGS, rm);
		goto done;
	}

	/* run through the entire scatter gather list and save off the buffers */
	for (i = 0; i < rm->data.op_nents; i++) {
		/* one to one mapping of frags to sg structures */
		frag = &skb_shinfo(skb)->frags[i];
		sg   = &rm->data.op_sg[i];

		/* save off all the sg pieces to the skb frags we are creating */
		frag->size        = sg->length;
		frag->page_offset = sg->offset;
		frag->page.p      = sg_page(sg);

		/* AA: do we need to bump up the page reference too */
		/* get_page(frag->page); */
	}

	/* track the full message length too */
	skb->len = len;

	/* all good */
	ret = 1;

done:
	/* track all the fragments we saved */
	skb_shinfo(skb)->nr_frags = i;

	return ret;
}
