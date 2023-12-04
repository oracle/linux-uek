/*
 * Copyright (c) 2006, 2023, Oracle and/or its affiliates.
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
#include <linux/topology.h>

#include "rds.h"
#include "lfstack.h"

static unsigned int	rds_exthdr_size[] = {
[RDS_EXTHDR_NONE]	= 0,
[RDS_EXTHDR_VERSION]	= sizeof(struct rds_ext_header_version),
[RDS_EXTHDR_RDMA]	= sizeof(struct rds_ext_header_rdma),
[RDS_EXTHDR_RDMA_DEST]	= sizeof(struct rds_ext_header_rdma_dest),
[RDS_EXTHDR_RDMA_BYTES] = sizeof(struct rds_ext_header_rdma_bytes),
[RDS_EXTHDR_NPATHS]     = sizeof(u16),
[RDS_EXTHDR_GEN_NUM]    = sizeof(u32),
[RDS_EXTHDR_CAP_BITS]   = sizeof(struct rds_ext_header_cap_bits),
[RDS_EXTHDR_SPORT_IDX]  = 1,
[RDS_EXTHDR_CSUM]       = sizeof(struct rds_ext_header_rdma_csum),
};

struct rds_cfu_cache_entry {
	struct page *pg;
	struct lfstack_el list;
};

struct rds_cfu_gc_control {
	int percent_cpus_to_clean;
	int next_cpu;
	struct delayed_work work;
};

static struct rds_cfu_gc_control gc_control;

DEFINE_PER_CPU(union lfstack, rds_cfu_cache) ____cacheline_aligned;
DEFINE_PER_CPU(atomic_t, rds_cfu_entries) ____cacheline_aligned;
static bool rds_cfu_cache_tearing_down;

void rds_message_addref(struct rds_message *rm)
{
	rdsdebug("addref rm %p ref %d\n", rm, atomic_read(&rm->m_refcount));
	atomic_inc(&rm->m_refcount);
}
EXPORT_SYMBOL_GPL(rds_message_addref);

static void rds_cfu_cache_do_gc(void)
{
	int cpus_to_check = num_possible_cpus() * gc_control.percent_cpus_to_clean / 100;
	int i;

	if (!cpus_to_check)
		cpus_to_check = 1;

	for (i = 0; i < cpus_to_check; ++i) {
		atomic_t *nmbr_entries_ptr = per_cpu_ptr(&rds_cfu_entries, gc_control.next_cpu);
		union lfstack *stack = per_cpu_ptr(&rds_cfu_cache, gc_control.next_cpu);
		unsigned int nmbr_cleaned = 0;
		struct lfstack_el *el;

		while ((el = lfstack_pop(stack))) {
			struct rds_cfu_cache_entry *entry =
				container_of(el, struct rds_cfu_cache_entry, list);

			++nmbr_cleaned;
			rds_page_free(entry->pg);
		}

		atomic_sub(nmbr_cleaned, nmbr_entries_ptr);
		rds_stats_add(s_copy_from_user_cache_get, nmbr_cleaned);
		if (++gc_control.next_cpu >= num_possible_cpus())
			gc_control.next_cpu = 0;
	}
}

static void rds_cfu_cache_gc_worker(struct work_struct *work)
{
	rds_cfu_cache_do_gc();

	/* To pair with smp_store_release() below */
	if (!smp_load_acquire(&rds_cfu_cache_tearing_down))
		rds_queue_delayed_work(NULL, rds_wq, &gc_control.work,
				       msecs_to_jiffies(rds_cfu_cache_gc_interval * 1000),
				       "CFU_Cache_gc");
}

void rds_cfu_init_cache(void)
{
	INIT_DELAYED_WORK(&gc_control.work, rds_cfu_cache_gc_worker);

	gc_control.percent_cpus_to_clean = 10;
	gc_control.next_cpu = 0;
	rds_queue_delayed_work(NULL, rds_wq, &gc_control.work,
			       msecs_to_jiffies(rds_cfu_cache_gc_interval * 1000),
			       "CFU_Cache_gc");
}

void rds_cfu_fini_cache(void)
{
	/* To pair with the smp_load_acquire() above */
	smp_store_release(&rds_cfu_cache_tearing_down, true);
	cancel_delayed_work_sync(&gc_control.work);

	gc_control.percent_cpus_to_clean = 100;
	rds_cfu_cache_do_gc();
}

/*
 * This relies on dma_map_sg() not touching sg[].page during merging.
 */
static void rds_message_purge(struct rds_message *rm)
{
	atomic_t *nmbr_entries_ptr = per_cpu_ptr(&rds_cfu_entries, rm->m_alloc_cpu);
	union lfstack *stack = per_cpu_ptr(&rds_cfu_cache, rm->m_alloc_cpu);
	struct lfstack_el *first = NULL;
	unsigned int cache_puts = 0;
	struct lfstack_el *last;
	unsigned long i;

	if (unlikely(test_bit(RDS_MSG_PAGEVEC, &rm->m_flags)))
		return;

	for (i = 0; i < rm->data.op_nents; i++) {
		if (rm->m_alloc_cpu != NUMA_NO_NODE && rm->data.op_sg[i].length >= PAGE_SIZE &&
		    atomic_read(nmbr_entries_ptr) < rds_sysctl_cfu_cache_cap) {
			struct rds_cfu_cache_entry *entry =
				page_address(sg_page(rm->data.op_sg + i));

			++cache_puts;
			if (!first) {
				first = &entry->list;
				last = first;
			} else {
				lfstack_link(last, &entry->list);
				last = lfstack_next(last);
			}
			entry->pg = sg_page(rm->data.op_sg + i);
			last->next = NULL;
		} else {
			rds_page_free(sg_page(&rm->data.op_sg[i]));
		}
	}
	if (first) {
		lfstack_push_many(stack, first, last);
		atomic_add(cache_puts, nmbr_entries_ptr);
		rds_stats_add(s_copy_from_user_cache_put, cache_puts);
	}

	rm->data.op_nents = 0;

	if (rm->rdma.op_active)
		rds_rdma_free_op(&rm->rdma);
	if (rm->rdma.op_rdma_mr)
		kref_put(&rm->rdma.op_rdma_mr->r_kref, __rds_put_mr_final);

	if (rm->atomic.op_active)
		rds_atomic_free_op(&rm->atomic);
	if (rm->atomic.op_rdma_mr)
		kref_put(&rm->atomic.op_rdma_mr->r_kref, __rds_put_mr_final);
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
 * Find the next place we can add an RDS header extension with
 * specific length. Extension headers are pushed one after the
 * other. In the following, the number after the colon is the number
 * of bytes:
 *
 * [ type1:1 dta1:len1 [ type2:1 dta2:len2 ] ... ] RDS_EXTHDR_NONE
 *
 * If the extension headers fill the complete extension header space
 * (16 bytes), the trailing RDS_EXTHDR_NONE is omitted.
 */
static int rds_find_next_ext_space(struct rds_header *hdr, unsigned int len,
	u8 **ext_start)
{
	unsigned int ext_len;
	unsigned int type;
	int ind = 0;

	while ((ind + 1 + len) <= RDS_HEADER_EXT_SPACE) {
		if (hdr->h_exthdr[ind] == RDS_EXTHDR_NONE) {
			*ext_start = hdr->h_exthdr + ind;
			return 0;
		}

		type = hdr->h_exthdr[ind];

		ext_len = (type <= __RDS_EXTHDR_MAX) ? rds_exthdr_size[type] : 0;
		if (WARN_ONCE(!ext_len, "Unknown ext hdr type (%d)\n", type))
			return -EINVAL;

		/* ind points to a valid ext hdr with known length */
		ind += 1 + ext_len;
	}

	/* no room for extension */
	return -ENOSPC;
}

/* The ext hdr space is prefilled with zero from the kzalloc() */
int rds_message_add_extension(struct rds_header *hdr,
			      unsigned int type, const void *data)
{
	unsigned char *dst;
	unsigned int len;

	len = (type <= __RDS_EXTHDR_MAX) ? rds_exthdr_size[type] : 0;
	if (!len)
		return 0;

	if (rds_find_next_ext_space(hdr, len, &dst))
		return 0;

	*dst++ = type;
	memcpy(dst, data, len);

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

	if (ext_type == RDS_EXTHDR_NONE || ext_type > __RDS_EXTHDR_MAX) {
		WARN_ONCE(ext_type > __RDS_EXTHDR_MAX,
			  "rds: received extension msg type (%u) > MAX (%u)\n",
			  ext_type, __RDS_EXTHDR_MAX);
		goto none;
	}

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
	return rds_message_add_extension(hdr, RDS_EXTHDR_VERSION, &ext_hdr);
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
	return rds_message_add_extension(hdr, RDS_EXTHDR_RDMA_DEST, &ext_hdr);
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
	rm->m_alloc_cpu = NUMA_NO_NODE;

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

int rds_message_copy_from_user(struct rds_message *rm, struct iov_iter *from)
{
	unsigned long to_copy, nbytes;
	unsigned long sg_off;
	struct scatterlist *sg;
	int ret = 0;

	rm->m_inc.i_hdr.h_len = cpu_to_be32(iov_iter_count(from));
	rm->m_payload_csum.csum_enabled = !!rds_sysctl_enable_payload_csum;

	/*
	 * now allocate and copy in the data payload.
	 */
	sg = rm->data.op_sg;
	sg_off = 0; /* Dear gcc, sg->page will be null from kzalloc. */

	while (iov_iter_count(from)) {
		if (!sg_page(sg)) {
			if (iov_iter_count(from) >= PAGE_SIZE) {
				union lfstack *stack = per_cpu_ptr(&rds_cfu_cache,
								    smp_processor_id());
				struct lfstack_el *el = lfstack_pop(stack);

				if (el) {
					atomic_t *nmbr_entries_ptr =
						per_cpu_ptr(&rds_cfu_entries, smp_processor_id());
					struct rds_cfu_cache_entry *entry =
						container_of(el, struct rds_cfu_cache_entry, list);

					sg_set_page(sg, entry->pg, PAGE_SIZE, 0);
					rds_stats_inc(s_copy_from_user_cache_get);
					atomic_dec(nmbr_entries_ptr);
				}
			}

			if (!sg_page(sg)) {
				ret = rds_page_remainder_alloc(sg, iov_iter_count(from),
							       GFP_HIGHUSER, NUMA_NO_NODE);
				if (ret)
					return ret;
			}

			rm->data.op_nents++;
			sg_off = 0;
			if (rm->m_alloc_cpu == NUMA_NO_NODE)
				rm->m_alloc_cpu = smp_processor_id();
		}

		to_copy = min_t(unsigned long, iov_iter_count(from),
				sg->length - sg_off);

		if (likely(!rm->m_payload_csum.csum_enabled)) {
			/* no checksum */
			nbytes = copy_page_from_iter(sg_page(sg), sg->offset + sg_off, to_copy,
						     from);
		} else {
			/* calculate full packet wsum checksum */
			nbytes = rds_csum_and_copy_page_from_iter(sg_page(sg), sg->offset + sg_off,
								  to_copy, &rm->m_payload_csum,
								  from);
		}

		if (nbytes != to_copy)
			return -EFAULT;

		rds_stats_add(s_copy_from_user, to_copy);
		sg_off += to_copy;

		if (sg_off == sg->length)
			sg++;
	}

	return ret;
}

int rds_message_inc_copy_to_user(struct rds_incoming *inc, struct iov_iter *to)
{
	struct rds_csum csum = { .csum_val.raw = 0 };
	struct rds_connection *conn;
	struct rds_message *rm;
	struct scatterlist *sg;
	unsigned long to_copy;
	unsigned long vec_off;
	int copied;
	int ret;
	u32 len;

	rm = container_of(inc, struct rds_message, m_inc);
	len = be32_to_cpu(rm->m_inc.i_hdr.h_len);
	conn = inc->i_conn;

	sg = rm->data.op_sg;
	vec_off = 0;
	copied = 0;

	while (iov_iter_count(to) && copied < len) {
		to_copy = min_t(unsigned long, iov_iter_count(to),
				sg->length - vec_off);
		to_copy = min_t(unsigned long, to_copy, len - copied);

		if (likely(!inc->i_payload_csum.csum_enabled)) {
			/* no checksum */
			ret = copy_page_to_iter(sg_page(sg), sg->offset + vec_off, to_copy, to);
		} else {
			/* calculate full packet wsum checksum */
			ret = rds_csum_and_copy_page_to_iter(sg_page(sg), sg->offset + vec_off,
							     to_copy, &csum, to);
		}

		if (ret != to_copy)
			return -EFAULT;

		rds_stats_add(s_copy_to_user, to_copy);
		atomic64_add(to_copy, &conn->c_recv_bytes);
		vec_off += to_copy;
		copied += to_copy;

		if (vec_off == sg->length) {
			vec_off = 0;
			sg++;
		}
	}

	if (unlikely(inc->i_payload_csum.csum_enabled) && copied) {
		rds_stats_inc(s_recv_payload_csum_loopback);
		rds_check_csum(inc, &csum);
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
	rds_clear_rm_flag_bit(rm, RDS_MSG_MAPPED);
	wake_up_interruptible(&rm->m_flush_wait);
}
EXPORT_SYMBOL_GPL(rds_message_unmapped);
