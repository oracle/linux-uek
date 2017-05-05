/*
 * Copyright (c) 2017, Oracle and/or its affiliates. All rights reserved.
 *
 * This work is licensed under the terms of the GNU GPL, version 2.
 */

#include "dax_impl.h"

/*
 * CCB buffer management
 *
 * A BIP-Buffer is used to track the outstanding CCBs.
 *
 * A BIP-Buffer is a well-known variant of a circular buffer that
 * returns variable length contiguous blocks.  The buffer is split
 * into two regions, A and B.  The buffer starts with a single region A.
 * When there is more space before region A than after, a new region B
 * is created and future allocations come from region B.  When region A
 * is completely deallocated, region B if in use is renamed to region A.
 */
static void dbg_bip_state(struct dax_ctx *ctx)
{
	dax_dbg("a_start=%d a_end=%d, b_end=%d, resv_start=%d, resv_end=%d, bufcnt=%d",
		ctx->a_start, ctx->a_end, ctx->b_end,  ctx->resv_start,
		ctx->resv_end, ctx->bufcnt);
}

/*
 * Reserves space in the bip buffer for the user ccbs.  Returns amount reserved
 * which may be less than requested len.
 *
 * If region B exists, then allocate from region B regardless of region A
 * freespace.  Else, compare freespace before and after region A.  If more space
 * before, then create new region B.
 */
union ccb *dax_ccb_buffer_reserve(struct dax_ctx *ctx, size_t len,
				  size_t *reserved)
{
	size_t avail;

	/* allocate from region B if B exists */
	if (ctx->b_end > 0) {
		avail = ctx->a_start - ctx->b_end;

		if (avail > len)
			avail = len;

		if (avail == 0)
			return NULL;

		*reserved = avail;
		ctx->resv_start = ctx->b_end;
		ctx->resv_end = ctx->b_end + avail;

		dax_dbg("region B reserve: reserved=%ld, resv_start=%d, resv_end=%d, ccb_bufp=0x%p",
			*reserved, ctx->resv_start, ctx->resv_end,
			(void *)((caddr_t *)(ctx->ccb_buf) + ctx->resv_start));
	} else {

		/*
		 * region A allocation. Check if there is more freespace after
		 * region A than before region A.  Allocate from the larger.
		 */
		avail = ctx->ccb_buflen - ctx->a_end;

		if (avail >= ctx->a_start) {
			/* more freespace after region A */

			if (avail == 0)
				return NULL;

			if (avail > len)
				avail = len;

			*reserved = avail;
			ctx->resv_start = ctx->a_end;
			ctx->resv_end = ctx->a_end + avail;

			dax_dbg("region A (after) reserve: reserved=%ld, resv_start=%d, resv_end=%d, ccb_bufp=0x%p",
				*reserved, ctx->resv_start, ctx->resv_end,
				(void *)((caddr_t)(ctx->ccb_buf) +
				ctx->resv_start));
		} else {
			/* before region A */
			avail = ctx->a_start;

			if (avail == 0)
				return NULL;

			if (avail > len)
				avail = len;

			*reserved = avail;
			ctx->resv_start = 0;
			ctx->resv_end = avail;

			dax_dbg("region A (before) reserve: reserved=%ld, resv_start=%d, resv_end=%d, ccb_bufp=0x%p",
				*reserved, ctx->resv_start, ctx->resv_end,
				(void *)((caddr_t)(ctx->ccb_buf) +
				ctx->resv_start));
		}
	}

	dbg_bip_state(ctx);

	return ((union ccb *)((caddr_t)(ctx->ccb_buf) + ctx->resv_start));
}

/* Marks the BIP region as used */
void dax_ccb_buffer_commit(struct dax_ctx *ctx, size_t len)
{
	if (ctx->resv_start == ctx->a_end)
		ctx->a_end += len;
	else
		ctx->b_end += len;

	ctx->resv_start = 0;
	ctx->resv_end = 0;
	ctx->bufcnt += len;

	dbg_bip_state(ctx);
}

/*
 * Return index to oldest contig block in buffer, or -1 if empty.
 * In either case, len is set to size of oldest contig block (which may be 0).
 */
int dax_ccb_buffer_get_contig_ccbs(struct dax_ctx *ctx, int *len_ccb)
{
	if (ctx->a_end == 0) {
		*len_ccb = 0;
		return -1;
	}

	*len_ccb = CCB_BYTE_TO_NCCB(ctx->a_end - ctx->a_start);
	return CCB_BYTE_TO_NCCB(ctx->a_start);
}

/*
 * Returns amount of contiguous memory decommitted from buffer.
 *
 * Note: If both regions are currently in use, it will only free the memory in
 * region A. If the amount returned to the pool is less than len, there may be
 * more memory left in buffer.   Caller may need to make multiple calls to
 * decommit all memory in buffer.
 */
void dax_ccb_buffer_decommit(struct dax_ctx *ctx, int n_ccb)
{
	size_t a_len;
	size_t len = NCCB_TO_CCB_BYTE(n_ccb);

	a_len = ctx->a_end - ctx->a_start;

	if (len >= a_len) {
		len = a_len;
		ctx->a_start = 0;
		ctx->a_end = ctx->b_end;
		ctx->b_end = 0;
	} else {
		ctx->a_start += len;
	}

	ctx->bufcnt -= len;

	dbg_bip_state(ctx);
	dax_dbg("decommited len=%ld", len);
}


