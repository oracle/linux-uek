/*
 * Copyright (c) 2018, Mellanox Technologies. All rights reserved.
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
 */

#include <linux/jhash.h>
#include <linux/mlx5/linux/list.h>
#ifndef MLX_DISABLE_TRACEPOINTS
#define CREATE_TRACE_POINTS
#include "fw_tracer_tracepoint.h"
#endif
#include "fw_tracer.h"

static int mlx5_query_mtrc_caps(struct mlx5_fw_tracer *tracer)
{
	struct mlx5_core_dev *dev = tracer->dev;
	u32 *string_db_base_address_out = tracer->str_db.base_address_out;
	u32 *string_db_size_out = tracer->str_db.size_out;
	u32 in[MLX5_ST_SZ_DW(mtrc_cap)] = {0};
	u32 out[MLX5_ST_SZ_DW(mtrc_cap)] = {0};
	void *mtrc_cap_sp;
	int err, i;

	err = mlx5_core_access_reg(dev, in, sizeof(in), out, sizeof(out),
				   MLX5_REG_MTRC_CAP, 0, 0);
	if (err) {
		mlx5_core_warn(dev, "FWTracer: Error reading tracer caps %d\n",
			       err);
		return err;
	}

	tracer->trace_to_memory = MLX5_GET(mtrc_cap, out, trace_to_memory);
	if (!tracer->trace_to_memory) {
		mlx5_core_dbg(dev, "FWTracer: Device does not support logging traces to memory\n");
		return -ENOTSUPP;
	}

	tracer->trc_ver = MLX5_GET(mtrc_cap, out, trc_ver);
	tracer->str_db.first_string_trace =
			MLX5_GET(mtrc_cap, out, first_string_trace);
	tracer->str_db.num_string_trace =
			MLX5_GET(mtrc_cap, out, num_string_trace);
	tracer->str_db.num_string_db = MLX5_GET(mtrc_cap, out, num_string_db);
	tracer->owner = MLX5_GET(mtrc_cap, out, trace_owner);

	for (i = 0; i < tracer->str_db.num_string_db; i++) {
		mtrc_cap_sp = MLX5_ADDR_OF(mtrc_cap, out, string_db_param[i]);
		string_db_base_address_out[i] = MLX5_GET(mtrc_string_db_param,
							 mtrc_cap_sp,
							 string_db_base_address);
		string_db_size_out[i] = MLX5_GET(mtrc_string_db_param,
						 mtrc_cap_sp, string_db_size);
	}

	return err;
}

static int mlx5_set_mtrc_caps_trace_owner(struct mlx5_fw_tracer *tracer, u32 *out,
					  u32 out_size, u8 trace_owner)
{
	struct mlx5_core_dev *dev = tracer->dev;
	u32 in[MLX5_ST_SZ_DW(mtrc_cap)] = {0};

	MLX5_SET(mtrc_cap, in, trace_owner, trace_owner);

	return mlx5_core_access_reg(dev, in, sizeof(in), out, out_size,
				    MLX5_REG_MTRC_CAP, 0, 1);
}

static int mlx5_fw_tracer_acquire_tracer_owner(struct mlx5_fw_tracer *tracer)
{
	struct mlx5_core_dev *dev = tracer->dev;
	u32 out[MLX5_ST_SZ_DW(mtrc_cap)] = {0};
	int err;

	err = mlx5_set_mtrc_caps_trace_owner(tracer, out, sizeof(out),
					     MLX5_FW_TRACER_ACQUIRE_OWNERSHIP);
	if (err) {
		mlx5_core_warn(dev, "FWTracer: Acquire tracer ownership failed %d\n",
			       err);
		return err;
	}

	tracer->owner = !!MLX5_GET(mtrc_cap, out, trace_owner);

	if (!tracer->owner) {
		mlx5_core_dbg(dev, "FWTracer: Ownership was not granted\n");
		return -EBUSY;
	}

	return 0;
}

static void mlx5_fw_tracer_release_tracer_owner(struct mlx5_fw_tracer *tracer)
{
	u32 out[MLX5_ST_SZ_DW(mtrc_cap)] = {0};

	mlx5_set_mtrc_caps_trace_owner(tracer, out, sizeof(out),
				       MLX5_FW_TRACER_RELEASE_OWNERSHIP);
	tracer->owner = false;
}

static int mlx5_tracer_create_mkey(struct mlx5_fw_tracer *tracer)
{
	struct mlx5_core_dev *dev = tracer->dev;
	int err, inlen, i;
	void *mkc;
	__be64 *mtt;
	u32 *in;

	inlen = MLX5_ST_SZ_BYTES(create_mkey_in) +
			sizeof(*mtt) * round_up(TRACER_BUFFER_PAGE_NUM, 2);

	in = kvzalloc(inlen, GFP_KERNEL);
	if (!in)
		return -ENOMEM;

	MLX5_SET(create_mkey_in, in, translations_octword_actual_size,
		 DIV_ROUND_UP(TRACER_BUFFER_PAGE_NUM, 2));
	mtt = (u64 *)MLX5_ADDR_OF(create_mkey_in, in, klm_pas_mtt);
	for (i = 0 ; i < TRACER_BUFFER_PAGE_NUM ; i++)
		mtt[i] = cpu_to_be64(tracer->buff.dma + i * PAGE_SIZE);

	mkc = MLX5_ADDR_OF(create_mkey_in, in, memory_key_mkey_entry);
	MLX5_SET(mkc, mkc, access_mode_1_0, MLX5_MKC_ACCESS_MODE_MTT);
	MLX5_SET(mkc, mkc, lr, 1);
	MLX5_SET(mkc, mkc, lw, 1);
	MLX5_SET(mkc, mkc, pd, tracer->buff.pdn);
	MLX5_SET(mkc, mkc, bsf_octword_size, 0);
	MLX5_SET(mkc, mkc, qpn, 0xffffff);
	MLX5_SET(mkc, mkc, log_page_size, PAGE_SHIFT);
	MLX5_SET(mkc, mkc, translations_octword_size,
		 DIV_ROUND_UP(TRACER_BUFFER_PAGE_NUM, 2));
	MLX5_SET64(mkc, mkc, start_addr, (u64)tracer->buff.dma);
	MLX5_SET64(mkc, mkc, len, tracer->buff.size);
	err = mlx5_core_create_mkey(dev, &tracer->buff.mkey, in, inlen);
	if (err)
		mlx5_core_warn(dev, "FWTracer: Failed to create mkey, %d\n",
			       err);

	kvfree(in);

	return err;
}

static int mlx5_tracer_create_log_buf(struct mlx5_fw_tracer *tracer)
{
	struct mlx5_core_dev *dev = tracer->dev;
	struct device *ddev = &dev->pdev->dev;
	dma_addr_t dma;
	void *buff;
	gfp_t gfp;
	int err;

	tracer->buff.size = TRACE_BUFFER_SIZE_BYTE;

	err = mlx5_core_alloc_pd(dev, &tracer->buff.pdn);
	if (err) {
		mlx5_core_warn(dev, "FWTracer: Failed to allocate PD %d\n",
			       err);
		return err;
	}

	gfp = GFP_KERNEL | __GFP_ZERO;
	buff = (void *)__get_free_pages(gfp,
					get_order(tracer->buff.size));
	if (!buff) {
		mlx5_core_warn(dev, "FWTracer: Failed to allocate pages, %d\n",
			       err);
		err = -ENOMEM;
		goto err_dealloc_pd;
	}
	tracer->buff.log_buf = buff;

	dma = dma_map_single(ddev, buff, tracer->buff.size,
			     DMA_FROM_DEVICE);
	if (dma_mapping_error(ddev, dma)) {
		mlx5_core_warn(dev, "FWTracer: Unable to map DMA\n");
		err = -ENOMEM;
		goto free_pages;
	}
	tracer->buff.dma = dma;

	err = mlx5_tracer_create_mkey(tracer);
	if (err) {
		mlx5_core_warn(dev, "FWTracer: Failed to create mkey %d\n",
			       err);
		goto unmap_single;
	}

	return 0;

unmap_single:
	dma_unmap_single(ddev, tracer->buff.dma, tracer->buff.size,
			 DMA_FROM_DEVICE);
free_pages:
	free_pages((unsigned long)tracer->buff.log_buf,
		   get_order(tracer->buff.size));
err_dealloc_pd:
	mlx5_core_dealloc_pd(dev, tracer->buff.pdn);
	return err;
}

static void mlx5_fw_tracer_destroy_log_buf(struct mlx5_fw_tracer *tracer)
{
	struct mlx5_core_dev *dev = tracer->dev;
	struct device *ddev = &dev->pdev->dev;

	if (!tracer->buff.log_buf)
		return;

	mlx5_core_destroy_mkey(dev, &tracer->buff.mkey);
	dma_unmap_single(ddev, tracer->buff.dma,
			 tracer->buff.size, DMA_FROM_DEVICE);
	free_pages((unsigned long)tracer->buff.log_buf,
		   get_order(tracer->buff.size));
	mlx5_core_dealloc_pd(dev, tracer->buff.pdn);
}

static void mlx5_fw_tracer_free_strings_db(struct mlx5_fw_tracer *tracer)
{
	u32 num_string_db = tracer->str_db.num_string_db;
	int i;

	for (i = 0; i < num_string_db; i++) {
		kfree(tracer->str_db.buffer[i]);
		tracer->str_db.buffer[i] = NULL;
	}
}

static int mlx5_tracer_allocate_strings_db(struct mlx5_fw_tracer *tracer)
{
	u32 *string_db_size_out = tracer->str_db.size_out;
	u32 num_string_db = tracer->str_db.num_string_db;
	int i;

	for (i = 0; i < num_string_db; i++) {
		tracer->str_db.buffer[i] = kzalloc(string_db_size_out[i],
						   GFP_KERNEL);
		if (!tracer->str_db.buffer[i])
			goto free_strings_db;
	}

	return 0;

free_strings_db:
	mlx5_fw_tracer_free_strings_db(tracer);
	return -ENOMEM;
}

static void mlx5_tracer_read_strings_db(struct work_struct *work)
{
	struct mlx5_fw_tracer *tracer =
				container_of(work, struct mlx5_fw_tracer,
					     read_fw_strings_work);
	struct mlx5_core_dev *dev = tracer->dev;
	u32 num_of_reads, num_string_db = tracer->str_db.num_string_db;
	u32 in[MLX5_ST_SZ_DW(mtrc_cap)] = {0};
	u32 leftovers, offset;
	int err = 0, i, j;
	u32 *out, outlen;
	void *out_value;

	outlen = MLX5_ST_SZ_BYTES(mtrc_stdb) + STRINGS_DB_READ_SIZE_BYTES;
	out = kzalloc(outlen, GFP_KERNEL);
	if (!out) {
		err = -ENOMEM;
		goto out;
	}

	for (i = 0; i < num_string_db; i++) {
		offset = 0;
		MLX5_SET(mtrc_stdb, in, string_db_index, i);
		num_of_reads = tracer->str_db.size_out[i] /
					STRINGS_DB_READ_SIZE_BYTES;
		leftovers = (tracer->str_db.size_out[i] % STRINGS_DB_READ_SIZE_BYTES) /
				STRINGS_DB_LEFTOVER_SIZE_BYTES;

		MLX5_SET(mtrc_stdb, in, read_size, STRINGS_DB_READ_SIZE_BYTES);
		for (j = 0; j < num_of_reads; j++) {
			MLX5_SET(mtrc_stdb, in, start_offset, offset);

			err = mlx5_core_access_reg(dev, in, sizeof(in), out,
						   outlen, MLX5_REG_MTRC_STDB,
						   0, 1);
			if (err) {
				mlx5_core_dbg(dev, "FWTracer: Failed to read strings DB %d\n",
					      err);
				goto out_free;
			}

			out_value = MLX5_ADDR_OF(mtrc_stdb, out, string_db_data);
			memcpy(tracer->str_db.buffer[i] + offset, out_value,
			       STRINGS_DB_READ_SIZE_BYTES);
			offset += STRINGS_DB_READ_SIZE_BYTES;
		}

		/* Strings database is aligned to 64, need to read leftovers*/
		MLX5_SET(mtrc_stdb, in, read_size,
			 STRINGS_DB_LEFTOVER_SIZE_BYTES);
		for (j = 0; j < leftovers; j++) {
			MLX5_SET(mtrc_stdb, in, start_offset, offset);

			err = mlx5_core_access_reg(dev, in, sizeof(in), out,
						   outlen, MLX5_REG_MTRC_STDB,
						   0, 1);
			if (err) {
				mlx5_core_dbg(dev, "FWTracer: Failed to read strings DB %d\n",
					      err);
				goto out_free;
			}

			out_value = MLX5_ADDR_OF(mtrc_stdb, out, string_db_data);
			memcpy(tracer->str_db.buffer[i] + offset, out_value,
			       STRINGS_DB_LEFTOVER_SIZE_BYTES);
			offset += STRINGS_DB_LEFTOVER_SIZE_BYTES;
		}

	}

	tracer->str_db.loaded = true;

out_free:
	kfree(out);
out:
	return;
}

static void mlx5_tracer_arm_event(struct mlx5_core_dev *dev)
{
	u32 in[MLX5_ST_SZ_DW(mtrc_ctrl)] = {0};
	u32 out[MLX5_ST_SZ_DW(mtrc_ctrl)] = {0};
	int err;

	MLX5_SET(mtrc_ctrl, in, arm_event, 1);

	err = mlx5_core_access_reg(dev, in, sizeof(in), out, sizeof(out),
				   MLX5_REG_MTRC_CTRL, 0, 1);
	if (err)
		mlx5_core_warn(dev, "FWTracer: Failed to arm tracer event %d\n",
			       err);
}

static const char *VAL_PARM		= "%llx";
static const char *REPLACE_64_VAL_PARM	= "%x%x";
static const char *PARAM_CHAR		= "%";

static inline int mlx5_tracer_message_hash(u32 message_id)
{
	return jhash_1word(message_id, 0) & (MESSAGE_HASH_SIZE - 1);
}

static struct tracer_string_format *mlx5_tracer_message_insert(struct mlx5_fw_tracer *tracer,
							       struct tracer_event *tracer_event)
{
	struct hlist_head *head =
		&tracer->hash[mlx5_tracer_message_hash(tracer_event->string_event.tmsn)];
	struct tracer_string_format *cur_string;

	cur_string = kzalloc(sizeof(*cur_string), GFP_KERNEL);
	if (!cur_string)
		return NULL;

	hlist_add_head(&cur_string->hlist, head);

	return cur_string;
}

static struct tracer_string_format *mlx5_tracer_get_string(struct mlx5_fw_tracer *tracer,
							   struct tracer_event *tracer_event)
{
	struct tracer_string_format *cur_string;
	u32 str_ptr, offset;
	int i;

	str_ptr = tracer_event->string_event.string_param;

	for (i = 0; i < tracer->str_db.num_string_db; i++) {
		if (str_ptr > tracer->str_db.base_address_out[i] &&
		    str_ptr < tracer->str_db.base_address_out[i] +
		    tracer->str_db.size_out[i]) {
			offset = str_ptr - tracer->str_db.base_address_out[i];
			/* add it to the hash */
			cur_string = mlx5_tracer_message_insert(tracer, tracer_event);
			if (!cur_string)
				return NULL;
			cur_string->string = (char *)(tracer->str_db.buffer[i] +
						      offset);
			return cur_string;
		}
	}

	return NULL;
}

static void mlx5_tracer_clean_message(struct tracer_string_format *str_frmt)
{
	hlist_del(&str_frmt->hlist);
	kfree(str_frmt);
}

static int mlx5_tracer_get_num_of_params(char *str)
{
	int num_of_params = 0;
	char *substr, *pstr = str;

	/* replace %llx with %x%x */
	substr = strstr(pstr, VAL_PARM);
	while (substr) {
		strncpy(substr, REPLACE_64_VAL_PARM, 4);
		pstr = substr;
		substr = strstr(pstr, VAL_PARM);
	}

	/* count all the % characters */
	substr = strstr(str, PARAM_CHAR);
	while (substr) {
		num_of_params += 1;
		str = substr + 1;
		substr = strstr(str, PARAM_CHAR);
	}

	return num_of_params;
}

static struct tracer_string_format *mlx5_tracer_message_find(struct hlist_head *head, u8 event_id, u32 tmsn)
{
	struct tracer_string_format *message;
	COMPAT_HL_NODE

	compat_hlist_for_each_entry(message, head, hlist)
		if (message->event_id == event_id && message->tmsn == tmsn)
			return message;

	return NULL;
}

static struct tracer_string_format *mlx5_tracer_message_get(struct mlx5_fw_tracer *tracer,
							    struct tracer_event *tracer_event)
{
	struct hlist_head *head =
		&tracer->hash[mlx5_tracer_message_hash(tracer_event->string_event.tmsn)];

	return mlx5_tracer_message_find(head, tracer_event->event_id, tracer_event->string_event.tmsn);
}

static struct tracer_event mlx5_tracer_poll_trace(struct mlx5_fw_tracer *tracer,
						  u64 *trace)
{
	u32 timestamp_low, timestamp_mid, timestamp_high, urts;
	struct tracer_event tracer_event;

	tracer_event.event_id = MLX5_GET(tracer_event, trace, event_id);
	tracer_event.lost_event = MLX5_GET(tracer_event, trace, lost);

	switch (tracer_event.event_id) {
	case TRACER_EVENT_TYPE_TIMESTAMP:
		tracer_event.type = TRACER_EVENT_TYPE_TIMESTAMP;
		urts = MLX5_GET(tracer_timestamp_event, trace, urts);
		if (tracer->trc_ver == 0)
			tracer_event.timestamp_event.unreliable = !!(urts >> 2);
		else
			tracer_event.timestamp_event.unreliable = !!(urts & 1);

		timestamp_low = MLX5_GET(tracer_timestamp_event,
					 trace, timestamp7_0);
		timestamp_mid = MLX5_GET(tracer_timestamp_event,
					 trace, timestamp39_8);
		timestamp_high = MLX5_GET(tracer_timestamp_event,
					  trace, timestamp52_40);

		tracer_event.timestamp_event.timestamp =
				((u64)timestamp_high << 40) |
				((u64)timestamp_mid << 8) |
				(u64)timestamp_low;
		break;
	default:
		if (tracer_event.event_id >= tracer->str_db.first_string_trace ||
		    tracer_event.event_id <= tracer->str_db.first_string_trace +
					      tracer->str_db.num_string_trace) {
			tracer_event.type = TRACER_EVENT_TYPE_STRING;
			tracer_event.string_event.timestamp =
				MLX5_GET(tracer_string_event, trace, timestamp);
			tracer_event.string_event.string_param =
				MLX5_GET(tracer_string_event, trace, string_param);
			tracer_event.string_event.tmsn =
				MLX5_GET(tracer_string_event, trace, tmsn);
			tracer_event.string_event.tdsn =
				MLX5_GET(tracer_string_event, trace, tdsn);
		} else {
			tracer_event.type = TRACER_EVENT_TYPE_UNRECOGNIZED;
		}
		break;
	}

	return tracer_event;
}

static u64 mlx5_tracer_get_block_timestamp(struct mlx5_fw_tracer *tracer,
					   u64 *ts_event)
{
	struct tracer_event tracer_event;
	u8 event_id;

	event_id = MLX5_GET(tracer_event, ts_event, event_id);

	if (event_id == TRACER_EVENT_TYPE_TIMESTAMP)
		tracer_event = mlx5_tracer_poll_trace(tracer, ts_event);
	else
		tracer_event.timestamp_event.timestamp = 0;

	return tracer_event.timestamp_event.timestamp;
}

static void mlx5_fw_tracer_clean_print_hash(struct mlx5_fw_tracer *tracer)
{
	struct tracer_string_format *str_frmt;
	struct hlist_node *n;
	COMPAT_HL_NODE
	int i;

	for (i = 0; i < MESSAGE_HASH_SIZE; i++) {
		compat_hlist_for_each_entry_safe(str_frmt, n, &tracer->hash[i], hlist)
			mlx5_tracer_clean_message(str_frmt);
	}
}

static void mlx5_fw_tracer_clean_ready_list(struct mlx5_fw_tracer *tracer)
{
	struct tracer_string_format *str_frmt, *tmp_str;

	list_for_each_entry_safe(str_frmt, tmp_str, &tracer->ready_strings_list,
				 list)
		list_del(&str_frmt->list);
}

static void mlx5_tracer_print_trace(struct tracer_string_format *str_frmt,
				    struct mlx5_core_dev *dev,
				    u64 trace_timestamp)
{
	struct mlx5_fw_tracer *tracer = dev->tracer;

	sprintf(tracer->ready_string, str_frmt->string,
		str_frmt->params[0],
		str_frmt->params[1],
		str_frmt->params[2],
		str_frmt->params[3],
		str_frmt->params[4],
		str_frmt->params[5],
		str_frmt->params[6],
		str_frmt->params[7],
		str_frmt->params[8],
		str_frmt->params[9],
		str_frmt->params[10]);

#ifndef MLX_DISABLE_TRACEPOINTS
	trace_fw_tracer(dev->tracer, trace_timestamp, str_frmt->lost,
			str_frmt->event_id, tracer->ready_string);
#else
	pr_debug("%s %llu %d %d %s\n", dev_name(&dev->pdev->dev),
		 trace_timestamp, str_frmt->lost,
		 str_frmt->event_id, tracer->ready_string);
#endif

	/* remove it from hash */
	mlx5_tracer_clean_message(str_frmt);
}

static int mlx5_tracer_handle_string_trace(struct mlx5_fw_tracer *tracer,
					   struct tracer_event *tracer_event)
{
	struct tracer_string_format *cur_string;

	if (tracer_event->string_event.tdsn == 0) {
		cur_string = mlx5_tracer_get_string(tracer, tracer_event);
		if (!cur_string)
			return -1;

		cur_string->num_of_params = mlx5_tracer_get_num_of_params(cur_string->string);
		cur_string->last_param_num = 0;
		cur_string->event_id = tracer_event->event_id;
		cur_string->tmsn = tracer_event->string_event.tmsn;
		cur_string->timestamp = tracer_event->string_event.timestamp;
		cur_string->lost = tracer_event->lost_event;
		if (cur_string->num_of_params == 0) /* trace with no params */
			list_add_tail(&cur_string->list, &tracer->ready_strings_list);
	} else {
		cur_string = mlx5_tracer_message_get(tracer, tracer_event);
		if (!cur_string) {
			pr_debug("%s Got string event for unknown string tdsm: %d\n",
				 __func__, tracer_event->string_event.tmsn);
			return -1;
		}
		cur_string->last_param_num += 1;
		if (cur_string->last_param_num > TRACER_MAX_PARAMS) {
			pr_debug("%s Number of params exceeds the max (%d)\n",
				 __func__, TRACER_MAX_PARAMS);
			list_add_tail(&cur_string->list, &tracer->ready_strings_list);
			return 0;
		}
		/* keep the new parameter */
		cur_string->params[cur_string->last_param_num - 1] =
			tracer_event->string_event.string_param;
		if (cur_string->last_param_num == cur_string->num_of_params)
			list_add_tail(&cur_string->list, &tracer->ready_strings_list);
	}

	return 0;
}

static void mlx5_tracer_handle_timestamp_trace(struct mlx5_fw_tracer *tracer,
					       struct tracer_event *tracer_event)
{
	struct mlx5_core_dev *dev = tracer->dev;
	struct tracer_timestamp_event timestamp_event =
						tracer_event->timestamp_event;
	struct tracer_string_format *str_frmt, *tmp_str;
	u64 trace_timestamp;

	list_for_each_entry_safe(str_frmt, tmp_str, &tracer->ready_strings_list, list) {
		list_del(&str_frmt->list);
		if (str_frmt->timestamp < (timestamp_event.timestamp & MASK_6_0))
			trace_timestamp = (timestamp_event.timestamp & MASK_52_7) |
					  (str_frmt->timestamp & MASK_6_0);
		else
			trace_timestamp = ((timestamp_event.timestamp & MASK_52_7) - 1) |
					  (str_frmt->timestamp & MASK_6_0);

		mlx5_tracer_print_trace(str_frmt, dev, trace_timestamp);
	}
}

static int mlx5_tracer_handle_trace(struct mlx5_fw_tracer *tracer,
				    struct tracer_event *tracer_event)
{
	if (tracer_event->type == TRACER_EVENT_TYPE_STRING) {
		mlx5_tracer_handle_string_trace(tracer, tracer_event);
	} else if (tracer_event->type == TRACER_EVENT_TYPE_TIMESTAMP) {
		if (!tracer_event->timestamp_event.unreliable)
			mlx5_tracer_handle_timestamp_trace(tracer, tracer_event);
	} else {
		pr_debug("%s Got unrecognised type %d for parsing, exiting..\n",
			 __func__, tracer_event->type);
	}
	return 0;
}

static void mlx5_tracer_handle_traces(struct work_struct *work)
{
	struct mlx5_fw_tracer *tracer = container_of(work, struct mlx5_fw_tracer,
						  handle_traces_work);
	struct mlx5_core_dev *dev = tracer->dev;
	u64 block_timestamp, last_block_timestamp, tmp_trace_block[TRACES_PER_BLOCK];
	u32 trace_event_size = MLX5_ST_SZ_BYTES(tracer_event);
	u32 block_count, start_offset, prev_start_offset, prev_consumer_index;
	struct tracer_event tracer_event;
	int i;

	if (!tracer->owner)
		return;

	block_count = tracer->buff.size / TRACER_BLOCK_SIZE_BYTE;
	start_offset = tracer->buff.consumer_index * TRACER_BLOCK_SIZE_BYTE;

	/* Copy the block to local buffer to avoid HW override while being processed*/
	memcpy(tmp_trace_block, tracer->buff.log_buf + start_offset,
	       TRACER_BLOCK_SIZE_BYTE);

	block_timestamp = mlx5_tracer_get_block_timestamp(tracer,
							  &tmp_trace_block[TRACES_PER_BLOCK - 1]);

	while (block_timestamp > tracer->last_timestamp) {
		/* Check block override if its not the first block */
		if (!tracer->last_timestamp) {
			/* To avoid block override be the HW in case of buffer
			 * wraparound, the time stamp of the previous block
			 * should be compared to the last timestamp handled
			 * by the driver.
			 */
			prev_consumer_index = (tracer->buff.consumer_index - 1) &
						(block_count - 1);
			prev_start_offset = prev_consumer_index * TRACER_BLOCK_SIZE_BYTE;
			last_block_timestamp = mlx5_tracer_get_block_timestamp(tracer,
									       tracer->buff.log_buf +
									       prev_start_offset +
									       (TRACES_PER_BLOCK - 1) *
									       trace_event_size);
			/* If previous timestamp different from last stored
			 * timestamp then there is a good chance that the
			 * current buffer is overwritten and therefore should
			 * not be parsed.
			 */
			if (tracer->last_timestamp != last_block_timestamp) {
				mlx5_core_warn(dev, "FWTracer: Events were lost\n");
				tracer->last_timestamp = block_timestamp;
				tracer->buff.consumer_index = (tracer->buff.consumer_index + 1) &
							 (block_count - 1);
				break;
			}
		}

		/* Parse events */
		for (i = 0; i < TRACES_PER_BLOCK ; i++) {
			tracer_event = mlx5_tracer_poll_trace(tracer,
							      &tmp_trace_block[i]);
			mlx5_tracer_handle_trace(tracer, &tracer_event);
		}

		tracer->buff.consumer_index = (tracer->buff.consumer_index + 1) &
						(block_count - 1);

		tracer->last_timestamp = block_timestamp;
		start_offset = tracer->buff.consumer_index * TRACER_BLOCK_SIZE_BYTE;
		memcpy(tmp_trace_block, tracer->buff.log_buf + start_offset,
		       TRACER_BLOCK_SIZE_BYTE);
		block_timestamp = mlx5_tracer_get_block_timestamp(tracer,
								  &tmp_trace_block[TRACES_PER_BLOCK - 1]);
	}

	mlx5_tracer_arm_event(dev);
}

static void mlx5_fw_tracer_free_resources(struct mlx5_fw_tracer *tracer)
{
	mlx5_fw_tracer_clean_ready_list(tracer);
	mlx5_fw_tracer_clean_print_hash(tracer);
	mlx5_fw_tracer_free_strings_db(tracer);
	mlx5_fw_tracer_destroy_log_buf(tracer);
}

static int mlx5_tracer_set_mtrc_conf(struct mlx5_fw_tracer *tracer)
{
	struct mlx5_core_dev *dev = tracer->dev;
	u32 in[MLX5_ST_SZ_DW(mtrc_conf)] = {0};
	u32 out[MLX5_ST_SZ_DW(mtrc_conf)] = {0};
	int err;

	MLX5_SET(mtrc_conf, in, trace_mode, TRACE_TO_MEMORY);
	MLX5_SET(mtrc_conf, in, log_trace_buffer_size,
		 ilog2(TRACER_BUFFER_PAGE_NUM));
	MLX5_SET(mtrc_conf, in, trace_mkey, tracer->buff.mkey.key);

	err = mlx5_core_access_reg(dev, in, sizeof(in), out, sizeof(out),
				   MLX5_REG_MTRC_CONF, 0, 1);
	if (err)
		mlx5_core_warn(dev, "FWTracer: Failed to set tracer configurations %d\n",
			       err);

	return err;
}

static int mlx5_tracer_set_mtrc_ctrl(struct mlx5_fw_tracer *tracer, u8 status,
				     u8 event_val)
{
	struct mlx5_core_dev *dev = tracer->dev;
	u32 in[MLX5_ST_SZ_DW(mtrc_ctrl)] = {0};
	u32 out[MLX5_ST_SZ_DW(mtrc_ctrl)] = {0};
	int err;

	MLX5_SET(mtrc_ctrl, in, modify_field_select, TRACE_STATUS);
	MLX5_SET(mtrc_ctrl, in, trace_status, status);
	MLX5_SET(mtrc_ctrl, in, arm_event, event_val);

	err = mlx5_core_access_reg(dev, in, sizeof(in), out, sizeof(out),
				   MLX5_REG_MTRC_CTRL, 0, 1);

	if (!err && status)
		tracer->last_timestamp = 0;

	return err;
}

static int mlx5_tracer_enable(struct mlx5_fw_tracer *tracer)
{
	struct mlx5_core_dev *dev = tracer->dev;
	int err;

	err = mlx5_tracer_set_mtrc_ctrl(tracer, true, true);
	if (err) {
		mlx5_core_warn(dev, "FWTracer: Failed to set tracer control %d\n",
			       err);
		return err;
	}

	return err;
}

static void mlx5_fw_tracer_ownership_change(struct work_struct *work)
{
	struct mlx5_fw_tracer *tracer = container_of(work, struct mlx5_fw_tracer,
						     ownership_change_work);
	struct mlx5_core_dev *dev = tracer->dev;
	int err;

	if (tracer->owner) {
		tracer->owner = false;
		tracer->buff.consumer_index = 0;
	} else {
		err = mlx5_fw_tracer_acquire_tracer_owner(tracer);
		if (err) {
			mlx5_core_dbg(dev, "FWTracer: Ownership was not granted %d\n",
				      err);
			return;
		}

		err = mlx5_tracer_set_mtrc_conf(tracer);
		if (err) {
			mlx5_core_warn(dev, "FWTracer: Failed to set tracer configuration %d\n"
				       , err);
			goto release_ownership;
		}

		err = mlx5_tracer_enable(tracer);
		if (err) {
			mlx5_core_warn(dev, "FWTracer: Failed to set tracer control %d\n"
				       , err);
			goto release_ownership;
		}

		mlx5_core_info(dev,"FW Tracer Owner\n");
	}

	return;

release_ownership:
	mlx5_fw_tracer_release_tracer_owner(tracer);
}

int mlx5_fw_tracer_init(struct mlx5_core_dev *dev)
{
	struct mlx5_fw_tracer *tracer = NULL;
	int err;

	if (!MLX5_CAP_MCAM_REG(dev, tracer_registers)) {
		mlx5_core_dbg(dev, "FWTracer: Tracer capability not present\n");
		return 0;
	}

	tracer = kzalloc(sizeof(*tracer), GFP_KERNEL);
	if (!tracer)
		return -ENOMEM;

	tracer->dev = dev;
	dev->tracer = tracer;

	INIT_LIST_HEAD(&tracer->ready_strings_list);
	INIT_WORK(&tracer->ownership_change_work,
		  mlx5_fw_tracer_ownership_change);
	INIT_WORK(&dev->tracer->handle_traces_work, mlx5_tracer_handle_traces);
	INIT_WORK(&tracer->read_fw_strings_work, mlx5_tracer_read_strings_db);

	err = mlx5_query_mtrc_caps(tracer);
	if (err) {
		mlx5_core_dbg(dev, "FWTracer: Failed to query capabilities %d\n",
			      err);
		goto free_tracer;
	}

	err = mlx5_tracer_create_log_buf(tracer);
	if (err) {
		mlx5_core_dbg(dev, "FWTracer: Acquire log buffer failed %d\n",
			      err);
		goto free_tracer;
	}

	err = mlx5_tracer_allocate_strings_db(tracer);
	if (err) {
		mlx5_core_warn(dev, "FWTracer: Allocate strings database failed %d\n",
			       err);
		goto free_log_buf;
	}

	schedule_work(&tracer->read_fw_strings_work);
	schedule_work(&tracer->ownership_change_work);

	return 0;

free_log_buf:
	mlx5_fw_tracer_destroy_log_buf(tracer);
free_tracer:
	kfree(tracer);
	return err;
}

void mlx5_fw_tracer_cleanup(struct mlx5_core_dev *dev)
{
	struct mlx5_fw_tracer *tracer = dev->tracer;

	if (!tracer)
		return;

	cancel_work_sync(&tracer->ownership_change_work);
	cancel_work_sync(&tracer->read_fw_strings_work);
	cancel_work_sync(&tracer->handle_traces_work);

	if (tracer->owner)
		mlx5_fw_tracer_release_tracer_owner(tracer);

	mlx5_fw_tracer_free_resources(tracer);

	kfree(tracer);
}

void mlx5_fw_tracer_event(struct mlx5_core_dev *dev, struct mlx5_eqe *eqe)
{
	struct mlx5_fw_tracer *tracer = dev->tracer;

	if (!tracer)
		return;

	switch (eqe->sub_type) {
	case MLX5_TRACER_SUBTYPE_OWNERSHIP_CHANGE:
		if (test_bit(MLX5_INTERFACE_STATE_UP, &dev->intf_state))
			schedule_work(&tracer->ownership_change_work);
		break;
	case MLX5_TRACER_SUBTYPE_TRACES_AVAILABLE:
		if (likely(tracer->str_db.loaded))
			schedule_work(&tracer->handle_traces_work);
		break;
	default:
		mlx5_core_dbg(dev, "FWTracer: Event with unrecognized subtype: sub_type %d\n",
			      eqe->sub_type);
	}
}

#ifndef MLX_DISABLE_TRACEPOINTS
EXPORT_TRACEPOINT_SYMBOL(fw_tracer);
#endif
