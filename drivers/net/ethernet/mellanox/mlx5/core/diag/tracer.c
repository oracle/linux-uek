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

#include "diag/tracer.h"
#include <linux/jhash.h>

static int mlx5_query_mtrc_caps(struct mlx5_core_dev *dev)
{
	struct mlx5_tracer *tracer = &dev->tracer;
	u32 *string_db_base_address_out = tracer->string_db_base_address_out;
	u32 *string_db_size_out = tracer->string_db_size_out;
	u32 in[MLX5_ST_SZ_DW(mtrc_cap)] = {0};
	u32 out[MLX5_ST_SZ_DW(mtrc_cap)] = {0};
	void *mtrc_cap_sp;
	int err, i;

	err = mlx5_core_access_reg(dev, in, sizeof(in), out, sizeof(out),
				   MLX5_REG_MTRC_CAP, 0, 0);
	if (err) {
		mlx5_core_warn(dev, "Error reading tracer caps %d\n", err);
		return err;
	}

	tracer->trace_to_memory = MLX5_GET(mtrc_cap, out, trace_to_memory);
	if (!tracer->trace_to_memory) {
		mlx5_core_dbg(dev, "Device does not support logging traces to memory\n");
		return -ENOTSUPP;
	}

	tracer->log_pointer_granularity =
			MLX5_GET(mtrc_cap, out, log_pointer_granularity);
	tracer->trc_ver = MLX5_GET(mtrc_cap, out, trc_ver);
	tracer->first_string_trace = MLX5_GET(mtrc_cap, out, first_string_trace);
	tracer->string_trace = MLX5_GET(mtrc_cap, out, num_string_trace);
	tracer->num_string_db = MLX5_GET(mtrc_cap, out, num_string_db);
	tracer->tracer_owner = MLX5_GET(mtrc_cap, out, trace_owner);

	for (i = 0; i < tracer->num_string_db; i++) {
		mtrc_cap_sp = MLX5_ADDR_OF(mtrc_cap, out, string_db_param[i]);
		string_db_base_address_out[i] = MLX5_GET(mtrc_string_db_param,
							 mtrc_cap_sp,
							 string_db_base_address);
		string_db_size_out[i] = MLX5_GET(mtrc_string_db_param,
						 mtrc_cap_sp, string_db_size);
	}

	return err;
}

static int mlx5_set_mtrc_caps_trace_owner(struct mlx5_core_dev *dev, u32 *out,
					  u8 trace_owner)
{
	u32 in[MLX5_ST_SZ_DW(mtrc_cap)] = {0};

	MLX5_SET(mtrc_cap, in, trace_owner, trace_owner);

	return mlx5_core_access_reg(dev, in, sizeof(in), out, sizeof(out),
				    MLX5_REG_MTRC_CAP, 0, 1);
}

static int mlx5_tracer_acquire_tracer_owner(struct mlx5_core_dev *dev)
{
	u32 out[MLX5_ST_SZ_DW(mtrc_cap)] = {0};
	int err;

	err = mlx5_set_mtrc_caps_trace_owner(dev, out,
					     MLX5_TRACER_ACQUIRE_OWNERSHIP);
	if (err) {
		mlx5_core_warn(dev, "Acquire tracer ownership failed %d\n",
			       err);
		return err;
	}

	dev->tracer.tracer_owner = MLX5_GET(mtrc_cap, out, trace_owner);

	if (!dev->tracer.tracer_owner) {
		mlx5_core_dbg(dev, "Tracer ownership was not granted\n");
		return -EBUSY;
	}

	return 0;
}

static void mlx5_tracer_release_tracer_owner(struct mlx5_core_dev *dev)
{
	u32 out[MLX5_ST_SZ_DW(mtrc_cap)] = {0};

	mlx5_set_mtrc_caps_trace_owner(dev, out, MLX5_TRACER_RELEASE_OWNERSHIP);
	dev->tracer.tracer_owner = MLX5_GET(mtrc_cap, out, trace_owner);
}

static int mlx5_tracer_set_mtrc_ctrl(struct mlx5_core_dev *dev, u8 status,
				     u8 event_val)
{
	u32 in[MLX5_ST_SZ_DW(mtrc_ctrl)] = {0};
	u32 out[MLX5_ST_SZ_DW(mtrc_ctrl)] = {0};

	MLX5_SET(mtrc_ctrl, in, modify_field_select, TRACE_STATUS);
	MLX5_SET(mtrc_ctrl, in, trace_status, status);
	MLX5_SET(mtrc_ctrl, in, arm_event, event_val);

	return mlx5_core_access_reg(dev, in, sizeof(in), out, sizeof(out),
				    MLX5_REG_MTRC_CTRL, 0, 1);
}

static int mlx5_tracer_enable(struct mlx5_core_dev *dev)
{
	int err;

	err = mlx5_tracer_set_mtrc_ctrl(dev, true, true);
	if (err) {
		mlx5_core_warn(dev, "Error setting tracer control %d\n", err);
		return err;
	}

	return err;
}

static int mlx5_tracer_disable(struct mlx5_core_dev *dev)
{
	return mlx5_tracer_set_mtrc_ctrl(dev, false, false);
}

static int mlx5_tracer_read_strings_db(struct mlx5_core_dev *dev)
{
	struct mlx5_tracer tracer = dev->tracer;
	u32 num_of_reads, num_string_db = tracer.num_string_db;
	u32 in[MLX5_ST_SZ_DW(mtrc_cap)] = {0};
	u32 outlen, strings_offset = 0;
	void *out_value;
	int err = 0, i, j;
	u32 *out;

	outlen = MLX5_ST_SZ_BYTES(mtrc_stdb) + STRINGS_DB_READ_SIZE_BYTES;
	out = kzalloc(outlen, GFP_KERNEL);
	if (!out) {
		err = -ENOMEM;
		mlx5_core_warn(dev, "Cannot allocate memory %d\n", err);
		goto out;
	}

	for (i = 0; i < num_string_db; i++) {
		MLX5_SET(mtrc_stdb, in, string_db_index, i);
		MLX5_SET(mtrc_stdb, in, read_size, STRINGS_DB_READ_SIZE_BYTES);
		num_of_reads = tracer.string_db_size_out[i] /
				STRINGS_DB_READ_SIZE_BYTES;

		for (j = 0; j < num_of_reads; j++) {
			MLX5_SET(mtrc_stdb, in, start_offset,
				 j * STRINGS_DB_READ_SIZE_BYTES);

			err = mlx5_core_access_reg(dev, in, sizeof(in), out,
						   outlen, MLX5_REG_MTRC_STDB,
						   0, 1);
			if (err) {
				mlx5_core_dbg(dev, "Error reading string db %d\n",
					      err);
				goto out_free;
			}

			out_value = MLX5_ADDR_OF(mtrc_stdb, out, string_db_data);
			memcpy(tracer.string_db_buffer[i] + j * STRINGS_DB_READ_SIZE_BYTES,
			       out_value, STRINGS_DB_READ_SIZE_BYTES);
			strings_offset += STRINGS_DB_READ_SIZE_BYTES;
		}
	}

out_free:
	kfree(out);
out:
	return err;
}

static void mlx5_tracer_release_strings_db(struct mlx5_core_dev *dev)
{
	u32 num_string_db = dev->tracer.num_string_db;
	int i;

	for (i = 0; i < num_string_db; i++)
		kfree(dev->tracer.string_db_buffer[i]);
}

static int mlx5_tracer_allocate_strings_db_buffers(struct mlx5_core_dev *dev)
{
	u32 *string_db_size_out = dev->tracer.string_db_size_out;
	u32 num_string_db = dev->tracer.num_string_db;
	int i;

	for (i = 0; i < num_string_db; i++) {
		dev->tracer.string_db_buffer[i] = kzalloc(string_db_size_out[i],
							  GFP_KERNEL);
		if (!dev->tracer.string_db_buffer[i])
			goto free_strings_db;
	}

	return 0;

free_strings_db:
	mlx5_tracer_release_strings_db(dev);
	return -ENOMEM;
}

static int mlx5_tracer_create_mkey(struct mlx5_core_dev *dev)
{
	int err, inlen, i;
	void *mkc;
	u64 *mtt;
	u32 *in;

	inlen = MLX5_ST_SZ_BYTES(create_mkey_in) +
			sizeof(mtt) * round_up(TRACER_BUFFER_PAGE_NUM, 2);

	in = kvzalloc(inlen, GFP_KERNEL);
	if (!in)
		return -ENOMEM;

	MLX5_SET(create_mkey_in, in, translations_octword_actual_size,
		 DIV_ROUND_UP(TRACER_BUFFER_PAGE_NUM, 2));
	mtt = (u64 *)MLX5_ADDR_OF(create_mkey_in, in, klm_pas_mtt);
	for (i = 0 ; i < TRACER_BUFFER_PAGE_NUM ; i++)
		mtt[i] = cpu_to_be64(dev->tracer.dma + i * PAGE_SIZE);

	mkc = MLX5_ADDR_OF(create_mkey_in, in, memory_key_mkey_entry);
	MLX5_SET(mkc, mkc, access_mode_1_0, MLX5_MKC_ACCESS_MODE_MTT);
	MLX5_SET(mkc, mkc, lr, 1);
	MLX5_SET(mkc, mkc, lw, 1);
	MLX5_SET(mkc, mkc, pd, dev->tracer.pdn);
	MLX5_SET(mkc, mkc, bsf_octword_size, 0);
	MLX5_SET(mkc, mkc, qpn, 0xffffff);
	MLX5_SET(mkc, mkc, log_page_size, PAGE_SHIFT);
	MLX5_SET(mkc, mkc, translations_octword_size,
		 DIV_ROUND_UP(TRACER_BUFFER_PAGE_NUM, 2));
	MLX5_SET64(mkc, mkc, start_addr, (u64)dev->tracer.log_buf);
	MLX5_SET64(mkc, mkc, len, dev->tracer.trace_buffer_size);
	err = mlx5_core_create_mkey(dev, &dev->tracer.mkey, in, inlen);
	if (err)
		mlx5_core_warn(dev, "Failed to create mkey, %d\n", err);

	kvfree(in);

	return err;
}

static void mlx5_tracer_release_log_buf(struct mlx5_core_dev *dev)
{
	struct mlx5_tracer *tracer = &dev->tracer;
	struct device *ddev = &dev->pdev->dev;

	if (tracer->mkey.key)
		mlx5_core_destroy_mkey(dev, &tracer->mkey);
	if (tracer->dma)
		dma_unmap_single(ddev, tracer->dma,
				 tracer->trace_buffer_size, DMA_FROM_DEVICE);
	if (tracer->log_buf)
		free_pages((unsigned long)tracer->log_buf,
			   get_order(tracer->trace_buffer_size));
	if (tracer->pdn)
		mlx5_core_dealloc_pd(dev, tracer->pdn);
}

static int mlx5_tracer_acquire_log_buf(struct mlx5_core_dev *dev)
{
	struct mlx5_tracer *tracer = &dev->tracer;
	struct device *ddev = &dev->pdev->dev;
	dma_addr_t dma;
	void *buff;
	gfp_t gfp;
	int err;

	tracer->trace_buffer_size = TRACE_BUFFER_SIZE_BYTE;

	err = mlx5_core_alloc_pd(dev, &tracer->pdn);
	if (err) {
		mlx5_core_warn(dev, "Alloc PD failed, %d\n", err);
		return err;
	}

	gfp = GFP_KERNEL | __GFP_ZERO;
	buff = (void *)__get_free_pages(gfp, get_order(tracer->trace_buffer_size));
	if (!buff) {
		mlx5_core_warn(dev, "Failed to allocate pages, %d\n", err);
		err = -ENOMEM;
		goto err_dealloc_pd;
	}
	tracer->log_buf = buff;

	dma = dma_map_single(ddev, buff, tracer->trace_buffer_size, DMA_FROM_DEVICE);
	if (dma_mapping_error(ddev, dma)) {
		mlx5_core_warn(dev, "unable to map DMA\n");
		err = -ENOMEM;
		goto free_pages;
	}
	tracer->dma = dma;

	err = mlx5_tracer_create_mkey(dev);
	if (err) {
		mlx5_core_warn(dev, "create mkey failed, %d\n", err);
		goto unmap_single;
	}

	return 0;

unmap_single:
	dma_unmap_single(ddev, tracer->dma, tracer->trace_buffer_size, DMA_FROM_DEVICE);
free_pages:
	free_pages((unsigned long)buff, get_order(tracer->trace_buffer_size));
err_dealloc_pd:
	mlx5_core_dealloc_pd(dev, tracer->pdn);
	return err;
}

static int mlx5_tracer_set_mtrc_conf(struct mlx5_core_dev *dev)
{
	struct mlx5_tracer *tracer = &dev->tracer;
	u32 in[MLX5_ST_SZ_DW(mtrc_conf)] = {0};
	u32 out[MLX5_ST_SZ_DW(mtrc_conf)] = {0};
	int err;

	MLX5_SET(mtrc_conf, in, trace_mode, TRACE_TO_MEMORY);
	MLX5_SET(mtrc_conf, in, trace_buffer_size,
		 ilog2(TRACER_BUFFER_PAGE_NUM));
	MLX5_SET(mtrc_conf, in, trace_mkey, tracer->mkey.key);

	err = mlx5_core_access_reg(dev, in, sizeof(in), out, sizeof(out),
				   MLX5_REG_MTRC_CONF, 0, 1);
	if (err) {
		mlx5_core_warn(dev, "Error setting tracer configurations %d\n",
			       err);
		return err;
	}

	return err;
}

static int mlx5_tracer_set_mtrc_ctrl_event(struct mlx5_core_dev *dev,
					   u8 event_val)
{
	u32 in[MLX5_ST_SZ_DW(mtrc_ctrl)] = {0};
	u32 out[MLX5_ST_SZ_DW(mtrc_ctrl)] = {0};

	MLX5_SET(mtrc_ctrl, in, arm_event, event_val);

	return mlx5_core_access_reg(dev, in, sizeof(in), out, sizeof(out),
				    MLX5_REG_MTRC_CTRL, 0, 1);
}

static int mlx5_tracer_set_mtrc_ctrl_arm_event(struct mlx5_core_dev *dev)
{
	int err;

	err = mlx5_tracer_set_mtrc_ctrl_event(dev, 1);
	if (err) {
		mlx5_core_warn(dev, "Error setting tracer control %d\n", err);
		return err;
	}

	return err;
}

static int mlx5_tracer_set_mtrc_ctrl_ci(struct mlx5_core_dev *dev, u32 ci)
{
	u32 in[MLX5_ST_SZ_DW(mtrc_ctrl)] = {0};
	u32 out[MLX5_ST_SZ_DW(mtrc_ctrl)] = {0};
	int err;

	MLX5_SET(mtrc_ctrl, in, modify_field_select, CONSUMER_INDEX);
	MLX5_SET(mtrc_ctrl, in, consumer_index, ci);

	err = mlx5_core_access_reg(dev, in, sizeof(in), out, sizeof(out),
				   MLX5_REG_MTRC_CTRL, 0, 1);
	if (err) {
		mlx5_core_warn(dev, "Error setting tracer control %d\n", err);
		return err;
	}

	return err;
}

static int mlx5_tracer_query_mtrc_ctrl(struct mlx5_core_dev *dev, u32 *out)
{
	u32 in[MLX5_ST_SZ_DW(mtrc_ctrl)] = {0};
	int err = 0;

	err = mlx5_core_access_reg(dev, in, sizeof(in), out, sizeof(in),
				   MLX5_REG_MTRC_CTRL, 0, 0);
	if (err) {
		mlx5_core_warn(dev, "Error query tracer control %d\n", err);
		return err;
	}

	return err;
}

static int mlx5_tracer_poll_trace(struct mlx5_core_dev *dev,
				  struct tracer_event *tracer_event,
				  u32 *trace)
{
	struct mlx5_tracer tracer = dev->tracer;
	u32 timestamp_low, timestamp_mid, timestamp_high, urts;

	tracer_event->event_id = MLX5_GET(tracer_event, trace, event_id);
	tracer_event->lost_event = MLX5_GET(tracer_event, trace, lost);

	switch (tracer_event->event_id) {
	case TRACER_EVENT_TYPE_TIMESTAMP:
		tracer_event->type = TRACER_EVENT_TYPE_TIMESTAMP;
		urts = MLX5_GET(tracer_timestamp_event, trace, urts);
		if (tracer.trc_ver == 0)
			tracer_event->timestamp_event.unreliable = !!(urts >> 2);
		else
			tracer_event->timestamp_event.unreliable = !!(urts & 1);

		timestamp_low = MLX5_GET(tracer_timestamp_event,
					 trace, timestamp7_0);
		timestamp_mid = MLX5_GET(tracer_timestamp_event,
					 trace, timestamp39_8);
		timestamp_high = MLX5_GET(tracer_timestamp_event,
					  trace, timestamp52_40);

		tracer_event->timestamp_event.timestamp =
				((u64)timestamp_high << 40) |
				((u64)timestamp_mid << 8) |
				(u64)timestamp_low;
		break;
	default:
		if (tracer_event->event_id >= tracer.first_string_trace ||
		    tracer_event->event_id <= tracer.string_trace) {
			tracer_event->type = TRACER_EVENT_TYPE_STRING;
			tracer_event->string_event.timestamp = MLX5_GET(tracer_string_event, trace, timestamp);
			tracer_event->string_event.string_param = MLX5_GET(tracer_string_event, trace, string_param);
			tracer_event->string_event.tmsn = MLX5_GET(tracer_string_event, trace, tmsn);
			tracer_event->string_event.tdsn = MLX5_GET(tracer_string_event, trace, tdsn);
		} else {
			tracer_event->type = TRACER_EVENT_TYPE_UNRECOGNIZED;
		}
	}

	return 0;
}

const char *VAL_PARM		= "%llx";
const char *REPLACE_64_VAL_PARM	= "%x%x";
const char *PARAM_CHAR		= "%";

static inline int mlx5_tracer_message_hash(u32 message_id)
{
	/* TODO: replace the 0 with some salt */
	return jhash_1word(message_id, 0) & (MESSAGE_HASH_SIZE - 1);
}

static struct tracer_string_format *mlx5_tracer_message_insert(struct mlx5_tracer *tracer,
							       struct tracer_event *tracer_event)
{
	struct tracer_string_format *cur_string;
	struct hlist_head *head =
		&tracer->hash[mlx5_tracer_message_hash(tracer_event->string_event.tmsn)];

	cur_string = kzalloc(sizeof(*cur_string), GFP_KERNEL);
	if (!cur_string)
		return NULL;

	hlist_add_head(&cur_string->hlist, head);

	return cur_string;
}

static struct tracer_string_format *mlx5_tracer_message_find(struct hlist_head *head, u8 event_id, u32 tmsn)
{
	struct tracer_string_format *message;

	hlist_for_each_entry(message, head, hlist)
		if (message->event_id == event_id && message->tmsn == tmsn)
			return message;

	return NULL;
}

static struct tracer_string_format *mlx5_tracer_message_get(struct mlx5_tracer *tracer,
							    struct tracer_event *tracer_event)
{
	struct hlist_head *head =
		&tracer->hash[mlx5_tracer_message_hash(tracer_event->string_event.tmsn)];

	return mlx5_tracer_message_find(head, tracer_event->event_id, tracer_event->string_event.tmsn);
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

struct tracer_string_format *mlx5_tracer_get_string(struct mlx5_tracer *tracer,
						    struct tracer_event *tracer_event)
{
	int i;
	u32 offset;
	u32 str_ptr;
	struct tracer_string_format *cur_string;

	str_ptr = tracer_event->string_event.string_param;

	for (i = 0; i < tracer->num_string_db; i++) {
		if (str_ptr > tracer->string_db_base_address_out[i] &&
		    str_ptr < tracer->string_db_base_address_out[i] +
		    tracer->string_db_size_out[i]) {
			offset = str_ptr - tracer->string_db_base_address_out[i];
			/* add it to the hash */
			cur_string = mlx5_tracer_message_insert(tracer, tracer_event);
			if (!cur_string)
				return NULL;
			cur_string->string = (char *)(tracer->string_db_buffer[i] + offset);
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

static void mlx5_tracer_clean_print_hash(struct mlx5_tracer *tracer)
{
	struct tracer_string_format *str_frmt;
	struct hlist_node *n;
	int i;

	for (i = 0; i < MESSAGE_HASH_SIZE; i++) {
		hlist_for_each_entry_safe(str_frmt, n, &tracer->hash[i], hlist)
			mlx5_tracer_clean_message(str_frmt);
	}
}

static void mlx5_tracer_print_trace(struct tracer_string_format *str_frmt,
				    struct mlx5_core_dev *dev)
{
	char	tmp[1024];

	sprintf(tmp, str_frmt->string,
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

	pr_debug("%s %d %s\n", dev_name(&dev->pdev->dev), str_frmt->event_id,
		 tmp);

	/* remove it from hash */
	mlx5_tracer_clean_message(str_frmt);
}

static int mlx5_tracer_parse_string(struct mlx5_tracer *tracer,
				    struct tracer_event *tracer_event)
{
	struct mlx5_core_dev *dev = container_of(tracer, struct mlx5_core_dev,
						 tracer);
	struct tracer_string_format *cur_string;

	if (tracer_event->string_event.tdsn == 0) {
		cur_string = mlx5_tracer_get_string(tracer, tracer_event);
		if (!cur_string)
			return -1;

		cur_string->num_of_params = mlx5_tracer_get_num_of_params(cur_string->string);
		cur_string->last_param_num = 0;
		cur_string->event_id = tracer_event->event_id;
		cur_string->tmsn = tracer_event->string_event.tmsn;
		if (cur_string->num_of_params == 0) /* tracewith no params */
			mlx5_tracer_print_trace(cur_string, dev);
	} else {
		cur_string = mlx5_tracer_message_get(tracer, tracer_event);
		if (!cur_string) {
			pr_debug("%s Got string event for unknown string tdsm: %d\n",
				 __func__, tracer_event->string_event.tmsn);
			return -1;
		}
		cur_string->last_param_num += 1;
		if (cur_string->last_param_num > TRACER_MAX_PARAMS) {
			pr_debug("%s Got unexpactable params (%d)\n",
				 __func__, TRACER_MAX_PARAMS);
			mlx5_tracer_print_trace(cur_string, dev);
			return 0;
		}
		/* keep the new parameter */
		cur_string->params[cur_string->last_param_num - 1] =
			tracer_event->string_event.string_param;
		if (cur_string->last_param_num == cur_string->num_of_params)
			mlx5_tracer_print_trace(cur_string, dev);
	}

	return 0;
}

static int parse_trase(struct mlx5_tracer *tracer,
		       struct tracer_event *tracer_event)
{
	if (tracer_event->type == TRACER_EVENT_TYPE_STRING)
		mlx5_tracer_parse_string(tracer, tracer_event);
	else if (tracer_event->type != TRACER_EVENT_TYPE_TIMESTAMP)
		pr_debug("%s Got unrecognised type %d for parsing, exiting..\n",
			 __func__, tracer_event->type);
	return 0;
}

static void mlx5_tracer_handle_traces(struct work_struct *work)
{
	struct mlx5_tracer *tracer = container_of(work, struct mlx5_tracer, log_work);
	struct mlx5_core_dev *dev = container_of(tracer, struct mlx5_core_dev, tracer);
	struct tracer_event tracer_event;
	u32 trace_event_size = MLX5_ST_SZ_BYTES(tracer_event);
	u32 pi, ci, num_of_traces, start_offset, out[MLX5_ST_SZ_DW(mtrc_ctrl)] = {0};
	u8 trace_status, trace_count;
	u32 *trace, trace_entries_count;
	int err, i, j;

	trace_count = 1 << tracer->log_pointer_granularity;
	trace_entries_count = tracer->trace_buffer_size /
				(trace_count * trace_event_size);

	err = mlx5_tracer_query_mtrc_ctrl(dev, out);
	if (err) {
		mlx5_core_warn(dev, "Query tracer control failed %d\n", err);
		return;
	}

	trace_status = MLX5_GET(mtrc_ctrl, out, trace_status);
	pi = MLX5_GET(mtrc_ctrl, out, producer_index);
	ci = MLX5_GET(mtrc_ctrl, out, consumer_index);

	if (!trace_status)
		return;

	num_of_traces = (pi - ci - 1) & (trace_entries_count - 1);

	for (i = 0 ; i < num_of_traces ; i++) {
		ci = (ci + 1) & (trace_entries_count - 1);
		for (j = 0; j < trace_count ; j++) {
			start_offset = (ci << dev->tracer.log_pointer_granularity) * trace_event_size;
			trace = (u32 *)(tracer->log_buf + start_offset + j * trace_event_size);
			err = mlx5_tracer_poll_trace(dev, &tracer_event, trace);
			if (err)
				mlx5_core_warn(dev, "mlx5_tracer_poll_trace failed %d\n", err);
			else
				parse_trase(tracer, &tracer_event);
		}

		err = mlx5_tracer_set_mtrc_ctrl_ci(dev, ci);
		if (err) {
			mlx5_core_warn(dev, "Set consumer index failed %d\n", err);
			return;
		}
	}

	err = mlx5_tracer_set_mtrc_ctrl_arm_event(dev);
	if (err) {
		mlx5_core_warn(dev, "Set consumer index failed %d\n", err);
		return;
	}

}

static void mlx5_tracer_free_resources(struct mlx5_core_dev *dev)
{
	mlx5_tracer_release_strings_db(dev);
	mlx5_tracer_release_log_buf(dev);
	mlx5_tracer_clean_print_hash(&dev->tracer);
}

static void mlx5_tracer_ownership_change(struct work_struct *work)
{
	struct mlx5_tracer *tracer = container_of(work, struct mlx5_tracer,
						  ownership_change_work);
	struct mlx5_core_dev *dev = container_of(tracer, struct mlx5_core_dev,
						 tracer);
	int err;

	if (!MLX5_CAP_MCAM_REG(dev, tracer_registers)) {
		mlx5_core_dbg(dev, "Tracer capability not present\n");
		return;
	}

	if (tracer->tracer_owner) {
		/* Our ownership was released */
 		tracer->tracer_owner = 0;
		mlx5_tracer_free_resources(dev);
	} else {
		/* Try to get ownership */
		err = mlx5_query_mtrc_caps(dev);
		if (err) {
			mlx5_core_dbg(dev, "Failed to query tracer capabilities %d\n",
				      err);
			return;
		}

		err = mlx5_tracer_acquire_tracer_owner(dev);
		if (err) {
			mlx5_core_dbg(dev, "Tracer ownership was not granted %d\n",
				      err);
			return;
		}
		err = mlx5_tracer_acquire_log_buf(dev);
		if (err) {
			mlx5_core_dbg(dev, "Acquire log buffer failed %d\n",
				      err);
			return;
		}
		err = mlx5_tracer_allocate_strings_db_buffers(dev);
		if (err) {
			mlx5_core_warn(dev, "Allocate strings database failed %d\n",
				       err);
			goto free_log_buf;
		}
		err = mlx5_tracer_read_strings_db(dev);
		if (err) {
			mlx5_core_warn(dev, "Read strings DB failed %d\n", err);
			goto free_string_db;
		}
		err = mlx5_tracer_set_mtrc_conf(dev);
		if (err) {
			mlx5_core_warn(dev, "Failed to set tracer configuration %d\n"
				       , err);
			goto free_string_db;
		}
		err = mlx5_tracer_enable(dev);
		if (err) {
			mlx5_core_warn(dev, "Failed to set tracer control %d\n"
				       , err);
			goto free_string_db;
		}


	}

	return;

free_string_db:
	mlx5_tracer_release_strings_db(dev);
free_log_buf:
	mlx5_tracer_release_log_buf(dev);
}

int mlx5_tracer_init(struct mlx5_core_dev *dev)
{
	/* Temporary block for iTrace */
	return 0;
	INIT_WORK(&dev->tracer.log_work, mlx5_tracer_handle_traces);
	INIT_WORK(&dev->tracer.ownership_change_work,
		  mlx5_tracer_ownership_change);

	schedule_work(&dev->tracer.ownership_change_work);
	return 0;
}

void mlx5_tracer_cleanup(struct mlx5_core_dev *dev)
{
	if (!MLX5_CAP_MCAM_REG(dev, tracer_registers)) {
		mlx5_core_dbg(dev, "Tracer capability not present\n");
		return;
	}

	cancel_work_sync(&dev->tracer.ownership_change_work);

	mlx5_tracer_disable(dev);
	cancel_work_sync(&dev->tracer.log_work);

	if (dev->tracer.tracer_owner)
		mlx5_tracer_release_tracer_owner(dev);
	mlx5_tracer_free_resources(dev);
}

void mlx5_tracer_event(struct mlx5_core_dev *dev, struct mlx5_eqe *eqe)
{
	switch (eqe->sub_type) {
	case MLX5_TRACER_SUBTYPE_OWNERSHIP_CHANGE:
		if (test_bit(MLX5_INTERFACE_STATE_UP, &dev->intf_state))
			schedule_work(&dev->tracer.ownership_change_work);
		break;
	case MLX5_TRACER_SUBTYPE_TRACES_AVAILABLE:
		schedule_work(&dev->tracer.log_work);
		break;
	default:
		mlx5_core_dbg(dev, "Device tracer event with unrecognized subtype: sub_type %d\n",
			      eqe->sub_type);
	}
}
