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

#include "diag_cnt.h"
#include <linux/debugfs.h>

static int get_supported_cnt_ids(struct mlx5_core_dev *dev);
static int enable_cnt_id(struct mlx5_core_dev *dev, u16 id);
static void reset_cnt_id(struct mlx5_core_dev *dev);
static void reset_params(struct mlx5_diag_cnt *diag_cnt);

static ssize_t counter_id_write(struct file *filp, const char __user *buf,
				size_t count, loff_t *pos)
{
	struct mlx5_core_dev *dev = filp->private_data;
	struct mlx5_diag_cnt *diag_cnt;
	unsigned int temp;
	char *options;
	char *kbuf;
	char *p;
	int err;
	int i;

	if (*pos)
		return 0;

	diag_cnt = &dev->diag_cnt;
	reset_cnt_id(dev);

	/* Collect cnt_id input. Quit if cnt_id does not exist */
	kbuf = kzalloc(count, GFP_KERNEL);
	if (!kbuf)
		return -ENOMEM;

	if (copy_from_user(kbuf, buf, count))
		return -EFAULT;

	i = 0;
	options = kbuf;
	while ((p = strsep(&options, ",")) != NULL &&
	       i < MLX5_CAP_GEN(dev, num_of_diagnostic_counters)) {
		if (sscanf(p, "%x", &temp) != 1)
			continue;
		err = enable_cnt_id(dev, temp);
		if (err)
			goto out_err;
		i++;
	}

	diag_cnt->num_cnt_id = i;
	*pos = count;

	kfree(kbuf);
	return count;

out_err:
	kfree(kbuf);
	reset_cnt_id(dev);
	return err;
}

static ssize_t counter_id_read(struct file *filp, char __user *buf,
			       size_t count, loff_t *pos)
{
	struct mlx5_core_dev *dev = filp->private_data;
	struct mlx5_diag_cnt *diag_cnt;
	char *kbuf;
	int len = 0;
	int i;

	diag_cnt = &dev->diag_cnt;
	if (*pos || !diag_cnt->num_cnt_id)
		return -EPERM;

	kbuf = kzalloc(5 * diag_cnt->num_cnt_id + 2, GFP_KERNEL);
	if (!kbuf)
		return -ENOMEM;

	for (i = 0; i < MLX5_CAP_GEN(dev, num_of_diagnostic_counters); i++)
		if (diag_cnt->cnt_id[i].enabled)
			len += sprintf(kbuf + len, "%04x,", diag_cnt->cnt_id[i].id);

	if (len) {
		len += sprintf(kbuf + len, "\n");
		len = min_t(int, len, count);
		if (copy_to_user(buf, kbuf, len)) {
			len = 0;
			goto out;
		}
	}

out:
	kfree(kbuf);
	*pos = len;
	return len;
}

static const struct file_operations counter_id_fops = {
	.owner	= THIS_MODULE,
	.open	= simple_open,
	.write	= counter_id_write,
	.read	= counter_id_read,
};

#define NUM_OF_DIAG_PARAMS 5
static ssize_t params_write(struct file *filp, const char __user *buf,
			    size_t count, loff_t *pos)
{
	struct mlx5_core_dev *dev = filp->private_data;
	struct mlx5_diag_cnt *diag_cnt;
	unsigned int temp;
	char *options;
	char *kbuf;
	char *p;
	int err;
	int i;

	diag_cnt = &dev->diag_cnt;
	if (*pos || !diag_cnt->num_cnt_id)
		return -EPERM;

	kbuf = kzalloc(count, GFP_KERNEL);
	if (!kbuf)
		return -ENOMEM;

	if (copy_from_user(kbuf, buf, count))
		return -EFAULT;

	/* Five parameters
	 * log_num_of_samples (dec)
	 * logSamplePeriod (dec)
	 * flags (hex)
	 * num_of_samples (dec)
	 * sample_index (dec)
	 */
	i = 0;
	err = -EINVAL;
	options = kbuf;
	reset_params(diag_cnt);

	while ((p = strsep(&options, ",")) != NULL && i < NUM_OF_DIAG_PARAMS) {
		if (i == 0) {
			if (sscanf(p, "%d", &temp) != 1)
				goto out_err;

			if ((1 << (MLX5_CAP_DEBUG(dev, log_max_samples) - temp)) <
			     diag_cnt->num_cnt_id) {
				mlx5_core_warn(dev, "log_num_of_samples is too big for num_cnt_id=%d\n",
					       diag_cnt->num_cnt_id);
				goto out_err;
			} else {
				diag_cnt->log_num_of_samples = temp;
			}
		}

		if (i == 1) {
			if (sscanf(p, "%d", &temp) != 1)
				goto out_err;

			if (temp < MLX5_CAP_DEBUG(dev, log_min_sample_period)) {
				mlx5_core_warn(dev, "log_sample_period smaller than log_min_sample_period\n");
				goto out_err;
			} else {
				diag_cnt->log_sample_period = temp;
			}
		}

		if (i == 2) {
			if (sscanf(p, "%x", &temp) != 1)
				goto out_err;

			if (temp > 0xFF)
				goto out_err;
			else
				diag_cnt->flag = temp;
		}

		if (i == 3) {
			if (sscanf(p, "%d", &temp) != 1)
				goto out_err;

			if (temp > (1 << diag_cnt->log_num_of_samples)) {
				mlx5_core_warn(dev, "num_of_samples bigger than log_num_of_samples\n");
				goto out_err;
			} else {
				diag_cnt->num_of_samples = temp;
			}
		}

		if (i == 4) {
			if (sscanf(p, "%d", &temp) != 1)
				goto out_err;
			if (temp > (1 << diag_cnt->log_num_of_samples))
				goto out_err;
			else
				diag_cnt->sample_index = temp;
		}

		i++;
	}

	if (i < NUM_OF_DIAG_PARAMS)
		goto out_err;

	*pos = count;
	kfree(kbuf);
	return count;

out_err:
	kfree(kbuf);
	reset_params(diag_cnt);
	return err;
}

#define PARAM_PRINT_SZ 104
static ssize_t params_read(struct file *filp, char __user *buf,
			   size_t count, loff_t *pos)
{
	struct mlx5_core_dev *dev = filp->private_data;
	char kbuf[PARAM_PRINT_SZ] = {0};
	struct mlx5_diag_cnt *diag_cnt;
	int len = 0;

	if (*pos)
		return 0;

	diag_cnt = &dev->diag_cnt;

	len += sprintf(kbuf + len, "log_num_of_samples=%d\n",
		       diag_cnt->log_num_of_samples);
	len += sprintf(kbuf + len, "log_sample_period=%d\n",
		       diag_cnt->log_sample_period);
	len += sprintf(kbuf + len, "flag=0x%02x\n", diag_cnt->flag);
	len += sprintf(kbuf + len, "num_of_samples=%d\n",
		       diag_cnt->num_of_samples);
	len += sprintf(kbuf + len, "sample_index=%d\n",
		       diag_cnt->sample_index);

	if (len) {
		len = min_t(int, len, count);
		if (copy_to_user(buf, kbuf, len)) {
			len = 0;
			goto out;
		}
	}

out:
	*pos = len;
	return len;
}

static const struct file_operations params_fops = {
	.owner	= THIS_MODULE,
	.open	= simple_open,
	.write	= params_write,
	.read	= params_read,
};

#define DUMP_WRITE_BUF_LEN 4
static ssize_t dump_write(struct file *filp, const char __user *buf,
			  size_t count, loff_t *pos)
{
	struct mlx5_core_dev *dev = filp->private_data;
	char kbuf[DUMP_WRITE_BUF_LEN] = {0};
	int err;

	if (*pos || count > DUMP_WRITE_BUF_LEN)
		return -EINVAL;

	if (copy_from_user(kbuf, buf, count))
		return -EFAULT;

	if (strncmp(kbuf, "set", DUMP_WRITE_BUF_LEN - 1))
		return -EINVAL;

	err = mlx5_diag_set_params(dev);
	if (err)
		return err;

	return count;
}

#define SAMPLE_PRINT_SZ 36
static int decode_cnt_buffer(u16 num_of_samples, u8 *out, size_t count, char **out_str)
{
	u16 num_samples;
	char *kbuf;
	void *cnt;
	u64 temp;
	int len;
	int i;

	len = num_of_samples * SAMPLE_PRINT_SZ;
	len = min_t(int, len, count);

	kbuf = kzalloc(len, GFP_KERNEL);
	if (!kbuf)
		return -ENOMEM;

	num_samples = len / SAMPLE_PRINT_SZ;
	len = 0;
	for (i = 0; i < num_samples; i++) {
		cnt = MLX5_ADDR_OF(query_diagnostic_cntrs_out,
				   out, diag_counter[i]);
		temp = MLX5_GET(diagnostic_cntr_struct, cnt, counter_value_h);
		temp = (temp << 32) |
		       MLX5_GET(diagnostic_cntr_struct, cnt, counter_value_l);

		len += sprintf(kbuf + len,
			       "%04x,%04x,%08x,%016llx\n",
			       MLX5_GET(diagnostic_cntr_struct, cnt, counter_id),
			       MLX5_GET(diagnostic_cntr_struct, cnt, sample_id),
			       MLX5_GET(diagnostic_cntr_struct, cnt, time_stamp_31_0),
			       temp);
	}

	*out_str = kbuf;
	return 0;
}

static ssize_t dump_read(struct file *filp, char __user *buf,
			 size_t count, loff_t *pos)
{
	struct mlx5_core_dev *dev = filp->private_data;
	char *out_str;
	u8 *out;
	int err;
	int len;

	if (*pos || !dev->diag_cnt.num_of_samples)
		return -EPERM;

	err = mlx5_diag_query_counters(dev, &out);
	if (err)
		return 0;

	err = decode_cnt_buffer(dev->diag_cnt.num_of_samples *
				dev->diag_cnt.num_cnt_id,
				out, count, &out_str);
	if (err) {
		kfree(out);
		return 0;
	}

	len = min_t(int, strlen(out_str), count);
	if (copy_to_user(buf, out_str, len))
		len = 0;

	kfree(out_str);
	kfree(out);
	*pos = len;
	return len;
}

static const struct file_operations dump_fops = {
	.owner	= THIS_MODULE,
	.open	= simple_open,
	.write	= dump_write,
	.read	= dump_read,
};

#define CAPABILITY_PRINT_SZ 130
#define COUNTER_ID_PRINT_SZ 5
static ssize_t cap_read(struct file *filp, char __user *buf,
			size_t count, loff_t *pos)
{
	struct mlx5_core_dev *dev = filp->private_data;
	struct mlx5_diag_cnt *diag_cnt;
	int len = 0;
	char *kbuf;
	int i;

	if (*pos)
		return 0;

	kbuf = kzalloc(CAPABILITY_PRINT_SZ +
		       MLX5_CAP_GEN(dev, num_of_diagnostic_counters) *
		       COUNTER_ID_PRINT_SZ,
		       GFP_KERNEL);
	if (!kbuf)
		return 0;

	diag_cnt = &dev->diag_cnt;

	/* print cap */
	len += sprintf(kbuf + len, "log_max_samples=%d\n",
		       MLX5_CAP_DEBUG(dev, log_max_samples));
	len += sprintf(kbuf + len, "log_min_sample_period=%d\n",
		       MLX5_CAP_DEBUG(dev, log_min_sample_period));
	len += sprintf(kbuf + len, "repetitive=%d\n",
		       MLX5_CAP_DEBUG(dev, repetitive));
	len += sprintf(kbuf + len, "single=%d\n",
		       MLX5_CAP_DEBUG(dev, single));
	len += sprintf(kbuf + len, "num_of_diagnostic_counters=%d\n",
		       MLX5_CAP_GEN(dev, num_of_diagnostic_counters));

	/* print list of supported counter */
	len += sprintf(kbuf + len, "supported counter id:\n");
	for (i = 0; i < MLX5_CAP_GEN(dev, num_of_diagnostic_counters); i++)
		len += sprintf(kbuf + len, "%04x,", diag_cnt->cnt_id[i].id);
	len += sprintf(kbuf + len, "\n");

	len = min_t(int, len, count);
	if (copy_to_user(buf, kbuf, len)) {
		len = 0;
		goto out;
	}

out:
	kfree(kbuf);
	*pos = len;
	return len;
}

static const struct file_operations cap_fops = {
	.owner	= THIS_MODULE,
	.open	= simple_open,
	.read	= cap_read,
};

static int diag_cnt_debugfs_init(struct mlx5_core_dev *dev)
{
	struct mlx5_diag_cnt *diag_cnt = &dev->diag_cnt;
	struct dentry *entry = NULL;

	diag_cnt->debugfs = debugfs_create_dir("diag_cnt", dev->priv.dbg_root);

	if (!diag_cnt->debugfs)
		return -ENOMEM;

	entry = debugfs_create_file("counter_id", 0400, diag_cnt->debugfs,
				    dev, &counter_id_fops);
	if (!entry)
		goto out_err;

	entry = debugfs_create_file("params", 0400, diag_cnt->debugfs,
				    dev, &params_fops);
	if (!entry)
		goto out_err;

	entry = debugfs_create_file("dump", 0400, diag_cnt->debugfs,
				    dev, &dump_fops);
	if (!entry)
		goto out_err;

	entry = debugfs_create_file("cap", 0400, diag_cnt->debugfs,
				    dev, &cap_fops);
	if (!entry)
		goto out_err;

	return 0;

out_err:
	mlx5_diag_cnt_cleanup(dev);
	return -ENOMEM;
}

static int get_supported_cnt_ids(struct mlx5_core_dev *dev)
{
	int num_counters = MLX5_CAP_GEN(dev, num_of_diagnostic_counters);
	struct mlx5_diag_cnt *diag_cnt = &dev->diag_cnt;
	int i;

	diag_cnt->cnt_id = kzalloc(sizeof(*diag_cnt->cnt_id) * num_counters,
				   GFP_KERNEL);
	if (!diag_cnt->cnt_id)
		return -ENOMEM;

	for (i = 0; i < num_counters; i++)
		diag_cnt->cnt_id[i].id =
			MLX5_CAP_DEBUG(dev, diagnostic_counter[i]) & 0xFFFF;

	return 0;
}

static void reset_cnt_id(struct mlx5_core_dev *dev)
{
	struct mlx5_diag_cnt *diag_cnt = &dev->diag_cnt;
	int i;

	diag_cnt->num_cnt_id = 0;
	for (i = 0; i < MLX5_CAP_GEN(dev, num_of_diagnostic_counters); i++)
		diag_cnt->cnt_id[i].enabled = false;
}

static int enable_cnt_id(struct mlx5_core_dev *dev, u16 id)
{
	struct mlx5_diag_cnt *diag_cnt = &dev->diag_cnt;
	int i;

	for (i = 0; i < MLX5_CAP_GEN(dev, num_of_diagnostic_counters); i++)
		if (diag_cnt->cnt_id[i].id == id) {
			if (diag_cnt->cnt_id[i].enabled)
				return -EINVAL;

			diag_cnt->cnt_id[i].enabled = true;
			break;
		}

	if (i == MLX5_CAP_GEN(dev, num_of_diagnostic_counters))
		return -ENOENT;
	else
		return 0;
}

static void reset_params(struct mlx5_diag_cnt *diag_cnt)
{
	diag_cnt->log_num_of_samples = 0;
	diag_cnt->log_sample_period = 0;
	diag_cnt->flag = 0;
	diag_cnt->num_of_samples = 0;
	diag_cnt->sample_index = 0;
}

int mlx5_diag_set_params(struct mlx5_core_dev *dev)
{
	u8 out[MLX5_ST_SZ_BYTES(set_diagnostic_params_out)] = {0};
	struct mlx5_diag_cnt *diag_cnt = &dev->diag_cnt;
	void *cnt_id;
	void *ctx;
	u16 in_sz;
	int err;
	u8 *in;
	int i;
	int j;

	if (!diag_cnt->num_cnt_id)
		return -EINVAL;

	in_sz = MLX5_ST_SZ_BYTES(set_diagnostic_params_in) +
		diag_cnt->num_cnt_id * MLX5_ST_SZ_BYTES(counter_id);
	in = kzalloc(in_sz, GFP_KERNEL);
	if (!in)
		return -ENOMEM;

	MLX5_SET(set_diagnostic_params_in, in, opcode,
		 MLX5_CMD_OP_SET_DIAGNOSTIC_PARAMS);

	ctx = MLX5_ADDR_OF(set_diagnostic_params_in, in,
			   diagnostic_params_context);
	MLX5_SET(diagnostic_params_context, ctx, num_of_counters,
		 diag_cnt->num_cnt_id);
	MLX5_SET(diagnostic_params_context, ctx, log_num_of_samples,
		 diag_cnt->log_num_of_samples);

	MLX5_SET(diagnostic_params_context, ctx, single,
		 (diag_cnt->flag >> 7) & 1);
	MLX5_SET(diagnostic_params_context, ctx, repetitive,
		 (diag_cnt->flag >> 6) & 1);
	MLX5_SET(diagnostic_params_context, ctx, sync,
		 (diag_cnt->flag >> 5) & 1);
	MLX5_SET(diagnostic_params_context, ctx, clear,
		 (diag_cnt->flag >> 4) & 1);
	MLX5_SET(diagnostic_params_context, ctx, on_demand,
		 (diag_cnt->flag >> 3) & 1);
	MLX5_SET(diagnostic_params_context, ctx, enable,
		 (diag_cnt->flag >> 2) & 1);
	MLX5_SET(diagnostic_params_context, ctx, log_sample_period,
		 diag_cnt->log_sample_period);

	j = 0;
	for (i = 0; i < MLX5_CAP_GEN(dev, num_of_diagnostic_counters); i++) {
		if (diag_cnt->cnt_id[i].enabled) {
			cnt_id = MLX5_ADDR_OF(diagnostic_params_context,
					      ctx, counter_id[j]);
			MLX5_SET(counter_id, cnt_id, counter_id,
				 diag_cnt->cnt_id[i].id);
			j++;
		}
	}

	err = mlx5_cmd_exec(dev, in, in_sz, out, sizeof(out));

	kfree(in);
	return err;
}

/* This function is for debug purpose */
int mlx5_diag_query_params(struct mlx5_core_dev *dev)
{
	u8 in[MLX5_ST_SZ_BYTES(query_diagnostic_params_in)] = {0};
	struct mlx5_diag_cnt *diag_cnt = &dev->diag_cnt;
	void *cnt_id;
	u16 out_sz;
	void *ctx;
	int err;
	u8 *out;
	int i;

	out_sz = MLX5_ST_SZ_BYTES(query_diagnostic_params_out) +
		 diag_cnt->num_cnt_id * MLX5_ST_SZ_BYTES(counter_id);

	out = kzalloc(out_sz, GFP_KERNEL);
	if (!out)
		return -ENOMEM;

	MLX5_SET(query_diagnostic_params_in, in, opcode,
		 MLX5_CMD_OP_QUERY_DIAGNOSTIC_PARAMS);
	err = mlx5_cmd_exec(dev, in, sizeof(in), out, out_sz);
	if (err)
		goto out;

	ctx = MLX5_ADDR_OF(query_diagnostic_params_out, out,
			   diagnostic_params_context);
	mlx5_core_dbg(dev, "single=%x\n",
		      MLX5_GET(diagnostic_params_context, ctx, single));
	mlx5_core_dbg(dev, "repetitive=%x\n",
		      MLX5_GET(diagnostic_params_context, ctx, repetitive));
	mlx5_core_dbg(dev, "sync=%x\n",
		      MLX5_GET(diagnostic_params_context, ctx, sync));
	mlx5_core_dbg(dev, "clear=%x\n",
		      MLX5_GET(diagnostic_params_context, ctx, clear));
	mlx5_core_dbg(dev, "on_demand=%x\n",
		      MLX5_GET(diagnostic_params_context, ctx, on_demand));
	mlx5_core_dbg(dev, "enable=%x\n",
		      MLX5_GET(diagnostic_params_context, ctx, enable));
	mlx5_core_dbg(dev, "log_sample_period=%x\n",
		      MLX5_GET(diagnostic_params_context, ctx,
			       log_sample_period));

	for (i = 0; i < diag_cnt->num_cnt_id; i++) {
		cnt_id = MLX5_ADDR_OF(diagnostic_params_context,
				      ctx, counter_id[i]);
		mlx5_core_dbg(dev, "counter_id[%d]=%x\n", i,
			      MLX5_GET(counter_id, cnt_id, counter_id));
	}
out:
	kfree(out);
	return err;
}

int mlx5_diag_query_counters(struct mlx5_core_dev *dev, u8 **out_buffer)
{
	u8 in[MLX5_ST_SZ_BYTES(query_diagnostic_cntrs_in)] = {0};
	struct mlx5_diag_cnt *diag_cnt = &dev->diag_cnt;
	u16  out_sz;
	u8 *out;
	int err;

	out_sz = MLX5_ST_SZ_BYTES(query_diagnostic_cntrs_out) +
		 diag_cnt->num_of_samples * diag_cnt->num_cnt_id *
		 MLX5_ST_SZ_BYTES(diagnostic_cntr_struct);

	out = kzalloc(out_sz, GFP_KERNEL);
	if (!out)
		return -ENOMEM;

	MLX5_SET(query_diagnostic_cntrs_in, in, opcode,
		 MLX5_CMD_OP_QUERY_DIAGNOSTIC_COUNTERS);
	MLX5_SET(query_diagnostic_cntrs_in, in, num_of_samples,
		 diag_cnt->num_of_samples);
	MLX5_SET(query_diagnostic_cntrs_in, in, sample_index,
		 diag_cnt->sample_index);

	err = mlx5_cmd_exec(dev, in, sizeof(in), out, out_sz);

	if (!err)
		*out_buffer = out;
	else
		kfree(out);

	return err;
}

void mlx5_diag_cnt_init(struct mlx5_core_dev *dev)
{
	int err;

	if (!MLX5_DIAG_CNT_SUPPORTED(dev))
		return;

	/* Build private data */
	err = get_supported_cnt_ids(dev);
	if (err)
		return;

	/* Create debugfs */
	if (!dev->priv.dbg_root)
		return;

	err = diag_cnt_debugfs_init(dev);
	if (err)
		return;
}

void mlx5_diag_cnt_cleanup(struct mlx5_core_dev *dev)
{
	struct mlx5_diag_cnt *diag_cnt = &dev->diag_cnt;

	if (!MLX5_DIAG_CNT_SUPPORTED(dev))
		return;

	if (diag_cnt->debugfs) {
		debugfs_remove_recursive(diag_cnt->debugfs);
		diag_cnt->debugfs = NULL;
	}

	kfree(diag_cnt->cnt_id);
	reset_params(diag_cnt);
}
