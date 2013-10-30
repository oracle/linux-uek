/*
 * Copyright (c) 2011-2012 Xsigo Systems. All rights reserved
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

#include "xve.h"
#include "xve_compat.h"

#if defined(CONFIG_INFINIBAND_XVE_DEBUG)
const struct file_operations;
static struct dentry *xve_root;

static void format_gid(union ib_gid *gid, char *buf)
{
	int i, n;

	for (n = 0, i = 0; i < 8; ++i) {
		n += sprintf(buf + n, "%x",
			     be16_to_cpu(((__be16 *) gid->raw)[i]));
		if (i < 7)
			buf[n++] = ':';
	}
}

static void *xve_mcg_seq_start(struct seq_file *file, loff_t *pos)
{
	struct xve_mcast_iter *iter;
	loff_t n = *pos;

	iter = xve_mcast_iter_init(file->private);
	if (!iter)
		return NULL;

	while (n--) {
		if (xve_mcast_iter_next(iter)) {
			kfree(iter);
			return NULL;
		}
	}

	return iter;
}

static void *xve_mcg_seq_next(struct seq_file *file, void *iter_ptr,
			      loff_t *pos)
{
	struct xve_mcast_iter *iter = iter_ptr;

	(*pos)++;

	if (xve_mcast_iter_next(iter)) {
		kfree(iter);
		return NULL;
	}

	return iter;
}

static void xve_mcg_seq_stop(struct seq_file *file, void *iter_ptr)
{
	/* nothing for now */
}

static int xve_mcg_seq_show(struct seq_file *file, void *iter_ptr)
{
	struct xve_mcast_iter *iter = iter_ptr;
	char gid_buf[sizeof "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"];
	union ib_gid mgid;
	unsigned long created;
	unsigned int queuelen, complete, send_only;

	if (!iter)
		return 0;

	xve_mcast_iter_read(iter, &mgid, &created, &queuelen,
			    &complete, &send_only);

	format_gid(&mgid, gid_buf);

	seq_printf(file,
		   "GID: %s\n"
		   "  created: %10ld\n"
		   "  queuelen: %9d\n"
		   "  complete: %9s\n"
		   "  send_only: %8s\n"
		   "\n",
		   gid_buf, created, queuelen,
		   complete ? "yes" : "no", send_only ? "yes" : "no");

	return 0;
}

static const struct seq_operations xve_mcg_seq_ops = {
	.start = xve_mcg_seq_start,
	.next = xve_mcg_seq_next,
	.stop = xve_mcg_seq_stop,
	.show = xve_mcg_seq_show,
};

static int xve_mcg_open(struct inode *inode, struct file *file)
{
	struct seq_file *seq;
	int ret;

	ret = seq_open(file, &xve_mcg_seq_ops);
	if (ret)
		return ret;

	seq = file->private_data;
	seq->private = inode->i_private;

	return 0;
}

static const struct file_operations xve_mcg_fops = {
	.owner = THIS_MODULE,
	.open = xve_mcg_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = seq_release
};

static void *xve_path_seq_start(struct seq_file *file, loff_t *pos)
{
	struct xve_path_iter *iter;
	loff_t n = *pos;

	iter = xve_path_iter_init(file->private);
	if (!iter)
		return NULL;

	while (n--) {
		if (xve_path_iter_next(iter)) {
			kfree(iter);
			return NULL;
		}
	}

	return iter;
}

static void *xve_path_seq_next(struct seq_file *file, void *iter_ptr,
			       loff_t *pos)
{
	struct xve_path_iter *iter = iter_ptr;

	(*pos)++;

	if (xve_path_iter_next(iter)) {
		kfree(iter);
		return NULL;
	}

	return iter;
}

static void xve_path_seq_stop(struct seq_file *file, void *iter_ptr)
{
	/* nothing for now */
}

static int xve_path_seq_show(struct seq_file *file, void *iter_ptr)
{
	struct xve_path_iter *iter = iter_ptr;
	char gid_buf[sizeof "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"];
	struct xve_path path;
	int rate;

	if (!iter)
		return 0;

	xve_path_iter_read(iter, &path);

	format_gid(&path.pathrec.dgid, gid_buf);

	seq_printf(file,
		   "GID: %s\n"
		   "  complete: %6s\n",
		   gid_buf, path.pathrec.dlid ? "yes" : "no");

	if (path.pathrec.dlid) {
		rate = ib_rate_to_mult(path.pathrec.rate) * 25;

		seq_printf(file,
			   "  DLID:     0x%04x\n"
			   "  SL: %12d\n"
			   "  rate: %*d%s Gb/sec\n",
			   be16_to_cpu(path.pathrec.dlid),
			   path.pathrec.sl,
			   10 - ((rate % 10) ? 2 : 0),
			   rate / 10, rate % 10 ? ".5" : "");
	}

	seq_putc(file, '\n');

	return 0;
}

static const struct seq_operations xve_path_seq_ops = {
	.start = xve_path_seq_start,
	.next = xve_path_seq_next,
	.stop = xve_path_seq_stop,
	.show = xve_path_seq_show,
};

static int xve_path_open(struct inode *inode, struct file *file)
{
	struct seq_file *seq;
	int ret;

	ret = seq_open(file, &xve_path_seq_ops);
	if (ret)
		return ret;

	seq = file->private_data;
	seq->private = inode->i_private;

	return 0;
}

static const struct file_operations xve_path_fops = {
	.owner = THIS_MODULE,
	.open = xve_path_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = seq_release
};

void xve_create_debug_files(struct net_device *dev)
{
	struct xve_dev_priv *priv = netdev_priv(dev);
	char name[IFNAMSIZ + sizeof "_path"];

	snprintf(name, sizeof(name), "%s_mcg", dev->name);
	priv->mcg_dentry = debugfs_create_file(name, S_IFREG | S_IRUGO,
					       xve_root, dev, &xve_mcg_fops);
	if (!priv->mcg_dentry)
		xve_warn(priv, "failed to create mcg debug file\n");

	snprintf(name, sizeof(name), "%s_path", dev->name);
	priv->path_dentry = debugfs_create_file(name, S_IFREG | S_IRUGO,
						xve_root, dev, &xve_path_fops);
	if (!priv->path_dentry)
		xve_warn(priv, "failed to create path debug file\n");
}

void xve_delete_debug_files(struct net_device *dev)
{
	struct xve_dev_priv *priv = netdev_priv(dev);

	if (priv->mcg_dentry != NULL)
		debugfs_remove(priv->mcg_dentry);
	if (priv->path_dentry != NULL)
		debugfs_remove(priv->path_dentry);
}

int xve_register_debugfs(void)
{
	xve_root = debugfs_create_dir("xve", NULL);
	return xve_root ? 0 : -ENOMEM;
}

void xve_unregister_debugfs(void)
{
	debugfs_remove(xve_root);
}
#endif
