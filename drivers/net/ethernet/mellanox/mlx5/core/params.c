/*
 * Copyright (c) 2013-2017, Mellanox Technologies. All rights reserved.
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

#include <linux/module.h>
#include <linux/mlx5/driver.h>
#include <linux/mlx5/vport.h>

static char *guids;
module_param_named(guids, guids, charp, 0444);
MODULE_PARM_DESC(node_guid, "guids configuration. This module parameter will be obsolete!");

/* format: dddd:bb:vv.f-nn:nn:nn:nn:nn:nn:nn:nn:pp:pp:pp:pp:pp:pp:pp:pp:qq:qq:qq:qq:qq:qq:qq:qq,
 *
 * dddd:bb:vv.f are domain, bus, device, function for the device
 * nn:nn:nn:nn:nn:nn:nn:nn is node guid to configure
 * pp:pp:pp:pp:pp:pp:pp:pp is port 1 GUID
 * qq:qq:qq:qq:qq:qq:qq:qq is port 2 GUID. this param is optional
 *
 * The comma indicates another record follows
 */

static u64 extract_guid(int *g)
{
	return	((u64)g[0] << 56)	|
		((u64)g[1] << 48)	|
		((u64)g[2] << 40)	|
		((u64)g[3] << 32)	|
		((u64)g[4] << 24)	|
		((u64)g[5] << 16)	|
		((u64)g[6] << 8)	|
		(u64)g[7];
}

static int is_valid_len(const char *p, int *nport)
{
	int tmp;
	char *x;

	x = strchr(p, ',');
	if (x)
		tmp = (int)(x - p);
	else
		tmp = strlen(p);

	switch (tmp) {
	case 47:
		*nport = 1;
		break;

	case 71:
		*nport = 2;
		break;

	default:
		return 0;
	}

	return 1;
}

static int get_record(const char *p, u64 *node_guid, u64 *port1_guid,
		      u64 *port2_guid, int *nport)
{
	int tmp[8];
	int err;
	const char *guid_format = "%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x";
	int np;

	if (!is_valid_len(p, &np))
		return -EINVAL;

	err = sscanf(p, guid_format, tmp, tmp + 1, tmp + 2, tmp + 3, tmp + 4,
		     tmp + 5, tmp + 6, tmp + 7);
	if (err != 8)
		return -EINVAL;

	*node_guid = extract_guid(tmp);
	p += 23;
	if (*p != ':')
		return -EINVAL;
	p++;

	err = sscanf(p, guid_format, tmp, tmp + 1, tmp + 2, tmp + 3, tmp + 4,
		     tmp + 5, tmp + 6, tmp + 7);
	if (err != 8)
		return -EINVAL;
	*port1_guid = extract_guid(tmp);
	if (np != 2) {
		*nport = np;
		return 0;
	}

	p += 23;
	if (*p != ':')
		return -EINVAL;
	p++;

	err = sscanf(p, guid_format, tmp, tmp + 1, tmp + 2, tmp + 3, tmp + 4,
		     tmp + 5, tmp + 6, tmp + 7);
	if (err != 8)
		return -EINVAL;
	*port2_guid = extract_guid(tmp);
	*nport = np;

	return 0;
}

int mlx5_update_guids(struct mlx5_core_dev *dev)
{
	struct pci_dev *pdev = dev->pdev;
	const char *devp;
	char *p = guids;
	u64 port1_guid = 0;
	u64 port2_guid = 0;
	u64 node_guid;
	int nport;
	int dlen;
	int err;
	struct mlx5_hca_vport_context *req;

	if (!p)
		return 0;

	devp = dev_name(&pdev->dev);
	dlen = strlen(devp);
	while (1) {
		if (dlen >= strlen(p))
			return -ENODEV;

		if (!memcmp(devp, p, dlen)) {
			p += dlen;
			if (*p != '-')
				return -EINVAL;
			p++;
			break;
		}

		p = strchr(p, ',');
		if (!p)
			return -ENODEV;
		p++;
	}

	err = get_record(p, &node_guid, &port1_guid, &port2_guid, &nport);
	if (err)
		return err;

	req = kzalloc(sizeof(*req), GFP_KERNEL);
	if (!req)
		return -ENOMEM;

	req->node_guid = node_guid;
	req->port_guid = port1_guid;
	req->field_select = MLX5_HCA_VPORT_SEL_NODE_GUID | MLX5_HCA_VPORT_SEL_PORT_GUID;
	err = mlx5_core_modify_hca_vport_context(dev, 0, 1, 0, req);
	if (err)
		goto out;

	if (nport == 2) {
		req->port_guid = port2_guid;
		err = mlx5_core_modify_hca_vport_context(dev, 0, 2, 0, req);
	}

out:
	kfree(req);

	return err;
}
