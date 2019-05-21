/*
 * Copyright (c) 2017, Mellanox Technologies. All rights reserved.
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
#ifndef __CAPI_H_
#define __CAPI_H_
#ifdef CONFIG_CXL_LIB
#include<linux/mlx5/device.h>
#include<linux/mlx5/driver.h>
#include<misc/cxllib.h>

int mlx5_core_create_pec(struct mlx5_core_dev *dev,
			 struct cxllib_pe_attributes *attr, u32 *pasid);
int mlx5_core_destroy_pec(struct mlx5_core_dev *dev, u32 pasid);
#endif

static inline bool mlx5_capi_supported(struct mlx5_core_dev *dev)
{
#ifdef CONFIG_CXL_LIB
	return dev->capi.icmd_caps & ((u64)1 << 56);
#else
	return 0;
#endif
}

#endif /* __CAPI_H_ */
