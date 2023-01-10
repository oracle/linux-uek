/*
 * Copyright (c) 2006, 2023 Oracle and/or its affiliates.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *	Redistribution and use in source and binary forms, with or
 *	without modification, are permitted provided that the following
 *	conditions are met:
 *
 *	 - Redistributions of source code must retain the above
 *	   copyright notice, this list of conditions and the following
 *	   disclaimer.
 *
 *	 - Redistributions in binary form must reproduce the above
 *	   copyright notice, this list of conditions and the following
 *	   disclaimer in the documentation and/or other materials
 *	   provided with the distribution.
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

#ifndef __ORACLE_EXT_H__
#define __ORACLE_EXT_H__

#include <linux/types.h>
#include <linux/kernel.h>

#ifndef WITHOUT_ORACLE_EXTENSIONS

extern unsigned int mlx5_core_verify_eqe_flag;
void verify_eqe(struct mlx5_eq *eq, struct mlx5_eqe *eqe);

#endif /* !WITHOUT_ORACLE_EXTENSIONS */

#endif /* __ORACLE_EXT_H__ */
