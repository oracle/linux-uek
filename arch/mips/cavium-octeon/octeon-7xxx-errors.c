/***********************license start***************
 * Copyright (c) 2003-2017  Cavium Inc. (support@cavium.com). All rights
 * reserved.
 *
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *   * Redistributions in binary form must reproduce the above
 *     copyright notice, this list of conditions and the following
 *     disclaimer in the documentation and/or other materials provided
 *     with the distribution.

 *   * Neither the name of Cavium Inc. nor the names of
 *     its contributors may be used to endorse or promote products
 *     derived from this software without specific prior written
 *     permission.

 * This Software, including technical data, may be subject to U.S. export  control
 * laws, including the U.S. Export Administration Act and its  associated
 * regulations, and may be subject to export or import  regulations in other
 * countries.

 * TO THE MAXIMUM EXTENT PERMITTED BY LAW, THE SOFTWARE IS PROVIDED "AS IS"
 * AND WITH ALL FAULTS AND CAVIUM INC. MAKES NO PROMISES, REPRESENTATIONS OR
 * WARRANTIES, EITHER EXPRESS, IMPLIED, STATUTORY, OR OTHERWISE, WITH RESPECT TO
 * THE SOFTWARE, INCLUDING ITS CONDITION, ITS CONFORMITY TO ANY REPRESENTATION OR
 * DESCRIPTION, OR THE EXISTENCE OF ANY LATENT OR PATENT DEFECTS, AND CAVIUM
 * SPECIFICALLY DISCLAIMS ALL IMPLIED (IF ANY) WARRANTIES OF TITLE,
 * MERCHANTABILITY, NONINFRINGEMENT, FITNESS FOR A PARTICULAR PURPOSE, LACK OF
 * VIRUSES, ACCURACY OR COMPLETENESS, QUIET ENJOYMENT, QUIET POSSESSION OR
 * CORRESPONDENCE TO DESCRIPTION. THE ENTIRE  RISK ARISING OUT OF USE OR
 * PERFORMANCE OF THE SOFTWARE LIES WITH YOU.
 ***********************license end**************************************/


/**
 * @file
 *
 * Automatically generated error messages for 7xxx.
 *
 * This file is auto generated. Do not edit.
 */

#ifdef CVMX_BUILD_FOR_LINUX_KERNEL
#include <linux/module.h>
#include <asm/octeon/octeon.h>
#include <asm/octeon/cvmx.h>
#else
#include "cvmx.h"
#include "cvmx-error.h"
#include "cvmx-error-arrays-cn78xx.h"
#endif

struct cvmx_error_array octeon_error_arrays[] = {
   {(struct cvmx_error_78xx *)&error_array_cn78xx, 0xff00, 0x9500},
   {(struct cvmx_error_78xx *)&error_array_cn78xxp2, 0xfff8, 0x9508},
   {(struct cvmx_error_78xx *)&error_array_cn73xx, 0xff00, 0x9700},
   {(struct cvmx_error_78xx *)&error_array_cnf75xx, 0xff00, 0x9800},
   {0, 0, 0}};

unsigned int cvmx_error_78xx_array_sizes [] = {
	2682,
	2682,
	1534,
	949};
