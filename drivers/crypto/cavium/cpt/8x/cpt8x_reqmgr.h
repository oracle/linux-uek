// SPDX-License-Identifier: GPL-2.0
/* Marvell OcteonTx2 RVU Admin Function driver
 *
 * Copyright (C) 2018 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef __CPT8X_REQUEST_MANAGER_H
#define __CPT8X_REQUEST_MANAGER_H

#include "cpt_common.h"

void vq_post_process(struct cpt_vf *cptvf, u32 qno);

#endif /* __CPT8X_REQUEST_MANAGER_H */
