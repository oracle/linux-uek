/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2025, Advanced Micro Devices, Inc.
 */

#ifndef _PEN_SECURE_H_
#define _PEN_SECURE_H_

/* Refer Pensando BL31 Function Registry.docx */
#define PEN_SECREG_SMC_CALL_FID       0xC200000B

enum pen_sbus_smc_sub_fid {
    PEN_SECREG_SMC_REG_READ = 0,
    PEN_SECREG_SMC_REG_WRITE = 1,
};

enum pen_sbus_smc_err_codes {
    PEN_SECREG_SMC_ERR_NONE = 0,
    PEN_SECREG_SMC_ERR_INVALID = -1,
    PEN_SECREG_SMC_ERR_UNSUPPORTED = -2,
};

uint32_t pen_secure_regread(void *addr);
void pen_secure_regwrite(void *addr, uint32_t val);
bool pen_secure_mode_enabled(void);

#endif /* _PEN_SECURE_H_ */
