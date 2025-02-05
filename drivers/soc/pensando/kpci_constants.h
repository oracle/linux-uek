/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2021, 2022, Oracle and/or its affiliates.
 */
/*
 * Layout of non-Linux Memory:
 *  (base address provided in device tree and may change)
 *  C5F8 D000  kpcimgr state (kstate_t) [140k]
 *  C5FB 0000  relocated code [kstate + KSTATE_CODE_OFFSET] [284k]
 *       ....  code grows upwards and stack downwards
 *  C5FF 7000  top of stack [kstate + KSTATE_STACK_OFFSET]
 *  C5FF 7000 - C5FF F000 Reserved
 *  C5FF FFE0  fake efi.mem area for LPI
 *  C5FF FFFF  end of HWMEM range
 */
#define COMPAT_SHMEM_KSTATE_OFFSET 0xF00000
#define SHMEM_KSTATE_SIZE_OLD	0x30000
#define SHMEM_KSTATE_SIZE	0x23000
#define KSTATE_CODE_OFFSET	SHMEM_KSTATE_SIZE
#define KSTATE_CODE_SIZE	(284 * 1024)
#define KSTATE_STACK_OFFSET	(KSTATE_CODE_OFFSET + KSTATE_CODE_SIZE)
#define KSTATE_MAGIC            0x1743BA1F

/* size of trace data arrays */
#define DATA_SIZE 100

/* phases */
#define NOMMU 0
#define NORMAL 1
#define NUM_PHASES 2

#define MSI_INDIRECT_IDX	0	/* indirect vector */
#define MSI_NOTIFY_IDX		1	/* notify vector */
#define MSI_NVECTORS		2

