/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (C) 1995, 96, 97, 98, 99, 2000 by Ralf Baechle
 * Copyright (C) 1999, 2000 Silicon Graphics, Inc.
 *
 */
#ifndef _UAPI_ASM_UNISTD_H
#define _UAPI_ASM_UNISTD_H

#include <asm/sgidefs.h>

#if (defined(__WANT_SYSCALL_NUMBERS) &&                                        \
	(__WANT_SYSCALL_NUMBERS == _MIPS_SIM_ABI32)) ||                 \
	(!defined(__WANT_SYSCALL_NUMBERS) && _MIPS_SIM == _MIPS_SIM_ABI32)


#define __NR_Linux	4000
#include <asm/unistd_o32.h>

#endif /* Want O32 ||_MIPS_SIM == _MIPS_SIM_ABI32 */

#if (defined(__WANT_SYSCALL_NUMBERS) &&                                        \
	(__WANT_SYSCALL_NUMBERS == _MIPS_SIM_ABI64)) ||                 \
	(!defined(__WANT_SYSCALL_NUMBERS) && _MIPS_SIM == _MIPS_SIM_ABI64)

#define __NR_Linux	5000
#include <asm/unistd_n64.h>

#endif /* Want N64 || _MIPS_SIM == _MIPS_SIM_ABI64  */

#if (defined(__WANT_SYSCALL_NUMBERS) &&                                        \
	(__WANT_SYSCALL_NUMBERS == _MIPS_SIM_NABI32)) ||                \
	(!defined(__WANT_SYSCALL_NUMBERS) && _MIPS_SIM == _MIPS_SIM_NABI32)

#define __NR_Linux	6000
#include <asm/unistd_n32.h>

#endif /* Want N32 || _MIPS_SIM == _MIPS_SIM_NABI32  */

#endif /* _UAPI_ASM_UNISTD_H */
