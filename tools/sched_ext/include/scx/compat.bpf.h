/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2024 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2024 Tejun Heo <tj@kernel.org>
 * Copyright (c) 2024 David Vernet <dvernet@meta.com>
 */
#ifndef __SCX_COMPAT_BPF_H
#define __SCX_COMPAT_BPF_H

static inline u64 __COMPAT_SCX_KICK_IDLE(void)
{
	if (bpf_core_enum_value_exists(enum scx_kick_flags, SCX_KICK_IDLE))
		return SCX_KICK_IDLE;
	else
		return 0;
}

/*
 * %SCX_KICK_IDLE is a later addition. To support both before and after, use
 * %__COMPAT_SCX_KICK_IDLE which becomes 0 on kernels which don't support it.
 */
#define __COMPAT_SCX_KICK_IDLE __COMPAT_SCX_KICK_IDLE()

/*
 * scx_switch_all() was replaced by %SCX_OPS_SWITCH_PARTIAL. See
 * %__COMPAT_SCX_OPS_SWITCH_PARTIAL in compat.h.
 */
void scx_bpf_switch_all(void) __ksym __weak;

static inline void __COMPAT_scx_bpf_switch_all(void)
{
	if (!bpf_core_enum_value_exists(enum scx_ops_flags, SCX_OPS_SWITCH_PARTIAL))
		scx_bpf_switch_all();
}

#endif
