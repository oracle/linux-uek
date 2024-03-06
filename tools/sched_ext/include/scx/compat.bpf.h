/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2024 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2024 Tejun Heo <tj@kernel.org>
 * Copyright (c) 2024 David Vernet <dvernet@meta.com>
 */
#ifndef __SCX_COMPAT_BPF_H
#define __SCX_COMPAT_BPF_H

/* SCX_KICK_IDLE is a later addition, use if available */
static inline void __COMPAT_scx_bpf_kick_cpu_IDLE(s32 cpu)
{
	if (bpf_core_enum_value_exists(enum scx_kick_flags, SCX_KICK_IDLE))
		scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
	else
		scx_bpf_kick_cpu(cpu, 0);
}

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
