/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2024 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2024 Tejun Heo <tj@kernel.org>
 * Copyright (c) 2024 David Vernet <dvernet@meta.com>
 */
#ifndef __SCX_COMPAT_H
#define __SCX_COMPAT_H

#include <bpf/btf.h>
#include <errno.h>

struct btf *__COMPAT_vmlinux_btf __attribute__((weak));

static inline void __COMPAT_load_vmlinux_btf(void)
{
	if (!__COMPAT_vmlinux_btf) {
		__COMPAT_vmlinux_btf = btf__load_vmlinux_btf();
		SCX_BUG_ON(!__COMPAT_vmlinux_btf, "btf__load_vmlinux_btf() (%s)",
			   strerror(errno));
	}
}

static inline bool __COMPAT_read_enum(const char *type, const char *name, u64 *v)
{
	const struct btf_type *t;
	const char *n;
	s32 tid;
	int i;

	__COMPAT_load_vmlinux_btf();

	tid = btf__find_by_name_kind(__COMPAT_vmlinux_btf, type, BTF_KIND_ENUM);
	if (tid < 0)
		return false;

	t = btf__type_by_id(__COMPAT_vmlinux_btf, tid);
	SCX_BUG_ON(!t, "btf__type_by_id(%d) (%s)", tid, strerror(errno));

	if (btf_is_enum(t)) {
		struct btf_enum *e = btf_enum(t);

		for (i = 0; i < BTF_INFO_VLEN(t->info); i++) {
			n = btf__name_by_offset(__COMPAT_vmlinux_btf, e[i].name_off);
			SCX_BUG_ON(!n, "btf__name_by_offset() (%s)", strerror(errno));
			if (!strcmp(n, name)) {
				*v = e[i].val;
				return true;
			}
		}
	} else if (btf_is_enum64(t)) {
		struct btf_enum64 *e = btf_enum64(t);

		for (i = 0; i < BTF_INFO_VLEN(t->info); i++) {
			n = btf__name_by_offset(__COMPAT_vmlinux_btf, e[i].name_off);
			SCX_BUG_ON(!n, "btf__name_by_offset() (%s)", strerror(errno));
			if (!strcmp(n, name)) {
				*v = btf_enum64_value(&e[i]);
				return true;
			}
		}
	}

	return false;
}

static inline u64 __COMPAT_SCX_OPS_SWITCH_PARTIAL(void)
{
	u64 v = 0;

	__COMPAT_read_enum("scx_ops_flags", "SCX_OPS_SWITCH_PARTIAL", &v);
	return v;
}

/*
 * An ops flag, %SCX_OPS_SWITCH_PARTIAL, replaced scx_bpf_switch_all() which had
 * to be called from ops.init(). To support both before and after, use both
 * %__COMPAT_SCX_OPS_SWITCH_PARTIAL and %__COMPAT_scx_bpf_switch_all() defined
 * in compat.bpf.h.
 */
#define __COMPAT_SCX_OPS_SWITCH_PARTIAL __COMPAT_SCX_OPS_SWITCH_PARTIAL()

#endif
