/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2024 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2024 Tejun Heo <tj@kernel.org>
 * Copyright (c) 2024 David Vernet <dvernet@meta.com>
 */
#ifndef __SCX_COMPAT_H
#define __SCX_COMPAT_H

#include <bpf/btf.h>

struct btf *__COMPAT_vmlinux_btf __attribute__((weak));

static inline void __COMPAT_load_vmlinux_btf(void)
{
	if (!__COMPAT_vmlinux_btf) {
		__COMPAT_vmlinux_btf = btf__load_vmlinux_btf();
		SCX_BUG_ON(!__COMPAT_vmlinux_btf, "btf__load_vmlinux_btf()");
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
	SCX_BUG_ON(!t, "btf__type_by_id(%d)", tid);

	if (btf_is_enum(t)) {
		struct btf_enum *e = btf_enum(t);

		for (i = 0; i < BTF_INFO_VLEN(t->info); i++) {
			n = btf__name_by_offset(__COMPAT_vmlinux_btf, e[i].name_off);
			SCX_BUG_ON(!n, "btf__name_by_offset()");
			if (!strcmp(n, name)) {
				*v = e[i].val;
				return true;
			}
		}
	} else if (btf_is_enum64(t)) {
		struct btf_enum64 *e = btf_enum64(t);

		for (i = 0; i < BTF_INFO_VLEN(t->info); i++) {
			n = btf__name_by_offset(__COMPAT_vmlinux_btf, e[i].name_off);
			SCX_BUG_ON(!n, "btf__name_by_offset()");
			if (!strcmp(n, name)) {
				*v = btf_enum64_value(&e[i]);
				return true;
			}
		}
	}

	return false;
}

#define __COMPAT_ENUM_OR_ZERO(__type, __ent)					\
({										\
	u64 __val = 0;								\
	__COMPAT_read_enum(__type, __ent, &__val);				\
	__val;									\
})

static inline bool __COMPAT_struct_has_field(const char *type, const char *field)
{
	const struct btf_type *t;
	const struct btf_member *m;
	const char *n;
	s32 tid;
	int i;

	__COMPAT_load_vmlinux_btf();
	tid = btf__find_by_name_kind(__COMPAT_vmlinux_btf, type, BTF_KIND_STRUCT);
	if (tid < 0)
		return false;

	t = btf__type_by_id(__COMPAT_vmlinux_btf, tid);
	SCX_BUG_ON(!t, "btf__type_by_id(%d)", tid);

	m = btf_members(t);

	for (i = 0; i < BTF_INFO_VLEN(t->info); i++) {
		n = btf__name_by_offset(__COMPAT_vmlinux_btf, m[i].name_off);
		SCX_BUG_ON(!n, "btf__name_by_offset()");
			if (!strcmp(n, field))
				return true;
	}

	return false;
}

/*
 * An ops flag, %SCX_OPS_SWITCH_PARTIAL, replaced scx_bpf_switch_all() which had
 * to be called from ops.init(). To support both before and after, use both
 * %__COMPAT_SCX_OPS_SWITCH_PARTIAL and %__COMPAT_scx_bpf_switch_all() defined
 * in compat.bpf.h.
 */
#define __COMPAT_SCX_OPS_SWITCH_PARTIAL						\
	__COMPAT_ENUM_OR_ZERO("scx_ops_flags", "SCX_OPS_SWITCH_PARTIAL")

#define __COMPAT_KERNEL_HAS_OPS_EXIT_DUMP_LEN					\
	__COMPAT_struct_has_field("sched_ext_ops", "exit_dump_len")

#endif	/* __SCX_COMPAT_H */
