/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2023, Oracle and/or its affiliates.
 */

#ifndef __UEK_H__
#define __UEK_H__

#include <linux/jump_label.h>

#ifndef WITHOUT_ORACLE_EXTENSIONS
DECLARE_STATIC_KEY_FALSE(on_exadata);
extern int exadata_check_allowed(struct task_struct *p,
				 const struct cpumask *new_mask);
#else
static int inline exadata_check_allowed(struct task_struct *p,
					const struct cpumask *new_mask)
{
	return 0;
}
#endif /* !WITHOUT_ORACLE_EXTENSIONS */

#endif /* __UEK_H__ */
