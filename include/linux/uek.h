/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023, Oracle and/or its affiliates.
 */

#ifndef __UEK_H__
#define __UEK_H__

#include <linux/jump_label.h>

#ifndef WITHOUT_ORACLE_EXTENSIONS
DECLARE_STATIC_KEY_FALSE(on_exadata);
DECLARE_STATIC_KEY_FALSE(cls_enabled);
extern bool uek_runs_in_kvm(void);
#endif /* !WITHOUT_ORACLE_EXTENSIONS */

#endif /* __UEK_H__ */
