// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2025, Oracle and/or its affiliates.
 */

#include <linux/elfnote.h>

/* RDS_FEATURE
 *
 * Adds an ELFNOTE (type = 0) for the named feature with date as version.
 *
 * The date ought to be ISO8601-style (e.g. "2025-05-01") for user-space
 * to be able to use a string ">=" in order to determine if a declared
 * feature is compatible with the application.
 *
 * Even though about 50000 feature can be declared before things blow up,
 * *ONLY* declare a feature if it is known that a user-space application
 * *actually* ends up checking it.
 *
 * Otherwise there's too much bloat and clutter in the
 * /sys/module/rds/notes directory, which slows things down.
 */

#define RDS_FEATURE(feature, date) ELFNOTE64("rds.feature-" #feature, 0, date)

RDS_FEATURE(cmsg_tos, "2025-05-01");
