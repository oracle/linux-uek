/*
 * Preemptible hypercalls
 *
 * Copyright (C) 2014 Citrix Systems R&D ltd.
 *
 * This source code is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 */

#include <xen/xen-ops.h>
#include <linux/module.h>
#include <xen/xen-ops.h>

#ifndef CONFIG_PREEMPT
DEFINE_PER_CPU(bool, xen_in_preemptible_hcall);
EXPORT_PER_CPU_SYMBOL_GPL(xen_in_preemptible_hcall);
#endif
