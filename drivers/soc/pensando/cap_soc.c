
/*
 * Copyright (c) 2018, Pensando Systems Inc.
 */

#include <linux/spinlock.h>
#include <linux/export.h>

DEFINE_SPINLOCK(apb_bus_spinlock);
EXPORT_SYMBOL_GPL(apb_bus_spinlock);
