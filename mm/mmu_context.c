/* Copyright (C) 2009 Red Hat, Inc.
 *
 * See ../COPYING for licensing terms.
 */

#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/sched/task.h>
#include <linux/mmu_context.h>
#include <linux/export.h>
#include <linux/kthread.h>

#include <asm/mmu_context.h>

/*
 * NOTE: This is a wrapper to the new interface kthread_use_mm()
 * to maintain UEK-KABI compatibility.
 */
void use_mm(struct mm_struct *mm)
{
	kthread_use_mm(mm);
}
EXPORT_SYMBOL_GPL(use_mm);

/*
 * NOTE: This is a wrapper to the new interface kthread_unuse_mm()
 * to maintain UEK-KABI compatibility.
 */
void unuse_mm(struct mm_struct *mm)
{
	kthread_unuse_mm(mm);
}
EXPORT_SYMBOL_GPL(unuse_mm);
