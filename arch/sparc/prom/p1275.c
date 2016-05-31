/*
 * p1275.c: Sun IEEE 1275 PROM low level interface routines
 *
 * Copyright (C) 1996,1997 Jakub Jelinek (jj@sunsite.mff.cuni.cz)
 */

#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/smp.h>
#include <linux/string.h>
#include <linux/spinlock.h>
#include <linux/irqflags.h>
#include <linux/kexec.h>

#include <asm/openprom.h>
#include <asm/oplib.h>
#include <asm/spitfire.h>
#include <asm/pstate.h>
#include <asm/ldc.h>

struct {
	long prom_callback;			/* 0x00 */
	void (*prom_cif_handler)(long *);	/* 0x08 */
	unsigned long prom_cif_stack;		/* 0x10 */
} p1275buf;

extern void prom_world(int);

extern void prom_cif_direct(unsigned long *args);
extern void prom_cif_callback(void);

/*
 * This provides SMP safety on the p1275buf.
 */
DEFINE_RAW_SPINLOCK(prom_entry_lock);

void p1275_cmd_direct(unsigned long *args)
{
	unsigned long flags;

	local_save_flags(flags);
	local_irq_restore((unsigned long)PIL_NMI);
	raw_spin_lock(&prom_entry_lock);

	prom_world(1);
	prom_cif_direct(args);
	prom_world(0);

	raw_spin_unlock(&prom_entry_lock);
	local_irq_restore(flags);
}

void prom_cif_init(void *cif_handler, void *cif_stack)
{
	p1275buf.prom_cif_handler = (void (*)(long *))cif_handler;
	p1275buf.prom_cif_stack = (unsigned long)cif_stack;
}

#ifdef CONFIG_KEXEC
static int __init kexec_grab_obp_cif_stack(void)
{
	struct sparc64_kexec_shim *shimp = kexec_shim();

	shimp->obp_cif = (unsigned long) p1275buf.prom_cif_handler;
	shimp->obp_sp = (unsigned long) p1275buf.prom_cif_stack;
	return 0;
}
device_initcall(kexec_grab_obp_cif_stack);
#endif /* CONFIG_KEXEC */
