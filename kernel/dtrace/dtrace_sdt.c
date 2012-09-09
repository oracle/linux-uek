/* Copyright (C) 2010, 2011 Oracle Corporation */

/* register static dtrace probe points */

#include <linux/kernel.h>
#include <linux/memory.h>
#include <linux/module.h>
#include <linux/dtrace_os.h>
#include <linux/sdt.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <asm-generic/bitsperlong.h>
#include <asm-generic/sections.h>
#include <asm/alternative.h>
#include <asm/nmi.h>
#include <asm/nops.h>

#define	SDT_TRAP_INSTR	0xf0
#define	SDT_NOP_SIZE	5

const char		*sdt_prefix = "__dtrace_probe_";

/* This code is based on apply_alternatives and text_poke_early.  It needs to
 * run before SMP is initialized in order to avoid SMP problems with patching
 * code that might be accessed on another CPU.
 */
static void __init_or_module text_poke_batch(struct text_poke_param *reqs,
					     int cnt)
{
	int			i;
	unsigned long		flags;
	struct text_poke_param	*tpp;

	stop_nmi();
	local_irq_save(flags);

	for (i = 0; i < cnt; i++) {
		tpp = &reqs[i];
		memcpy(tpp->addr, tpp->opcode, tpp->len);
	}

	sync_core();
	local_irq_restore(flags);
	restart_nmi();
}

static int sdt_probe_add(struct module *mp, char *name, char *func,
			 uintptr_t addr, struct text_poke_param *tpp,
			 void *nops)
{
	sdt_probedesc_t *sdp;
	uint8_t *instr;

	if ((sdp = kmalloc(sizeof(sdt_probedesc_t), GFP_KERNEL)) == NULL)
		return 1;

	if ((sdp->sdpd_name = kstrdup(name, GFP_KERNEL)) == NULL) {
		kfree(sdp);
		return 1;
	}

	if ((sdp->sdpd_func = kstrdup(func, GFP_KERNEL)) == NULL) {
		kfree(sdp->sdpd_name);
		kfree(sdp);
		return 1;
	}

	/* adjust relocation address to beginning of call instruction */
	instr = (uint8_t *)(addr - 1);

	/* TBD: use a kernel list? */
	sdp->sdpd_offset = (uintptr_t)instr;
	sdp->sdpd_next = mp->sdt_probes;
	mp->sdt_probes = sdp;

	tpp->addr = instr;
	tpp->opcode = nops;
	tpp->len = SDT_NOP_SIZE;

	return 0;
}

void dtrace_sdt_register(struct module *mod)
{
	int			i, cnt;
	dtrace_sdt_probeinfo_t	*pi =
				(dtrace_sdt_probeinfo_t *)&dtrace_sdt_probes;
	void			*nextpi;
	uint8_t			nops[SDT_NOP_SIZE];
	struct text_poke_param	*reqs;

	if (mod == NULL) {
		pr_warning("%s: no module provided - nothing registered\n",
			   __func__);
		return;
	}

	if (dtrace_sdt_nprobes == 0)
		return;

	/*
	 * A little unusual, but potentially necessary.  While we could use a
	 * single NOP sequence of length SDT_NOP_SIZE, we need to consider the
	 * fact that when a SDT probe point is enabled, a single invalid opcode
	 * is written on the first byte of this NOP sequence.  By using a
	 * sequence of a 1-byte NOP, followed by a (SDT_NOP_SIZE - 1) byte NOP
	 * sequence, we play it pretty safe.
	 */
	add_nops(nops, 1);
	add_nops(nops + 1, SDT_NOP_SIZE - 1);

	/*
	 * Set up a batch of text_poke requests that will handle replacing all
	 * calls at SDT probe locations with the NOP sequence.  Allocate the
	 * requests array, and then fill it in.
	 */
	reqs = (struct text_poke_param *)
			vmalloc(dtrace_sdt_nprobes *
				sizeof(struct text_poke_param));
	if (reqs == NULL) {
		pr_warning("%s: failed to allocate text_poke_param array\n",
			   __func__);
		return;
	}

	for (i = cnt = 0; cnt < dtrace_sdt_nprobes; i++) {
		char	*func = pi->name + pi->name_len + 1;

		if (sdt_probe_add(dtrace_kmod, pi->name, func, pi->addr,
				  &reqs[cnt], nops))
			pr_warning("%s: failed to add SDT probe %s\n",
				   __func__, pi->name);
		else
			cnt++;

		nextpi = (void *)pi + sizeof(dtrace_sdt_probeinfo_t)
			+ roundup(pi->name_len + 1 +
				  pi->func_len + 1, BITS_PER_LONG / 8);
		pi = nextpi;
	}

	text_poke_batch(reqs, cnt);
}

static int __init nosdt(char *str)
{
        dtrace_sdt_nprobes = 0;

        return 0;
}

early_param("nosdt", nosdt);
