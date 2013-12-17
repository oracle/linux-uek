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
uint8_t			nops[SDT_NOP_SIZE];

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

static int sdt_probe_set(sdt_probedesc_t *sdp, char *name, char *func,
			 uintptr_t addr, struct text_poke_param *tpp)
{
	uint8_t		*instr;

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

	sdp->sdpd_offset = (uintptr_t)instr;

	tpp->addr = instr;
	tpp->opcode = nops;
	tpp->len = SDT_NOP_SIZE;

	return 0;
}

/*
 * Register the SDT probes for the core kernel, i.e. SDT probes that reside in
 * vmlinux.  For SDT probes in kernel modules, we use dtrace_mod_notifier().
 */
void dtrace_sdt_register(struct module *mod)
{
	int			i, cnt;
	dtrace_sdt_probeinfo_t	*pi =
				(dtrace_sdt_probeinfo_t *)&dtrace_sdt_probes;
	void			*nextpi;
	sdt_probedesc_t		*sdps;
	struct text_poke_param	*reqs;

	if (mod == NULL) {
		pr_warning("%s: no module provided - nothing registered\n",
			   __func__);
		return;
	}

	/*
	 * Just in case we run into failures further on...
	 */
	mod->sdt_probes = NULL;
	mod->num_dtrace_probes = 0;

	if (dtrace_sdt_nprobes == 0)
		return;

	/*
	 * Allocate the array of SDT probe descriptions to be registered in the
	 * vmlinux pseudo-module.
	 */
	sdps = (sdt_probedesc_t *)vmalloc(dtrace_sdt_nprobes *
				          sizeof(sdt_probedesc_t));
	if (sdps == NULL) {
		pr_warning("%s: cannot allocate SDT probe array\n", __func__);
		return;
	}

	/*
	 * Set up a batch of text_poke requests that will handle replacing all
	 * calls at SDT probe locations with the NOP sequence.  Allocate the
	 * requests array, and then fill it in.
	 */
	reqs = (struct text_poke_param *)
			vmalloc(dtrace_sdt_nprobes *
				sizeof(struct text_poke_param));
	if (reqs == NULL) {
		pr_warning("%s: cannot allocate text_poke_param array\n",
			   __func__);
		vfree(sdps);
		return;
	}

	for (i = cnt = 0; cnt < dtrace_sdt_nprobes; i++) {
		char	*func = pi->name + pi->name_len + 1;

		if (sdt_probe_set(&sdps[cnt], pi->name, func, pi->addr,
				  &reqs[cnt]))
			pr_warning("%s: failed to add SDT probe %s\n",
				   __func__, pi->name);
		else
			cnt++;

		nextpi = (void *)pi + sizeof(dtrace_sdt_probeinfo_t)
			+ roundup(pi->name_len + 1 +
				  pi->func_len + 1, BITS_PER_LONG / 8);
		pi = nextpi;
	}

	mod->sdt_probes = sdps;
	mod->num_dtrace_probes = cnt;

	text_poke_batch(reqs, cnt);

	vfree(reqs);
}

static int __init nosdt(char *str)
{
        dtrace_sdt_nprobes = 0;

        return 0;
}

early_param("nosdt", nosdt);

static int dtrace_mod_notifier(struct notifier_block *nb, unsigned long val,
			       void *args)
{
	struct module		*mod = args;
	struct text_poke_param	*reqs, *req;
	int			idx, cnt;
	sdt_probedesc_t		*sdp;

	/*
	 * We only need to capture modules in the COMING state, we need a valid
	 * module structure as argument, and the module needs to actually have
	 * SDT probes.  If not, ignore...
	 */
	if (val != MODULE_STATE_COMING)
		return NOTIFY_DONE;
	if (!mod)
		return NOTIFY_DONE;
	if (mod->num_dtrace_probes == 0 || mod->sdt_probes == NULL)
		return NOTIFY_DONE;

	/*
	 * Set up a batch of text_poke requests that will handle replacing all
	 * calls at SDT probe locations with the NOP sequence.  Allocate the
	 * requests array, and then fill it in.
	 */
	reqs = (struct text_poke_param *)
			vmalloc(dtrace_sdt_nprobes *
				sizeof(struct text_poke_param));
	if (reqs == NULL) {
		pr_warning("%s: cannot allocate text_poke_param array (%s)\n",
			   __func__, mod->name);
		return NOTIFY_DONE;
	}

	for (idx = cnt = 0, req = reqs, sdp = mod->sdt_probes;
	     idx < mod->num_dtrace_probes; idx++, sdp++) {
		/*
		 * Fix-up the offset to reflect the relocated address of the
		 * probe.  We subtract 1 to put us at the beginning of the call
		 * instruction.  We verify that the offset won't put us beyond
		 * the module core, just to be safe.
		 */
		sdp->sdpd_offset += (uintptr_t)mod->module_core - 1;
		if (!within_module_core(sdp->sdpd_offset, mod)) {
			pr_warning("%s: SDT probe outside module core %s\n",
				   __func__, mod->name);
			continue;
		}

		req->addr = (uint8_t *)sdp->sdpd_offset;
		req->opcode = nops;
		req->len = SDT_NOP_SIZE;

		cnt++;
		req++;
	}

	text_poke_batch(reqs, cnt);

	vfree(reqs);

	return NOTIFY_DONE;
}

static struct notifier_block	dtrace_modfix = {
	.notifier_call = dtrace_mod_notifier,
};

void dtrace_sdt_init(void)
{
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

	register_module_notifier(&dtrace_modfix);
}

#if defined(CONFIG_DT_DT_PERF) || defined(CONFIG_DT_DT_PERF_MODULE)
void dtrace_sdt_perf(void)
{
	DTRACE_PROBE(measure);
}
EXPORT_SYMBOL(dtrace_sdt_perf);
#endif
