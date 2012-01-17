/* Copyright (C) 2010, 2011 Oracle Corporation */

/* register static dtrace probe points */

#define DEBUG	1

#include <linux/kernel.h>
#include <linux/memory.h>
#include <linux/module.h>
#include <linux/sdt.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <asm-generic/bitsperlong.h>
#include <asm-generic/sections.h>
#include <asm/alternative.h>
#include <asm/nops.h>

#define	SDT_TRAP_INSTR	0xf0
#define	SDT_NOP_SIZE	5

const char		*sdt_prefix = "__dtrace_probe_";

struct module		*dtrace_kmod;
EXPORT_SYMBOL(dtrace_kmod);

void sdt_probe_enable(sdt_instr_t *addr)
{
	text_poke(addr, ((unsigned char []){SDT_TRAP_INSTR}), 1);
}
EXPORT_SYMBOL(sdt_probe_enable);

void sdt_probe_disable(sdt_instr_t *addr)
{
	text_poke((void *)addr, ideal_nops[1], 1);
}
EXPORT_SYMBOL(sdt_probe_disable);

static int sdt_probe_resolve(struct module *mp, char *name, char *func,
			     uintptr_t offset, uintptr_t base, void *nops)
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

	/* convert relative instr to absolute */
	instr = (uint8_t *)((uintptr_t)_text + base + offset - 1);

	/* TBD: use a kernel list? */
	sdp->sdpd_offset = (uintptr_t)instr;
	sdp->sdpd_next = mp->sdt_probes;
	mp->sdt_probes = sdp;

	mutex_lock(&text_mutex);
	text_poke(instr, nops, SDT_NOP_SIZE);
	mutex_unlock(&text_mutex);

	return 0;
}

void dtrace_register_builtins(void)
{
	unsigned long		cnt;
	dtrace_sdt_probeinfo_t	*pi =
				(dtrace_sdt_probeinfo_t *)&dtrace_sdt_probes;
	void			*nextpi;
	uint8_t			nops[SDT_NOP_SIZE];

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

	dtrace_kmod = kzalloc(sizeof(struct module), GFP_KERNEL);
	if (!dtrace_kmod) {
		pr_warning("%s: cannot allocate kernel pseudo-module\n",
			   __func__);
		return;
	}
	dtrace_kmod->state = MODULE_STATE_LIVE;
	strlcpy(dtrace_kmod->name, "vmlinux", MODULE_NAME_LEN);

	if (dtrace_sdt_nprobes == 0)
		return;

	for (cnt = 0; cnt < dtrace_sdt_nprobes; cnt++) {
		char	*func = pi->name + pi->name_len + 1;

		if (sdt_probe_resolve(dtrace_kmod, pi->name, func,
				      pi->offset, pi->base, nops))
			pr_warning("%s: cannot resolve %s\n",
				   __func__, pi->name);

		nextpi = (void *)pi + sizeof(dtrace_sdt_probeinfo_t)
			+ roundup(pi->name_len + 1 +
				  pi->func_len + 1, BITS_PER_LONG / 8);
		pi = nextpi;
	}
}
EXPORT_SYMBOL(dtrace_register_builtins);
