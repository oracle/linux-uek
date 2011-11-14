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

#define	SDT_NOP		0x90
#define	SDT_NOP_SIZE	5

const char		*sdt_prefix = "__dtrace_probe_";

static struct module	*kernmod; /* for kernel builtins; TBD: temporary ??? */

static int sdt_reloc_resolve(struct module *mp, char *symname,
			     uintptr_t offset, uintptr_t base, void *nops)
{
	sdt_probedesc_t *sdp;
	uint8_t *instr;

	/*
	 * The "statically defined tracing" (SDT) provider for DTrace uses
	 * a mechanism similar to TNF, but somewhat simpler.  (Surprise,
	 * surprise.)  The SDT mechanism works by replacing calls to the
	 * undefined routine __dtrace_probe_[name] with nop instructions.
	 * The relocations are logged, and SDT itself will later patch the
	 * running binary appropriately.
	 */
	if (strncmp(symname, sdt_prefix, strlen(sdt_prefix)) != 0)
		return 1;

	symname += strlen(sdt_prefix);

	sdp = kmalloc(sizeof(sdt_probedesc_t), GFP_KERNEL);
	if (!sdp)
		return 1;

	sdp->sdpd_name = kmalloc(strlen(symname) + 1, GFP_KERNEL);
	if (!sdp->sdpd_name) {
		kfree(sdp);
		return 1;
	}
	memcpy(sdp->sdpd_name, symname, strlen(symname) + 1);

	/* FIXME:
	 * instr is still relative, not absolute; for some reason,
	 * vmlinux_info.S shows absolute addresses but it is not being
	 * rebuilt again when needed, so vmlinux_info.o still contains
	 * relative addresses.
	 * Hack this for now by adding _stext to instr, but this should
	 * not be necessary.
	 */
	/* convert relative instr to absolute */
	instr = (uint8_t *)((uintptr_t)_text + base + offset - 1);

	/* TBD: use a kernel list? */
	sdp->sdpd_offset = (uintptr_t)instr;
	sdp->sdpd_next = mp->sdt_probes;
	mp->sdt_probes = sdp;

	DPRINTK("sdt_probes -> 0x%p\n", mp->sdt_probes);
	DPRINTK("this probe: instr offset=0x%lx, next ptr=0x%p, probe_name=%s\n",
		sdp->sdpd_offset, sdp->sdpd_next, sdp->sdpd_name);

	mutex_lock(&text_mutex);
	text_poke(instr, nops, SDT_NOP_SIZE);
	mutex_unlock(&text_mutex);
	DPRINTK(" %02x %02x %02x %02x %02x\n", instr[0], instr[1], instr[2], instr[3], instr[4]);

	return 0;
}

void dtrace_register_builtins(void)
{
	unsigned long cnt;
	struct reloc_info *ri = (struct reloc_info *)&dtrace_relocs;
	void *nextri;
	uint8_t nops[SDT_NOP_SIZE];

	add_nops(nops, SDT_NOP_SIZE);

	kernmod = kzalloc(sizeof(struct module), GFP_KERNEL);
	if (!kernmod) {
		printk(KERN_WARNING
			"%s: cannot allocate kernel builtin module memory\n",
			__func__);
		return;
	}
	kernmod->state = MODULE_STATE_LIVE;
	strlcpy(kernmod->name, "kernel_builtins", MODULE_NAME_LEN);

	DPRINTK("%lu SDT relocation entries beg. @0x%p\n",
		dtrace_relocs_count, &dtrace_relocs);

	if (dtrace_relocs_count == 0)
		return;

	for (cnt = 0; cnt < dtrace_relocs_count; cnt++) {
		DPRINTK("SDT relocs [%lu]: "
			"probe_offset=0x%lx, section_base=0x%lx, "
			"name_len=0x%lx, probe_name=%s\n",
			cnt, ri->probe_offset, ri->section_base,
			ri->probe_name_len, ri->probe_name);
		if (sdt_reloc_resolve(kernmod, ri->probe_name,
				      ri->probe_offset, ri->section_base,
				      nops))
			printk(KERN_WARNING "%s: cannot resolve %s\n",
				__func__, ri->probe_name);

		nextri = (void *)ri + sizeof(struct reloc_info)
			+ roundup(ri->probe_name_len + 1, BITS_PER_LONG / 8);
		ri = nextri;
		DPRINTK("SDT relocs: next entry at 0x%p\n", ri);
	}
}
