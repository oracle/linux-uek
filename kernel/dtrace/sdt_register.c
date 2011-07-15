/* register static dtrace probe points */

#define DEBUG	1

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sdt.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <asm-generic/bitsperlong.h>
#include <asm-generic/sections.h>

///#include <sys/types.h>
///#include <sys/param.h>
///#include <sys/sysmacros.h>
///#include <sys/systm.h>
///#include <sys/user.h>
///#include <sys/bootconf.h>
///#include <sys/modctl.h>
///#include <sys/elf.h>
///#include <sys/kobj.h>
///#include <sys/kobj_impl.h>
///#include "reloc.h"

#define LOAD_ADDR	0xffffffff00000000ULL	/* temporary */

#define	SDT_NOP		0x90
#define	SDT_NOPS	5

const char		*sdt_prefix = "__dtrace_probe_";

static struct module	*kernmod; /* for kernel builtins; TBD: temporary ??? */

static int sdt_reloc_resolve(struct module *mp, char *symname, uint8_t *instr)
{
	sdt_probedesc_t *sdp;
	int i;

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
	if ((unsigned long)instr < 0x1000000000000000UL)
		instr = (uint8_t *)((unsigned long)instr +
					(unsigned long)_stext);

	/* TBD: use a kernel list? */
	sdp->sdpd_offset = (uintptr_t)instr;
	sdp->sdpd_next = mp->sdt_probes;
	mp->sdt_probes = sdp;

	DPRINTK("sdt_probes -> 0x%p\n", mp->sdt_probes);
	DPRINTK("this probe: instr offset=0x%lx, next ptr=0x%p, probe_name=%s\n",
		sdp->sdpd_offset, sdp->sdpd_next, sdp->sdpd_name);

	/* TBD: need a safer write-to-exec-memory ? */
	for (i = 0; i < SDT_NOPS; i++)
		instr[i - 1] = SDT_NOP;

	return 0;
}

void dtrace_register_builtins(void)
{
	unsigned long cnt;
	struct reloc_info *ri = (struct reloc_info *)&dtrace_relocs;
	void *nextri;

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
		    (uint8_t *)ri->probe_offset))
			printk(KERN_WARNING "%s: cannot resolve %s\n",
				__func__, ri->probe_name);

		nextri = (void *)ri + sizeof(struct reloc_info)
			+ roundup(ri->probe_name_len + 1, BITS_PER_LONG / 8);
		ri = nextri;
		DPRINTK("SDT relocs: next entry at 0x%p\n", ri);
	}

#if 0
	dtrace_module_loaded(kernmod);
#endif
}
