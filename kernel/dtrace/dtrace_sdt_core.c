/*
 * FILE:        dtrace_sdt_core.c
 * DESCRIPTION: Dynamic Tracing: SDT probe point registration
 *
 * Copyright (C) 2010-2016 Oracle Corporation
 */

#include <linux/kernel.h>
#include <linux/memory.h>
#include <linux/module.h>
#include <linux/dtrace_os.h>
#include <linux/dtrace_sdt.h>
#include <linux/jhash.h>
#include <linux/sdt.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/vmalloc.h>
#include <asm-generic/bitsperlong.h>
#include <asm-generic/sections.h>

const char		*sdt_prefix = "__dtrace_probe_";

/*
 * Markers of core-kernel sdt_args and sdt_names sections.
 */
extern const char __start_dtrace_sdt_args[];
extern const char __stop_dtrace_sdt_args[];
extern const char __start_dtrace_sdt_names[];
extern const char __stop_dtrace_sdt_names[];

static int sdt_probe_set(sdt_probedesc_t *sdp, char *name, char *func,
			 uintptr_t addr, asm_instr_t **paddr,\
			 sdt_probedesc_t *prv)
{
	if ((sdp->sdpd_name = kstrdup(name, GFP_KERNEL)) == NULL) {
		kfree(sdp);
		return 1;
	}

	if ((sdp->sdpd_func = kstrdup(func, GFP_KERNEL)) == NULL) {
		kfree(sdp->sdpd_name);
		kfree(sdp);
		return 1;
	}

	sdp->sdpd_args = NULL;
	sdp->sdpd_offset = addr;
	sdp->sdpd_next = NULL;

	*paddr = (asm_instr_t *)addr;

	if (prv && strcmp(prv->sdpd_name, sdp->sdpd_name) == 0
		&& strcmp(prv->sdpd_func, sdp->sdpd_func) == 0)
		prv->sdpd_next = sdp;

	return 0;
}

/*
 * Transfer the SDT args section into the sdpd_args field left NULL above.
 *
 * The memory pointed to by args_start must have a lifetime at least as long as
 * that pointed to by sdpd.
 */
void dtrace_sdt_stash_args(const char *module_name,
			   sdt_probedesc_t *sdpd, size_t nprobes,
			   const char *names_start, size_t names_len,
			   const char *args_start, size_t args_len)
{
	struct probe_name_hashent_t {
		const char *pnhe_name;
		const char *pnhe_args;
	} *args_by_name;
	int i;
	const char *namep, *argp;
	size_t hashsize;

	/*
	 * We need to find the probes (and there may be many) in the sdpd
	 * corresponding to the probe with that name in the argtype section.
	 *
	 * Build a hashtable mapping from probe name -> args string, ignoring
	 * duplicate probe names except to check (in debugging mode) that they
	 * have the same args string as the first.  Then cycle over the sdpd
	 * looking up each probe in turn and pointing to the same place.
	 *
	 * We don't know how many entries there are in the table, but we do know
	 * there cannot be more than nprobes (and are probably less).
	 */

	hashsize = nprobes * 4;			/* arbitrary expansion factor */
	args_by_name = vzalloc(hashsize * sizeof (struct probe_name_hashent_t));
	if (args_by_name == NULL) {
		pr_warning("%s: cannot allocate hash for sdt args population\n",
			   __func__);
		return;
	}

	namep = names_start;
	argp = args_start;
	while ((namep < names_start + names_len) &&
	       (argp < args_start + args_len)) {

		size_t l = strlen(namep);
		u32 h = jhash(namep, l, 0);
		h = h % hashsize;

		while (args_by_name[h].pnhe_name != NULL &&
		       strcmp(args_by_name[h].pnhe_name, namep) != 0) {
			h++;
			h %= hashsize;
		}

		if (args_by_name[h].pnhe_name == NULL) {
			args_by_name[h].pnhe_name = namep;
			args_by_name[h].pnhe_args = argp;
		}
#if defined(CONFIG_DT_DEBUG)
		else if (strcmp(args_by_name[h].pnhe_name, namep) != 0)
			printk(KERN_WARNING "%s: multiple "
			       "distinct arg strings for probe "
			       "%s found: %s versus %s",
			       module_name, namep,
			       args_by_name[h].pnhe_args,
			       argp);
#endif
		namep += l + 1;
		argp += strlen(argp) + 1;
	}

#if defined(CONFIG_DT_DEBUG)
	if ((namep < names_start + names_len) || (argp < args_start + args_len))
		printk(KERN_WARNING "%s: Not all SDT names or args consumed: %zi "
		       "bytes of names and %zi of args left over.  Some arg types "
		       "will be mis-assigned.\n", module_name,
		       namep - (names_start + names_len),
		       argp - (args_start + args_len));
#endif

	for (i = 0; i < nprobes; i++) {
		size_t l = strlen(sdpd[i].sdpd_name);
		u32 h = jhash(sdpd[i].sdpd_name, l, 0);
		h = h % hashsize;

		/*
		 * Is-enabled probes have no arg string.
		 */
		if (sdpd[i].sdpd_name[0] == '?')
			continue;

		while (args_by_name[h].pnhe_name != NULL &&
		       strcmp(sdpd[i].sdpd_name,
			      args_by_name[h].pnhe_name) != 0) {
			h++;
			h %= hashsize;
		}

		if (args_by_name[h].pnhe_name == NULL) {
			/*
			 * No arg string. Peculiar: report in debugging mode.
			 */
#if defined(CONFIG_DT_DEBUG)
			printk(KERN_WARNING "%s: probe %s has no arg string.\n",
			       module_name, sdpd[i].sdpd_name);
#endif
			continue;
		}

		sdpd[i].sdpd_args = args_by_name[h].pnhe_args;
	}
	vfree(args_by_name);
}

/*
 * Register the SDT probes for the core kernel, i.e. SDT probes that reside in
 * vmlinux.  For SDT probes in kernel modules, we use dtrace_mod_notifier().
 */
void dtrace_sdt_register(struct module *mp)
{
	int			i, cnt;
	dtrace_sdt_probeinfo_t	*pi =
				(dtrace_sdt_probeinfo_t *)&dtrace_sdt_probes;
	void			*nextpi;
	sdt_probedesc_t		*sdps;
	asm_instr_t		**addrs;
	int			*is_enabled;
	void			*args;
	size_t			args_len;

	if (mp == NULL) {
		pr_warning("%s: no module provided - nothing registered\n",
			   __func__);
		return;
	}

	/*
	 * Just in case we run into failures further on...
	 */
	mp->sdt_probes = NULL;
	mp->sdt_probec = 0;

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
	 * Create a list of addresses (SDT probe locations) that need to be
	 * patched with a NOP instruction (or instruction sequence), and another
	 * array indicating whether each probe needs patching with an
	 * arch-dependent false return instead.
	 */
	addrs = (asm_instr_t **)vmalloc(dtrace_sdt_nprobes *
					sizeof(asm_instr_t *));
	is_enabled = (int *)vmalloc(dtrace_sdt_nprobes * sizeof(int));
	if ((addrs == NULL) || (is_enabled == NULL)) {
		pr_warning("%s: cannot allocate SDT probe address/is-enabled "
			   "lists\n", __func__);
		vfree(sdps);
		vfree(addrs);
		vfree(is_enabled);
		return;
	}

	for (i = cnt = 0; cnt < dtrace_sdt_nprobes; i++) {
		char	*func = pi->name + pi->name_len + 1;

		is_enabled[cnt] = (pi->name[0] == '?');

		if (sdt_probe_set(&sdps[cnt], pi->name, func, pi->addr,
				  &addrs[cnt],
				  cnt > 0 ? &sdps[cnt - 1] : NULL))
			pr_warning("%s: failed to add SDT probe %s\n",
				   __func__, pi->name);
		else
			cnt++;

		nextpi = (void *)pi + sizeof(dtrace_sdt_probeinfo_t)
			+ roundup(pi->name_len + 1 +
				  pi->func_len + 1, BITS_PER_LONG / 8);
		pi = nextpi;
	}

	mp->sdt_probes = sdps;
	mp->sdt_probec = cnt;

	dtrace_sdt_nop_multi(addrs, is_enabled, cnt);

	/*
	 * Allocate space for the array of arg types, and copy it in from the
	 * (discardable) kernel section.  We will need to keep it.  (The
	 * identically-ordered array of probe names is not needed after
	 * initialization.)
	 */
	args_len = __stop_dtrace_sdt_args - __start_dtrace_sdt_args;
	args = vmalloc(args_len);
	if (args == NULL) {
		pr_warning("%s: cannot allocate table of SDT arg types\n",
			__func__);
		goto end;
	}

	memcpy(args, __start_dtrace_sdt_args, args_len);

	dtrace_sdt_stash_args("vmlinux", sdps, cnt,
			      __start_dtrace_sdt_names,
			      (__stop_dtrace_sdt_names - __start_dtrace_sdt_names),
			      args, args_len);

end:
	vfree(addrs);
	vfree(is_enabled);
}

static int __init nosdt(char *str)
{
        dtrace_sdt_nprobes = 0;

        return 0;
}

early_param("nosdt", nosdt);

void dtrace_sdt_register_module(struct module *mp,
				void *sdt_names_addr, size_t sdt_names_len,
				void *sdt_args_addr, size_t sdt_args_len)
{
	int			i, cnt;
	sdt_probedesc_t		*sdp;
	asm_instr_t		**addrs;
	int			*is_enabled;

	if (mp->sdt_probec == 0 || mp->sdt_probes == NULL)
		return;

	/*
	 * Create a list of addresses (SDT probe locations) that need to be
	 * patched with a NOP instruction (or instruction sequence).
	 */
	addrs = (asm_instr_t **)vmalloc(mp->sdt_probec *
					sizeof(asm_instr_t *));
	is_enabled = (int *)vmalloc(mp->sdt_probec * sizeof(int));
	if ((addrs == NULL) || (is_enabled == NULL)) {
		pr_warning("%s: cannot allocate SDT probe address list (%s)\n",
			   __func__, mp->name);
		vfree(addrs);
		vfree(is_enabled);
		return;
	}

	for (i = cnt = 0, sdp = mp->sdt_probes; i < mp->sdt_probec;
	     i++, sdp++) {
		addrs[cnt] = (asm_instr_t *)sdp->sdpd_offset;
		is_enabled[cnt++] = (sdp->sdpd_name[0] == '?');
	}

	dtrace_sdt_nop_multi(addrs, is_enabled, cnt);

	dtrace_sdt_stash_args(mp->name, mp->sdt_probes, mp->sdt_probec,
			      sdt_names_addr, sdt_names_len,
			      sdt_args_addr, sdt_args_len);

	vfree(addrs);
	vfree(is_enabled);
}

void dtrace_sdt_init(void)
{
	dtrace_sdt_init_arch();
}

#if defined(CONFIG_DT_DT_PERF) || defined(CONFIG_DT_DT_PERF_MODULE)
void dtrace_sdt_perf(void)
{
	DTRACE_PROBE(measure);
}
EXPORT_SYMBOL(dtrace_sdt_perf);
#endif
