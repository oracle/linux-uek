/*
 * FILE:	sdt_mod.c
 * DESCRIPTION:	Statically Defined Tracing: module handling
 *
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 *
 * Copyright 2010, 2011 Oracle, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <linux/gfp.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/ptrace.h>
#include <linux/sdt.h>
#include <linux/slab.h>

#include "dtrace.h"
#include "dtrace_dev.h"
#include "sdt.h"
#include "sdt_impl.h"

#define	SDT_PATCHVAL	0xf0
#define	SDT_ADDR2NDX(addr)	((((uintptr_t)(addr)) >> 4) & sdt_probetab_mask)
#define	SDT_PROBETAB_SIZE	0x1000		/* 4k entries -- 16K total */

///static dev_info_t		*sdt_devi;
static int			sdt_verbose = 0;
static sdt_probe_t		**sdt_probetab;
static int			sdt_probetab_size;
static int			sdt_probetab_mask;

struct frame {	/* TBD: move to header file, used in dtrace_isa.c also */
	struct frame	*fr_savfp;
	unsigned long	fr_savpc;
} __attribute__((packed));

static inline bool mod_loaded(struct module *mod)
{
	return mod->state == MODULE_STATE_LIVE;
}

static unsigned int mod_loadcnt(struct module *mod)
{
#ifdef CONFIG_MODULE_UNLOAD
	return module_refcount(mod);
#else
	return 1;
#endif
}

#if ELF_CLASS == ELFCLASS32
typedef Elf32_Sym Sym;
#else
typedef Elf64_Sym Sym;
#endif

char *
kernel_searchsym(struct module *mp, uintptr_t value, ulong_t *offset)
{
	Sym *symtabptr;
	char *strtabptr;
	int symnum;
	Sym *sym;
	Sym *cursym;
	uintptr_t curval;

	*offset = (ulong_t)-1l;		/* assume not found */
	cursym  = NULL;

	if (!within_module_core((unsigned long)value, mp) &&
	    !within_module_init((unsigned long)value, mp))
		return NULL;		/* not in this module */

	strtabptr  = NULL; ///FIXME: mp->strings;
	symtabptr  = (Sym *)mp->symtab;

	/*
	 * Scan the module's symbol table for a symbol <= value
	 */
	for (symnum = 1, sym = symtabptr + 1;
	    symnum < mp->num_symtab; symnum++, sym = (Sym *)
	    ((uintptr_t)sym /* FIXME: + mp->symhdr->sh_entsize*/)) {
		if (ELF_ST_BIND(sym->st_info) != STB_GLOBAL) {
			if (ELF_ST_BIND(sym->st_info) != STB_LOCAL)
				continue;
			if (ELF_ST_TYPE(sym->st_info) != STT_OBJECT &&
			    ELF_ST_TYPE(sym->st_info) != STT_FUNC)
				continue;
		}

		curval = (uintptr_t)sym->st_value;

		if (curval > value)
			continue;

		/*
		 * If one or both are functions...
		 */
		if (ELF_ST_TYPE(sym->st_info) == STT_FUNC || (cursym != NULL &&
		    ELF_ST_TYPE(cursym->st_info) == STT_FUNC)) {
			/* Ignore if the address is out of the bounds */
			if (value - sym->st_value >= sym->st_size)
				continue;

			if (cursym != NULL &&
			    ELF_ST_TYPE(cursym->st_info) == STT_FUNC) {
				/* Prefer the function to the non-function */
				if (ELF_ST_TYPE(sym->st_info) != STT_FUNC)
					continue;

				/* Prefer the larger of the two functions */
				if (sym->st_size <= cursym->st_size)
					continue;
			}
		} else if (value - curval >= *offset) {
			continue;
		}

		*offset = (ulong_t)(value - curval);
		cursym = sym;
	}
	if (cursym == NULL)
		return (NULL);

	return (strtabptr + cursym->st_name);
}

static void dtrace_invop_callsite(void)	/* TBD: copied from dtrace_isa.c */
{
}

/*ARGSUSED*/
static int
sdt_invop(uintptr_t addr, uintptr_t *stack, uintptr_t eax)
{
	uintptr_t stack0, stack1, stack2, stack3, stack4;
	int i = 0;
	sdt_probe_t *sdt = sdt_probetab[SDT_ADDR2NDX(addr)];

#ifdef __x86_64__
	/*
	 * On amd64, stack[0] contains the dereferenced stack pointer,
	 * stack[1] contains savfp, stack[2] contains savpc.  We want
	 * to step over these entries.
	 */
	i += 3;
#endif

	for (; sdt != NULL; sdt = sdt->sdp_hashnext) {
		if ((uintptr_t)sdt->sdp_patchpoint == addr) {
			/*
			 * When accessing the arguments on the stack, we must
			 * protect against accessing beyond the stack.  We can
			 * safely set NOFAULT here -- we know that interrupts
			 * are already disabled.
			 */
			DTRACE_CPUFLAG_SET(CPU_DTRACE_NOFAULT);
			stack0 = stack[i++];
			stack1 = stack[i++];
			stack2 = stack[i++];
			stack3 = stack[i++];
			stack4 = stack[i++];
			DTRACE_CPUFLAG_CLEAR(CPU_DTRACE_NOFAULT |
			    CPU_DTRACE_BADADDR);

			dtrace_probe(sdt->sdp_id, stack0, stack1,
			    stack2, stack3, stack4);

			return (DTRACE_INVOP_NOP);
		}
	}

	return (0);
}

/*ARGSUSED*/
static void
sdt_provide_module(void *arg, struct module *module)
{
	char *modname = module->name;
	sdt_probedesc_t *sdpd;
	sdt_probe_t *sdp, *old;
	sdt_provider_t *prov;
	int len;

	/*
	 * One for all, and all for one:  if we haven't yet registered all of
	 * our providers, we'll refuse to provide anything.
	 */
	for (prov = sdt_providers; prov->sdtp_name != NULL; prov++) {
		if (prov->sdtp_id == DTRACE_PROVNONE)
			return;
	}

	if (module->sdt_nprobes != 0 || (sdpd = module->sdt_probes) == NULL)
		return;

	for (sdpd = module->sdt_probes; sdpd != NULL; sdpd = sdpd->sdpd_next) {
		char *name = sdpd->sdpd_name, *func, *nname;
		int i, j;
		sdt_provider_t *prov;
		ulong_t offs;
		dtrace_id_t id;

		for (prov = sdt_providers; prov->sdtp_prefix != NULL; prov++) {
			char *prefix = prov->sdtp_prefix;

			if (strncmp(name, prefix, strlen(prefix)) == 0) {
				name += strlen(prefix);
				break;
			}
		}

		nname = kmalloc(len = strlen(name) + 1, GFP_KERNEL);
		if (!nname) {
			pr_warning("sdt cannot allocate memory for module: %s",
				module->name);
			return;
		}

		for (i = 0, j = 0; name[j] != '\0'; i++) {
			if (name[j] == '_' && name[j + 1] == '_') {
				nname[i] = '-';
				j += 2;
			} else {
				nname[i] = name[j++];
			}
		}

		nname[i] = '\0';

		sdp = kzalloc(sizeof(sdt_probe_t), GFP_KERNEL);
		if (!sdp) {
			pr_warning("sdt cannot allocate probe for module: %s",
				module->name);
			kfree(nname);
			return;
		}
#ifdef CONFIG_MODULE_UNLOAD
		sdp->sdp_loadcnt = module_refcount(module); // TBD: not loadcnt
#else
		sdp->sdp_loadcnt = 1;
#endif
		sdp->sdp_ctl = module;
		sdp->sdp_name = nname;
		sdp->sdp_namelen = len;
		sdp->sdp_provider = prov;

		func = kernel_searchsym(module, sdpd->sdpd_offset, &offs);

		if (func == NULL)
			func = "<unknown>";

		/*
		 * We have our provider.  Now create the probe.
		 */
		if ((id = dtrace_probe_lookup(prov->sdtp_id, modname,
		    func, nname)) != DTRACE_IDNONE) {
			old = dtrace_probe_arg(prov->sdtp_id, id);
			ASSERT(old != NULL);

			sdp->sdp_next = old->sdp_next;
			sdp->sdp_id = id;
			old->sdp_next = sdp;
		} else {
			sdp->sdp_id = dtrace_probe_create(prov->sdtp_id,
			    modname, func, nname, 3, sdp);

			module->sdt_nprobes++;
		}

		sdp->sdp_hashnext =
		    sdt_probetab[SDT_ADDR2NDX(sdpd->sdpd_offset)];
		sdt_probetab[SDT_ADDR2NDX(sdpd->sdpd_offset)] = sdp;

		sdp->sdp_patchval = SDT_PATCHVAL;
		sdp->sdp_patchpoint = (uint8_t *)sdpd->sdpd_offset;
		sdp->sdp_savedval = *sdp->sdp_patchpoint;
	}
}

/*ARGSUSED*/
static void
sdt_destroy(void *arg, dtrace_id_t id, void *parg)
{
	sdt_probe_t *sdp = parg, *old, *last, *hash;
	struct module *module = sdp->sdp_ctl;
	int ndx;

	if (module != NULL && mod_loadcnt(module) == sdp->sdp_loadcnt) {
		if ((mod_loadcnt(module) == sdp->sdp_loadcnt &&
		    mod_loaded(module))) {
			module->sdt_nprobes--;
		}
	}

	while (sdp != NULL) {
		old = sdp;

		/*
		 * Now we need to remove this probe from the sdt_probetab.
		 */
		ndx = SDT_ADDR2NDX(sdp->sdp_patchpoint);
		last = NULL;
		hash = sdt_probetab[ndx];

		while (hash != sdp) {
			ASSERT(hash != NULL);
			last = hash;
			hash = hash->sdp_hashnext;
		}

		if (last != NULL) {
			last->sdp_hashnext = sdp->sdp_hashnext;
		} else {
			sdt_probetab[ndx] = sdp->sdp_hashnext;
		}

		kfree(sdp->sdp_name);
		sdp = sdp->sdp_next;
		kfree(old);
	}
}

/*ARGSUSED*/
static int
sdt_enable(void *arg, dtrace_id_t id, void *parg)
{
	sdt_probe_t *sdp = parg;
	struct module *module = sdp->sdp_ctl;

	module->mod_nenabled++;

	/*
	 * If this module has disappeared since we discovered its probes,
	 * refuse to enable it.
	 */
	if (!mod_loaded(module)) {
		if (sdt_verbose) {
			pr_warning( "sdt is failing for probe %s "
			    "(module %s unloaded)",
			    sdp->sdp_name, module->name);
		}
		goto err;
	}

	/*
	 * Now check that our module has the expected load count.  If it
	 * doesn't, this module must have been unloaded and reloaded -- and
	 * we're not going to touch it.
	 */
	if (mod_loadcnt(module) != sdp->sdp_loadcnt) {
		if (sdt_verbose) {
			pr_warning("sdt is failing for probe %s "
			    "(module %s reloaded)",
			    sdp->sdp_name, module->name);
		}
		goto err;
	}

	while (sdp != NULL) {
		*sdp->sdp_patchpoint = sdp->sdp_patchval;
		sdp = sdp->sdp_next;
	}
err:
	return (0);
}

/*ARGSUSED*/
static void
sdt_disable(void *arg, dtrace_id_t id, void *parg)
{
	sdt_probe_t *sdp = parg;
	struct module *module = sdp->sdp_ctl;

	module->mod_nenabled--;

	if (!mod_loaded(module) || mod_loadcnt(module) != sdp->sdp_loadcnt)
		goto err;

	while (sdp != NULL) {
		*sdp->sdp_patchpoint = sdp->sdp_savedval;
		sdp = sdp->sdp_next;
	}

err:
	;
}

/*ARGSUSED*/
uint64_t
sdt_getarg(void *arg, dtrace_id_t id, void *parg, int argno, int aframes)
{
	uintptr_t val;
	struct frame *fp = (struct frame *)dtrace_getfp();
	uintptr_t *stack;
	int i;
#if defined(__x86_64__)
	/*
	 * A total of 6 arguments are passed via registers; any argument with
	 * index of 5 or lower is therefore in a register.
	 */
	int inreg = 5;
#endif

	for (i = 1; i <= aframes; i++) {
		fp = (struct frame *)(fp->fr_savfp);

		if (fp->fr_savpc == (pc_t)dtrace_invop_callsite) {
#if !defined(__x86_64__)
			/*
			 * If we pass through the invalid op handler, we will
			 * use the pointer that it passed to the stack as the
			 * second argument to dtrace_invop() as the pointer to
			 * the stack.
			 */
			stack = ((uintptr_t **)&fp[1])[1];
#else
			/*
			 * In the case of amd64, we will use the pointer to the
			 * regs structure that was pushed when we took the
			 * trap.  To get this structure, we must increment
			 * beyond the frame structure.  If the argument that
			 * we're seeking is passed on the stack, we'll pull
			 * the true stack pointer out of the saved registers
			 * and decrement our argument by the number of
			 * arguments passed in registers; if the argument
			 * we're seeking is passed in regsiters, we can just
			 * load it directly.
			 */
			struct pt_regs *rp = (struct pt_regs *)((uintptr_t)&fp[1]
			    + sizeof(uintptr_t));	/* TBD: CHECK */

			if (argno <= inreg) {
				stack = (uintptr_t *)&rp->di;
			} else {
				stack = (uintptr_t *)(rp->sp);
				argno -= (inreg + 1);
			}
#endif
			goto load;
		}
	}

	/*
	 * We know that we did not come through a trap to get into
	 * dtrace_probe() -- the provider simply called dtrace_probe()
	 * directly.  As this is the case, we need to shift the argument
	 * that we're looking for:  the probe ID is the first argument to
	 * dtrace_probe(), so the argument n will actually be found where
	 * one would expect to find argument (n + 1).
	 */
	argno++;

#if defined(__x86_64__)
	if (argno <= inreg) {
		/*
		 * This shouldn't happen.  If the argument is passed in a
		 * register then it should have been, well, passed in a
		 * register...
		 */
		DTRACE_CPUFLAG_SET(CPU_DTRACE_ILLOP);
		return (0);
	}

	argno -= (inreg + 1);
#endif
	stack = (uintptr_t *)&fp[1];

load:
	DTRACE_CPUFLAG_SET(CPU_DTRACE_NOFAULT);
	val = stack[argno];
	DTRACE_CPUFLAG_CLEAR(CPU_DTRACE_NOFAULT);

	return (val);
}

static dtrace_pops_t sdt_pops = {
	NULL,
	sdt_provide_module,
	sdt_enable,
	sdt_disable,
	NULL,
	NULL,
	sdt_getargdesc,
	sdt_getarg,
	NULL,
	sdt_destroy
};

#if 0
/*ARGSUSED*/
static int
sdt_attach(dev_info_t *devi, ddi_attach_cmd_t cmd)
{
	sdt_provider_t *prov;

	if (ddi_create_minor_node(devi, "sdt", S_IFCHR,
	    0, DDI_PSEUDO, NULL) == DDI_FAILURE) {
		pr_warning("/dev/sdt couldn't create minor node");
		ddi_remove_minor_node(devi, NULL);
		return (DDI_FAILURE);
	}

	ddi_report_dev(devi);
	///sdt_devi = devi;

	if (sdt_probetab_size == 0)
		sdt_probetab_size = SDT_PROBETAB_SIZE;

	sdt_probetab_mask = sdt_probetab_size - 1;
	sdt_probetab =
	    kzalloc(sdt_probetab_size * sizeof(sdt_probe_t *), GFP_KERNEL);
	if (!sdt_probetab) {
		pr_warning("sdt cannot allocate/register provider: %s",
			prov->sdtp_name);
		ddi_remove_minor_node(devi, NULL);
		return (DDI_FAILURE);
	}

	dtrace_invop_add(sdt_invop);

	for (prov = sdt_providers; prov->sdtp_name != NULL; prov++) {
		if (dtrace_register(prov->sdtp_name, prov->sdtp_attr,
		    DTRACE_PRIV_KERNEL, NULL,
		    &sdt_pops, prov, &prov->sdtp_id) != 0) {
			pr_warning("failed to register sdt provider %s",
			    prov->sdtp_name);
		}
	}

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
static int
sdt_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	sdt_provider_t *prov;

	switch (cmd) {
	case DDI_DETACH:
		break;

	case DDI_SUSPEND:
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}

	for (prov = sdt_providers; prov->sdtp_name != NULL; prov++) {
		if (prov->sdtp_id != DTRACE_PROVNONE) {
			if (dtrace_unregister(prov->sdtp_id) != 0)
				return (DDI_FAILURE);

			prov->sdtp_id = DTRACE_PROVNONE;
		}
	}

	dtrace_invop_remove(sdt_invop);
	kmem_free(sdt_probetab, sdt_probetab_size * sizeof(sdt_probe_t *));

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
static int
sdt_info(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg, void **result)
{
	int error;

	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		*result = (void *)sdt_devi;
		error = DDI_SUCCESS;
		break;
	case DDI_INFO_DEVT2INSTANCE:
		*result = (void *)0;
		error = DDI_SUCCESS;
		break;
	default:
		error = DDI_FAILURE;
	}
	return (error);
}
#endif

/*ARGSUSED*/
static int
sdt_open(dev_t *devp, int flag, int otyp, cred_t *cred_p)
{
	return (0);
}

#if 0
int
sdt_init(void)
{
	return 0;
}

void
sdt_exit(void)
{
}
#endif

static const dtrace_pattr_t sdt_attr = {
};

extern int sdt_dev_init(void);
extern void sdt_dev_exit(void);

DT_PROVIDER_MODULE(sdt, DTRACE_PRIV_KERNEL)

MODULE_AUTHOR("Kris Van Hees (kris.van.hees@oracle.com)");
MODULE_DESCRIPTION("Statically Defined Tracing");
MODULE_VERSION("v0.1");
MODULE_LICENSE("CDDL");
