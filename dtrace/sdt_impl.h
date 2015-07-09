#ifndef _SDT_IMPL_H_
#define _SDT_IMPL_H_

#include <linux/sdt.h>
#include <asm/dtrace_arch.h>
#include <dtrace/sdt_arch.h>

extern struct module		*dtrace_kmod;

typedef struct sdt_probe {
	dtrace_mprovider_t	*sdp_provider;	/* provider */
	char			*sdp_name;	/* name of probe */
	int			sdp_namelen;	/* length of allocated name */
	dtrace_id_t		sdp_id;		/* probe ID */
	struct module		*sdp_module;	/* modctl for module */
	int			sdp_loadcnt;	/* load count for module */
	int			sdp_primary;	/* non-zero if primary mod */
	asm_instr_t		*sdp_patchpoint;/* patch point */
	asm_instr_t		sdp_patchval;	/* instruction to patch */
	asm_instr_t		sdp_savedval;	/* saved instruction value */
	struct sdt_probe	*sdp_next;	/* next probe */
	struct sdt_probe	*sdp_hashnext;	/* next on hash */
} sdt_probe_t;

typedef struct sdt_argdesc  {
	char			*sda_provider;
	char			*sda_name;
	int			sda_ndx;
	int			sda_mapping;
	char			*sda_native;
	char			*sda_xlate;
} sdt_argdesc_t;

extern dtrace_mprovider_t	sdt_providers[];
extern sdt_probe_t		**sdt_probetab;
extern int			sdt_probetab_size;
extern int			sdt_probetab_mask;

#define SDT_ADDR2NDX(addr)	((((uintptr_t)(addr)) >> 4) & \
					sdt_probetab_mask)

extern void sdt_provide_probe_arch(sdt_probe_t *, struct module *, int);
extern int sdt_provide_module_arch(void *, struct module *);
extern void sdt_enable_arch(sdt_probe_t *, dtrace_id_t, void *);
extern void sdt_disable_arch(sdt_probe_t *, dtrace_id_t, void *);

extern void sdt_provide_module(void *, struct module *);
extern void sdt_cleanup_module(void *, struct module *);
extern int _sdt_enable(void *, dtrace_id_t, void *);
extern void _sdt_disable(void *, dtrace_id_t, void *);
extern void sdt_getargdesc(void *, dtrace_id_t, void *, dtrace_argdesc_t *);
extern uint64_t sdt_getarg(void *, dtrace_id_t, void *, int, int);
extern void sdt_destroy(void *, dtrace_id_t, void *);

extern int sdt_dev_init(void);
extern void sdt_dev_exit(void);

extern int sdt_dev_init_arch(void);
extern void sdt_dev_exit_arch(void);

#endif /* _SDT_IMPL_H_ */
