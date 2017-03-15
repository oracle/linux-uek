#ifndef _FBT_H_
#define _FBT_H_

#include <asm/dtrace_arch.h>
#include <dtrace/fbt_arch.h>

typedef struct fbt_probe {
        char			*fbp_name;	/* name of probe */
        dtrace_id_t		fbp_id;		/* probe ID */
        struct module		*fbp_module;	/* defining module */
        int			fbp_loadcnt;	/* load count for module */
        int			fbp_primary;	/* non-zero if primary mod */
        asm_instr_t		*fbp_patchpoint;/* patch point */
        asm_instr_t		fbp_patchval;	/* instruction to patch */
        asm_instr_t		fbp_savedval;	/* saved instruction value */
	uintptr_t		fbp_roffset;
        int			fbp_rval;
        struct fbt_probe	*fbp_next;	/* next probe */
        struct fbt_probe	*fbp_hashnext;	/* next on hash */
} fbt_probe_t;

#define FBT_ADDR2NDX(addr)	((((uintptr_t)(addr)) >> 4) & \
					fbt_probetab_mask)

extern fbt_probe_t		**fbt_probetab;
extern int			fbt_probetab_size;
extern int			fbt_probetab_mask;

extern void fbt_provide_probe_arch(fbt_probe_t *, int, int);
extern void fbt_enable_arch(fbt_probe_t *, dtrace_id_t, void *);
extern void fbt_disable_arch(fbt_probe_t *, dtrace_id_t, void *);

extern void fbt_provide_module(void *, struct module *);
extern int _fbt_enable(void *, dtrace_id_t, void *);
extern void _fbt_disable(void *, dtrace_id_t, void *);
extern void fbt_destroy(void *, dtrace_id_t, void *);

extern dtrace_provider_id_t	fbt_id;

extern int fbt_dev_init_arch(void);
extern void fbt_dev_exit_arch(void);

extern int fbt_dev_init(void);
extern void fbt_dev_exit(void);

#endif /* _FBT_H_ */
