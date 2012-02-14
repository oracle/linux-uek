#ifndef _SDT_IMPL_H_
#define _SDT_IMPL_H_

#include <linux/sdt.h>

extern struct module		*dtrace_kmod;

typedef struct sdt_probe {
	dtrace_mprovider_t	*sdp_provider;	/* provider */
	char			*sdp_name;	/* name of probe */
	int			sdp_namelen;	/* length of allocated name */
	dtrace_id_t		sdp_id;		/* probe ID */
	struct module		*sdp_module;	/* modctl for module */
	int			sdp_loadcnt;	/* load count for module */
	int			sdp_primary;	/* non-zero if primary mod */
	sdt_instr_t		*sdp_patchpoint;/* patch point */
	sdt_instr_t		sdp_patchval;	/* instruction to patch */
	sdt_instr_t		sdp_savedval;	/* saved instruction value */
	struct sdt_probe	*sdp_next;	/* next probe */
	struct sdt_probe	*sdp_hashnext;	/* next on hash */
} sdt_probe_t;

extern dtrace_mprovider_t sdt_providers[];

extern void sdt_provide_module(void *, struct module *);
extern int _sdt_enable(void *, dtrace_id_t, void *);
extern void _sdt_disable(void *, dtrace_id_t, void *);
extern void sdt_getargdesc(void *, dtrace_id_t, void *, dtrace_argdesc_t *);
extern uint64_t sdt_getarg(void *, dtrace_id_t, void *, int, int);
extern void sdt_destroy(void *, dtrace_id_t, void *);

extern int sdt_dev_init(void);
extern void sdt_dev_exit(void);

#endif /* _SDT_IMPL_H_ */
