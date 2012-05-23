#ifndef _FBT_H_
#define _FBT_H_

typedef struct fbt_probe {
        char			*fbp_name;	/* name of probe */
        dtrace_id_t		fbp_id;		/* probe ID */
        struct module		*fbp_module;	/* defining module */
        int			fbp_loadcnt;	/* load count for module */
        int			fbp_primary;	/* non-zero if primary mod */
        uint8_t			*fbp_patchpoint;/* patch point */
        uint8_t			fbp_patchval;	/* instruction to patch */
        uint8_t			fbp_savedval;	/* saved instruction value */
	uintptr_t		fbp_roffset;
        int8_t			fbp_rval;
        struct fbt_probe	*fbp_next;	/* next probe */
        struct fbt_probe	*fbp_hashnext;	/* next on hash */
} fbt_probe_t;

extern void fbt_provide_module(void *, struct module *);
extern int _fbt_enable(void *arg, dtrace_id_t, void *);
extern void _fbt_disable(void *arg, dtrace_id_t, void *);
extern void fbt_destroy(void *, dtrace_id_t, void *);

extern dtrace_provider_id_t	fbt_id;

extern int fbt_dev_init(void);
extern void fbt_dev_exit(void);

#endif /* _FBT_H_ */
