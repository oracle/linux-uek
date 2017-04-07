#ifndef _FBT_H_
#define _FBT_H_

#include <asm/dtrace_arch.h>
#include <dtrace/fbt_arch.h>

#define FBT_ADDR2NDX(addr)	((((uintptr_t)(addr)) >> 4) & \
					fbt_probetab_mask)

extern fbt_probe_t		**fbt_probetab;
extern int			fbt_probetab_size;
extern int			fbt_probetab_mask;

extern void fbt_provide_probe_arch(fbt_probe_t *, int, int);
extern void fbt_enable_arch(fbt_probe_t *, dtrace_id_t, void *);
extern void fbt_disable_arch(fbt_probe_t *, dtrace_id_t, void *);
extern int fbt_can_patch_return_arch(asm_instr_t *);

extern int fbt_provide_module_arch(void *, struct module *);
extern void fbt_provide_module(void *, struct module *);
extern void fbt_destroy_module(void *, struct module *);
extern int _fbt_enable(void *, dtrace_id_t, void *);
extern void _fbt_disable(void *, dtrace_id_t, void *);
extern void fbt_destroy(void *, dtrace_id_t, void *);

extern dtrace_provider_id_t	fbt_id;

extern int fbt_dev_init_arch(void);
extern void fbt_dev_exit_arch(void);

extern int fbt_dev_init(void);
extern void fbt_dev_exit(void);

#endif /* _FBT_H_ */
