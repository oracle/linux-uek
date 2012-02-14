#ifndef _PROFILE_H_
#define _PROFILE_H_

extern void profile_provide(void *, const dtrace_probedesc_t *);
extern int _profile_enable(void *, dtrace_id_t, void *);
extern void _profile_disable(void *, dtrace_id_t, void *);
extern int profile_usermode(void *, dtrace_id_t, void *);
extern void profile_destroy(void *, dtrace_id_t, void *);

extern dtrace_provider_id_t	profile_id;

extern int profile_dev_init(void);
extern void profile_dev_exit(void);

#endif /* _PROFILE_H_ */
