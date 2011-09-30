#ifndef _DT_TEST_H_
#define _DT_TEST_H_

extern void dt_test_provide(void *, const dtrace_probedesc_t *);
extern int dt_test_enable(void *arg, dtrace_id_t, void *);
extern void dt_test_disable(void *arg, dtrace_id_t, void *);
extern void dt_test_destroy(void *, dtrace_id_t, void *);

extern dtrace_provider_id_t	dt_test_id;

extern int dt_test_dev_init(void);
extern void dt_test_dev_exit(void);

#endif /* _DT_TEST_H_ */
