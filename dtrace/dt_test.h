/*
 * Dynamic Tracing for Linux - test provider
 *
 * Copyright (c) 2011, 2012, Oracle and/or its affiliates. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#ifndef _DT_TEST_H_
#define _DT_TEST_H_

extern void dt_test_provide(void *, const dtrace_probedesc_t *);
extern int _dt_test_enable(void *arg, dtrace_id_t, void *);
extern void _dt_test_disable(void *arg, dtrace_id_t, void *);
extern void dt_test_destroy(void *, dtrace_id_t, void *);

extern dtrace_provider_id_t	dt_test_id;

extern int dt_test_dev_init(void);
extern void dt_test_dev_exit(void);

#endif /* _DT_TEST_H_ */
