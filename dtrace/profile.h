/*
 * Dynamic Tracing for Linux - profile provider
 *
 * Copyright (c) 2010, 2017, Oracle and/or its affiliates. All rights reserved.
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
