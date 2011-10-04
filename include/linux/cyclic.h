/*
 * Copyright (C) 2010, 2011 Oracle Corporation
 */

#ifndef _CYCLIC_H_
#define _CYCLIC_H_

#include <linux/ktime.h>
#include <linux/types.h>

#define CY_LOW_LEVEL	0
#define CY_LOCK_LEVEL	1
#define CY_HIGH_LEVEL	2
#define CY_SOFT_LEVELS	2
#define CY_LEVELS	3

typedef uintptr_t	cyclic_id_t;
typedef uint16_t	cyc_level_t;
typedef void		(*cyc_func_t)(void *);

#define CYCLIC_NONE	((cyclic_id_t)0)

typedef struct cyc_handler {
	cyc_func_t cyh_func;
	void *cyh_arg;
	cyc_level_t cyh_level;
} cyc_handler_t;

typedef struct cyc_time {
	ktime_t cyt_when;
	ktime_t cyt_interval;
} cyc_time_t;

extern cyclic_id_t cyclic_add(cyc_handler_t *, cyc_time_t *);
extern void cyclic_remove(cyclic_id_t);

#endif /* _CYCLIC_H_ */
