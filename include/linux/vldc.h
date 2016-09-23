/*
 * Copyright (C) 2014-2016 Oracle Corporation. All rights reserved.
 */

#ifndef _VLDC_H
#define _VLDC_H

#include <uapi/linux/vldc.h>

/* VLDC driver interfaces for kernel drivers */
extern int vldc_open(char *dev_name, u8 mode); /* Returns vldc_dev_id or */
					       /* error(<0). Must be called */
					       /* in process context. */
extern int vldc_close(int vldc_dev_id);
extern ssize_t vldc_read(int vldc_dev_id, char *buf,
			 size_t count, loff_t *offp);
extern ssize_t vldc_write(int vldc_dev_id, const char *buf,
			  size_t count, loff_t *off);

/* VLDC modes */
#define	VLDC_MODE_RAW		0x0
#define	VLDC_MODE_UNRELIABLE	0x1
#define	VLDC_MODE_RESERVED	0x2
#define	VLDC_MODE_STREAM	0x3

#endif /* _VLDC_H */
