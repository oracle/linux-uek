/* -*- mode: c; c-basic-offset: 8; -*-
 * vim: noexpandtab sw=8 ts=8 sts=0:
 *
 * compat.h
 *
 * Copyright (c) 2004-2009 Oracle Corporation.  All rights reserved.
 */


#ifndef _COMPAT_H
#define _COMPAT_H

/*
 * Modern kernels don't need this.  Older kernels will have it defined
 * by the compat code.
 */
#ifndef set_i_blksize
# define set_i_blksize(i, bs) do { /* Nothing */ } while (0)
#endif

#endif  /* _COMPAT_H */
