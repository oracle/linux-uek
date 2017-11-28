/*
 * Dynamic Tracing for Linux
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

#ifndef _DTRACE_DEBUG_H_
#define _DTRACE_DEBUG_H_

#ifdef CONFIG_DT_DEBUG

# undef DT_DBG_AGG
# undef DT_DBG_BUF
# undef DT_DBG_DIF
# undef DT_DBG_DOF
# undef DT_DBG_ENABLE
# undef DT_DBG_IOCTL
# undef DT_DBG_PMOD
# undef DT_DBG_PROBE

#else /* CONFIG_DT_DEBUG */

# undef DT_DBG_AGG
# undef DT_DBG_BUF
# undef DT_DBG_DIF
# undef DT_DBG_DOF
# undef DT_DBG_ENABLE
# undef DT_DBG_IOCTL
# undef DT_DBG_PMOD
# undef DT_DBG_PROBE

#endif /* CONFIG_DT_DEBUG */

/*
 * Here are the actual actions for the various debug cases.
 */
#ifdef DT_DBG_AGG
# define dt_dbg_agg(fmt, ...)		pr_info(fmt, ## __VA_ARGS__)
#else
# define dt_dbg_agg(fmt, ...)
#endif

#ifdef DT_DBG_BUF
# define dt_dbg_buf(fmt, ...)		pr_info(fmt, ## __VA_ARGS__)
#else
# define dt_dbg_buf(fmt, ...)
#endif

#ifdef DT_DBG_DIF
# define dt_dbg_dif(fmt, ...)		pr_info(fmt, ## __VA_ARGS__)
#else
# define dt_dbg_dif(fmt, ...)
#endif

#ifdef DT_DBG_DOF
# define dt_dbg_dof(fmt, ...)		pr_info(fmt, ## __VA_ARGS__)
#else
# define dt_dbg_dof(fmt, ...)
#endif

#ifdef DT_DBG_ENABLE
# define dt_dbg_enable(fmt, ...)	pr_info(fmt, ## __VA_ARGS__)
#else
# define dt_dbg_enable(fmt, ...)
#endif

#ifdef DT_DBG_IOCTL
# define dt_dbg_ioctl(fmt, ...)		pr_info(fmt, ## __VA_ARGS__)
#else
# define dt_dbg_ioctl(fmt, ...)
#endif

#ifdef DT_DBG_PMOD
# define dt_dbg_pmod(fmt, ...)		pr_info(fmt, ## __VA_ARGS__)
#else
# define dt_dbg_pmod(fmt, ...)
#endif

#ifdef DT_DBG_PROBE
# define dt_dbg_probe(fmt, ...)		pr_info(fmt, ## __VA_ARGS__)
#else
# define dt_dbg_probe(fmt, ...)
#endif

#endif /* _DTRACE_DEBUG_H_ */
