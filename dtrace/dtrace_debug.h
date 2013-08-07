#ifndef _DTRACE_DEBUG_H_
#define _DTRACE_DEBUG_H_

#ifdef CONFIG_DT_DEBUG

# undef DT_DBG_AGG
# undef DT_DBG_BUF
# undef DT_DBG_DOF
# undef DT_DBG_ENABLE
# undef DT_DBG_IOCTL
# undef DT_DBG_PMOD
# undef DT_DBG_PROBE

#else /* CONFIG_DT_DEBUG */

# undef DT_DBG_AGG
# undef DT_DBG_BUF
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
