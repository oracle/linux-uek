#ifndef _COMPAT_LINUX_BPF_TRACE_H
#define _COMPAT_LINUX_BPF_TRACE_H

#include <linux/mlx5/compat/config.h>

#ifdef HAVE_LINUX_BPF_TRACE_H
#include <linux/bpf.h>
#include_next <linux/bpf_trace.h>
#endif

#endif /* _COMPAT_LINUX_BPF_TRACE_H */
