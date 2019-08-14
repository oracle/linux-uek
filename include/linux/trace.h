/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_TRACE_H
#define _LINUX_TRACE_H

#ifdef CONFIG_TRACING

struct trace_array;

void trace_printk_init_buffers(void);
int trace_array_printk(struct trace_array *tr, unsigned long ip,
		const char *fmt, ...);
struct trace_array *trace_array_create(const char *name);
int trace_array_destroy(struct trace_array *tr);
#endif	/* CONFIG_TRACING */

#endif	/* _LINUX_TRACE_H */
