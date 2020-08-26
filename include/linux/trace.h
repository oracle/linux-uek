/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_TRACE_H
#define _LINUX_TRACE_H

#ifdef CONFIG_TRACING

struct trace_array;

void trace_printk_init_buffers(void);
int trace_array_printk(struct trace_array *tr, unsigned long ip,
		const char *fmt, ...);
void trace_array_put(struct trace_array *tr);
struct trace_array *trace_array_get_by_name(const char *name);
int trace_array_destroy(struct trace_array *tr);
#endif	/* CONFIG_TRACING */

#endif	/* _LINUX_TRACE_H */
