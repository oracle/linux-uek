/*
 * Copyright (C) 2017 Oracle Corporation
 */
#include <linux/ksplice.h>

static int init_trace_safe = 1;

struct ctl_table ksplice_sysctls[] = {
	{
		.procname	= "init_trace_safe",
		.data		= &init_trace_safe,
		.maxlen		= sizeof(int),
		.mode		= 0444,
		.proc_handler	= proc_dointvec,
	}
};

static int __init init_ksplice_sysctls(void)
{
	register_sysctl_init("kernel/ksplice", ksplice_sysctls);
	return 0;
}
early_initcall(init_ksplice_sysctls);
