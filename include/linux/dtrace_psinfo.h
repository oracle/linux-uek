/* Copyright (C) 2011, 2012, 2013 Oracle, Inc. */

#ifndef _LINUX_DTRACE_PSINFO_H_
#define _LINUX_DTRACE_PSINFO_H_

#define PR_PSARGS_SZ		80
#define PR_ARGV_SZ		512
#define PR_ENVP_SZ		512

typedef struct dtrace_psinfo {
/* Orabug 18383027 - Remove the conditionals at the next major UEK release. */
#ifndef __GENKSYMS__
	atomic_t usage;
#endif
	union {
		unsigned long argc;
		struct dtrace_psinfo *next;
	};
	char **argv;
	unsigned long envc;
	char **envp;
	char psargs[PR_PSARGS_SZ];
} dtrace_psinfo_t;

extern void dtrace_psinfo_alloc(struct task_struct *);
extern void dtrace_psinfo_free(struct task_struct *);

#define get_psinfo(tsk)							      \
	do {								      \
		if (likely((tsk)->dtrace_psinfo))			      \
			atomic_inc(&(tsk)->dtrace_psinfo->usage);	      \
	} while (0)
#define put_psinfo(tsk)							      \
	do {								      \
		if (likely((tsk)->dtrace_psinfo)) {			      \
			if (atomic_dec_and_test(&(tsk)->dtrace_psinfo->usage))\
				dtrace_psinfo_free(tsk);		      \
		}							      \
	} while (0)

#endif /* _LINUX_DTRACE_PSINFO_H_ */
