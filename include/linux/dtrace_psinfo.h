/* Copyright (C) 2011, 2012, 2013 Oracle, Inc. */

#ifndef _DTRACE_PSINFO_H_
#define _DTRACE_PSINFO_H_

#define PR_PSARGS_SZ		80

typedef struct dtrace_psinfo {
	union {
		unsigned long argc;
		struct dtrace_psinfo *next;
	};
	char **argv;
	char **envp;
	char psargs[PR_PSARGS_SZ];
} dtrace_psinfo_t;

extern dtrace_psinfo_t *dtrace_psinfo_alloc(struct task_struct *);
extern void dtrace_psinfo_free(dtrace_psinfo_t *);

#endif /* _DTRACE_PSINFO_H_ */
