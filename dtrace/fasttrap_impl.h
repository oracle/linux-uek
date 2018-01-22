/*
 * Dynamic Tracing for Linux - fasttrap provider
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

#ifndef _FASTTRAP_IMPL_H_
#define _FASTTRAP_IMPL_H_

#include <linux/dtrace/fasttrap.h>
#include <dtrace/fasttrap_arch.h>

/*
 * Fasttrap Providers, Probes and Tracepoints
 *
 * Each Solaris process can have multiple providers -- the pid provider as
 * well as any number of user-level statically defined tracing (USDT)
 * providers. Those providers are each represented by a fasttrap_provider_t.
 * All providers for a given process have a pointer to a shared
 * fasttrap_proc_t. The fasttrap_proc_t has two states: active or defunct.
 * When the count of active providers goes to zero it becomes defunct; a
 * provider drops its active count when it is removed individually or as part
 * of a mass removal when a process exits or performs an exec.
 *
 * Each probe is represented by a fasttrap_probe_t which has a pointer to
 * its associated provider as well as a list of fasttrap_id_tp_t structures
 * which are tuples combining a fasttrap_id_t and a fasttrap_tracepoint_t.
 * A fasttrap_tracepoint_t represents the actual point of instrumentation
 * and it contains two lists of fasttrap_id_t structures (to be fired pre-
 * and post-instruction emulation) that identify the probes attached to the
 * tracepoint. Tracepoints also have a pointer to the fasttrap_proc_t for the
 * process they trace which is used when looking up a tracepoint both when a
 * probe fires and when enabling and disabling probes.
 *
 * It's important to note that probes are preallocated with the necessary
 * number of tracepoints, but that tracepoints can be shared by probes and
 * swapped between probes. If a probe's preallocated tracepoint is enabled
 * (and, therefore, the associated probe is enabled), and that probe is
 * then disabled, ownership of that tracepoint may be exchanged for an
 * unused tracepoint belonging to another probe that was attached to the
 * enabled tracepoint.
 */
typedef struct fasttrap_proc {
	pid_t ftpc_pid;				/* process ID for this proc */
	atomic64_t ftpc_acount;			/* count of active providers */
	uint64_t ftpc_rcount;			/* count of extant providers */
	struct mutex ftpc_mtx;			/* lock on all but acount */
	struct fasttrap_proc *ftpc_next;	/* next proc in hash chain */
} fasttrap_proc_t;

typedef struct fasttrap_provider {
	pid_t ftp_pid;				/* process ID for this prov */
	char ftp_name[DTRACE_PROVNAMELEN];	/* prov name (w/o the pid) */
	dtrace_provider_id_t ftp_provid;	/* DTrace provider handle */
	uint_t ftp_marked;			/* mark for possible removal */
	uint_t ftp_retired;			/* mark when retired */
	struct mutex ftp_mtx;			/* provider lock */
	struct mutex ftp_cmtx;			/* lock on creating probes */
	uint64_t ftp_rcount;			/* enabled probes ref count */
	uint64_t ftp_ccount;			/* consumers creating probes */
	uint64_t ftp_mcount;			/* meta provider count */
	fasttrap_proc_t *ftp_proc;		/* shared proc for all provs */
	struct fasttrap_provider *ftp_next;	/* next prov in hash chain */
} fasttrap_provider_t;

typedef struct fasttrap_id		fasttrap_id_t;
typedef struct fasttrap_probe		fasttrap_probe_t;
typedef struct fasttrap_tracepoint	fasttrap_tracepoint_t;

struct fasttrap_id {
	fasttrap_probe_t *fti_probe;		/* referrring probe */
	fasttrap_id_t *fti_next;		/* enabled probe list on tp */
	fasttrap_probe_type_t fti_ptype;	/* probe type */
};

struct fasttrap_tracepoint {
	fasttrap_proc_t *ftt_proc;		/* associated process struct */
	uintptr_t ftt_pc;			/* address of tracepoint */
	pid_t ftt_pid;				/* pid of tracepoint */
	fasttrap_machtp_t ftt_mtp;		/* ISA-specific portion */
	fasttrap_id_t *ftt_ids;			/* NULL-terminated list */
	fasttrap_id_t *ftt_retids;		/* NULL-terminated list */
	fasttrap_tracepoint_t *ftt_next;	/* link in global hash */
};

typedef struct fasttrap_id_tp {
	fasttrap_id_t fit_id;
	fasttrap_tracepoint_t *fit_tp;
} fasttrap_id_tp_t;

struct fasttrap_probe {
	dtrace_id_t ftp_id;			/* DTrace probe identifier */
	pid_t ftp_pid;				/* pid for this probe */
	fasttrap_provider_t *ftp_prov;		/* this probe's provider */
	uintptr_t ftp_faddr;			/* associated function's addr */
	size_t ftp_fsize;			/* associated function's size */
	uint64_t ftp_gen;			/* modification generation */
	uint64_t ftp_ntps;			/* number of tracepoints */
	uint8_t *ftp_argmap;			/* native to translated args */
	uint8_t ftp_nargs;			/* translated argument count */
	uint8_t ftp_enabled;			/* is this probe enabled */
	char *ftp_xtypes;			/* translated types index */
	char *ftp_ntypes;			/* native types index */
	fasttrap_id_tp_t ftp_tps[1];		/* flexible array */
};

typedef struct fasttrap_bucket {
	struct mutex ftb_mtx;			/* bucket lock */
	void *ftb_data;				/* data payload */

	uint8_t ftb_pad[64 - sizeof(struct mutex) - sizeof(void *)];
} fasttrap_bucket_t;

typedef struct fasttrap_hash {
	ulong_t fth_nent;			/* power-of-2 num. of entries */
	ulong_t fth_mask;			/* fth_nent - 1 */
	fasttrap_bucket_t *fth_table;		/* array of buckets */
} fasttrap_hash_t;

extern fasttrap_hash_t			fasttrap_tpoints;

#define	FASTTRAP_ID_INDEX(id)						      \
	((fasttrap_id_tp_t *)(((char *)(id) -				      \
	 offsetof(fasttrap_id_tp_t, fit_id))) -				      \
	 &(id)->fti_probe->ftp_tps[0])
#define FASTTRAP_TPOINTS_INDEX(pid, pc)					      \
	(((pc) / sizeof (fasttrap_instr_t) + (pid)) &			      \
	 fasttrap_tpoints.fth_mask)

extern void fasttrap_usdt_args64_arch(fasttrap_probe_t *probe, struct pt_regs *regs,
				      int argc, uintptr_t *argv);
extern uint64_t fasttrap_usdt_getarg(void *arg, dtrace_id_t id, void *parg,
				     int argno, int aframes);
extern void fasttrap_pid_probe_arch(fasttrap_probe_t *ftp, struct pt_regs *regs);
extern void fasttrap_set_enabled(struct pt_regs *regs);

extern void fasttrap_meta_create_probe(void *, void *,
				       dtrace_helper_probedesc_t *);
extern void *fasttrap_meta_provide(void *, dtrace_helper_provdesc_t *, pid_t);
extern void fasttrap_meta_remove(void *, dtrace_helper_provdesc_t *, pid_t);

extern dtrace_meta_provider_id_t	fasttrap_id;

extern int fasttrap_dev_init(void);
extern void fasttrap_dev_exit(void);

#endif /* _FASTTRAP_IMPL_H_ */
