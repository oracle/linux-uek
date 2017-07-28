/*
 * Dynamic Tracing for Linux - Implementation
 *
 * Copyright (c) 2009, 2017, Oracle and/or its affiliates. All rights reserved.
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

/*
 * Note: The contents of this file are private to the implementation of the
 * DTrace subsystem and are subject to change at any time without notice.
 */

#ifndef _LINUX_DTRACE_IMPL_H
#define _LINUX_DTRACE_IMPL_H

#include <linux/cyclic.h>
#include <linux/idr.h>

#include <linux/dtrace/universal.h>
#include <linux/dtrace/dif.h>
#include <linux/dtrace/difo_defines.h>
#include <linux/dtrace/metadesc.h>
#include <linux/dtrace/stability.h>
#include <linux/dtrace/helpers.h>
#include <dtrace/types.h>
#include <dtrace/provider.h>
#include <dtrace/dtrace_impl_defines.h>

typedef struct dtrace_provider {
	dtrace_pattr_t dtpv_attr;
	dtrace_ppriv_t dtpv_priv;
	dtrace_pops_t dtpv_pops;
	char *dtpv_name;
	void *dtpv_arg;
	uint_t dtpv_defunct;
	struct dtrace_provider *dtpv_next;
} dtrace_provider_t;

typedef struct dtrace_predicate {
	struct dtrace_difo *dtp_difo;
	dtrace_cacheid_t dtp_cacheid;
	int dtp_refcnt;
} dtrace_predicate_t;

typedef struct dtrace_statvar {
	uint64_t dtsv_data;
	size_t dtsv_size;
	int dtsv_refcnt;
	dtrace_difv_t dtsv_var;
} dtrace_statvar_t;

typedef struct dtrace_action {
	dtrace_actkind_t dta_kind;
	uint16_t dta_intuple;
	uint32_t dta_refcnt;
	dtrace_difo_t *dta_difo;
	dtrace_recdesc_t dta_rec;
	struct dtrace_action *dta_prev;
	struct dtrace_action *dta_next;
} dtrace_action_t;

struct dtrace_ecb;
typedef struct dtrace_ecb	dtrace_ecb_t;

typedef struct dtrace_probe {
	dtrace_id_t dtpr_id;
	dtrace_ecb_t *dtpr_ecb;
	dtrace_ecb_t *dtpr_ecb_last;
	void *dtpr_arg;
	dtrace_cacheid_t dtpr_predcache;
	int dtpr_aframes;
	dtrace_provider_t *dtpr_provider;
	char *dtpr_mod;
	char *dtpr_func;
	char *dtpr_name;
	struct dtrace_probe *dtpr_nextmod;
	struct dtrace_probe *dtpr_prevmod;
	struct dtrace_probe *dtpr_nextfunc;
	struct dtrace_probe *dtpr_prevfunc;
	struct dtrace_probe *dtpr_nextname;
	struct dtrace_probe *dtpr_prevname;
	dtrace_genid_t dtpr_gen;
} dtrace_probe_t;

struct dtrace_state;
typedef struct dtrace_state	dtrace_state_t;

struct dtrace_ecb {
	dtrace_epid_t dte_epid;
	uint32_t dte_alignment;
	size_t dte_needed;
	size_t dte_size;
	dtrace_predicate_t *dte_predicate;
	dtrace_action_t *dte_action;
	struct dtrace_ecb *dte_next;
	dtrace_state_t *dte_state;
	uint32_t dte_cond;
	dtrace_probe_t *dte_probe;
	dtrace_action_t *dte_action_last;
	uint64_t dte_uarg;
};

typedef struct dtrace_key {
	uint64_t dttk_value;
	uint64_t dttk_size;
} dtrace_key_t;

typedef struct dtrace_tuple {
	uint32_t dtt_nkeys;
	uint32_t dtt_pad;
	dtrace_key_t dtt_key[1];
} dtrace_tuple_t;

typedef struct dtrace_dynvar {
	uint64_t dtdv_hashval;
	struct dtrace_dynvar *dtdv_next;
	void *dtdv_data;
	dtrace_tuple_t dtdv_tuple;
} dtrace_dynvar_t;

typedef struct dtrace_dstate_percpu {
	dtrace_dynvar_t *dtdsc_free;
	dtrace_dynvar_t *dtdsc_dirty;
	dtrace_dynvar_t *dtdsc_rinsing;
	dtrace_dynvar_t *dtdsc_clean;
	uint64_t dtdsc_drops;
	uint64_t dtdsc_dirty_drops;
	uint64_t dtdsc_rinsing_drops;
#ifdef CONFIG_64BIT
	uint64_t dtdsc_pad;
#else
	uint64_t dtdsc_pad[2];
#endif
} dtrace_dstate_percpu_t;

typedef struct dtrace_dynhash {
	dtrace_dynvar_t *dtdh_chain;
	uintptr_t dtdh_lock;
#ifdef CONFIG_64BIT
	uintptr_t dtdh_pad[6];
#else
	uintptr_t dtdh_pad[14];
#endif
} dtrace_dynhash_t;

typedef struct dtrace_dstate {
	void *dtds_base;
	size_t dtds_size;
	size_t dtds_hashsize;
	size_t dtds_chunksize;
	dtrace_dynhash_t *dtds_hash;
	dtrace_dstate_state_t dtds_state;
	dtrace_dstate_percpu_t *dtds_percpu;
} dtrace_dstate_t;

typedef struct dtrace_vstate {
	dtrace_state_t *dtvs_state;
	dtrace_statvar_t **dtvs_globals;
	int dtvs_nglobals;
	dtrace_difv_t *dtvs_tlocals;
	int dtvs_ntlocals;
	dtrace_statvar_t **dtvs_locals;
	int dtvs_nlocals;
	dtrace_dstate_t dtvs_dynvars;
} dtrace_vstate_t;

/*
 * DTrace Machine State
 *
 * In the process of processing a fired probe, DTrace needs to track and/or
 * cache some per-CPU state associated with that particular firing.  This is
 * state that is always discarded after the probe firing has completed, and
 * much of it is not specific to any DTrace consumer, remaining valid across
 * all ECBs.  This state is tracked in the dtrace_mstate structure.
 */

typedef struct dtrace_mstate {
	uintptr_t dtms_scratch_base;
	uintptr_t dtms_scratch_ptr;
	size_t dtms_scratch_size;
	uint32_t dtms_present;
	uint64_t dtms_arg[5];
	dtrace_epid_t dtms_epid;
	ktime_t dtms_timestamp;
	int dtms_stackdepth;
	int dtms_ustackdepth;
	struct dtrace_probe *dtms_probe;
	uintptr_t dtms_caller;
	uint64_t dtms_ucaller;
	int dtms_ipl;
	int dtms_fltoffs;
	uintptr_t dtms_strtok;
	uint32_t dtms_access;
	dtrace_difo_t *dtms_difo;
} dtrace_mstate_t;

typedef struct dtrace_buffer {
	uint64_t dtb_offset;
	uint64_t dtb_size;
	uint32_t dtb_flags;
	uint32_t dtb_drops;
	caddr_t dtb_tomax;
	caddr_t dtb_xamot;
	uint32_t dtb_xamot_flags;
	uint32_t dtb_xamot_drops;
	uint64_t dtb_xamot_offset;
	uint32_t dtb_errors;
	uint32_t dtb_xamot_errors;
#ifndef CONFIG_64BIT
	uint64_t dtb_pad1;
#endif
} dtrace_buffer_t;

typedef struct dtrace_speculation {
	dtrace_speculation_state_t dtsp_state;
	int dtsp_cleaning;
	dtrace_buffer_t *dtsp_buffer;
} dtrace_speculation_t;

typedef struct dtrace_aggregation {
	dtrace_action_t dtag_action;
	dtrace_aggid_t dtag_id;
	dtrace_ecb_t *dtag_ecb;
	dtrace_action_t *dtag_first;
	uint32_t dtag_base;
	uint8_t dtag_hasarg;
	uint64_t dtag_initial;
	void (*dtag_aggregate)(uint64_t *, uint64_t, uint64_t);
} dtrace_aggregation_t;

typedef struct dtrace_cred {
	const cred_t *dcr_cred;
	uint8_t dcr_destructive;
	uint8_t dcr_visible;
	uint16_t dcr_action;
} dtrace_cred_t;

struct dtrace_state {
	dev_t dts_dev;
	int dts_necbs;
	dtrace_ecb_t **dts_ecbs;
	dtrace_epid_t dts_epid;
	size_t dts_needed;
	struct dtrace_state *dts_anon;
	dtrace_activity_t dts_activity;
	dtrace_vstate_t dts_vstate;
	dtrace_buffer_t *dts_buffer;
	dtrace_buffer_t *dts_aggbuffer;
	dtrace_speculation_t *dts_speculations;
	int dts_nspeculations;
	struct idr dts_agg_idr;
	int dts_naggs;
	uint64_t dts_errors;
	uint32_t dts_speculations_busy;
	uint32_t dts_speculations_unavail;
	uint32_t dts_stkstroverflows;
	uint32_t dts_dblerrors;
	uint32_t dts_reserve;
	cyclic_id_t dts_cleaner;
	cyclic_id_t dts_deadman;
	uint64_t dts_laststatus;
	ktime_t dts_alive;
	char dts_speculates;
	char dts_destructive;
	int dts_nformats;
	char **dts_formats;
	dtrace_optval_t dts_options[DTRACEOPT_MAX];
	dtrace_cred_t dts_cred;
	size_t dts_nretained;
};

typedef struct dtrace_enabling {
	dtrace_ecbdesc_t **dten_desc;
	int dten_ndesc;
	int dten_maxdesc;
	dtrace_vstate_t *dten_vstate;
	dtrace_genid_t dten_probegen;
	dtrace_ecbdesc_t *dten_current;
	int dten_error;
	int dten_primed;
	struct dtrace_enabling *dten_prev;
	struct dtrace_enabling *dten_next;
} dtrace_enabling_t;

typedef int dtrace_probekey_f(const char *, const char *, int);

typedef struct dtrace_probekey {
	const char *dtpk_prov;
	dtrace_probekey_f *dtpk_pmatch;
	const char *dtpk_mod;
	dtrace_probekey_f *dtpk_mmatch;
	const char *dtpk_func;
	dtrace_probekey_f *dtpk_fmatch;
	const char *dtpk_name;
	dtrace_probekey_f *dtpk_nmatch;
	dtrace_id_t dtpk_id;
} dtrace_probekey_t;

typedef struct dtrace_hashbucket {
	struct dtrace_hashbucket *dthb_next;
	dtrace_probe_t *dthb_chain;
	int dthb_len;
} dtrace_hashbucket_t;

typedef struct dtrace_hash {
	dtrace_hashbucket_t **dth_tab;
	int dth_size;
	int dth_mask;
	int dth_nbuckets;
	uintptr_t dth_nextoffs;
	uintptr_t dth_prevoffs;
	uintptr_t dth_stroffs;
} dtrace_hash_t;

/*
 * DTrace supports safe loads from probe context; if the address turns out to
 * be invalid, a bit will be set by the kernel indicating that DTrace
 * encountered a memory error, and DTrace will propagate the error to the user
 * accordingly.  However, there may exist some regions of memory in which an
 * arbitrary load can change system state, and from which it is impossible to
 * recover from such a load after it has been attempted.  Examples of this may
 * include memory in which programmable I/O registers are mapped (for which a
 * read may have some implications for the device) or (in the specific case of
 * UltraSPARC-I and -II) the virtual address hole.  The platform is required
 * to make DTrace aware of these toxic ranges; DTrace will then check that
 * target addresses are not in a toxic range before attempting to issue a
 * safe load.
 */
typedef struct dtrace_toxrange {
	uintptr_t dtt_base;
	uintptr_t dtt_limit;
} dtrace_toxrange_t;

/*
 * DTrace Helper Implementation
 *
 * A description of the helper architecture may be found in <linux/dtrace.h>.
 * Each process contains a pointer to its helpers in its dtrace_helpers
 * member.  This is a pointer to a dtrace_helpers structure, which contains an
 * array of pointers to dtrace_helper structures, helper variable state (shared
 * among a process's helpers) and a generation count.  (The generation count is
 * used to provide an identifier when a helper is added so that it may be
 * subsequently removed.)  The dtrace_helper structure is self-explanatory,
 * containing pointers to the objects needed to execute the helper.  Note that
 * helpers are _duplicated_ across fork(2), and destroyed on exec(2).  No more
 * than dtrace_helpers_max are allowed per-process.
 */
typedef struct dtrace_helper_action {
	int dtha_generation;			/* helper action generation */
	int dtha_nactions;			/* number of actions */
	dtrace_difo_t *dtha_predicate;		/* helper action predicate */
	dtrace_difo_t **dtha_actions;		/* array of actions */
	struct dtrace_helper_action *dtha_next;	/* next helper action */
} dtrace_helper_action_t;

typedef struct dtrace_helper_provider {
	int dthp_generation;			/* helper provider generation */
	uint32_t dthp_ref;			/* reference count */
	dof_helper_t dthp_prov;			/* DOF w/ provider and probes */
} dtrace_helper_provider_t;

typedef struct dtrace_helpers {
	dtrace_helper_action_t **dthps_actions;	/* array of helper actions */
	dtrace_vstate_t dthps_vstate;	/* helper action var. state */
	dtrace_helper_provider_t **dthps_provs;	/* array of providers */
	uint_t dthps_nprovs;			/* count of providers */
	uint_t dthps_maxprovs;			/* provider array size */
	int dthps_generation;			/* current generation */
	pid_t dthps_pid;			/* pid of associated proc */
	int dthps_deferred;			/* helper in deferred list */
	struct dtrace_helpers *dthps_next;	/* next pointer */
	struct dtrace_helpers *dthps_prev;	/* prev pointer */
} dtrace_helpers_t;

/*
 * DTrace Helper Action Tracing
 *
 * Debugging helper actions can be arduous.  To ease the development and
 * debugging of helpers, DTrace contains a tracing-framework-within-a-tracing-
 * framework: helper tracing.  If dtrace_helptrace_enabled is non-zero (which
 * it is by default on DEBUG kernels), all helper activity will be traced to a
 * global, in-kernel ring buffer.  Each entry includes a pointer to the specific
 * helper, the location within the helper, and a trace of all local variables.
 * The ring buffer may be displayed in a human-readable format with the
 * ::dtrace_helptrace mdb(1) dcmd.
 */
typedef struct dtrace_helptrace {
	dtrace_helper_action_t  *dtht_helper;	/* helper action */
	int dtht_where;				/* where in helper action */
	int dtht_nlocals;			/* number of locals */
	int dtht_fault;				/* type of fault (if any) */
	int dtht_fltoffs;			/* DIF offset */
	uint64_t dtht_illval;			/* faulting value */
	uint64_t dtht_locals[1];		/* local variables */
} dtrace_helptrace_t;

extern struct mutex		dtrace_lock;
extern struct mutex		dtrace_provider_lock;
extern struct mutex		dtrace_meta_lock;

extern dtrace_genid_t		dtrace_probegen;
extern struct kmem_cache	*dtrace_probe_cachep;

extern dtrace_pops_t		dtrace_provider_ops;

extern int			dtrace_opens;
extern int			dtrace_err_verbose;

extern dtrace_toxrange_t	*dtrace_toxrange;
extern int			dtrace_toxranges;

extern void dtrace_nullop(void);
extern int dtrace_enable_nullop(void);
extern int dtrace_istoxic(uintptr_t, size_t);

/*
 * DTrace Probe Context Functions
 */

extern void dtrace_panic(const char *, ...);
extern int dtrace_assfail(const char *, const char *, int);
extern void dtrace_aggregate_min(uint64_t *, uint64_t, uint64_t);
extern void dtrace_aggregate_max(uint64_t *, uint64_t, uint64_t);
extern void dtrace_aggregate_quantize(uint64_t *, uint64_t, uint64_t);
extern void dtrace_aggregate_lquantize(uint64_t *, uint64_t, uint64_t);
extern void dtrace_aggregate_llquantize(uint64_t *, uint64_t, uint64_t);
extern void dtrace_aggregate_avg(uint64_t *, uint64_t, uint64_t);
extern void dtrace_aggregate_stddev(uint64_t *, uint64_t, uint64_t);
extern void dtrace_aggregate_count(uint64_t *, uint64_t, uint64_t);
extern void dtrace_aggregate_sum(uint64_t *, uint64_t, uint64_t);
extern void dtrace_aggregate(dtrace_aggregation_t *, dtrace_buffer_t *,
			     intptr_t, dtrace_buffer_t *, uint64_t, uint64_t);

/*
 * DTrace Probe Hashing Functions
 */

extern dtrace_hash_t *dtrace_hash_create(uintptr_t, uintptr_t, uintptr_t);
extern void dtrace_hash_destroy(dtrace_hash_t *);
extern int dtrace_hash_add(dtrace_hash_t *, dtrace_probe_t *);
extern dtrace_probe_t *dtrace_hash_lookup(dtrace_hash_t *, dtrace_probe_t *);
extern int dtrace_hash_collisions(dtrace_hash_t *, dtrace_probe_t *);
extern void dtrace_hash_remove(dtrace_hash_t *, dtrace_probe_t *);

/*
 * DTrace Speculation Functions
 */
extern int dtrace_speculation(dtrace_state_t *);
extern void dtrace_speculation_commit(dtrace_state_t *, processorid_t,
				      dtrace_specid_t);
extern void dtrace_speculation_discard(dtrace_state_t *, processorid_t,
				       dtrace_specid_t);
extern void dtrace_speculation_clean(dtrace_state_t *);
extern dtrace_buffer_t *dtrace_speculation_buffer(dtrace_state_t *,
                                           processorid_t, dtrace_specid_t);

/*
 * DTrace Non-Probe Context Utility Functions
 */

/*
 * DTrace Matching Functions
 */
extern dtrace_hash_t		*dtrace_bymod;
extern dtrace_hash_t		*dtrace_byfunc;
extern dtrace_hash_t		*dtrace_byname;

extern int dtrace_match_priv(const dtrace_probe_t *, uint32_t, kuid_t);
extern int dtrace_match_probe(const dtrace_probe_t *,
			      const dtrace_probekey_t *, uint32_t, kuid_t);
extern int dtrace_match_glob(const char *, const char *, int);
extern int dtrace_match_string(const char *, const char *, int);
extern int dtrace_match_nul(const char *, const char *, int);
extern int dtrace_match_nonzero(const char *, const char *, int);
extern int dtrace_match(const dtrace_probekey_t *, uint32_t, kuid_t,
			int (*matched)(dtrace_probe_t *, void *), void *);
extern void dtrace_probekey(const dtrace_probedesc_t *, dtrace_probekey_t *);

/*
 * DTrace Provider-to-Framework API Functions
 */

extern dtrace_provider_t	*dtrace_provider;
extern dtrace_meta_t		*dtrace_meta_pid;
extern dtrace_helpers_t		*dtrace_deferred_pid;

/*
 * DTrace Privilege Check Functions
 */
extern int dtrace_priv_proc_destructive(dtrace_state_t *);
extern int dtrace_priv_proc_control(dtrace_state_t *);
extern int dtrace_priv_proc(dtrace_state_t *);
extern int dtrace_priv_kernel(dtrace_state_t *);

/*
 * DTrace Probe Management Functions
 */

extern int dtrace_probe_enable(const dtrace_probedesc_t *,
			       dtrace_enabling_t *);
extern void dtrace_probe_description(const dtrace_probe_t *,
				     dtrace_probedesc_t *);
extern void dtrace_probe_provide(dtrace_probedesc_t *, dtrace_provider_t *);
extern int dtrace_probe_init(void);
extern void dtrace_probe_exit(void);
extern void dtrace_probe_remove_id(dtrace_id_t);
extern dtrace_probe_t *dtrace_probe_lookup_id(dtrace_id_t);
extern dtrace_probe_t *dtrace_probe_get_next(dtrace_id_t *);
extern int dtrace_probe_for_each(int (*)(int, void *, void *), void *);

/*
 * DTrace Kernel Hooks
 */
extern void (*dtrace_modload)(struct module *);
extern void (*dtrace_modunload)(struct module *);

extern uint8_t dtrace_load8(uintptr_t);
extern uint16_t dtrace_load16(uintptr_t);
extern uint32_t dtrace_load32(uintptr_t);
extern uint64_t dtrace_load64(uintptr_t);

extern void dtrace_bzero(void *, size_t);

extern int dtrace_vcanload(void *, dtrace_diftype_t *, dtrace_mstate_t *,
			   dtrace_vstate_t *);

extern int dtrace_difo_validate(dtrace_difo_t *, dtrace_vstate_t *, uint_t,
				const cred_t *);
extern int dtrace_difo_validate_helper(dtrace_difo_t *);
extern int dtrace_difo_cacheable(dtrace_difo_t *);
extern void dtrace_difo_hold(dtrace_difo_t *);
extern void dtrace_difo_init(dtrace_difo_t *, dtrace_vstate_t *);
extern dtrace_difo_t * dtrace_difo_duplicate(dtrace_difo_t *,
					     dtrace_vstate_t *);
extern void dtrace_difo_release(dtrace_difo_t *, dtrace_vstate_t *);

extern uint64_t			dtrace_vtime_references;

extern uint64_t dtrace_dif_emulate(dtrace_difo_t *, dtrace_mstate_t *,
				   dtrace_vstate_t *, dtrace_state_t *);

/*
 * DTrace Format Functions
 */
extern uint16_t dtrace_format_add(dtrace_state_t *, char *);
extern void dtrace_format_remove(dtrace_state_t *, uint16_t);
extern void dtrace_format_destroy(dtrace_state_t *);

/*
 * DTrace Predicate Functions
 */
extern dtrace_predicate_t *dtrace_predicate_create(dtrace_difo_t *);
extern void dtrace_predicate_hold(dtrace_predicate_t *);
extern void dtrace_predicate_release(dtrace_predicate_t *, dtrace_vstate_t *);

/*
 * DTrace Action Description Functions
 */
extern dtrace_actdesc_t *dtrace_actdesc_create(dtrace_actkind_t, uint32_t,
					       uint64_t, uint64_t);
extern void dtrace_actdesc_hold(dtrace_actdesc_t *);
extern void dtrace_actdesc_release(dtrace_actdesc_t *, dtrace_vstate_t *);

/*
 * DTrace Helper Functions
 */
extern void dtrace_helpers_destroy(struct task_struct *);
extern void dtrace_helpers_duplicate(struct task_struct *,
				     struct task_struct *);
extern uint64_t dtrace_helper(int, dtrace_mstate_t *, dtrace_state_t *,
			      uint64_t, uint64_t);

/*
 * DTrace ECB Functions
 */
extern dtrace_ecb_t		*dtrace_ecb_create_cache;

extern int dtrace_ecb_create_enable(dtrace_probe_t *, void *);
extern void dtrace_ecb_disable(dtrace_ecb_t *);
extern void dtrace_ecb_destroy(dtrace_ecb_t *);
extern void dtrace_ecb_resize(dtrace_ecb_t *);
extern int dtrace_ecb_enable(dtrace_ecb_t *);
extern dtrace_ecb_t *dtrace_epid2ecb(dtrace_state_t *, dtrace_epid_t);
extern dtrace_aggregation_t *dtrace_aggid2agg(dtrace_state_t *,
					      dtrace_aggid_t);

/*
 * DTrace Buffer Functions
 *
 * DTrace Buffers
 *
 * Principal buffers, aggregation buffers, and speculative buffers are all
 * managed with the dtrace_buffer structure.  By default, this structure
 * includes twin data buffers -- dtb_tomax and dtb_xamot -- that serve as the
 * active and passive buffers, respectively.  For speculative buffers,
 * dtb_xamot will be NULL; for "ring" and "fill" buffers, dtb_xamot will point
 * to a scratch buffer.  For all buffer types, the dtrace_buffer structure is
 * always allocated on a per-CPU basis; a single dtrace_buffer structure is
 * never shared among CPUs.  (That is, there is never true sharing of the
 * dtrace_buffer structure; to prevent false sharing of the structure, it must
 * always be aligned to the coherence granularity -- generally 64 bytes.)
 *
 * One of the critical design decisions of DTrace is that a given ECB always
 * stores the same quantity and type of data.  This is done to assure that the
 * only metadata required for an ECB's traced data is the EPID.  That is, from
 * the EPID, the consumer can determine the data layout.  (The data buffer
 * layout is shown schematically below.)  By assuring that one can determine
 * data layout from the EPID, the metadata stream can be separated from the
 * data stream -- simplifying the data stream enormously.
 *
 *      base of data buffer --->  +------+--------------------+------+
 *                                | EPID | data               | EPID |
 *                                +------+--------+------+----+------+
 *                                | data          | EPID | data      |
 *                                +---------------+------+-----------+
 *                                | data, cont.                      |
 *                                +------+--------------------+------+
 *                                | EPID | data               |      |
 *                                +------+--------------------+      |
 *                                |                ||                |
 *                                |                ||                |
 *                                |                \/                |
 *                                :                                  :
 *                                .                                  .
 *                                .                                  .
 *                                .                                  .
 *                                :                                  :
 *                                |                                  |
 *     limit of data buffer --->  +----------------------------------+
 *
 * When evaluating an ECB, dtrace_probe() determines if the ECB's needs of the
 * principal buffer (both scratch and payload) exceed the available space.  If
 * the ECB's needs exceed available space (and if the principal buffer policy
 * is the default "switch" policy), the ECB is dropped, the buffer's drop count
 * is incremented, and processing advances to the next ECB.  If the ECB's needs
 * can be met with the available space, the ECB is processed, but the offset in
 * the principal buffer is only advanced if the ECB completes processing
 * without error.
 *
 * When a buffer is to be switched (either because the buffer is the principal
 * buffer with a "switch" policy or because it is an aggregation buffer), a
 * cross call is issued to the CPU associated with the buffer.  In the cross
 * call context, interrupts are disabled, and the active and the inactive
 * buffers are atomically switched.  This involves switching the data pointers,
 * copying the various state fields (offset, drops, errors, etc.) into their
 * inactive equivalents, and clearing the state fields.  Because interrupts are
 * disabled during this procedure, the switch is guaranteed to appear atomic to
 * dtrace_probe().
 *
 * DTrace Ring Buffering
 *
 * To process a ring buffer correctly, one must know the oldest valid record.
 * Processing starts at the oldest record in the buffer and continues until
 * the end of the buffer is reached.  Processing then resumes starting with
 * the record stored at offset 0 in the buffer, and continues until the
 * youngest record is processed.  If trace records are of a fixed-length,
 * determining the oldest record is trivial:
 *
 *   - If the ring buffer has not wrapped, the oldest record is the record
 *     stored at offset 0.
 *
 *   - If the ring buffer has wrapped, the oldest record is the record stored
 *     at the current offset.
 *
 * With variable length records, however, just knowing the current offset
 * doesn't suffice for determining the oldest valid record:  assuming that one
 * allows for arbitrary data, one has no way of searching forward from the
 * current offset to find the oldest valid record.  (That is, one has no way
 * of separating data from metadata.) It would be possible to simply refuse to
 * process any data in the ring buffer between the current offset and the
 * limit, but this leaves (potentially) an enormous amount of otherwise valid
 * data unprocessed.
 *
 * To effect ring buffering, we track two offsets in the buffer:  the current
 * offset and the _wrapped_ offset.  If a request is made to reserve some
 * amount of data, and the buffer has wrapped, the wrapped offset is
 * incremented until the wrapped offset minus the current offset is greater
 * than or equal to the reserve request.  This is done by repeatedly looking
 * up the ECB corresponding to the EPID at the current wrapped offset, and
 * incrementing the wrapped offset by the size of the data payload
 * corresponding to that ECB.  If this offset is greater than or equal to the
 * limit of the data buffer, the wrapped offset is set to 0.  Thus, the
 * current offset effectively "chases" the wrapped offset around the buffer.
 * Schematically:
 *
 *      base of data buffer --->  +------+--------------------+------+
 *                                | EPID | data               | EPID |
 *                                +------+--------+------+----+------+
 *                                | data          | EPID | data      |
 *                                +---------------+------+-----------+
 *                                | data, cont.                      |
 *                                +------+---------------------------+
 *                                | EPID | data                      |
 *           current offset --->  +------+---------------------------+
 *                                | invalid data                     |
 *           wrapped offset --->  +------+--------------------+------+
 *                                | EPID | data               | EPID |
 *                                +------+--------+------+----+------+
 *                                | data          | EPID | data      |
 *                                +---------------+------+-----------+
 *                                :                                  :
 *                                .                                  .
 *                                .        ... valid data ...        .
 *                                .                                  .
 *                                :                                  :
 *                                +------+-------------+------+------+
 *                                | EPID | data        | EPID | data |
 *                                +------+------------++------+------+
 *                                | data, cont.       | leftover     |
 *     limit of data buffer --->  +-------------------+--------------+
 *
 * If the amount of requested buffer space exceeds the amount of space
 * available between the current offset and the end of the buffer:
 *
 *  (1)  all words in the data buffer between the current offset and the limit
 *       of the data buffer (marked "leftover", above) are set to
 *       DTRACE_EPIDNONE
 *
 *  (2)  the wrapped offset is set to zero
 *
 *  (3)  the iteration process described above occurs until the wrapped offset
 *       is greater than the amount of desired space.
 *
 * The wrapped offset is implemented by (re-)using the inactive offset.
 * In a "switch" buffer policy, the inactive offset stores the offset in
 * the inactive buffer; in a "ring" buffer policy, it stores the wrapped
 * offset.
 *
 * DTrace Scratch Buffering
 *
 * Some ECBs may wish to allocate dynamically-sized temporary scratch memory.
 * To accommodate such requests easily, scratch memory may be allocated in
 * the buffer beyond the current offset plus the needed memory of the current
 * ECB.  If there isn't sufficient room in the buffer for the requested amount
 * of scratch space, the allocation fails and an error is generated.  Scratch
 * memory is tracked in the dtrace_mstate_t and is automatically freed when
 * the ECB ceases processing.  Note that ring buffers cannot allocate their
 * scratch from the principal buffer -- lest they needlessly overwrite older,
 * valid data.  Ring buffers therefore have their own dedicated scratch buffer
 * from which scratch is allocated.
 */

extern void dtrace_buffer_switch(dtrace_buffer_t *);
extern void dtrace_buffer_activate(dtrace_state_t *);
extern int dtrace_buffer_alloc(dtrace_buffer_t *, size_t, int, processorid_t);
extern void dtrace_buffer_drop(dtrace_buffer_t *);
extern intptr_t dtrace_buffer_reserve(dtrace_buffer_t *, size_t, size_t,
				      dtrace_state_t *, dtrace_mstate_t *);
extern void dtrace_buffer_polish(dtrace_buffer_t *);
extern void dtrace_buffer_free(dtrace_buffer_t *);

/*
 * DTrace framework/probe data synchronization
 * -------------------------------------------
 *
 * The dtrace_sync() facility is used to synchronize global DTrace framework
 * data with DTrace probe context.  The framework updates data and then calls
 * dtrace_sync().  dtrace_sync() loops until it observes all CPUs have been out
 * of probe context at least once.  This ensures all consumers are using the
 * updated data.
 *
 * DTrace probes have several requirements.  First DTrace probe context cannot
 * block.  DTrace probes execute with interrupts disabled.  Locks cannot be
 * acquired in DTrace probe context.  A second requirement is that DTrace
 * probes need to be as high performance as possible to minimize the effect of
 * enabled probes.
 *
 * DTrace framework data changes have their own requirements.  DTrace data
 * changes/syncs are extremely infrequent compared to DTrace probe firings.
 * Probes can be in commonly executed code.  A good trade-off is to favor
 * DTrace probe context performance over DTrace sync performance.
 *
 * To meet the above requirements, the DTrace data synchronization algorithm
 * is lock-less.  The DTrace probe path is wait-free.  The DTrace probe path
 * is memory-barrier-free in the common case to minimize probe effect.
 * dtrace_probe has been made membar free in the common case by adding a read
 * in dtrace_probe and adding an additional write and membar to dtrace_sync().
 *
 * A simple algorithm is to have dtrace_probe set a flag for its CPU when
 * entering DTrace probe context and clear the flag when it exits DTrace probe
 * context.  A producer of DTrace framework data checks the flag to detect and
 * synchronize with probe context.  Unfortunately memory ordering issues
 * complicate the implementation.  Memory barriers are required in probe
 * context for this simple approach to work.
 *
 * A simple implementation to sync with one CPU that works with any memory
 * ordering model is:
 *
 * DTrace probe:
 *    1. CPU->in_probe_context = B_TRUE;
 *    2. dtrace_membar_enter()// membar #StoreLoad|#StoreStore
 *    3. access framework shared data// critical section
 *    4. dtrace_membar_exit()// membar #LoadStore|#StoreStore
 *    5. CPU->in_probe_context = B_FALSE;
 *
 * DTrace framework dtrace_sync:
 *    0. update framework shared data
 *    1. dtrace_membar_enter()// membar #StoreLoad|#StoreStore
 *    2. while (CPU->in_probe_context == B_TRUE)
 *    3.     spin
 *    4. dtrace_membar_exit()// membar #LoadStore|#StoreStore
 *    5. produce shared dtrace data
 *
 * A note on memory ordering
 * -------------------------
 *
 * dtrace_membar_enter() guarantees later loads cannot complete before earlier
 * stores, and it guarantees later stores cannot complete before earlier stores.
 * dtrace_membar_enter() is, in SPARC parlance, a membar #StoreLoad|#StoreStore.
 *
 * dtrace_membar_exit() guarantees later stores cannot complete before earlier
 * loads, and it guarantees later stores cannot complete before earlier stores.
 * dtrace_membar_exit() is, in SPARC parlance, a membar #LoadStore|#StoreStore.
 *
 * Please see the SPARC and Intel processor guides on memory ordering.
 * All sun4v and Fujitsu processors are TSO (Total Store Order).  Modern
 * supported Intel and AMD processors have similar load and store ordering
 * to SPARC.  All processors currently supported by Solaris have these memory
 * ordering properties:
 * 1) Loads are ordered with respect to earlier loads.
 * 2) Stores are ordered with respect to earlier stores.
 * 3a) SPARC Atomic load-store behaves as if it were followed by a
 *     MEMBAR #LoadLoad, #LoadStore, and #StoreStore.
 * 3b) X86 Atomic operations serialize load and store.
 * 4) Stores cannot bypass earlier loads.
 *
 * The above implementation details allow the membars to be simplified thus:
 * A) dtrace_membar_enter() can be reduced to "membar #StoreLoad" on sparc.
 *    See property number 4 above.
 *    Since dtrace_membar_enter() is an atomic operation on x86, it cannot be
 *    reduced further.
 * B) dtrace_membar_exit() becomes a NOP on both SPARC and x86.
 *    See properties 2 and 4.
 *
 *
 * Elimination of membar #StoreLoad from dtrace probe context
 * ----------------------------------------------------------
 *
 * Furthermore it is possible to eliminate all memory barriers from the common
 * dtrace_probe() entry case.  The only membar needed in dtrace_probe is there
 * to prevent Loads of global DTrace framework data from passing the Store to
 * the "in_probe_context" flag (i.e. the dtrace_membar_enter()).
 * A Load at the beginning of the algorithm is also ordered with these later
 * Loads and Stores: the membar #StoreLoad can be replaced with a early Load of
 * a "sync_request" flag and a conditional branch on the flag value.
 *
 * dtrace_sync() first Stores to the "sync_request" flag, and dtrace_probe()
 * starts by Loading the flag.  This Load in dtrace_probe() of "sync_request"
 * is ordered with its later Store to the "in_probe_context" flag and
 * dtrace_probe's later Loads of DTrace framework data.  dtrace_probe() only
 * needs a membar #StoreLoad iff the "sync_request" flag is set.
 *
 * Optimized Synchronization Algorithm
 * -----------------------------------
 *
 * DTrace probe:
 * +  1a. request_flag = CPU->sync_request		// Load
 *    1b. CPU->in_probe_context = B_TRUE		// Store
 * +  2.  if request_flag > 0
 *            dtrace_membar_enter()			// membar #StoreLoad
 *    3. access framework shared data			// critical section
 * -
 *    5. CPU->in_probe_context = B_FALSE		// Store
 *
 * DTrace framework dtrace_sync:
 * +  1a. atomically add 1 to CPU->sync_request		// Store and
 *    1b. dtrace_membar_enter()				// membar #StoreLoad
 *    2.  while (CPU->in_probe_context == B_TRUE)	// Load
 *    3.      spin
 * +  4a. atomically subtract 1 from CPU->sync_request	// Load + Store
 * -
 *    5.  produce shared dtrace data
 *
 * This algorithm has been proven correct by analysis of all interleaving
 * scenarios of the above operations with the hardware memory ordering
 * described above.
 *
 * The Load and store of the flag pair is very inexpensive.  The cacheline with
 * the flag pair is never accessed by a different CPU except by dtrace_sync.
 * dtrace_sync is very uncommon compared to typical probe firings.  The removal
 * of membars from DTrace probe context at the expense of a Load and Store and
 * a conditional branch is a good performance win.
 *
 * As implemented there is one pair of flags per CPU.  The flags are in one
 * cacheline; they could be split into two cachelines if dtrace_sync was more
 * common.  dtrace_sync loops over all NCPU sets of flags.  dtrace_sync lazily
 * only does one dtrace_membar_enter() (step 1b) after setting all NCPU
 * sync_request flags.
 *
 * Sample aliasing could cause dtrace_sync() to always sample a CPU's
 * in_probe_context flag when the CPU is in probe context even if the CPU
 * left and returned to probe context one or more times since the last sample.
 * cpuc_in_probe_ctxt is implemented as an even/odd counter instead of a
 * boolean flag.  cpuc_in_probe_ctxt is odd when in probe context and even
 * when not in probe context.  Probe context increments cpuc_in_probe_ctxt when
 * entering and exiting.  dtrace_probe() handles re-entry by not increment the
 * counter for re-enterant entry and exit.
 */

/*
 * dtrace_membar_exit() is a NOP on current SPARC and X86 hardware.
 * It is defined as an inline asm statement to prevent the C optimizer from
 * moving C statements around the membar.
 */
#define	dtrace_membar_exit()						\
	__asm__ __volatile__("" ::: "memory")

/*
 * dtrace_membar_enter() does not need an explicit membar #StoreStore because
 * modern SPARC hardware is TSO: stores are ordered with other stores.
 */
#define	dtrace_membar_enter()						\
	mb();

#define	dtrace_safe_smt_pause()						\
	cpu_relax();

/*
 * Used by dtrace_probe() to flag entry to the the critical section.
 * dtrace_probe() context may be consuming DTrace framework data.
 *
 * cpuc_in_probe_ctxt is odd when in probe context and even when not in
 * probe context.  The flag must not be incremented when re-entering from
 * probe context.
 */
#define	DTRACE_SYNC_ENTER_CRITICAL(cookie, re_entry)			\
{									\
	uint64_t	requests;					\
	uint64_t	count;						\
									\
	local_irq_save(cookie);						\
									\
	requests = atomic64_read(&this_cpu_core->cpuc_sync_requests);	\
									\
	/* Increment flag iff it is even */				\
	count = atomic64_read(&this_cpu_core->cpuc_in_probe_ctx);	\
	re_entry = count & 0x1;						\
	atomic64_set(&this_cpu_core->cpuc_in_probe_ctx, count | 0x1);	\
	ASSERT(DTRACE_SYNC_IN_CRITICAL(smp_processor_id()));		\
									\
	/*								\
	 * Later Loads are ordered with respect to the Load of		\
	 * cpuc_sync_requests.  The Load is also guaranteed to complete	\
	 * before the store to cpuc_in_probe_ctxt.  Thus a member_enter	\
	 * is only needed when requests is not 0.  This is very		\
	 * uncommon.							\
	 */								\
	if (requests > 0) {						\
		dtrace_membar_enter();					\
	}								\
}

/*
 * Used by dtrace_probe() to flag exit from the critical section.
 * dtrace_probe context is no longer using DTrace framework data.
 */
#define	DTRACE_SYNC_EXIT_CRITICAL(cookie, re_entry)			\
{									\
	dtrace_membar_exit();						\
	ASSERT((re_entry | 0x1) ==  0x1);				\
									\
	/*								\
	 * flag must not be incremented when returning to probe context.\
	 */								\
	atomic64_add(~re_entry & 0x1, &this_cpu_core->cpuc_in_probe_ctx); \
	ASSERT(re_entry ==						\
	    (atomic64_read(&this_cpu_core->cpuc_in_probe_ctx) & 0x1));	\
	local_irq_restore(cookie);					\
}

/*
 * Used by dtrace_sync to inform dtrace_probe it needs to synchronize with
 * dtrace_sync.  dtrace_probe consumes the cpuc_sync_requests flag to determine
 * if it needs a membar_enter.  Not called from probe context.
 *
 * cpuc_sync_requests must be updated atomically by dtrace_sync because there
 * may be multiple dtrace_sync operations executing at the same time.
 * cpuc_sync_requests is a simple count of the number of concurrent
 * dtrace_sync requests.
 */
#define	DTRACE_SYNC_START(cpuid)					\
{									\
	atomic64_add(1, &(per_cpu_core(cpuid))->cpuc_sync_requests);	\
	ASSERT(atomic64_read(&per_cpu_core(cpuid)->cpuc_sync_requests) > 0);	\
}

/*
 * Used by dtrace_sync to flag dtrace_probe that it no longer needs to
 * synchronize with dtrace_sync.  Not called from probe context.
 */
#define	DTRACE_SYNC_END(cpuid)						\
{									\
	atomic64_add(-1, &(per_cpu_core(cpuid))->cpuc_sync_requests);	\
	ASSERT(atomic64_read(&per_cpu_core(cpuid)->cpuc_sync_requests) >= 0);	\
}

/*
 * The next two macros are used by dtrace_sync to check if the target CPU is in
 * DTrace probe context.  cpuc_in_probe_ctxt is a monotonically increasing
 * count which dtrace_probe() increments when entering and exiting probe
 * context.  The flag is odd when in probe context, and even when not in probe
 * context.
 */
#define	DTRACE_SYNC_IN_CRITICAL(cpuid)					\
	(atomic64_read(&per_cpu_core(cpuid)->cpuc_in_probe_ctx) & 0x1)

/*
 * Used to check if the target CPU left and then entered probe context again.
 */
#define	DTRACE_SYNC_CRITICAL_COUNT(cpuid)				\
	(atomic64_read(&per_cpu_core(cpuid)->cpuc_in_probe_ctx))

/*
 * The next three macros are bitmap operations used by dtrace_sync to keep track
 * of which CPUs it still needs to synchronize with.
 */
#define	DTRACE_SYNC_OUTSTANDING(cpuid, bitmap)				\
	(cpumask_test_cpu(cpuid, bitmap) == 1)

#define	DTRACE_SYNC_NEEDED(cpuid, bitmap)				\
	cpumask_set_cpu(cpuid, bitmap)

#define	DTRACE_SYNC_DONE(cpuid, bitmap)					\
	cpumask_clear_cpu(cpuid, bitmap)

extern uint64_t dtrace_sync_sample_count;
extern void dtrace_sync(void);

/*
 * DTrace Enabling Functions
 */
extern dtrace_enabling_t	*dtrace_retained;
extern dtrace_genid_t		dtrace_retained_gen;

extern dtrace_enabling_t *dtrace_enabling_create(dtrace_vstate_t *);
extern void dtrace_enabling_add(dtrace_enabling_t *, dtrace_ecbdesc_t *);
extern void dtrace_enabling_dump(dtrace_enabling_t *);
extern void dtrace_enabling_destroy(dtrace_enabling_t *);
extern int dtrace_enabling_retain(dtrace_enabling_t *);
extern int dtrace_enabling_replicate(dtrace_state_t *, dtrace_probedesc_t *,
				     dtrace_probedesc_t *);
extern void dtrace_enabling_retract(dtrace_state_t *);
extern int dtrace_enabling_match(dtrace_enabling_t *, int *);
extern void dtrace_enabling_matchall(void);
extern void dtrace_enabling_prime(dtrace_state_t *);
extern void dtrace_enabling_provide(dtrace_provider_t *);

/*
 * DOF functions
 */
extern void dtrace_dof_error(dof_hdr_t *, const char *);
extern dof_hdr_t *dtrace_dof_create(dtrace_state_t *);
extern dof_hdr_t *dtrace_dof_copyin(void __user *, int *);
extern dof_hdr_t *dtrace_dof_property(const char *);
extern void dtrace_dof_destroy(dof_hdr_t *);
extern int dtrace_dof_slurp(dof_hdr_t *, dtrace_vstate_t *, const cred_t *,
			    dtrace_enabling_t **, uint64_t, int);
extern int dtrace_dof_options(dof_hdr_t *, dtrace_state_t *);
extern void dtrace_helper_provide(dof_helper_t *dhp, pid_t pid);
extern int dtrace_helper_slurp(dof_hdr_t *, dof_helper_t *);
extern int dtrace_helper_destroygen(int);

/*
 * DTrace Anonymous Enabling Functions
 */
typedef struct dtrace_anon {
	dtrace_state_t *dta_state;
	dtrace_enabling_t *dta_enabling;
	processorid_t dta_beganon;
} dtrace_anon_t;

extern dtrace_anon_t		dtrace_anon;

extern dtrace_state_t *dtrace_anon_grab(void);
extern void dtrace_anon_property(void);

/*
 * DTrace Consumer State Functions
 */
extern struct kmem_cache	*dtrace_state_cachep;
extern size_t			dtrace_strsize_default;

extern ktime_t			dtrace_deadman_timeout;
extern int			dtrace_destructive_disallow;

extern dtrace_id_t		dtrace_probeid_begin;
extern dtrace_id_t		dtrace_probeid_end;
extern dtrace_id_t		dtrace_probeid_error;

extern dtrace_dynvar_t		dtrace_dynhash_sink;

extern struct user_namespace	*init_user_namespace;

extern int dtrace_dstate_init(dtrace_dstate_t *, size_t);
extern void dtrace_dstate_fini(dtrace_dstate_t *);
extern void dtrace_vstate_fini(dtrace_vstate_t *);
extern dtrace_state_t *dtrace_state_create(struct file *);
extern int dtrace_state_go(dtrace_state_t *, processorid_t *);
extern int dtrace_state_stop(dtrace_state_t *, processorid_t *);
extern int dtrace_state_option(dtrace_state_t *, dtrace_optid_t,
			       dtrace_optval_t);
extern void dtrace_state_destroy(dtrace_state_t *);

/*
 * DTrace Utility Functions
 */
extern void *dtrace_vzalloc(unsigned long);
extern void *dtrace_vzalloc_try(unsigned long);
extern char *dtrace_strdup(const char *);
extern int dtrace_strncmp(char *, char *, size_t);
extern size_t dtrace_strlen(const char *, size_t);
extern int dtrace_badattr(const dtrace_attribute_t *);
extern int dtrace_badname(const char *);
extern void dtrace_cred2priv(const cred_t *, uint32_t *, kuid_t *);

extern void ctf_forceload(void);

#define dtrace_membar_producer()	smp_wmb()
#define dtrace_membar_consumer()	smp_rmb()

typedef unsigned long	dtrace_icookie_t;

extern struct mutex	cpu_lock;

extern void dtrace_toxic_ranges(void (*)(uintptr_t, uintptr_t));
extern void dtrace_vpanic(const char *, va_list);
extern int dtrace_getipl(void);

extern dtrace_icookie_t dtrace_interrupt_disable(void);
extern void dtrace_interrupt_enable(dtrace_icookie_t);

typedef void 		(*dtrace_xcall_t)(void *);

extern void dtrace_xcall(processorid_t, dtrace_xcall_t, void *);

extern uintptr_t dtrace_fulword(void *);
extern uint8_t dtrace_fuword8(void *);
extern uint16_t dtrace_fuword16(void *);
extern uint32_t dtrace_fuword32(void *);
extern uint64_t dtrace_fuword64(void *);

extern void dtrace_probe_error(dtrace_state_t *, dtrace_epid_t, int, int, int,
			       uintptr_t);

extern void dtrace_getpcstack(uint64_t *, int, int, uint32_t *);
extern void dtrace_getupcstack(uint64_t *, int);
extern unsigned long dtrace_getufpstack(uint64_t *, uint64_t *, int);
extern uintptr_t dtrace_getfp(void);
extern uint64_t dtrace_getarg(int, int);
extern int dtrace_getstackdepth(dtrace_mstate_t *, int);
extern int dtrace_getustackdepth(void);
extern ulong_t dtrace_getreg(struct task_struct *, uint_t);
extern void dtrace_copyin(uintptr_t, uintptr_t, size_t,
			  volatile uint16_t *);
extern void dtrace_copyout(uintptr_t, uintptr_t, size_t,
			   volatile uint16_t *);
extern void dtrace_copyinstr(uintptr_t, uintptr_t, size_t,
			     volatile uint16_t *);
extern void dtrace_copyoutstr(uintptr_t, uintptr_t, size_t,
			      volatile uint16_t *);

/*
 * Plaforms that support a fast path to obtain the caller implement the
 * dtrace_caller() function.
 *
 * The first argument is the number of frames that should be skipped when
 * looking for a caller address.  The 2nd argument is a dummy argument that
 * is necessary for SPARC.
 *
 * On x86 this is effectively a NOP.
 *
 * On SPARC it is possible to retrieve the caller address from the register
 * windows without flushing them to the stack.  This involves performing
 * explicit rotation of the register windows.  Modification of the windowing
 * mechanism state alters all %i, %o, and %l registers so we are can only use
 * %g registers to store temporary data.
 *
 * On Linux a lot of %g registers are already allocated for specific purpose.
 * Saving temporaries to the stack would be a violation of the fast path code
 * logic. Therefore, the function prototype declares a 2nd argument that serves
 * as a temporary value.  A compiler will not expect that the value in %o1
 * will survive the call and therefore dtrace_caller() can use %o1 as a
 * temporary registe.
 */
extern uintptr_t dtrace_caller(int, int);

extern void dtrace_copyin_arch(uintptr_t, uintptr_t, size_t,
			       volatile uint16_t *);
extern void dtrace_copyinstr_arch(uintptr_t, uintptr_t, size_t,
				  volatile uint16_t *);

extern void pdata_init(dtrace_module_t *, struct module *);
extern void pdata_cleanup(dtrace_module_t *, struct module *);

extern void debug_enter(char *);

#endif /* _LINUX_DTRACE_IMPL_H */
