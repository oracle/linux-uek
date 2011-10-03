#ifndef _DTRACE_H_
#define _DTRACE_H_

#include <linux/cred.h>
#include <linux/idr.h>
#include <linux/ktime.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/stringify.h>
#include <linux/types.h>
#include <asm/bitsperlong.h>
#include <asm/ptrace.h>
#include <asm/sections.h>

#include "cyclic.h"

#define UINT8_MAX		(0xff)
#define UINT8_MIN		0
#define UINT16_MAX		(0xffff)
#define UINT16_MIN		0
#define UINT32_MAX		(0xffffffff)
#define UINT32_MIN		0
#define UINT64_MAX		(~0ULL)
#define UINT64_MIN		(0)
#define INT64_MAX		((long long)(~0ULL>>1))

#define NBBY			(__BITS_PER_LONG / sizeof (long))

/*
 * This is a bit unusual, but OpenSolaris seems to like it.  Basically, the
 * values below are the number of time units (sec, milli, micro, nano) that
 * comprise 1 second.  As such, it is the value of the respective multiplier.
 */
#define SEC			1
#define MILLISEC		1000
#define MICROSEC		1000000
#define NANOSEC			1000000000

#define DTRACE_CPUALL		-1
#define DTRACE_IDNONE		0
#define DTRACE_EPIDNONE		0
#define DTRACE_AGGIDNONE	0
#define DTRACE_AGGVARIDNONE	0
#define DTRACE_CACHEIDNONE	0
#define DTRACE_PROVNONE		0
#define DTRACE_METAPROVNONE	0
#define DTRACE_ARGNONE		-1

#define DTRACE_PROVNAMELEN	64
#define DTRACE_MODNAMELEN	64
#define DTRACE_FUNCNAMELEN	128
#define DTRACE_NAMELEN		64
#define DTRACE_FULLNAMELEN	(DTRACE_PROVNAMELEN + DTRACE_MODNAMELEN + \
				 DTRACE_FUNCNAMELEN + DTRACE_NAMELEN + 4)
#define DTRACE_ARGTYPELEN	128

#define DTRACE_PROBEKEY_MAXDEPTH	8

#define DTRACE_STABILITY_INTERNAL	0
#define DTRACE_STABILITY_PRIVATE	1
#define DTRACE_STABILITY_OBSOLETE	2
#define DTRACE_STABILITY_EXTERNAL	3
#define DTRACE_STABILITY_UNSTABLE	4
#define DTRACE_STABILITY_EVOLVING	5
#define DTRACE_STABILITY_STABLE		6
#define DTRACE_STABILITY_STANDARD	7
#define DTRACE_STABILITY_MAX		7

#define DTRACE_CLASS_UNKNOWN	0
#define DTRACE_CLASS_CPU	1
#define DTRACE_CLASS_PLATFORM	2
#define DTRACE_CLASS_GROUP	3
#define DTRACE_CLASS_ISA	4
#define DTRACE_CLASS_COMMON	5
#define DTRACE_CLASS_MAX	5

#define DTRACE_COND_OWNER	0x01
#define DTRACE_COND_USERMODE	0x02

#define DTRACE_ACCESS_KERNEL	0x1

#define DTRACE_CRA_PROC				0x0001
#define DTRACE_CRA_PROC_CONTROL			0x0002
#define DTRACE_CRA_PROC_DESTRUCTIVE_ALLUSER	0x0004
#define DTRACE_CRA_PROC_DESTRUCTIVE_CREDCHG	0x0010
#define DTRACE_CRA_KERNEL			0x0020
#define DTRACE_CRA_KERNEL_DESTRUCTIVE		0x0040

#define DTRACE_CRA_ALL		(DTRACE_CRA_PROC | \
				 DTRACE_CRA_PROC_CONTROL | \
				 DTRACE_CRA_PROC_DESTRUCTIVE_ALLUSER | \
				 DTRACE_CRA_PROC_DESTRUCTIVE_CREDCHG | \
				 DTRACE_CRA_KERNEL | \
				 DTRACE_CRA_KERNEL_DESTRUCTIVE)

#define DTRACE_CRV_ALLPROC	0x01
#define DTRACE_CRV_KERNEL	0x02
#define DTRACE_CRV_ALL		(DTRACE_CRV_ALLPROC | DTRACE_CRV_KERNEL)

#define DTRACE_MATCH_FAIL	-1
#define DTRACE_MATCH_NEXT	0
#define DTRACE_MATCH_DONE	1

#define DTRACE_PRIV_NONE	0x0000
#define DTRACE_PRIV_KERNEL	0x0001
#define DTRACE_PRIV_USER	0x0002
#define DTRACE_PRIV_PROC	0x0004
#define DTRACE_PRIV_OWNER	0x0008
#define DTRACE_PRIV_ALL		(DTRACE_PRIV_KERNEL | DTRACE_PRIV_USER | \
				 DTRACE_PRIV_PROC | DTRACE_PRIV_OWNER)

#define DTRACE_QUANTIZE_NBUCKETS		\
		(((sizeof (uint64_t) * NBBY) - 1) * 2 + 1)

#define DTRACE_QUANTIZE_ZEROBUCKET	((sizeof (uint64_t) * NBBY) - 1)

#define DTRACE_QUANTIZE_BUCKETVAL(buck)		\
	(int64_t)((buck) < DTRACE_QUANTIZE_ZEROBUCKET ? \
		  -(1LL << (DTRACE_QUANTIZE_ZEROBUCKET - 1 - (buck))) : \
		  (buck) == DTRACE_QUANTIZE_ZEROBUCKET ? 0 : \
		  1LL << ((buck) - DTRACE_QUANTIZE_ZEROBUCKET - 1))

#define DTRACE_LQUANTIZE_STEPSHIFT	48
#define DTRACE_LQUANTIZE_STEPMASK	((uint64_t)UINT16_MAX << 48)
#define DTRACE_LQUANTIZE_LEVELSHIFT	32
#define DTRACE_LQUANTIZE_LEVELMASK	((uint64_t)UINT16_MAX << 32)
#define DTRACE_LQUANTIZE_BASESHIFT	0
#define DTRACE_LQUANTIZE_BASEMASK	UINT32_MAX

#define DTRACE_LQUANTIZE_STEP(x)		\
		(uint16_t)(((x) & DTRACE_LQUANTIZE_STEPMASK) >> \
			   DTRACE_LQUANTIZE_STEPSHIFT)

#define DTRACE_LQUANTIZE_LEVELS(x)		\
		(uint16_t)(((x) & DTRACE_LQUANTIZE_LEVELMASK) >> \
			   DTRACE_LQUANTIZE_LEVELSHIFT)

#define DTRACE_LQUANTIZE_BASE(x)		\
		(int32_t)(((x) & DTRACE_LQUANTIZE_BASEMASK) >> \
			  DTRACE_LQUANTIZE_BASESHIFT)

#define DTRACE_USTACK_NFRAMES(x)	(uint32_t)((x) & UINT32_MAX)
#define DTRACE_USTACK_STRSIZE(x)	(uint32_t)((x) >> 32)
#define DTRACE_USTACK_ARG(x, y)		\
		((((uint64_t)(y)) << 32) | ((x) & UINT32_MAX))

#ifndef CONFIG_64BIT
# ifndef __LITTLE_ENDIAN
#  define DTRACE_PTR(type, name)	uint32_t name##pad; type *name
# else
#  define DTRACE_PTR(type, name)	type *name; uint32_t name##pad
# endif
#else
# define DTRACE_PTR(type, name)		type *name
#endif

#define DTRACEACT_NONE			0
#define DTRACEACT_DIFEXPR		1
#define DTRACEACT_EXIT			2
#define DTRACEACT_PRINTF		3
#define DTRACEACT_PRINTA		4
#define DTRACEACT_LIBACT		5

#define DTRACEACT_PROC			0x0100
#define DTRACEACT_USTACK		(DTRACEACT_PROC + 1)
#define DTRACEACT_JSTACK		(DTRACEACT_PROC + 2)
#define DTRACEACT_USYM			(DTRACEACT_PROC + 3)
#define DTRACEACT_UMOD			(DTRACEACT_PROC + 4)
#define DTRACEACT_UADDR			(DTRACEACT_PROC + 5)

#define DTRACEACT_PROC_DESTRUCTIVE	0x0200
#define DTRACEACT_STOP			(DTRACEACT_PROC_DESTRUCTIVE + 1)
#define DTRACEACT_RAISE			(DTRACEACT_PROC_DESTRUCTIVE + 2)
#define DTRACEACT_SYSTEM		(DTRACEACT_PROC_DESTRUCTIVE + 3)
#define DTRACEACT_FREOPEN		(DTRACEACT_PROC_DESTRUCTIVE + 4)

#define DTRACEACT_PROC_CONTROL		0x0300

#define DTRACEACT_KERNEL		0x0400
#define DTRACEACT_STACK			(DTRACEACT_KERNEL + 1)
#define DTRACEACT_SYM			(DTRACEACT_KERNEL + 2)
#define DTRACEACT_MOD			(DTRACEACT_KERNEL + 3)

#define DTRACEACT_KERNEL_DESTRUCTIVE	0x0500
#define DTRACEACT_BREAKPOINT		(DTRACEACT_KERNEL_DESTRUCTIVE + 1)
#define DTRACEACT_PANIC			(DTRACEACT_KERNEL_DESTRUCTIVE + 2)
#define DTRACEACT_CHILL			(DTRACEACT_KERNEL_DESTRUCTIVE + 3)

#define DTRACEACT_SPECULATIVE           0x0600
#define DTRACEACT_SPECULATE		(DTRACEACT_SPECULATIVE + 1)
#define DTRACEACT_COMMIT		(DTRACEACT_SPECULATIVE + 2)
#define DTRACEACT_DISCARD		(DTRACEACT_SPECULATIVE + 3)

#define DTRACEACT_AGGREGATION		0x0700
#define DTRACEAGG_COUNT			(DTRACEACT_AGGREGATION + 1)
#define DTRACEAGG_MIN			(DTRACEACT_AGGREGATION + 2)
#define DTRACEAGG_MAX			(DTRACEACT_AGGREGATION + 3)
#define DTRACEAGG_AVG			(DTRACEACT_AGGREGATION + 4)
#define DTRACEAGG_SUM			(DTRACEACT_AGGREGATION + 5)
#define DTRACEAGG_STDDEV		(DTRACEACT_AGGREGATION + 6)
#define DTRACEAGG_QUANTIZE		(DTRACEACT_AGGREGATION + 7)
#define DTRACEAGG_LQUANTIZE		(DTRACEACT_AGGREGATION + 8)

#define DTRACEACT_CLASS(x)		((x) & 0xff00)

#define DTRACEACT_ISAGG(x)		\
		(DTRACEACT_CLASS(x) == DTRACEACT_AGGREGATION)

#define DTRACEACT_ISDESTRUCTIVE(x)	\
		(DTRACEACT_CLASS(x) == DTRACEACT_PROC_DESTRUCTIVE || \
		 DTRACEACT_CLASS(x) == DTRACEACT_KERNEL_DESTRUCTIVE)

#define DTRACEACT_ISSPECULATIVE(x)	\
		(DTRACEACT_CLASS(x) == DTRACEACT_SPECULATIVE)

#define DTRACEACT_ISPRINTFLIKE(x)	\
		((x) == DTRACEACT_PRINTF || (x) == DTRACEACT_PRINTA || \
		 (x) == DTRACEACT_SYSTEM || (x) == DTRACEACT_FREOPEN)

/*
 * DTrace Faults
 *
 * The constants below DTRACEFLT_LIBRARY indicate probe processing faults;
 * constants at or above DTRACEFLT_LIBRARY indicate faults in probe
 * postprocessing at user-level.  Probe processing faults induce an ERROR
 * probe and are replicated in unistd.d to allow users' ERROR probes to decode
 * the error condition using thse symbolic labels.
 */
#define DTRACEFLT_UNKNOWN		0	/* Unknown fault */
#define DTRACEFLT_BADADDR		1	/* Bad address */
#define DTRACEFLT_BADALIGN		2	/* Bad alignment */
#define DTRACEFLT_ILLOP			3	/* Illegal operation */
#define DTRACEFLT_DIVZERO		4	/* Divide-by-zero */
#define DTRACEFLT_NOSCRATCH		5	/* Out of scratch space */
#define DTRACEFLT_KPRIV			6	/* Illegal kernel access */
#define DTRACEFLT_UPRIV			7	/* Illegal user access */
#define DTRACEFLT_TUPOFLOW		8	/* Tuple stack overflow */
#define DTRACEFLT_BADSTACK		9	/* Bad stack */

#define DTRACEFLT_LIBRARY		1000	/* Library-level fault */

#define DTRACEOPT_BUFSIZE	0
#define DTRACEOPT_BUFPOLICY	1
#define DTRACEOPT_DYNVARSIZE	2
#define DTRACEOPT_AGGSIZE	3
#define DTRACEOPT_SPECSIZE	4
#define DTRACEOPT_NSPEC		5
#define DTRACEOPT_STRSIZE	6
#define DTRACEOPT_CLEANRATE	7
#define DTRACEOPT_CPU		8
#define DTRACEOPT_BUFRESIZE	9
#define DTRACEOPT_GRABANON	10
#define DTRACEOPT_FLOWINDENT	11
#define DTRACEOPT_QUIET		12
#define DTRACEOPT_STACKFRAMES	13
#define DTRACEOPT_USTACKFRAMES	14
#define DTRACEOPT_AGGRATE	15
#define DTRACEOPT_SWITCHRATE	16
#define DTRACEOPT_STATUSRATE	17
#define DTRACEOPT_DESTRUCTIVE	18
#define DTRACEOPT_STACKINDENT	19
#define DTRACEOPT_RAWBYTES	20
#define DTRACEOPT_JSTACKFRAMES	21
#define DTRACEOPT_JSTACKSTRSIZE	22
#define DTRACEOPT_AGGSORTKEY	23
#define DTRACEOPT_AGGSORTREV	24
#define DTRACEOPT_AGGSORTPOS	25
#define DTRACEOPT_AGGSORTKEYPOS	26
#define DTRACEOPT_MAX		27

#define DTRACEOPT_UNSET		(dtrace_optval_t)-2

#define DTRACEOPT_BUFPOLICY_RING	0
#define DTRACEOPT_BUFPOLICY_FILL	1
#define DTRACEOPT_BUFPOLICY_SWITCH	2

#define DTRACEOPT_BUFRESIZE_AUTO	0
#define DTRACEOPT_BUFRESIZE_MANUAL	1

typedef unsigned char	uchar_t;
typedef unsigned int	uint_t;
typedef unsigned long	ulong_t;

typedef long		intptr_t;

typedef uint8_t		dtrace_stability_t;
typedef uint8_t		dtrace_class_t;

typedef uint16_t	dtrace_actkind_t;

typedef uint32_t	dtrace_aggid_t;
typedef uint32_t	dtrace_cacheid_t;
typedef uint32_t	dtrace_epid_t;
typedef uint32_t	dtrace_optid_t;
typedef uint32_t	dtrace_specid_t;
typedef uint32_t	processorid_t;

typedef uint64_t	dtrace_aggvarid_t;
typedef uint64_t	dtrace_genid_t;
typedef uint64_t	dtrace_optval_t;

typedef enum {
	TRUE = -1,
	FALSE = 0
} boolean_t;

typedef struct cred	cred_t;
typedef __be32		ipaddr_t;

typedef typeof(((struct pt_regs *)0)->ip)	pc_t;

#define P2ROUNDUP(x, a)	(-(-(x) & -(a)))

#if (BITS_PER_LONG == 64) || defined(CONFIG_KTIME_SCALAR)
# define KTIME_INIT(s, ns)	{ .tv64 = (s64)(s) * NSEC_PER_SEC + (s64)(ns) }
#else
# define KTIME_INIT(n, ns)	{ .tv = { .sec = (s), .nsec = (ns) } }
#endif
#define ktime_lt(t0, t1)	((t0).tv64 < (t1).tv64)
#define ktime_le(t0, t1)	((t0).tv64 <= (t1).tv64)
#define ktime_ge(t0, t1)	((t0).tv64 >= (t1).tv64)
#define ktime_gt(t0, t1)	((t0).tv64 > (t1).tv64)
#define ktime_nz(t0)		((t0).tv64 != 0LL)
#define ktime_cp(t0, t1)	((t0).tv64 = (t1).tv64)

#define idr_empty(idp)		((idp)->top == NULL)

typedef struct dtrace_ppriv {
	uint32_t dtpp_flags;
	uid_t dtpp_uid;
} dtrace_ppriv_t;

typedef struct dtrace_attribute {
	dtrace_stability_t dtat_name;
	dtrace_stability_t dtat_data;
	dtrace_class_t dtat_class;
} dtrace_attribute_t;

typedef struct dtrace_pattr {
	dtrace_attribute_t dtpa_provider;
	dtrace_attribute_t dtpa_mod;
	dtrace_attribute_t dtpa_func;
	dtrace_attribute_t dtpa_name;
	dtrace_attribute_t dtpa_args;
} dtrace_pattr_t;

typedef struct dtrace_providerdesc {
	char dtvd_name[DTRACE_PROVNAMELEN];
	dtrace_pattr_t dtvd_attr;
	dtrace_ppriv_t dtvd_priv;
} dtrace_providerdesc_t;

typedef uint32_t dtrace_id_t;

typedef struct dtrace_probedesc {
	dtrace_id_t dtpd_id;
	char dtpd_provider[DTRACE_PROVNAMELEN];
	char dtpd_mod[DTRACE_MODNAMELEN];
	char dtpd_func[DTRACE_FUNCNAMELEN];
	char dtpd_name[DTRACE_NAMELEN];
} dtrace_probedesc_t;

typedef struct dtrace_repldesc {
	dtrace_probedesc_t dtrpd_match;
	dtrace_probedesc_t dtrpd_create;
} dtrace_repldesc_t;

typedef struct dtrace_argdesc {
	dtrace_id_t dtargd_id;
	int dtargd_ndx;
	int dtargd_mapping;
	char dtargd_native[DTRACE_ARGTYPELEN];
	char dtargd_xlate[DTRACE_ARGTYPELEN];
} dtrace_argdesc_t;

typedef struct dtrace_pops {
	void (*dtps_provide)(void *, const dtrace_probedesc_t *);
	void (*dtps_provide_module)(void *, struct module *);
	int (*dtps_enable)(void *, dtrace_id_t, void *);
	void (*dtps_disable)(void *, dtrace_id_t, void *);
	void (*dtps_suspend)(void *, dtrace_id_t, void *);
	void (*dtps_resume)(void *, dtrace_id_t, void *);
	void (*dtps_getargdesc)(void *, dtrace_id_t, void *,
				dtrace_argdesc_t *);
	uint64_t (*dtps_getargval)(void *, dtrace_id_t, void *, int, int);
	int (*dtps_usermode)(void *, dtrace_id_t, void *);
	void (*dtps_destroy)(void *, dtrace_id_t, void *);
} dtrace_pops_t;

typedef struct dtrace_helper_probedesc {
	char *dthpb_mod;
	char *dthpb_func;
	char *dthpb_name;
	uint64_t dthpb_base;
	uint32_t *dthpb_offs;
	uint32_t *dthpb_enoffs;
	uint32_t dthpb_noffs;
	uint32_t dthpb_nenoffs;
	uint8_t *dthpb_args;
	uint8_t dthpb_xargc;
	uint8_t dthpb_nargc;
	char *dthpb_xtypes;
	char *dthpb_ntypes;
} dtrace_helper_probedesc_t;

typedef struct dtrace_helper_provdesc {
	char *dthpv_provname;
	dtrace_pattr_t dthpv_pattr;
} dtrace_helper_provdesc_t;

typedef struct dtrace_mops {
	void (*dtms_create_probe)(void *, void *, dtrace_helper_probedesc_t *);
	void (*dtms_provide_pid)(void *, dtrace_helper_provdesc_t *, pid_t);
	void (*dtms_remove_pid)(void *, dtrace_helper_provdesc_t *, pid_t);
} dtrace_mops_t;

typedef struct dtrace_provider {
	dtrace_pattr_t dtpv_attr;
	dtrace_ppriv_t dtpv_priv;
	dtrace_pops_t dtpv_pops;
	char *dtpv_name;
	void *dtpv_arg;
	uint_t dtpv_defunct;
	struct dtrace_provider *dtpv_next;
} dtrace_provider_t;

typedef uint32_t	dif_instr_t;

typedef struct dtrace_diftype {
	uint8_t dtdt_kind;
	uint8_t dtdt_ckind;
	uint8_t dtdt_flags;
	uint8_t dtdt_pad;
	uint32_t dtdt_size;
} dtrace_diftype_t;

typedef struct dtrace_difv {
	uint32_t dtdv_name;
	uint32_t dtdv_id;
	uint8_t dtdv_kind;
	uint8_t dtdv_scope;
	uint16_t dtdv_flags;
	dtrace_diftype_t dtdv_type;
} dtrace_difv_t;

typedef struct dtrace_difo {
	dif_instr_t *dtdo_buf;
	uint64_t *dtdo_inttab;
	char *dtdo_strtab;
	dtrace_difv_t *dtdo_vartab;
	uint_t dtdo_len;
	uint_t dtdo_intlen;
	uint_t dtdo_strlen;
	uint_t dtdo_varlen;
	dtrace_diftype_t dtdo_rtype;
	uint_t dtdo_refcnt;
	uint_t dtdo_destructive;
#ifndef __KERNEL__
	dtrace_diftype_t orig_dtdo_rtype;
	dof_relodesc_t *dtdo_kreltab;
	dof_relodesc_t *dtdo_ureltab;
	struct dt_node **dtdo_xlmtab;
	uint_t dtdo_krelen;
	uint_t dtdo_urelen;
	uint_t dtdo_xlmlen;
#endif
} dtrace_difo_t;

typedef struct dtrace_actdesc {
	dtrace_difo_t *dtad_difo;
	struct dtrace_actdesc *dtad_next;
	dtrace_actkind_t dtad_kind;
	uint32_t dtad_ntuple;
	uint64_t dtad_arg;
	uint64_t dtad_uarg;
	int dtad_refcnt;
} dtrace_actdesc_t;

typedef struct dtrace_predicate {
	dtrace_difo_t *dtp_difo;
	dtrace_cacheid_t dtp_cacheid;
	int dtp_refcnt;
} dtrace_predicate_t;

typedef struct dtrace_preddesc {
	dtrace_difo_t *dtpdd_difo;
	dtrace_predicate_t *dtpdd_predicate;
} dtrace_preddesc_t;

typedef struct dtrace_ecbdesc {
	dtrace_actdesc_t *dted_action;
	dtrace_preddesc_t dted_pred;
	dtrace_probedesc_t dted_probe;
	uint64_t dted_uarg;
	int dted_refcnt;
} dtrace_ecbdesc_t;

typedef struct dtrace_statvar {
	uint64_t dtsv_data;
	size_t dtsv_size;
	int dtsv_refcnt;
	dtrace_difv_t dtsv_var;
} dtrace_statvar_t;

/*
 * DTrace Metadata Description Structures
 *
 * DTrace separates the trace data stream from the metadata stream.  The only
 * metadata tokens placed in the data stream are enabled probe identifiers
 * (EPIDs) or (in the case of aggregations) aggregation identifiers.  In order
 * to determine the structure of the data, DTrace consumers pass the token to
 * the kernel, and receive in return a corresponding description of the enabled
 * probe (via the dtrace_eprobedesc structure) or the aggregation (via the
 * dtrace_aggdesc structure).  Both of these structures are expressed in terms
 * of record descriptions (via the dtrace_recdesc structure) that describe the
 * exact structure of the data.  Some record descriptions may also contain a
 * format identifier; this additional bit of metadata can be retrieved from the
 * kernel, for which a format description is returned via the dtrace_fmtdesc
 * structure.  Note that all four of these structures must be bitness-neutral
 * to allow for a 32-bit DTrace consumer on a 64-bit kernel.
 */
typedef struct dtrace_recdesc {
	dtrace_actkind_t dtrd_action;		/* kind of action */
	uint32_t dtrd_size;			/* size of record */
	uint32_t dtrd_offset;			/* offset in ECB's data */
	uint16_t dtrd_alignment;		/* required alignment */
	uint16_t dtrd_format;			/* format, if any */
	uint64_t dtrd_arg;			/* action argument */
	uint64_t dtrd_uarg;			/* user argument */
} dtrace_recdesc_t;

typedef struct dtrace_eprobedesc {
	dtrace_epid_t dtepd_epid;		/* enabled probe ID */
	dtrace_id_t dtepd_probeid;		/* probe ID */
	uint64_t dtepd_uarg;			/* library argument */
	uint32_t dtepd_size;			/* total size */
	int dtepd_nrecs;			/* number of records */
	dtrace_recdesc_t dtepd_rec[1];		/* recods themselves */
} dtrace_eprobedesc_t;

typedef struct dtrace_aggdesc {
	DTRACE_PTR(char, dtagd_name);		/* not filled in by kernel */
	dtrace_aggvarid_t dtagd_varid;		/* not filled in by kernel */
	int dtagd_flags;			/* not filled in by kernel */
	dtrace_aggid_t dtagd_id;		/* aggregation ID */
	dtrace_epid_t dtagd_epid;		/* enabled probe ID */
	uint32_t dtagd_size;			/* size in bytes */
	int dtagd_nrecs;			/* number of records */
	uint32_t dtagd_pad;			/* explicit padding */
	dtrace_recdesc_t dtagd_rec[1];		/* record descriptions */
} dtrace_aggdesc_t;

typedef struct dtrace_fmtdesc {
	DTRACE_PTR(char, dtfd_string);		/* format string */
	int dtfd_length;			/* length of format string */
	uint16_t dtfd_format;			/* format identifier */
} dtrace_fmtdesc_t;

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

typedef enum dtrace_activity {
	DTRACE_ACTIVITY_INACTIVE = 0,
	DTRACE_ACTIVITY_WARMUP,
	DTRACE_ACTIVITY_ACTIVE,
	DTRACE_ACTIVITY_DRAINING,
	DTRACE_ACTIVITY_COOLDOWN,
	DTRACE_ACTIVITY_STOPPED,
	DTRACE_ACTIVITY_KILLED
} dtrace_activity_t;

typedef enum dtrace_dstate_state {
	DTRACE_DSTATE_CLEAN = 0,
	DTRACE_DSTATE_EMPTY,
	DTRACE_DSTATE_DIRTY,
	DTRACE_DSTATE_RINSING
} dtrace_dstate_state_t;

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

typedef enum dtrace_dynvar_op {
	DTRACE_DYNVAR_ALLOC,
	DTRACE_DYNVAR_NOALLOC,
	DTRACE_DYNVAR_DEALLOC
} dtrace_dynvar_op_t;

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
#define DTRACE_MSTATE_ARGS		0x00000001
#define DTRACE_MSTATE_PROBE		0x00000002
#define DTRACE_MSTATE_EPID		0x00000004
#define DTRACE_MSTATE_TIMESTAMP		0x00000008
#define DTRACE_MSTATE_STACKDEPTH	0x00000010
#define DTRACE_MSTATE_CALLER		0x00000020
#define DTRACE_MSTATE_IPL		0x00000040
#define DTRACE_MSTATE_FLTOFFS		0x00000080
#define DTRACE_MSTATE_USTACKDEPTH	0x00000100
#define DTRACE_MSTATE_UCALLER		0x00000200

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

typedef enum dtrace_speculation_state {
	DTRACESPEC_INACTIVE = 0,
	DTRACESPEC_ACTIVE,
	DTRACESPEC_ACTIVEONE,
	DTRACESPEC_ACTIVEMANY,
	DTRACESPEC_COMMITTING,
	DTRACESPEC_COMMITTINGMANY,
	DTRACESPEC_DISCARDING
} dtrace_speculation_state_t;

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
	uint64_t dts_errors;
	uint32_t dts_speculations_busy;
	uint32_t dts_speculations_unavail;
	uint32_t dts_stkstroverflows;
	uint32_t dts_dblerrors;
	uint32_t dts_reserve;
	ktime_t dts_laststatus;
	cyclic_id_t dts_cleaner;
	cyclic_id_t dts_deadman;
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
 * DTrace Helpers
 *
 * In general, DTrace establishes probes in processes and takes actions on
 * processes without knowing their specific user-level structures.  Instead of
 * existing in the framework, process-specific knowledge is contained by the
 * enabling D program -- which can apply process-specific knowledge by making
 * appropriate use of DTrace primitives like copyin() and copyinstr() to
 * operate on user-level data.  However, there may exist some specific probes
 * of particular semantic relevance that the application developer may wish to
 * explicitly export.  For example, an application may wish to export a probe
 * at the point that it begins and ends certain well-defined transactions.  In
 * addition to providing probes, programs may wish to offer assistance for
 * certain actions.  For example, in highly dynamic environments (e.g., Java),
 * it may be difficult to obtain a stack trace in terms of meaningful symbol
 * names (the translation from instruction addresses to corresponding symbol
 * names may only be possible in situ); these environments may wish to define
 * a series of actions to be applied in situ to obtain a meaningful stack
 * trace.
 *
 * These two mechanisms -- user-level statically defined tracing and assisting
 * DTrace actions -- are provided via DTrace _helpers_.  Helpers are specified
 * via DOF, but unlike enabling DOF, helper DOF may contain definitions of
 * providers, probes and their arguments.  If a helper wishes to provide
 * action assistance, probe descriptions and corresponding DIF actions may be
 * specified in the helper DOF.  For such helper actions, however, the probe
 * description describes the specific helper:  all DTrace helpers have the
 * provider name "dtrace" and the module name "helper", and the name of the
 * helper is contained in the function name (for example, the ustack() helper
 * is named "ustack").  Any helper-specific name may be contained in the name
 * (for example, if a helper were to have a constructor, it might be named
 * "dtrace:helper:<helper>:init").  Helper actions are only called when the
 * action that they are helping is taken.  Helper actions may only return DIF
 * expressions, and may only call the following subroutines:
 *
 *    alloca()      <= Allocates memory out of the consumer's scratch space
 *    bcopy()       <= Copies memory to scratch space
 *    copyin()      <= Copies memory from user-level into consumer's scratch
 *    copyinto()    <= Copies memory into a specific location in scratch
 *    copyinstr()   <= Copies a string into a specific location in scratch
 *
 * Helper actions may only access the following built-in variables:
 *
 *    curthread     <= Current kthread_t pointer
 *    tid           <= Current thread identifier
 *    pid           <= Current process identifier
 *    ppid          <= Parent process identifier
 *    uid           <= Current user ID
 *    gid           <= Current group ID
 *    execname      <= Current executable name
 *    zonename      <= Current zone name
 *
 * Helper actions may not manipulate or allocate dynamic variables, but they
 * may have clause-local and statically-allocated global variables.  The
 * helper action variable state is specific to the helper action -- variables
 * used by the helper action may not be accessed outside of the helper
 * action, and the helper action may not access variables that like outside
 * of it.  Helper actions may not load from kernel memory at-large; they are
 * restricting to loading current user state (via copyin() and variants) and
 * scratch space.  As with probe enablings, helper actions are executed in
 * program order.  The result of the helper action is the result of the last
 * executing helper expression.
 *
 * Helpers -- composed of either providers/probes or probes/actions (or both)
 * -- are added by opening the "helper" minor node, and issuing an ioctl(2)
 * (DTRACEHIOC_ADDDOF) that specifies the dof_helper_t structure. This
 * encapsulates the name and base address of the user-level library or
 * executable publishing the helpers and probes as well as the DOF that
 * contains the definitions of those helpers and probes.
 *
 * The DTRACEHIOC_ADD and DTRACEHIOC_REMOVE are left in place for legacy
 * helpers and should no longer be used.  No other ioctls are valid on the
 * helper minor node.
 */
typedef struct dof_helper {
	char dofhp_mod[DTRACE_MODNAMELEN];	/* executable or library name */
	uint64_t dofhp_addr;			/* base address of object */
	uint64_t dofhp_dof;			/* address of helper DOF */
} dof_helper_t;

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
#define DTRACE_HELPER_ACTION_USTACK	0
#define DTRACE_NHELPER_ACTIONS		1

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
#define DTRACE_HELPTRACE_NEXT	(-1)
#define DTRACE_HELPTRACE_DONE	(-2)
#define DTRACE_HELPTRACE_ERR	(-3)

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

extern dtrace_pops_t		dtrace_provider_ops;

extern int			dtrace_opens;
extern int			dtrace_err_verbose;

extern dtrace_toxrange_t	*dtrace_toxrange;
extern int			dtrace_toxranges;

extern void dtrace_nullop(void);
extern int dtrace_enable_nullop(void);
extern int dtrace_istoxic(uintptr_t, size_t);

/*
 * DTrace Buffer Interface
 *
 * In order to get a snapshot of the principal or aggregation buffer,
 * user-level passes a buffer description to the kernel with the dtrace_bufdesc
 * structure.  This describes which CPU user-level is interested in, and
 * where user-level wishes the kernel to snapshot the buffer to (the
 * dtbd_data field).  The kernel uses the same structure to pass back some
 * information regarding the buffer:  the size of data actually copied out, the
 * number of drops, the number of errors, and the offset of the oldest record.
 * If the buffer policy is a "switch" policy, taking a snapshot of the
 * principal buffer has the additional effect of switching the active and
 * inactive buffers.  Taking a snapshot of the aggregation buffer _always_ has
 * the additional effect of switching the active and inactive buffers.
 */
typedef struct dtrace_bufdesc {
	uint64_t dtbd_size;			/* size of buffer */
	uint32_t dtbd_cpu;			/* CPU or DTRACE_CPUALL */
	uint32_t dtbd_errors;			/* number of errors */
	uint64_t dtbd_drops;			/* number of drops */
	DTRACE_PTR(char, dtbd_data);		/* data */
	uint64_t dtbd_oldest;			/* offset of oldest record */
} dtrace_bufdesc_t;

/*
 * DTrace Status
 *
 * The status of DTrace is relayed via the dtrace_status structure.  This
 * structure contains members to count drops other than the capacity drops
 * available via the buffer interface (see above).  This consists of dynamic
 * drops (including capacity dynamic drops, rinsing drops and dirty drops), and
 * speculative drops (including capacity speculative drops, drops due to busy
 * speculative buffers and drops due to unavailable speculative buffers).
 * Additionally, the status structure contains a field to indicate the number
 * of "fill"-policy buffers have been filled and a boolean field to indicate
 * that exit() has been called.  If the dtst_exiting field is non-zero, no
 * further data will be generated until tracing is stopped (at which time any
 * enablings of the END action will be processed); if user-level sees that
 * this field is non-zero, tracing should be stopped as soon as possible.
 */
typedef struct dtrace_status {
	uint64_t dtst_dyndrops;			/* dynamic drops */
	uint64_t dtst_dyndrops_rinsing;		/* dyn drops due to rinsing */
	uint64_t dtst_dyndrops_dirty;		/* dyn drops due to dirty */
	uint64_t dtst_specdrops;		/* speculative drops */
	uint64_t dtst_specdrops_busy;		/* spec drops due to busy */
	uint64_t dtst_specdrops_unavail;	/* spec drops due to unavail */
	uint64_t dtst_errors;			/* total errors */
	uint64_t dtst_filled;			/* number of filled bufs */
	uint64_t dtst_stkstroverflows;		/* stack string tab overflows */
	uint64_t dtst_dblerrors;		/* errors in ERROR probes */
	char dtst_killed;			/* non-zero if killed */
	char dtst_exiting;			/* non-zero if exit() called */
	char dtst_pad[6];			/* pad out to 64-bit align */
} dtrace_status_t;

/*
 * DTrace Configuration
 *
 * User-level may need to understand some elements of the kernel DTrace
 * configuration in order to generate correct DIF.  This information is
 * conveyed via the dtrace_conf structure.
 */
typedef struct dtrace_conf {
	uint_t dtc_difversion;			/* supported DIF version */
	uint_t dtc_difintregs;			/* # of DIF integer registers */
	uint_t dtc_diftupregs;			/* # of DIF tuple registers */
	uint_t dtc_ctfmodel;			/* CTF data model */
	/* Deviation from Solaris...  Used to just be 8 padding entries. */
	uint_t dtc_maxbufs;			/* max # of buffers */
	uint_t dtc_pad[7];			/* reserved for future use */
} dtrace_conf_t;

/*
 * DTrace Probe Context Functions
 */
#undef ASSERT
#ifdef CONFIG_DT_DEBUG
# define ASSERT(x)	((void)((x) || dtrace_assfail(#x, __FILE__, __LINE__)))
#else
# define ASSERT(x)	((void)0)
#endif

extern void dtrace_panic(const char *, ...);
extern int dtrace_assfail(const char *, const char *, int);
extern void dtrace_aggregate_min(uint64_t *, uint64_t, uint64_t);
extern void dtrace_aggregate_max(uint64_t *, uint64_t, uint64_t);
extern void dtrace_aggregate_quantize(uint64_t *, uint64_t, uint64_t);
extern void dtrace_aggregate_lquantize(uint64_t *, uint64_t, uint64_t);
extern void dtrace_aggregate_avg(uint64_t *, uint64_t, uint64_t);
extern void dtrace_aggregate_stddev(uint64_t *, uint64_t, uint64_t);
extern void dtrace_aggregate_count(uint64_t *, uint64_t, uint64_t);
extern void dtrace_aggregate_sum(uint64_t *, uint64_t, uint64_t);
extern void dtrace_aggregate(dtrace_aggregation_t *, dtrace_buffer_t *,
			     intptr_t, dtrace_buffer_t *, uint64_t, uint64_t);

/*
 * DTrace Probe Hashing Functions
 */
#define DTRACE_HASHNEXT(hash, probe)	\
	(dtrace_probe_t **)((uintptr_t)(probe) + (hash)->dth_nextoffs)
#define DTRACE_HASHPREV(hash, probe)	\
	(dtrace_probe_t **)((uintptr_t)(probe) + (hash)->dth_prevoffs)

extern dtrace_hash_t *dtrace_hash_create(uintptr_t, uintptr_t, uintptr_t);
extern void dtrace_hash_add(dtrace_hash_t *, dtrace_probe_t *);
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

extern int dtrace_match_priv(const dtrace_probe_t *, uint32_t, uid_t);
extern int dtrace_match_probe(const dtrace_probe_t *,
			      const dtrace_probekey_t *, uint32_t, uid_t);
extern int dtrace_match_glob(const char *, const char *, int);
extern int dtrace_match_string(const char *, const char *, int);
extern int dtrace_match_nul(const char *, const char *, int);
extern int dtrace_match_nonzero(const char *, const char *, int);
extern int dtrace_match(const dtrace_probekey_t *, uint32_t, uid_t,
			int (*matched)(dtrace_probe_t *, void *), void *);
extern void dtrace_probekey(const dtrace_probedesc_t *, dtrace_probekey_t *);

/*
 * DTrace Provider-to-Framework API Functions
 */
typedef uintptr_t		dtrace_provider_id_t;
typedef uintptr_t		dtrace_meta_provider_id_t;

extern dtrace_provider_t	*dtrace_provider;

extern int dtrace_register(const char *, const dtrace_pattr_t *, uint32_t,
			   cred_t *, const dtrace_pops_t *, void *,
			   dtrace_provider_id_t *);
extern int dtrace_unregister(dtrace_provider_id_t);
extern void dtrace_invalidate(dtrace_provider_id_t);
extern int dtrace_attached(void);
extern int dtrace_condense(dtrace_provider_id_t);

extern int dtrace_meta_register(const char *, const dtrace_mops_t *, void *,
				dtrace_meta_provider_id_t *);
extern int dtrace_meta_unregister(dtrace_meta_provider_id_t);

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
#define DTRACE_ANCHORED(probe)	((probe)->dtpr_func[0] != '\0')
#define DTRACE_FLAGS2FLT(flags)						\
	(((flags) & CPU_DTRACE_BADADDR) ? DTRACEFLT_BADADDR :		\
	 ((flags) & CPU_DTRACE_ILLOP) ? DTRACEFLT_ILLOP :		\
	 ((flags) & CPU_DTRACE_DIVZERO) ? DTRACEFLT_DIVZERO :		\
	 ((flags) & CPU_DTRACE_KPRIV) ? DTRACEFLT_KPRIV :		\
	 ((flags) & CPU_DTRACE_UPRIV) ? DTRACEFLT_UPRIV :		\
	 ((flags) & CPU_DTRACE_TUPOFLOW) ?  DTRACEFLT_TUPOFLOW :	\
	 ((flags) & CPU_DTRACE_BADALIGN) ?  DTRACEFLT_BADALIGN :	\
	 ((flags) & CPU_DTRACE_NOSCRATCH) ?  DTRACEFLT_NOSCRATCH :	\
	 ((flags) & CPU_DTRACE_BADSTACK) ?  DTRACEFLT_BADSTACK :	\
	 DTRACEFLT_UNKNOWN)


extern dtrace_id_t dtrace_probe_create(dtrace_provider_id_t, const char *,
				       const char *, const char *, int,
				       void *);
extern int dtrace_probe_enable(const dtrace_probedesc_t *,
			       dtrace_enabling_t *);
extern void *dtrace_probe_arg(dtrace_provider_id_t, dtrace_id_t);
extern void dtrace_probe_description(const dtrace_probe_t *,
				     dtrace_probedesc_t *);
extern void dtrace_probe_provide(dtrace_probedesc_t *, dtrace_provider_t *);
extern void dtrace_probe(dtrace_id_t, uintptr_t, uintptr_t, uintptr_t,
			 uintptr_t, uintptr_t);
extern void dtrace_probe_init(void);
extern void dtrace_probe_exit(void);
extern void dtrace_probe_remove_id(dtrace_id_t);
extern dtrace_probe_t *dtrace_probe_lookup_id(dtrace_id_t);
extern dtrace_id_t dtrace_probe_lookup(dtrace_provider_id_t, const char *,
				       const char *, const char *);
extern dtrace_probe_t *dtrace_probe_get_next(dtrace_id_t);
extern int dtrace_probe_for_each(int (*)(int, void *, void *), void *);

/*
 * DTrace Kernel Hooks
 */
extern void (*dtrace_modload)(struct module *);
extern void (*dtrace_modunload)(struct module *);

/*
 * DTrace DIF Object Functions
 *
 * DTrace Intermediate Format (DIF)
 *
 * The following definitions describe the DTrace Intermediate Format (DIF), a
 * a RISC-like instruction set and program encoding used to represent
 * predicates and actions that can be bound to DTrace probes.  The constants
 * below defining the number of available registers are suggested minimums; the
 * compiler should use DTRACEIOC_CONF to dynamically obtain the number of
 * registers provided by the current DTrace implementation.
 */
#define DIF_VERSION_1	1
#define DIF_VERSION_2	2
#define DIF_VERSION	DIF_VERSION_2
#define DIF_DIR_NREGS	8
#define DIF_DTR_NREGS	8

#define DIF_OP_OR	1		/* or   r1, r2, rd */
#define DIF_OP_XOR	2		/* xor  r1, r2, rd */
#define DIF_OP_AND	3		/* and  r1, r2, rd */
#define DIF_OP_SLL	4		/* sll  r1, r2, rd */
#define DIF_OP_SRL	5		/* srl  r1, r2, rd */
#define DIF_OP_SUB	6		/* sub  r1, r2, rd */
#define DIF_OP_ADD	7		/* add  r1, r2, rd */
#define DIF_OP_MUL	8		/* mul  r1, r2, rd */
#define DIF_OP_SDIV	9		/* sdiv r1, r2, rd */
#define DIF_OP_UDIV	10		/* udiv r1, r2, rd */
#define DIF_OP_SREM	11		/* srem r1, r2, rd */
#define DIF_OP_UREM	12		/* urem r1, r2, rd */
#define DIF_OP_NOT	13		/* not  r1, rd */
#define DIF_OP_MOV	14		/* mov  r1, rd */
#define DIF_OP_CMP	15		/* cmp  r1, r2 */
#define DIF_OP_TST	16		/* tst  r1 */
#define DIF_OP_BA	17		/* ba   label */
#define DIF_OP_BE	18		/* be   label */
#define DIF_OP_BNE	19		/* bne  label */
#define DIF_OP_BG	20		/* bg   label */
#define DIF_OP_BGU	21		/* bgu  label */
#define DIF_OP_BGE	22		/* bge  label */
#define DIF_OP_BGEU	23		/* bgeu label */
#define DIF_OP_BL	24		/* bl   label */
#define DIF_OP_BLU	25		/* blu  label */
#define DIF_OP_BLE	26		/* ble  label */
#define DIF_OP_BLEU	27		/* bleu label */
#define DIF_OP_LDSB	28		/* ldsb [r1], rd */
#define DIF_OP_LDSH	29		/* ldsh [r1], rd */
#define DIF_OP_LDSW	30		/* ldsw [r1], rd */
#define DIF_OP_LDUB	31		/* ldub [r1], rd */
#define DIF_OP_LDUH	32		/* lduh [r1], rd */
#define DIF_OP_LDUW	33		/* lduw [r1], rd */
#define DIF_OP_LDX	34		/* ldx  [r1], rd */
#define DIF_OP_RET	35		/* ret  rd */
#define DIF_OP_NOP	36		/* nop */
#define DIF_OP_SETX	37		/* setx intindex, rd */
#define DIF_OP_SETS	38		/* sets strindex, rd */
#define DIF_OP_SCMP	39		/* scmp r1, r2 */
#define DIF_OP_LDGA	40		/* ldga var, ri, rd */
#define DIF_OP_LDGS	41		/* ldgs var, rd */
#define DIF_OP_STGS	42		/* stgs var, rs */
#define DIF_OP_LDTA	43		/* ldta var, ri, rd */
#define DIF_OP_LDTS	44		/* ldts var, rd */
#define DIF_OP_STTS	45		/* stts var, rs */
#define DIF_OP_SRA	46		/* sra  r1, r2, rd */
#define DIF_OP_CALL	47		/* call subr, rd */
#define DIF_OP_PUSHTR	48		/* pushtr type, rs, rr */
#define DIF_OP_PUSHTV	49		/* pushtv type, rs, rv */
#define DIF_OP_POPTS	50		/* popts */
#define DIF_OP_FLUSHTS	51		/* flushts */
#define DIF_OP_LDGAA	52		/* ldgaa var, rd */
#define DIF_OP_LDTAA	53		/* ldtaa var, rd */
#define DIF_OP_STGAA	54		/* stgaa var, rs */
#define DIF_OP_STTAA	55		/* sttaa var, rs */
#define DIF_OP_LDLS	56		/* ldls var, rd */
#define DIF_OP_STLS	57		/* stls var, rs */
#define DIF_OP_ALLOCS	58		/* allocs r1, rd */
#define DIF_OP_COPYS	59		/* copys  r1, r2, rd */
#define DIF_OP_STB	60		/* stb  r1, [rd] */
#define DIF_OP_STH	61		/* sth  r1, [rd] */
#define DIF_OP_STW	62		/* stw  r1, [rd] */
#define DIF_OP_STX	63		/* stx  r1, [rd] */
#define DIF_OP_ULDSB	64		/* uldsb [r1], rd */
#define DIF_OP_ULDSH	65		/* uldsh [r1], rd */
#define DIF_OP_ULDSW	66		/* uldsw [r1], rd */
#define DIF_OP_ULDUB	67		/* uldub [r1], rd */
#define DIF_OP_ULDUH	68		/* ulduh [r1], rd */
#define DIF_OP_ULDUW	69		/* ulduw [r1], rd */
#define DIF_OP_ULDX	70		/* uldx  [r1], rd */
#define DIF_OP_RLDSB	71		/* rldsb [r1], rd */
#define DIF_OP_RLDSH	72		/* rldsh [r1], rd */
#define DIF_OP_RLDSW	73		/* rldsw [r1], rd */
#define DIF_OP_RLDUB	74		/* rldub [r1], rd */
#define DIF_OP_RLDUH	75		/* rlduh [r1], rd */
#define DIF_OP_RLDUW	76		/* rlduw [r1], rd */
#define DIF_OP_RLDX	77		/* rldx  [r1], rd */
#define DIF_OP_XLATE	78		/* xlate xlrindex, rd */
#define DIF_OP_XLARG	79		/* xlarg xlrindex, rd */

#define DIF_INTOFF_MAX		0xffff
#define DIF_STROFF_MAX		0xffff
#define DIF_REGISTER_MAX	0xff
#define DIF_VARIABLE_MAX	0xffff
#define DIF_SUBROUTINE_MAX	0xffff

#define DIF_VAR_ARRAY_MIN	0x0000
#define DIF_VAR_ARRAY_UBASE	0x0080
#define DIF_VAR_ARRAY_MAX	0x00ff

#define DIF_VAR_OTHER_MIN	0x0100
#define DIF_VAR_OTHER_UBASE	0x0500
#define DIF_VAR_OTHER_MAX	0xffff

#define DIF_VAR_ARGS		0x0000
#define DIF_VAR_REGS		0x0001
#define DIF_VAR_UREGS		0x0002
#define DIF_VAR_CURTHREAD	0x0100
#define DIF_VAR_TIMESTAMP	0x0101
#define DIF_VAR_VTIMESTAMP	0x0102
#define DIF_VAR_IPL		0x0103
#define DIF_VAR_EPID		0x0104
#define DIF_VAR_ID		0x0105
#define DIF_VAR_ARG0		0x0106
#define DIF_VAR_ARG1		0x0107
#define DIF_VAR_ARG2		0x0108
#define DIF_VAR_ARG3		0x0109
#define DIF_VAR_ARG4		0x010a
#define DIF_VAR_ARG5		0x010b
#define DIF_VAR_ARG6		0x010c
#define DIF_VAR_ARG7		0x010d
#define DIF_VAR_ARG8		0x010e
#define DIF_VAR_ARG9		0x010f
#define DIF_VAR_STACKDEPTH	0x0110
#define DIF_VAR_CALLER		0x0111
#define DIF_VAR_PROBEPROV	0x0112
#define DIF_VAR_PROBEMOD	0x0113
#define DIF_VAR_PROBEFUNC	0x0114
#define DIF_VAR_PROBENAME	0x0115
#define DIF_VAR_PID		0x0116
#define DIF_VAR_TID		0x0117
#define DIF_VAR_EXECNAME	0x0118
#define DIF_VAR_ZONENAME	0x0119
#define DIF_VAR_WALLTIMESTAMP	0x011a
#define DIF_VAR_USTACKDEPTH	0x011b
#define DIF_VAR_UCALLER		0x011c
#define DIF_VAR_PPID		0x011d
#define DIF_VAR_UID		0x011e
#define DIF_VAR_GID		0x011f
#define DIF_VAR_ERRNO		0x0120

#define DIF_SUBR_RAND			0
#define DIF_SUBR_MUTEX_OWNED		1
#define DIF_SUBR_MUTEX_OWNER		2
#define DIF_SUBR_MUTEX_TYPE_ADAPTIVE	3
#define DIF_SUBR_MUTEX_TYPE_SPIN	4
#define DIF_SUBR_RW_READ_HELD		5
#define DIF_SUBR_RW_WRITE_HELD		6
#define DIF_SUBR_RW_ISWRITER		7
#define DIF_SUBR_COPYIN			8
#define DIF_SUBR_COPYINSTR		9
#define DIF_SUBR_SPECULATION		10
#define DIF_SUBR_PROGENYOF		11
#define DIF_SUBR_STRLEN			12
#define DIF_SUBR_COPYOUT		13
#define DIF_SUBR_COPYOUTSTR		14
#define DIF_SUBR_ALLOCA			15
#define DIF_SUBR_BCOPY			16
#define DIF_SUBR_COPYINTO		17
#define DIF_SUBR_MSGDSIZE		18
#define DIF_SUBR_MSGSIZE		19
#define DIF_SUBR_GETMAJOR		20
#define DIF_SUBR_GETMINOR		21
#define DIF_SUBR_DDI_PATHNAME		22
#define DIF_SUBR_STRJOIN		23
#define DIF_SUBR_LLTOSTR		24
#define DIF_SUBR_BASENAME		25
#define DIF_SUBR_DIRNAME		26
#define DIF_SUBR_CLEANPATH		27
#define DIF_SUBR_STRCHR			28
#define DIF_SUBR_STRRCHR		29
#define DIF_SUBR_STRSTR			30
#define DIF_SUBR_STRTOK			31
#define DIF_SUBR_SUBSTR			32
#define DIF_SUBR_INDEX			33
#define DIF_SUBR_RINDEX			34
#define DIF_SUBR_HTONS			35
#define DIF_SUBR_HTONL			36
#define DIF_SUBR_HTONLL			37
#define DIF_SUBR_NTOHS			38
#define DIF_SUBR_NTOHL			39
#define DIF_SUBR_NTOHLL			40
#define DIF_SUBR_INET_NTOP		41
#define DIF_SUBR_INET_NTOA		42
#define DIF_SUBR_INET_NTOA6		43

#define DIF_SUBR_MAX			43

#define DIF_INSTR_OP(i)			(((i) >> 24) & 0xff)
#define DIF_INSTR_R1(i)			(((i) >> 16) & 0xff)
#define DIF_INSTR_R2(i)			(((i) >>  8) & 0xff)
#define DIF_INSTR_RD(i)			((i) & 0xff)
#define DIF_INSTR_RS(i)			((i) & 0xff)
#define DIF_INSTR_LABEL(i)		((i) & 0xffffff)
#define DIF_INSTR_VAR(i)		(((i) >>  8) & 0xffff)
#define DIF_INSTR_INTEGER(i)		(((i) >>  8) & 0xffff)
#define DIF_INSTR_STRING(i)		(((i) >>  8) & 0xffff)
#define DIF_INSTR_SUBR(i)		(((i) >>  8) & 0xffff)
#define DIF_INSTR_TYPE(i)		(((i) >> 16) & 0xff)
#define DIF_INSTR_XLREF(i)		(((i) >>  8) & 0xffff)
#define DIF_INSTR_FMT(op, r1, r2, d) \
			(((op) << 24) | ((r1) << 16) | ((r2) << 8) | (d))

#define DIF_INSTR_NOT(r1, d)		(DIF_INSTR_FMT(DIF_OP_NOT, r1, 0, d))
#define DIF_INSTR_MOV(r1, d)		(DIF_INSTR_FMT(DIF_OP_MOV, r1, 0, d))
#define DIF_INSTR_CMP(op, r1, r2)	(DIF_INSTR_FMT(op, r1, r2, 0))
#define DIF_INSTR_TST(r1)		(DIF_INSTR_FMT(DIF_OP_TST, r1, 0, 0))
#define DIF_INSTR_BRANCH(op, label)	(((op) << 24) | (label))
#define DIF_INSTR_LOAD(op, r1, d)	(DIF_INSTR_FMT(op, r1, 0, d))
#define DIF_INSTR_STORE(op, r1, d)	(DIF_INSTR_FMT(op, r1, 0, d))
#define DIF_INSTR_SETX(i, d)		((DIF_OP_SETX << 24) | ((i) << 8) | (d))
#define DIF_INSTR_SETS(s, d)		((DIF_OP_SETS << 24) | ((s) << 8) | (d))
#define DIF_INSTR_RET(d)		(DIF_INSTR_FMT(DIF_OP_RET, 0, 0, d))
#define DIF_INSTR_NOP			(DIF_OP_NOP << 24)
#define DIF_INSTR_LDA(op, v, r, d)	(DIF_INSTR_FMT(op, v, r, d))
#define DIF_INSTR_LDV(op, v, d)		(((op) << 24) | ((v) << 8) | (d))
#define DIF_INSTR_STV(op, v, rs)	(((op) << 24) | ((v) << 8) | (rs))
#define DIF_INSTR_CALL(s, d)		((DIF_OP_CALL << 24) | ((s) << 8) | (d))
#define DIF_INSTR_PUSHTS(op, t, r2, rs)	(DIF_INSTR_FMT(op, t, r2, rs))
#define DIF_INSTR_POPTS			(DIF_OP_POPTS << 24)
#define DIF_INSTR_FLUSHTS		(DIF_OP_FLUSHTS << 24)
#define DIF_INSTR_ALLOCS(r1, d)		(DIF_INSTR_FMT(DIF_OP_ALLOCS, r1, 0, d))
#define DIF_INSTR_COPYS(r1, r2, d)	(DIF_INSTR_FMT(DIF_OP_COPYS, r1, r2, d))
#define DIF_INSTR_XLATE(op, r, d)	(((op) << 24) | ((r) << 8) | (d))

#define DIF_REG_R0		0

#define DIF_TYPE_CTF		0
#define DIF_TYPE_STRING		1

#define DIF_TF_BYREF		0x1

#define DIFV_KIND_ARRAY		0
#define DIFV_KIND_SCALAR	1

#define DIFV_SCOPE_GLOBAL	0
#define DIFV_SCOPE_THREAD	1
#define DIFV_SCOPE_LOCAL	2

#define DIFV_F_REF		0x1
#define DIFV_F_MOD		0x2

/*
 * Test whether alloc_sz bytes will fit in the scratch region.  We isolate
 * alloc_sz on the righthand side of the comparison in order to avoid overflow
 * or underflow in the comparison with it.  This is simpler than the INRANGE
 * check above, because we know that the dtms_scratch_ptr is valid in the
 * range.  Allocations of size zero are allowed.
 */
#define DTRACE_INSCRATCH(mstate, alloc_sz) \
	((mstate)->dtms_scratch_base + (mstate)->dtms_scratch_size - \
	 (mstate)->dtms_scratch_ptr >= (alloc_sz))

extern uint8_t dtrace_load8(uintptr_t);
extern uint16_t dtrace_load16(uintptr_t);
extern uint32_t dtrace_load32(uintptr_t);
extern uint64_t dtrace_load64(uintptr_t);

extern void dtrace_bzero(void *, size_t);

extern int dtrace_vcanload(void *, dtrace_diftype_t *, dtrace_mstate_t *,
			   dtrace_vstate_t *);

extern int dtrace_difo_validate(dtrace_difo_t *, dtrace_vstate_t *, uint_t,
				const cred_t *);
extern int dtrace_difo_cacheable(dtrace_difo_t *);
extern void dtrace_difo_hold(dtrace_difo_t *);
extern void dtrace_difo_init(dtrace_difo_t *, dtrace_vstate_t *);
extern void dtrace_difo_release(dtrace_difo_t *, dtrace_vstate_t *);

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

#define DTRACEBUF_RING		0x0001		/* bufpolicy set to "ring" */
#define DTRACEBUF_FILL		0x0002		/* bufpolicy set to "fill" */
#define DTRACEBUF_NOSWITCH	0x0004		/* do not switch buffer */
#define DTRACEBUF_WRAPPED	0x0008		/* ring buffer has wrapped */
#define DTRACEBUF_DROPPED	0x0010		/* drops occurred */
#define DTRACEBUF_ERROR		0x0020		/* errors occurred */
#define DTRACEBUF_FULL		0x0040		/* "fill" buffer is full */
#define DTRACEBUF_CONSUMED	0x0080		/* buffer has been consumed */
#define DTRACEBUF_INACTIVE	0x0100		/* buffer is not yet active */

#define DTRACE_STORE(type, tomax, offset, what) \
	do { \
	*((type *)((uintptr_t)(tomax) + (uintptr_t)(offset))) = (type)(what); \
	} while (0)

extern void dtrace_buffer_switch(dtrace_buffer_t *);
extern void dtrace_buffer_activate(dtrace_state_t *);
extern int dtrace_buffer_alloc(dtrace_buffer_t *, size_t, int, processorid_t);
extern void dtrace_buffer_drop(dtrace_buffer_t *);
extern intptr_t dtrace_buffer_reserve(dtrace_buffer_t *, size_t, size_t,
				      dtrace_state_t *, dtrace_mstate_t *);
extern void dtrace_buffer_polish(dtrace_buffer_t *);
extern void dtrace_buffer_free(dtrace_buffer_t *);

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
 * DTrace DOF Functions
 */

/*
 * DTrace Object Format (DOF)
 *
 * DTrace programs can be persistently encoded in the DOF format so that they
 * may be embedded in other programs (for example, in an ELF file) or in the
 * dtrace driver configuration file for use in anonymous tracing.  The DOF
 * format is versioned and extensible so that it can be revised and so that
 * internal data structures can be modified or extended compatibly.  All DOF
 * structures use fixed-size types, so the 32-bit and 64-bit representations
 * are identical and consumers can use either data model transparently.
 *
 * The file layout is structured as follows:
 *
 * +---------------+-------------------+----- ... ----+---- ... ------+
 * |   dof_hdr_t   |  dof_sec_t[ ... ] |   loadable   | non-loadable  |
 * | (file header) | (section headers) | section data | section data  |
 * +---------------+-------------------+----- ... ----+---- ... ------+
 * |<------------ dof_hdr.dofh_loadsz --------------->|               |
 * |<------------ dof_hdr.dofh_filesz ------------------------------->|
 *
 * The file header stores meta-data including a magic number, data model for
 * the instrumentation, data encoding, and properties of the DIF code within.
 * The header describes its own size and the size of the section headers.  By
 * convention, an array of section headers follows the file header, and then
 * the data for all loadable sections and unloadable sections.  This permits
 * consumer code to easily download the headers and all loadable data into the
 * DTrace driver in one contiguous chunk, omitting other extraneous sections.
 *
 * The section headers describe the size, offset, alignment, and section type
 * for each section.  Sections are described using a set of #defines that tell
 * the consumer what kind of data is expected.  Sections can contain links to
 * other sections by storing a dof_secidx_t, an index into the section header
 * array, inside of the section data structures.  The section header includes
 * an entry size so that sections with data arrays can grow their structures.
 *
 * The DOF data itself can contain many snippets of DIF (i.e. >1 DIFOs), which
 * are represented themselves as a collection of related DOF sections.  This
 * permits us to change the set of sections associated with a DIFO over time,
 * and also permits us to encode DIFOs that contain different sets of sections.
 * When a DOF section wants to refer to a DIFO, it stores the dof_secidx_t of a
 * section of type DOF_SECT_DIFOHDR.  This section's data is then an array of
 * dof_secidx_t's which in turn denote the sections associated with this DIFO.
 *
 * This loose coupling of the file structure (header and sections) to the
 * structure of the DTrace program itself (ECB descriptions, action
 * descriptions, and DIFOs) permits activities such as relocation processing
 * to occur in a single pass without having to understand D program structure.
 *
 * Finally, strings are always stored in ELF-style string tables along with a
 * string table section index and string table offset.  Therefore strings in
 * DOF are always arbitrary-length and not bound to the current implementation.
 */

#define DOF_ID_SIZE     16      /* total size of dofh_ident[] in bytes */

typedef struct dof_hdr {
	uint8_t dofh_ident[DOF_ID_SIZE];
	uint32_t dofh_flags;
	uint32_t dofh_hdrsize;
	uint32_t dofh_secsize;
	uint32_t dofh_secnum;
	uint64_t dofh_secoff;
	uint64_t dofh_loadsz;
	uint64_t dofh_filesz;
	uint64_t dofh_pad;
} dof_hdr_t;

#define DOF_ID_MAG0	0
#define DOF_ID_MAG1	1
#define DOF_ID_MAG2	2
#define DOF_ID_MAG3	3
#define DOF_ID_MODEL	4
#define DOF_ID_ENCODING	5
#define DOF_ID_VERSION	6
#define DOF_ID_DIFVERS	7
#define DOF_ID_DIFIREG	8
#define DOF_ID_DIFTREG	9
#define DOF_ID_PAD	10

#define DOF_MAG_MAG0	0x7F
#define DOF_MAG_MAG1	'D'
#define DOF_MAG_MAG2	'O'
#define DOF_MAG_MAG3	'F'

#define DOF_MAG_STRING	"\177DOF"
#define DOF_MAG_STRLEN	4

#define DOF_MODEL_NONE	0
#define DOF_MODEL_ILP32	1
#define DOF_MODEL_LP64	2

#ifdef CONFIG_64BIT
#define DOF_MODEL_NATIVE	DOF_MODEL_LP64
#else
#define DOF_MODEL_NATIVE	DOF_MODEL_ILP32
#endif

#define DOF_ENCODE_NONE	0
#define DOF_ENCODE_LSB	1
#define DOF_ENCODE_MSB	2

#ifdef _BIG_ENDIAN
#define DOF_ENCODE_NATIVE	DOF_ENCODE_MSB
#else
#define DOF_ENCODE_NATIVE	DOF_ENCODE_LSB
#endif

#define DOF_VERSION_1	1
#define DOF_VERSION_2	2
#define DOF_VERSION	DOF_VERSION_2

#define DOF_FL_VALID	0

typedef uint32_t	dof_secidx_t;
typedef uint32_t	dof_stridx_t;

#define DOF_SECIDX_NONE	-1U
#define DOF_STRIDX_NONE	-1U

typedef struct dof_sec {
	uint32_t dofs_type;
	uint32_t dofs_align;
	uint32_t dofs_flags;
	uint32_t dofs_entsize;
	uint64_t dofs_offset;
	uint64_t dofs_size;
} dof_sec_t;

#define DOF_SECT_NONE		0
#define DOF_SECT_COMMENTS	1
#define DOF_SECT_SOURCE		2
#define DOF_SECT_ECBDESC	3
#define DOF_SECT_PROBEDESC	4
#define DOF_SECT_ACTDESC	5
#define DOF_SECT_DIFOHDR	6
#define DOF_SECT_DIF		7
#define DOF_SECT_STRTAB		8
#define DOF_SECT_VARTAB		9
#define DOF_SECT_RELTAB		10
#define DOF_SECT_TYPTAB		11
#define DOF_SECT_URELHDR	12
#define DOF_SECT_KRELHDR	13
#define DOF_SECT_OPTDESC	14
#define DOF_SECT_PROVIDER	15
#define DOF_SECT_PROBES		16
#define DOF_SECT_PRARGS		17
#define DOF_SECT_PROFFS		18
#define DOF_SECT_INTTAB		19
#define DOF_SECT_UTSNAME	20
#define DOF_SECT_XLTAB		21
#define DOF_SECT_XLMEMBERS	22
#define DOF_SECT_XLIMPORT	23
#define DOF_SECT_XLEXPORT	24
#define DOF_SECT_PREXPORT	25
#define DOF_SECT_PRENOFFS       26

#define DOF_SECF_LOAD		1

#define DOF_SEC_ISLOADABLE(x)						      \
		(((x) == DOF_SECT_ECBDESC) || ((x) == DOF_SECT_PROBEDESC) ||  \
		((x) == DOF_SECT_ACTDESC) || ((x) == DOF_SECT_DIFOHDR) ||     \
		((x) == DOF_SECT_DIF) || ((x) == DOF_SECT_STRTAB) ||	      \
		((x) == DOF_SECT_VARTAB) || ((x) == DOF_SECT_RELTAB) ||	      \
		((x) == DOF_SECT_TYPTAB) || ((x) == DOF_SECT_URELHDR) ||      \
		((x) == DOF_SECT_KRELHDR) || ((x) == DOF_SECT_OPTDESC) ||     \
		((x) == DOF_SECT_PROVIDER) || ((x) == DOF_SECT_PROBES) ||     \
		((x) == DOF_SECT_PRARGS) || ((x) == DOF_SECT_PROFFS) ||	      \
		((x) == DOF_SECT_INTTAB) || ((x) == DOF_SECT_XLTAB) ||	      \
		((x) == DOF_SECT_XLMEMBERS) || ((x) == DOF_SECT_XLIMPORT) ||  \
		((x) == DOF_SECT_XLIMPORT) || ((x) == DOF_SECT_XLEXPORT) ||   \
		((x) == DOF_SECT_PREXPORT) || ((x) == DOF_SECT_PRENOFFS))

typedef struct dof_ecbdesc {
	dof_secidx_t dofe_probes;
	dof_secidx_t dofe_pred;
	dof_secidx_t dofe_actions;
	uint32_t dofe_pad;
	uint64_t dofe_uarg;
} dof_ecbdesc_t;

typedef struct dof_probedesc {
	dof_secidx_t dofp_strtab;
	dof_stridx_t dofp_provider;
	dof_stridx_t dofp_mod;
	dof_stridx_t dofp_func;
	dof_stridx_t dofp_name;
	uint32_t dofp_id;
} dof_probedesc_t;

typedef struct dof_actdesc {
	dof_secidx_t dofa_difo;
	dof_secidx_t dofa_strtab;
	uint32_t dofa_kind;
	uint32_t dofa_ntuple;
	uint64_t dofa_arg;
	uint64_t dofa_uarg;
} dof_actdesc_t;

typedef struct dof_difohdr {
	dtrace_diftype_t dofd_rtype;
	dof_secidx_t dofd_links[1];
 } dof_difohdr_t;

typedef struct dof_relohdr {
	dof_secidx_t dofr_strtab;
	dof_secidx_t dofr_relsec;
	dof_secidx_t dofr_tgtsec;
} dof_relohdr_t;

typedef struct dof_relodesc {
	dof_stridx_t dofr_name;
	uint32_t dofr_type;
	uint64_t dofr_offset;
	uint64_t dofr_data;
} dof_relodesc_t;

#define DOF_RELO_NONE	0
#define DOF_RELO_SETX	1

typedef struct dof_optdesc {
	uint32_t dofo_option;
	dof_secidx_t dofo_strtab;
	uint64_t dofo_value;
} dof_optdesc_t;

typedef uint32_t	dof_attr_t;

#define DOF_ATTR(n, d, c)	(((n) << 24) | ((d) << 16) | ((c) << 8))
#define DOF_ATTR_NAME(a)	(((a) >> 24) & 0xff)
#define DOF_ATTR_DATA(a)	(((a) >> 16) & 0xff)
#define DOF_ATTR_CLASS(a)	(((a) >>  8) & 0xff)

typedef struct dof_provider {
	dof_secidx_t dofpv_strtab;
	dof_secidx_t dofpv_probes;
	dof_secidx_t dofpv_prargs;
	dof_secidx_t dofpv_proffs;
	dof_stridx_t dofpv_name;
	dof_attr_t dofpv_provattr;
	dof_attr_t dofpv_modattr;
	dof_attr_t dofpv_funcattr;
	dof_attr_t dofpv_nameattr;
	dof_attr_t dofpv_argsattr;
	dof_secidx_t dofpv_prenoffs;
} dof_provider_t;

typedef struct dof_probe {
	uint64_t dofpr_addr;
	dof_stridx_t dofpr_func;
	dof_stridx_t dofpr_name;
	dof_stridx_t dofpr_nargv;
	dof_stridx_t dofpr_xargv;
	uint32_t dofpr_argidx;
	uint32_t dofpr_offidx;
	uint8_t dofpr_nargc;
	uint8_t dofpr_xargc;
	uint16_t dofpr_noffs;
	uint32_t dofpr_enoffidx;
	uint16_t dofpr_nenoffs;
	uint16_t dofpr_pad1;
	uint32_t dofpr_pad2;
} dof_probe_t;

typedef struct dof_xlator {
	dof_secidx_t dofxl_members;
	dof_secidx_t dofxl_strtab;
	dof_stridx_t dofxl_argv;
	uint32_t dofxl_argc;
	dof_stridx_t dofxl_type;
	dof_attr_t dofxl_attr;
} dof_xlator_t;

typedef struct dof_xlmember {
	dof_secidx_t dofxm_difo;
	dof_stridx_t dofxm_name;
	dtrace_diftype_t dofxm_type;
} dof_xlmember_t;

typedef struct dof_xlref {
	dof_secidx_t dofxr_xlator;
	uint32_t dofxr_member;
	uint32_t dofxr_argn;
} dof_xlref_t;

extern dof_hdr_t *dtrace_dof_create(dtrace_state_t *);
extern dof_hdr_t *dtrace_dof_copyin(void __user *, int *);
extern dof_hdr_t *dtrace_dof_property(const char *);
extern void dtrace_dof_destroy(dof_hdr_t *);
extern int dtrace_dof_slurp(dof_hdr_t *, dtrace_vstate_t *, const cred_t *,
			    dtrace_enabling_t **, uint64_t, int);
extern int dtrace_dof_options(dof_hdr_t *, dtrace_state_t *);

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
extern struct kmem_cache	*dtrace_state_cache;
extern size_t			dtrace_strsize_default;

extern ktime_t			dtrace_deadman_timeout;
extern int			dtrace_destructive_disallow;

extern dtrace_id_t		dtrace_probeid_begin;
extern dtrace_id_t		dtrace_probeid_end;
extern dtrace_id_t		dtrace_probeid_error;

extern dtrace_dynvar_t		dtrace_dynhash_sink;

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
extern void dtrace_cred2priv(const cred_t *, uint32_t *, uid_t *);

#define DT_PROVIDER_MODULE(name, priv)					\
  dtrace_provider_id_t name##_id;					\
									\
  static int __init name##_init(void)					\
  {									\
	int ret = 0;							\
									\
	ret = name##_dev_init();					\
	if (ret)							\
		goto failed;						\
									\
	ret = dtrace_register(__stringify(name), &name##_attr, priv,	\
			      NULL, &name##_pops, NULL, &name##_id);	\
	if (ret)							\
		goto failed;						\
									\
	return 0;							\
									\
  failed:								\
	return ret;							\
  }									\
									\
  static void __exit name##_exit(void)					\
  {									\
	dtrace_unregister(name##_id);					\
	name##_dev_exit();						\
  }									\
									\
  module_init(name##_init);						\
  module_exit(name##_exit);

#define dtrace_membar_producer()	mb()
#define dtrace_membar_consumer()	mb()

typedef unsigned long	dtrace_icookie_t;

#define DTRACE_CPUFLAG_ISSET(flag) \
	(cpu_core[smp_processor_id()].cpuc_dtrace_flags & (flag))

#define DTRACE_CPUFLAG_SET(flag) \
	(cpu_core[smp_processor_id()].cpuc_dtrace_flags |= (flag))

#define DTRACE_CPUFLAG_CLEAR(flag) \
	(cpu_core[smp_processor_id()].cpuc_dtrace_flags &= ~(flag))

#define CPU_DTRACE_NOFAULT	0x0001
#define CPU_DTRACE_DROP		0x0002
#define CPU_DTRACE_BADADDR	0x0004
#define CPU_DTRACE_BADALIGN	0x0008
#define CPU_DTRACE_DIVZERO	0x0010
#define CPU_DTRACE_ILLOP	0x0020
#define CPU_DTRACE_NOSCRATCH	0x0040
#define CPU_DTRACE_KPRIV	0x0080
#define CPU_DTRACE_UPRIV	0x0100
#define CPU_DTRACE_TUPOFLOW	0x0200
#define CPU_DTRACE_ENTRY	0x0800
#define CPU_DTRACE_BADSTACK	0x1000

#define CPU_DTRACE_FAULT	(CPU_DTRACE_BADADDR | CPU_DTRACE_BADALIGN | \
				 CPU_DTRACE_DIVZERO | CPU_DTRACE_ILLOP | \
				 CPU_DTRACE_NOSCRATCH | CPU_DTRACE_KPRIV | \
				 CPU_DTRACE_UPRIV | CPU_DTRACE_TUPOFLOW | \
				 CPU_DTRACE_BADSTACK)
#define CPU_DTRACE_ERROR	(CPU_DTRACE_FAULT | CPU_DTRACE_DROP)

#define CPUC_SIZE	(sizeof (uint16_t) + sizeof(uint8_t) + \
			 sizeof(uintptr_t) + sizeof(struct mutex))
#define CPUC_PADSIZE	(192 - CPUC_SIZE)

typedef struct cpu_core {
	uint16_t cpuc_dtrace_flags;
	uint8_t cpuc_dcpc_intr_state;
	uint8_t cpuc_pad[CPUC_PADSIZE];
	uintptr_t cpuc_dtrace_illval;
	struct mutex cpuc_pid_lock;

	uintptr_t cpu_dtrace_caller;
	ktime_t cpu_dtrace_chillmark;
	ktime_t cpu_dtrace_chilled;
} cpu_core_t;

extern cpu_core_t		cpu_core[];
extern struct mutex		cpu_lock;

extern void dtrace_sync(void);
extern void dtrace_toxic_ranges(void (*)(uintptr_t, uintptr_t));
extern void dtrace_vpanic(const char *, va_list);
extern int dtrace_getipl(void);

extern ktime_t dtrace_gethrestime(void);

typedef enum dtrace_vtime_state {
	DTRACE_VTIME_INACTIVE = 0,	/* No DTrace, no TNF */
	DTRACE_VTIME_ACTIVE,		/* DTrace virtual time, no TNF */
	DTRACE_VTIME_INACTIVE_TNF,	/* No DTrace, TNF active */
	DTRACE_VTIME_ACTIVE_TNF		/* DTrace virtual time _and_ TNF */
} dtrace_vtime_state_t;

extern dtrace_vtime_state_t	dtrace_vtime_active;

extern void dtrace_vtime_enable(void);
extern void dtrace_vtime_disable(void);

extern ktime_t dtrace_gethrtime(void);
extern ktime_t dtrace_getwalltime(void);

extern dtrace_icookie_t dtrace_interrupt_disable(void);
extern void dtrace_interrupt_enable(dtrace_icookie_t);

typedef void 		(*dtrace_xcall_t)(void *);

extern void dtrace_xcall(processorid_t, dtrace_xcall_t, void *);

extern uint8_t dtrace_fuword8(void *);
extern uint16_t dtrace_fuword16(void *);
extern uint32_t dtrace_fuword32(void *);
extern uint64_t dtrace_fuword64(void *);

extern void dtrace_probe_error(dtrace_state_t *, dtrace_epid_t, int, int, int,
			       uintptr_t);

extern void dtrace_getpcstack(uint64_t *, int, int, uint32_t *);
extern void dtrace_getupcstack(uint64_t *, int);
extern void dtrace_getufpstack(uint64_t *, uint64_t *, int);
extern uintptr_t dtrace_getfp(void);
extern uint64_t dtrace_getarg(int, int);
extern int dtrace_getstackdepth(int);
extern int dtrace_getustackdepth(void);
extern ulong_t dtrace_getreg(struct pt_regs *, uint_t);
extern void dtrace_copyin(uintptr_t, uintptr_t, size_t, volatile uint16_t *);
extern void dtrace_copyout(uintptr_t, uintptr_t, size_t, volatile uint16_t *);
extern void dtrace_copyinstr(uintptr_t, uintptr_t, size_t,
			     volatile uint16_t *);
extern void dtrace_copyoutstr(uintptr_t, uintptr_t, size_t,
			      volatile uint16_t *);
extern uintptr_t dtrace_caller(int);

extern void debug_enter(char *);

#define KERNELBASE	(uintptr_t)_text

/*
 * regset.h information
 */
#ifdef __i386__
# define REG_SS		18      /* only stored on a privilege transition */
# define REG_UESP	17      /* only stored on a privilege transition */
# define REG_EFL	16
# define REG_CS		15
# define REG_EIP	14
# define REG_ERR	13
# define REG_TRAPNO	12
# define REG_EAX	11
# define REG_ECX	10
# define REG_EDX	9
# define REG_EBX	8
# define REG_ESP	7
# define REG_EBP	6
# define REG_ESI	5
# define REG_EDI	4
# define REG_DS		3
# define REG_ES		2
# define REG_FS		1
# define REG_GS		0
#else
# define REG_DS		25
# define REG_ES		24
# define REG_GS		23
# define REG_FS		22
# define REG_SS		21
# define REG_RSP	20
# define REG_RFL	19
# define REG_CS		18
# define REG_RIP	17
# define REG_ERR	16
# define REG_TRAPNO	15
# define REG_RAX	14
# define REG_RCX	13
# define REG_RDX	12
# define REG_RBX	11
# define REG_RBP	10
# define REG_RSI	9
# define REG_RDI	8
# define REG_R8		7
# define REG_R9		6
# define REG_R10	5
# define REG_R11	4
# define REG_R12	3
# define REG_R13	2
# define REG_R14	1
# define REG_R15	0
#endif

#if defined(__i386__) || defined(__x86_64__)
# define DTRACE_INVOP_PUSHL_EBP	1
# define DTRACE_INVOP_POPL_EBP	2
# define DTRACE_INVOP_LEAVE	3
# define DTRACE_INVOP_NOP	4
# define DTRACE_INVOP_RET	5
#endif

#ifdef CONFIG_DT_DEBUG_MUTEX
# define _mutex_lock(x)		mutex_lock(x)
# define _mutex_unlock(x)	mutex_unlock(x)

# define mutex_lock(x)		do {					      \
				    printk(KERN_DEBUG			      \
					   "mutex_lock(%s) at %s::%d\n",      \
					   __stringify(x),		      \
					   __FILE__, __LINE__);		      \
				    _mutex_lock(x);			      \
				} while (0)
# define mutex_unlock(x)	do {					      \
				    printk(KERN_DEBUG			      \
					   "mutex_unlock(%s) at %s::%d\n",    \
					   __stringify(x),		      \
					   __FILE__, __LINE__);		      \
				    _mutex_unlock(x);			      \
				} while (0)
#endif

#endif /* _DTRACE_H_ */
