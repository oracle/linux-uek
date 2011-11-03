/*
 * FILE:	profile_dev.c
 * DESCRIPTION:	Profile Interrupt Tracing: device file handling
 *
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 *
 * Copyright 2010, 2011 Oracle, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <linux/fs.h>
#include <linux/ktime.h>
#include <linux/miscdevice.h>
#include <linux/slab.h>
#include <asm/irq_regs.h>
#include <asm/ptrace.h>

#include "dtrace.h"
#include "dtrace_dev.h"
#include "profile.h"

/* #define OMNI_CYCLICS */
/* #define PROBE_PCS */

#define PROF_NAMELEN		15
#define PROF_PROFILE		0
#define PROF_TICK		1
#define PROF_PREFIX_PROFILE	"profile-"
#define PROF_PREFIX_TICK	"tick-"

typedef struct profile_probe {
	char		prof_name[PROF_NAMELEN];
	dtrace_id_t	prof_id;
	int		prof_kind;
	ktime_t		prof_interval;
	cyclic_id_t	prof_cyclic;
} profile_probe_t;

typedef struct profile_probe_percpu {
	ktime_t		profc_expected;
	ktime_t		profc_interval;
	profile_probe_t	*profc_probe;
} profile_probe_percpu_t;

static ktime_t	profile_interval_min = KTIME_INIT(0, NANOSEC / 5000);
static int	profile_aframes = 0;

#ifdef OMNI_CYCLICS
static int	profile_rates[] = {
				    97, 199, 499, 997, 1999,
				    4001, 4999, 0, 0, 0,
				    0, 0, 0, 0, 0,
				    0, 0, 0, 0, 0,
				  };
#endif
static int	profile_ticks[] = {
				    1, 10, 100, 500, 1000,
				    5000, 0, 0, 0, 0,
				    0, 0, 0, 0, 0,
				  };

/*
 * profile_max defines the upper bound on the number of profile probes that
 * can exist (this is to prevent malicious or clumsy users from exhausing
 * system resources by creating a slew of profile probes). At mod load time,
 * this gets its value from PROFILE_MAX_DEFAULT or profile-max-probes if it's
 * present as module parameter.
 * FIXME: module parameter yet to be implemented.
 */
#define PROFILE_MAX_DEFAULT	1000	/* default max. number of probes */

static int	profile_max;		/* maximum number of profile probes */
static atomic_t	profile_total;		/* current number of profile probes */

static void profile_tick(void *arg)
{
	profile_probe_t	*prof = arg;
	struct pt_regs	*regs = get_irq_regs();
	unsigned long	pc = 0, upc = 0;

#ifdef PROBE_PCS
	if (user_mode(regs))
		upc = GET_IP(regs);
	else
		pc = GET_IP(regs);
#endif

	dtrace_probe(prof->prof_id, pc, upc, 0, 0, 0);
}

#ifdef OMNI_CYCLICS
static void profile_prof(void *arg)
{
	profile_probe_percpu_t	*pcpu = arg;
	profile_probe_t		*prof = pcpu->profc_probe;
	ktime_t			late;
	struct pt_regs		*regs = get_irq_regs();
	unsigned long		pc = 0, upc = 0;

	late = ktime_sub(dtrace_gethrtime(), pcpu->profc_expected);
	pcpu->profc_expected = ktime_add(pcpu->profc_expected,
					 pcpu->profc_interval);

#ifdef PROBE_PCS
	if (user_mode(regs))
		upc = GET_IP(regs);
	else
		pc = GET_IP(regs);
#endif

	dtrace_probe(prof->prof_id, pc, upc, ktime_to_ns(late), 0, 0);
}

static void profile_online(void *arg, processorid_t cpu, cyc_handler_t *hdlr,
			   cyc_time_t *when)
{
	profile_probe_t		*prof = arg;
	profile_probe_percpu_t	*pcpu;

	pcpu = kzalloc(sizeof(profile_probe_percpu_t), GFP_KERNEL);
	pcpu->profc_probe = prof;

	hdlr->cyh_func = profile_prof;
	hdlr->cyh_arg = pcpu;
	hdlr->cyh_level = CY_HIGH_LEVEL;

	when->cyt_interval = prof->prof_interval;
	when->cyt_when = ktime_add(dtrace_gethrtime(), when->cyt_interval);

	pcpu->profc_expected = when->cyt_when;
	pcpu->profc_interval = when->cyt_interval;
}

static void profile_offline(void *arg, processorid_t cpu, void *oarg)
{
	profile_probe_percpu_t	*pcpu = oarg;

	ASSERT(pcpu->profc_probe == arg);

	kfree(pcpu);
}
#endif

static void profile_create(ktime_t interval, const char *name, int kind)
{
	profile_probe_t	*prof;
	int		nr_frames = 0; /* FIXME */

	if (profile_aframes)
		nr_frames = profile_aframes;

	if (ktime_lt(interval, profile_interval_min))
		return;

	if (dtrace_probe_lookup(profile_id, NULL, NULL, name) != 0)
		return;

	atomic_inc(&profile_total);
	if (atomic_read(&profile_total) > profile_max) {
		atomic_dec(&profile_total);
		return;
	}

	prof = kzalloc(sizeof(profile_probe_t), GFP_KERNEL);
	strcpy(prof->prof_name, name);
	prof->prof_interval = interval;
	prof->prof_cyclic = CYCLIC_NONE;
	prof->prof_kind = kind;
	prof->prof_id = dtrace_probe_create(profile_id, NULL, NULL, name,
					    nr_frames, prof);
}

void profile_provide(void *arg, const dtrace_probedesc_t *desc)
{
	int		i, j, rate, kind;
	long		val = 0, mult = 1, mult_s = 0, mult_ns = 0, len;
	ktime_t		interval;
	const char	*name, *suffix = NULL;
	const struct {
			char	*prefix;
			int	kind;
	} types[] = {
#ifdef OMNI_CYCLIC
			{ PROF_PREFIX_PROFILE, PROF_PROFILE },
#endif
			{ PROF_PREFIX_TICK, PROF_TICK },
			{ NULL, 0 },
		    };

	const struct {
			char	*name;
			long	mult_s;
			long	mult_ns;
	} suffixes[] = {
			{ "ns",		0, 1 },
			{ "nsec",	0, 1 },
			{ "us",		0, NANOSEC / MICROSEC },
			{ "usec",	0, NANOSEC / MICROSEC },
			{ "ms",		0, NANOSEC / MILLISEC },
			{ "msec",	0, NANOSEC / MILLISEC },
			{ "s",		1, 0 },
			{ "sec",	1, 0 },
			{ "m",		60, 0 },
			{ "min",	60, 0 },
			{ "h",		60 * 60, 0 },
			{ "hour",	60 * 60, 0 },
			{ "d",		24 * 60 * 60, 0 },
			{ "day",	24 * 60 * 60, 0 },
			{ "hz",		0, 0 },
			{ NULL, },
		       };

	if (desc == NULL) {
		char	n[PROF_NAMELEN];

		/*
		 * If no description was provided, provide all of our probes.
		 */
#ifdef OMNI_CYCLICS
		for (i = 0; i < sizeof(profile_rates) / sizeof(int); i++) {
			if ((rate = profile_rates[i]) == 0)
				continue;

			snprintf(n, PROF_NAMELEN, "%s%d",
				 PROF_PREFIX_PROFILE, rate);
			profile_create(ktime_set(0, NANOSEC / rate),
				       n, PROF_PROFILE);
		}
#endif

		for (i = 0; i < sizeof(profile_ticks) / sizeof(int); i++) {
			if ((rate = profile_ticks[i]) == 0)
				continue;

			snprintf(n, PROF_NAMELEN, "%s%d",
				 PROF_PREFIX_TICK, rate);
			profile_create(ktime_set(0, NANOSEC / rate),
				       n, PROF_TICK);
		}

		return;
	}

	name = desc->dtpd_name;

	for (i = 0; types[i].prefix != NULL; i++) {
		len = strlen(types[i].prefix);

		if (strncmp(name, types[i].prefix, len) != 0)
			continue;

		break;
	}

	if (types[i].prefix == NULL)
		return;

	kind = types[i].kind;

	/*
	 * We need to start before any time suffix.
	 */
	for (j = strlen(name); j >= len; j--) {
		if (name[j] >= '0' && name[j] <= '9')
			break;

		suffix = &name[j];
	}

	ASSERT(suffix != NULL);

	/*
	 * Now determine the numerical value present in the probe name.
	 */
	for (; j >= len; j--) {
		if (name[j] < '0' || name[j] > '9')
			return;

		val += (name[j] - '0') * mult;
		mult *= 10;
	}

	if (val == 0)
		return;

	/*
	 * Look up the suffix to determine the multiplier.
	 */
	for (i = 0; suffixes[i].name != NULL; i++) {
		if (strcasecmp(suffixes[i].name, suffix) == 0) {
			mult_s = suffixes[i].mult_s;
			mult_ns = suffixes[i].mult_ns;
			break;
		}
	}

	if (suffixes[i].name == NULL && *suffix != '\0')
		return;

	if (mult_s == 0 && mult_ns == 0) {
		/*
		 * The default is frequency-per-second.
		 */
		interval = ns_to_ktime((int64_t)NANOSEC / val);
	} else {
		long	sec;
		long	nsec = val * mult_ns;

		sec = nsec / NANOSEC;
		nsec %= NANOSEC;

		interval = ktime_set(val * mult_s + sec, nsec);
	}


	profile_create(interval, name, kind);
}

int profile_enable(void *arg, dtrace_id_t id, void *parg)
{
	profile_probe_t		*prof = parg;
	cyc_omni_handler_t	omni;
	cyc_handler_t		hdlr;
	cyc_time_t		when;

	ASSERT(ktime_nz(prof->prof_interval));
	ASSERT(mutex_is_locked(&cpu_lock));

	if (prof->prof_kind == PROF_TICK) {
		hdlr.cyh_func = profile_tick;
		hdlr.cyh_arg = prof;
		hdlr.cyh_level = CY_HIGH_LEVEL;

		when.cyt_interval = prof->prof_interval;
		when.cyt_when = ktime_set(0, 0);

		prof->prof_cyclic = cyclic_add(&hdlr, &when);
#ifdef OMNI_CYCLICS
	} else {
		ASSERT(prof->prof_kind == PROF_PROFILE);	

		omni.cyo_online = profile_online;
		omni.cyo_offline = profile_offline;
		omni.cyo_arg = prof;

		prof->prof_cyclic = cyclic_add_omni(&omni);
#endif
	}

	return 0;
}

void profile_disable(void *arg, dtrace_id_t id, void *parg)
{
	profile_probe_t	*prof = parg;

	ASSERT(prof->prof_cyclic != CYCLIC_NONE);
	ASSERT(mutex_is_locked(&cpu_lock));

	cyclic_remove(prof->prof_cyclic);
	prof->prof_cyclic = CYCLIC_NONE;
}

int profile_usermode(void *arg, dtrace_id_t id, void *parg)
{
	return 1; /* FIXME */
}

void profile_destroy(void *arg, dtrace_id_t id, void *parg)
{
	profile_probe_t	*prof = parg;

	ASSERT(prof->prof_cyclic == CYCLIC_NONE);
	kfree(prof);

	ASSERT(atomic_read(&profile_total) >= 1);
	atomic_dec(&profile_total);
}

static int profile_open(struct inode *inode, struct file *file)
{
	return 0;
}

static int profile_close(struct inode *inode, struct file *file)
{
	return 0;
}

static const struct file_operations profile_fops = {
	.owner  = THIS_MODULE,
        .open   = profile_open,
        .release = profile_close,
};

static struct miscdevice profile_dev = {
	.minor = DT_DEV_PROFILE_MINOR,
	.name = "profile",
	.nodename = "dtrace/provider/profile",
	.fops = &profile_fops,
};

int profile_dev_init(void)
{
	int ret = 0;

	ret = misc_register(&profile_dev);
	if (ret)
		pr_err("%s: Can't register misc device %d\n",
		       profile_dev.name, profile_dev.minor);

	profile_max = PROFILE_MAX_DEFAULT;

	return ret;
}

void profile_dev_exit(void)
{
	misc_deregister(&profile_dev);
}
