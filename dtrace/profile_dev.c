/*
 * FILE:	profile_dev.c
 * DESCRIPTION:	Profile Interrupt Tracing: device file handling
 *
 * Copyright (C) 2010 Oracle Corporation
 */

#include <linux/fs.h>
#include <linux/miscdevice.h>

#include "dtrace.h"
#include "dtrace_dev.h"
#include "profile.h"

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

static int	profile_rates[] = {
				    97, 199, 499, 997, 1999,
				    4001, 4999, 0, 0, 0,
				    0, 0, 0, 0, 0,
				    0, 0, 0, 0, 0,
				  };
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

	dtrace_probe(prof->prof_id, 0, 0, 0, 0, 0); /* FIXME */
}

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
			{ PROF_PREFIX_PROFILE, PROF_PROFILE },
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
		for (i = 0; i < sizeof(profile_rates) / sizeof(int); i++) {
			if ((rate = profile_rates[i]) == 0)
				continue;

			snprintf(n, PROF_NAMELEN, "%s%d",
				 PROF_PREFIX_PROFILE, rate);
			profile_create(ktime_set(0, NANOSEC / rate),
				       n, PROF_PROFILE);
		}

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
#ifdef FIXME
	cyc_omni_handler_t	omni;
#endif
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
	} else {
		ASSERT(prof->prof_kind == PROF_PROFILE);	

#ifdef FIXME
		omni.cyo_online = profile_online;
		omni.cyo_offline = profile_offline;
		omni.cyo_arg = prof;

		prof->prof_cyclic = cyclic_add_omni(&omni);
#else
		prof->prof_cyclic = CYCLIC_NONE;
		return -ENOTSUPP;
#endif
	}

	return 0;
}

void profile_disable(void *arg, dtrace_id_t id, void *parg)
{
	profile_probe_t	*prof = parg;

if (prof->prof_cyclic == CYCLIC_NONE) return;
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
