/*
 * octeon-power-throttle.c - interface for controlling power
 * throttling on OCTEON II based platforms (6xxx and above).  OCTEON II
 * supports dynamic power control which aids to cut down power
 * consumption. The code exposes a "percentage" power throttling
 * limiter by means of /sys interface for each available cpu. Setting
 * this value to 0 will set power consumption to a minimum as it will
 * only execute a couple instructions every PERIOD as set in the
 * PowThrottle register.  If set to 100% for that particular cpu, it
 * may consume maximum power.
 *
 * Copyright (C) 2012-2013 Cavium, Inc.
 *
 * Copyright (C) 2012 MontaVista LLC.
 * Author: Philby John <pjohn@mvista.com>
 * Credits: This driver is derived from Dmitriy Zavin's (dmitriyz@google.com)
 * thermal throttle event support code.
 */
#include <linux/kernel.h>
#include <linux/stat.h>
#include <linux/init.h>
#include <linux/smp.h>
#include <linux/cpu.h>
#include <linux/moduleparam.h>

#include <asm/byteorder.h>
#include <asm/octeon/octeon.h>

union octeon_power_throttle_bits {
	u64 raw;
	struct {
#ifdef __BIG_ENDIAN_BITFIELD
		u64 maxpow:8;		/* 63:56 */
		u64 powe:8;		/* 55:48 */
		u64 thrott:8;		/* 47:40 */
		u64 hrmpowadj:8;	/* 39:32 reserved in cn63XX */
		u64 reserved:3;		/* 31:29 */
		u64 ovrrd:1;		/* 28  reserved in cn63XX */
		u64 distag:1;		/* 27 */
		u64 period:3;		/* 26:24 */
		u64 powlim:8;		/* 23:16 */
		u64 maxthr:8;		/* 15:8 */
		u64 minthr:8;		/* 7:0 */
#else
		u64 minthr:8;
		u64 maxthr:8;
		u64 powlim:8;
		u64 period:3;
		u64 distag:1;
		u64 ovrrd:1;
		u64 reserved:3;
		u64 hrmpowadj:8;
		u64 thrott:8;
		u64 powe:8;
		u64 maxpow:8;
#endif
	} s;
};

/*
 * Boot-time power limit as percentage,
 * settable by bootparam: octeon_power_throttle.start=85
 * Useful for situations where full-throttle boot would exceed power budget.
 * Individual cores' power can be throttled up/down after boot.
 * Default of -1 retains reset/bootloader powlim setting.
 */
static long boot_powlim = -1;
module_param_named(start, boot_powlim, long, 0444);

/* IPI calls to ask target CPU to access own registers ... */
static inline void read_my_power_throttle(void *info)
{
	*(u64 *)info = __read_64bit_c0_register($11, 6);
}

static inline void write_my_power_throttle(void *info)
{
	__write_64bit_c0_register($11, 6, *(u64 *)info);
}

/*
 * Read/Write POW_THROTTLE.
 */
static int throttle_op(int cpu,
	union octeon_power_throttle_bits *r, bool write)
{
	int err =
	smp_call_function_single(cpu,
				 (write ? write_my_power_throttle
				  : read_my_power_throttle),
				 r, 1);
	return err;
}

/* get default max power, unscaled */
static int get_powbase(union octeon_power_throttle_bits r)
{
	int lim = r.s.maxpow;
	int adj = r.s.hrmpowadj;

	if (!OCTEON_IS_MODEL(OCTEON_CN63XX))
		lim -= adj;

	return lim;
}

/*
 * Throttle given core's power
 */
static void octeon_power_throttle_init_cpu(int cpu)
{
	union octeon_power_throttle_bits r;

	if (throttle_op(cpu, &r, false))
		return;

	if (cpu == 0)
		pr_debug("old power_throttle %llx\n",
			r.raw);

	r.s.ovrrd = 0;		/* MBZ */
	r.s.distag = 0;		/* MBZ */
	r.s.period = 2;		/* 256 cycles */
	r.s.minthr = 0;
	r.s.maxthr = 0xff;

	/* limit average power to boot_powlim% of max power */
	if (boot_powlim >= 0)
		r.s.powlim = (r.s.maxpow * boot_powlim) / 100;
	else
		r.s.powlim = get_powbase(r);

	throttle_op(cpu, &r, true);
}

/* scale a throttle value as percentage of max power */
static int scaled(union octeon_power_throttle_bits r, int val)
{
	int base = r.s.maxpow;

	if (base <= 0)
		return 100;
	return ((val * 100) / base);
}

/*
 * Set the POWLIM field as percentage% of the MAXPOW field in r.
 */
static int set_powlim(union octeon_power_throttle_bits *r,
		      unsigned long percentage)
{
	int maxpow = r->s.maxpow;	/* max with override */
	int base = get_powbase(*r);	/* max without override */
	int newlim;
	int ret = 0;

	if (percentage < 0)
		percentage = 0;

	newlim = (maxpow * percentage) / 100;

	if (newlim > maxpow)
		newlim = maxpow;
	if (newlim > base && !r->s.ovrrd)
		newlim = base;

	r->s.powlim = newlim;

	return ret;
}

/* read actor for all throttle attributes */
static ssize_t show(
	struct device *dev,
	struct device_attribute *attr,
	char *buf)
{
	union octeon_power_throttle_bits r;
	unsigned int cpu = dev->id;
	int ret = -EBUSY;

	get_online_cpus();
	if (!cpu_online(cpu))
		goto bye;
	ret = throttle_op(cpu, &r, false);
	if (ret)
		goto bye;

	switch (attr->attr.name[0]) {
		int maxt;

	case 'p': /* percent */
		ret = sprintf(buf, "%d\n", scaled(r, r.s.powlim));
		break;

	case 'd': /* default */
		ret = sprintf(buf, "%d\n", scaled(r, get_powbase(r)));
		break;

	case 'o': /* override */
		ret = sprintf(buf, "%d\n",
			OCTEON_IS_MODEL(OCTEON_CN63XX) ? 0 : r.s.ovrrd);
		break;

	case 'c': /* cycles */
		ret = sprintf(buf, "%d\n", (1024 >> r.s.period));
		break;

	case 'm': /* maxthr/minthr */
		/* this name[0] "perfect hash" just broke ... */
		maxt = (attr->attr.name[2] == 'x');
		ret = sprintf(buf, "%d\n", maxt ? r.s.maxthr : r.s.minthr);
		break;

	case 's':
		ret = sprintf(buf,
			"recent power:         %d\n"
			"recent throttle:      %d\n"
			"power limit:          %d%% %d\n"
			"default limit:        %d%% %d\n"
			"boot_powlim:          %ld%%\n"
			"adjustment cycles:    %d\n"
			"throttle_range:       %d..%d\n"
			"allow override:       %c\n"
			"raw:                  %llx\n",
			r.s.powe,
			r.s.thrott,
			scaled(r, r.s.powlim), r.s.powlim,
			scaled(r, get_powbase(r)), get_powbase(r),
			(boot_powlim >= 0
				? boot_powlim
				: (get_powbase(r) * 100) / r.s.maxpow),
			(1024 >> r.s.period),
			r.s.minthr, r.s.maxthr,
			"NY"[r.s.ovrrd],
			r.raw);
		break;

	default:
		ret = -ENXIO;
		break;
	}

bye:
	put_online_cpus();

	return (ssize_t) ret;
}

/*
 * write actor for all writeable throttle attributes.
 * Generally take a single decimal input,
 * but percentage allows 'd...' to reset to base-power default.
 */
static ssize_t store(
	struct device *dev,
	struct device_attribute *attr,
	const char *buf,
	size_t size)
{
	unsigned int cpu = dev->id;
	unsigned long val = 0;
	union octeon_power_throttle_bits r;
	int error = 0;
	bool restore_default_powlim =
		(buf[0] == 'd' && attr->attr.name[0] == 'p');

	if (!restore_default_powlim)
		error = kstrtoul(buf, 0, &val);

	if (error)
		return error;

	get_online_cpus();
	error = -EBUSY;
	if (!cpu_online(cpu))
		goto bye;
	error = throttle_op(cpu, &r, false);
	if (error)
		goto bye;

	switch (attr->attr.name[0]) {
		int maxt;

	case 'p': /* percent */
		if (restore_default_powlim)
			val = get_powbase(r);
		error = set_powlim(&r, val);
		break;

	case 'o': /* override */
		if (val < 0 || val > 1 ||
		    OCTEON_IS_MODEL(OCTEON_CN63XX)) {
			error = -EINVAL;
		} else {
			if (r.s.ovrrd && r.s.powlim > get_powbase(r))
				r.s.powlim = get_powbase(r);
			r.s.ovrrd = val;
		}
		break;

	case 'c': /* cycles */
		/* set throttle period, either cycles or 0..3 encoding */
		if (val >= 0 && val <= 3)
			r.s.period = val;
		else if (val >= 1024)
			r.s.period = 0;
		else if (val >= 512)
			r.s.period = 1;
		else if (val >= 256)
			r.s.period = 2;
		else if (val >= 128)
			r.s.period = 3;
		else
			error = -EINVAL;
		break;

	case 'm': /* maxthr/minthr */
		/* this name[0] "perfect hash" just broke ... */
		maxt = (attr->attr.name[2] == 'x');
		if (maxt)
			r.s.maxthr = val;
		else
			r.s.minthr = val;
		break;

	default:
		error = -EINVAL;
		break;
	}

	if (!error)
		error = throttle_op(cpu, &r, true);

bye:
	put_online_cpus();

	if (error)
		return error;
	return size;
}

static DEVICE_ATTR(percentage, 0644, show, store);
static DEVICE_ATTR(override, 0644, show, store);
static DEVICE_ATTR(cycles, 0644, show, store);
static DEVICE_ATTR(maxthr, 0644, show, store);
static DEVICE_ATTR(minthr, 0644, show, store);
static DEVICE_ATTR(default, 0444, show, NULL);
static DEVICE_ATTR(state, 0444, show, NULL);

static struct attribute *octeon_power_throttle_attrs[] = {
	&dev_attr_percentage.attr,
	&dev_attr_override.attr,
	&dev_attr_cycles.attr,
	&dev_attr_maxthr.attr,
	&dev_attr_minthr.attr,
	&dev_attr_default.attr,
	&dev_attr_state.attr,
	NULL
};

static struct attribute_group octeon_power_throttle_attr_group = {
	.attrs	= octeon_power_throttle_attrs,
	.name	= "power_throttle"
};

static int octeon_power_throttle_add_dev(struct device *dev)
{
	return sysfs_create_group(&dev->kobj,
				  &octeon_power_throttle_attr_group);
}

static __init int octeon_power_throttle_init(void)
{
	unsigned int cpu = 0;
	int err = 0;

	if (!(current_cpu_type() == CPU_CAVIUM_OCTEON2 ||
	      current_cpu_type() == CPU_CAVIUM_OCTEON3))
		return 0;

	get_online_cpus();
	/* connect live CPUs to sysfs */
	for_each_online_cpu(cpu) {
		err = octeon_power_throttle_add_dev(get_cpu_device(cpu));
		if (err) {
			pr_err("Error: octeon_power_throttle_add_dev() failed\n");
			break;
		}
		octeon_power_throttle_init_cpu(cpu);
	}
	put_online_cpus();
	return err;
}
device_initcall(octeon_power_throttle_init);
