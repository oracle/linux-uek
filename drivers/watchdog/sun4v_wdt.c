/*
 *	sun4v watchdog timer
 *	(c) Copyright 2016 Oracle Corporation
 *
 *	Implement a simple watchdog driver using the built-in sun4v hypervisor
 *	watchdog support. If time expires, the hypervisor stops or bounces
 *	the guest domain.
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	as published by the Free Software Foundation; either version
 *	2 of the License, or (at your option) any later version.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/errno.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/watchdog.h>
#include <asm/hypervisor.h>
#include <asm/mdesc.h>

#define WDT_TIMEOUT_MS			60000	/* 60 seconds */
#define WDT_MAX_TIMEOUT_MS		180000	/* 180 seconds */
#define WDT_MIN_TIMEOUT_MS		1000	/* 1 second */
#define WDT_DEFAULT_RESOLUTION_MS	1000	/* 1 second */

static unsigned int wdt_max_timeout_ms = WDT_MAX_TIMEOUT_MS;
static unsigned int wdt_resolution_ms = WDT_DEFAULT_RESOLUTION_MS;

static unsigned int timeout_ms = WDT_TIMEOUT_MS;
module_param(timeout_ms, uint, S_IRUGO);
MODULE_PARM_DESC(timeout_ms, "Watchdog timeout in ms (default="
	__MODULE_STRING(WDT_TIMEOUT_MS) ")");

static bool nowayout = WATCHDOG_NOWAYOUT;
module_param(nowayout, bool, S_IRUGO);
MODULE_PARM_DESC(nowayout, "Watchdog cannot be stopped once started (default="
	__MODULE_STRING(WATCHDOG_NOWAYOUT) ")");

static int sun4v_wdt_stop(struct watchdog_device *wdd)
{
	sun4v_mach_set_watchdog(0, NULL);

	return 0;
}

static int sun4v_wdt_ping(struct watchdog_device *wdd)
{
	int hverr;

	hverr = sun4v_mach_set_watchdog(wdd->timeout, NULL);
	if (hverr == HV_EINVAL)
		return -EINVAL;

	return 0;
}

static int sun4v_wdt_set_timeout(struct watchdog_device *wdd,
				 unsigned int timeout)
{
	wdd->timeout = timeout - (timeout % wdt_resolution_ms);

	return 0;
}

static const struct watchdog_info sun4v_wdt_ident = {
	.options =	WDIOF_SETTIMEOUT | WDIOF_MAGICCLOSE,
	.identity =	"sun4v hypervisor watchdog",
	.firmware_version = 0,
};

static struct watchdog_ops sun4v_wdt_ops = {
	.owner =	THIS_MODULE,
	.start =	sun4v_wdt_ping,
	.stop =		sun4v_wdt_stop,
	.ping =		sun4v_wdt_ping,
	.set_timeout =	sun4v_wdt_set_timeout,
};

static struct watchdog_device wdd = {
	.info = &sun4v_wdt_ident,
	.ops = &sun4v_wdt_ops,
	.min_timeout = WDT_MIN_TIMEOUT_MS,
};

static int hvapi_registered;

static int __init sun4v_wdt_init(void)
{
	struct mdesc_handle *handle;
	u64 node;
	const u64 *value;
	int ret = 0;
	unsigned long major = 1, minor = 1;

	if (sun4v_hvapi_register(HV_GRP_CORE, major, &minor) != 0)
		return -ENODEV;
	if (minor < 1) {
		sun4v_hvapi_unregister(HV_GRP_CORE);
		return -ENODEV;
	}
	hvapi_registered = 1;

	/*
	 * There are 2 properties that can be set from the control
	 * domain for the watchdog.
	 * watchdog-resolution
	 * watchdog-max-timeout
	 *
	 * If there is no handle returned, this is no sun4v system
	 * so it's correct to return -ENODEV. Same for missing of the
	 * platform node.
	 */

	handle = mdesc_grab();
	if (!handle)
		return -ENODEV;

	node = mdesc_node_by_name(handle, MDESC_NODE_NULL, "platform");
	if (node == MDESC_NODE_NULL) {
		mdesc_release(handle);
		return -ENODEV;
	}

	value = mdesc_get_property(handle, node, "watchdog-resolution", NULL);
	if (value) {
		wdt_resolution_ms = *value;
		if (wdt_resolution_ms == 0 ||
		    wdt_resolution_ms > WDT_DEFAULT_RESOLUTION_MS)
			wdt_resolution_ms = WDT_DEFAULT_RESOLUTION_MS;
	}

	value = mdesc_get_property(handle, node, "watchdog-max-timeout", NULL);
	if (value) {
		wdt_max_timeout_ms = *value;
		/*
		 * If the property is defined to be smaller than default
		 * then set it to default.
		 */
		if (wdt_max_timeout_ms < WDT_MIN_TIMEOUT_MS) {
			mdesc_release(handle);
			return -EINVAL;
		}
	}

	mdesc_release(handle);

	if (timeout_ms < WDT_MIN_TIMEOUT_MS)
		timeout_ms = WDT_MIN_TIMEOUT_MS;
	if (timeout_ms > WDT_MAX_TIMEOUT_MS)
		timeout_ms = WDT_MAX_TIMEOUT_MS;
	if (timeout_ms > wdt_max_timeout_ms)
		timeout_ms = wdt_max_timeout_ms;

	/*
	 * round to nearest smaller value
	 */
	wdt_max_timeout_ms -= wdt_max_timeout_ms % wdt_resolution_ms;
	timeout_ms -= timeout_ms % wdt_resolution_ms;

	wdd.max_timeout = wdt_max_timeout_ms;
	wdd.timeout = timeout_ms;

	watchdog_set_nowayout(&wdd, nowayout);

	ret = watchdog_register_device(&wdd);
	if (ret) {
		pr_err("Failed to register watchdog device\n");
		return ret;
	}

	pr_info("initialized (timeout_ms=%dms, nowayout=%d)\n",
		 wdd.timeout, nowayout);

	return 0;
}


static void __exit sun4v_wdt_exit(void)
{
	if (hvapi_registered)
		sun4v_hvapi_unregister(HV_GRP_CORE);
	sun4v_wdt_stop(&wdd);
	watchdog_unregister_device(&wdd);
}

module_init(sun4v_wdt_init);
module_exit(sun4v_wdt_exit);

MODULE_AUTHOR("Wim Coekaerts <wim.coekaerts@oracle.com>");
MODULE_DESCRIPTION("sun4v watchdog driver");
MODULE_LICENSE("GPL");
MODULE_ALIAS("sun4v_wdt");
