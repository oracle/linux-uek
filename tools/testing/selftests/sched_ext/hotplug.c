/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2024 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2024 David Vernet <dvernet@meta.com>
 */
#include <bpf/bpf.h>
#include <sched.h>
#include <scx/common.h>
#include <sched.h>
#include <sys/wait.h>
#include <unistd.h>

#include "hotplug_test.h"
#include "hotplug.bpf.skel.h"
#include "scx_test.h"
#include "util.h"

struct hotplug *skel;

const char *online_path = "/sys/devices/system/cpu/cpu1/online";

static bool is_cpu_online(void)
{
	return file_read_long(online_path) > 0;
}

static void toggle_online_status(bool online)
{
	long val = online ? 1 : 0;
	int ret;

	ret = file_write_long(online_path, val);
	if (ret != 0)
		fprintf(stderr, "Failed to bring CPU %s (%s)",
			online ? "online" : "offline", strerror(errno));
}

static enum scx_test_status setup(void **ctx)
{
	if (!is_cpu_online())
		return SCX_TEST_SKIP;

	skel = hotplug__open_and_load();
	if (!skel) {
		SCX_ERR("Failed to open and load hotplug skel");
		return SCX_TEST_FAIL;
	}

	return SCX_TEST_PASS;
}

static enum scx_test_status test_hotplug(bool onlining, bool cbs_defined)
{
	struct bpf_link *link;
	long kind, code;

	SCX_ASSERT(is_cpu_online());

	/* Testing the offline -> online path, so go offline before starting */
	if (onlining)
		toggle_online_status(0);

	if (cbs_defined) {
		kind = SCX_KIND_VAL(SCX_EXIT_UNREG_BPF);
		code = SCX_ECODE_VAL(SCX_ECODE_ACT_RESTART) | HOTPLUG_EXIT_RSN;
		if (onlining)
			code |= HOTPLUG_ONLINING;
	} else {
		kind = SCX_KIND_VAL(SCX_EXIT_UNREG_KERN);
		code = SCX_ECODE_VAL(SCX_ECODE_ACT_RESTART) |
		       SCX_ECODE_VAL(SCX_ECODE_RSN_HOTPLUG);
	}

	if (cbs_defined)
		link = bpf_map__attach_struct_ops(skel->maps.hotplug_cb_ops);
	else
		link = bpf_map__attach_struct_ops(skel->maps.hotplug_nocb_ops);

	if (!link) {
		SCX_ERR("Failed to attach scheduler");
		return SCX_TEST_FAIL;
	}

	toggle_online_status(onlining ? 1 : 0);

	while (!UEI_EXITED(skel, uei))
		sched_yield();

	SCX_EQ(UEI_KIND(skel, uei), kind);
	SCX_EQ(UEI_ECODE(skel, uei), code);

	if (!onlining)
		toggle_online_status(1);

	bpf_link__destroy(link);

	UEI_RESET(skel, uei);

	return SCX_TEST_PASS;
}

static enum scx_test_status run(void *ctx)
{

#define HP_TEST(__onlining, __cbs_defined) ({				\
	if (test_hotplug(__onlining, __cbs_defined) != SCX_TEST_PASS)	\
		return SCX_TEST_FAIL;					\
})

	HP_TEST(true, true);
	HP_TEST(false, true);
	HP_TEST(true, false);
	HP_TEST(false, false);

#undef HP_TEST

	return SCX_TEST_PASS;
}

static void cleanup(void *ctx)
{
	hotplug__destroy(skel);
	toggle_online_status(1);
}

struct scx_test hotplug_test = {
	.name = "hotplug",
	.description = "Verify hotplug behavior",
	.setup = setup,
	.run = run,
	.cleanup = cleanup,
};
REGISTER_SCX_TEST(&hotplug_test)
