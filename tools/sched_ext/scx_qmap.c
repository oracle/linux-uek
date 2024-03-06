/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2022 Tejun Heo <tj@kernel.org>
 * Copyright (c) 2022 David Vernet <dvernet@meta.com>
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <inttypes.h>
#include <signal.h>
#include <libgen.h>
#include <bpf/bpf.h>
#include <scx/common.h>
#include "scx_qmap.bpf.skel.h"

const char help_fmt[] =
"A simple five-level FIFO queue sched_ext scheduler.\n"
"\n"
"See the top-level comment in .bpf.c for more details.\n"
"\n"
"Usage: %s [-s SLICE_US] [-e COUNT] [-t COUNT] [-T COUNT] [-l COUNT] [-d PID]\n"
"       [-D LEN] [-p]\n"
"\n"
"  -s SLICE_US   Override slice duration\n"
"  -e COUNT      Trigger scx_bpf_error() after COUNT enqueues\n"
"  -t COUNT      Stall every COUNT'th user thread\n"
"  -T COUNT      Stall every COUNT'th kernel thread\n"
"  -l COUNT      Trigger dispatch infinite looping after COUNT dispatches\n"
"  -d PID        Disallow a process from switching into SCHED_EXT (-1 for self)\n"
"  -D LEN        Set scx_exit_info.dump buffer length\n"
"  -p            Switch only tasks on SCHED_EXT policy intead of all\n"
"  -h            Display this help and exit\n";

static volatile int exit_req;

static void sigint_handler(int dummy)
{
	exit_req = 1;
}

int main(int argc, char **argv)
{
	bool has_ops_exit_dump_len = __COMPAT_KERNEL_HAS_OPS_EXIT_DUMP_LEN;
	struct scx_qmap *skel;
	struct bpf_link *link;
	int opt;

	signal(SIGINT, sigint_handler);
	signal(SIGTERM, sigint_handler);

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

	skel = scx_qmap__open();
	SCX_BUG_ON(!skel, "Failed to open skel");

	if (has_ops_exit_dump_len) {
		bpf_map__set_autocreate(skel->maps.qmap_ops, true);
		bpf_map__set_autocreate(skel->maps.qmap_ops___no_exit_dump_len, false);
	} else {
		bpf_map__set_autocreate(skel->maps.qmap_ops, false);
		bpf_map__set_autocreate(skel->maps.qmap_ops___no_exit_dump_len, true);
	}

	while ((opt = getopt(argc, argv, "s:e:t:T:l:d:D:ph")) != -1) {
		switch (opt) {
		case 's':
			skel->rodata->slice_ns = strtoull(optarg, NULL, 0) * 1000;
			break;
		case 'e':
			skel->bss->test_error_cnt = strtoul(optarg, NULL, 0);
			break;
		case 't':
			skel->rodata->stall_user_nth = strtoul(optarg, NULL, 0);
			break;
		case 'T':
			skel->rodata->stall_kernel_nth = strtoul(optarg, NULL, 0);
			break;
		case 'l':
			skel->rodata->dsp_inf_loop_after = strtoul(optarg, NULL, 0);
			break;
		case 'd':
			skel->rodata->disallow_tgid = strtol(optarg, NULL, 0);
			if (skel->rodata->disallow_tgid < 0)
				skel->rodata->disallow_tgid = getpid();
			break;
		case 'D':
			if (!has_ops_exit_dump_len)
				fprintf(stderr, "WARNING: kernel doesn't support setting exit dump len\n");
			skel->struct_ops.qmap_ops->exit_dump_len = strtoul(optarg, NULL, 0);
			break;
		case 'p':
			skel->rodata->switch_partial = true;
			skel->struct_ops.qmap_ops->flags |= __COMPAT_SCX_OPS_SWITCH_PARTIAL;
			break;
		default:
			fprintf(stderr, help_fmt, basename(argv[0]));
			return opt != 'h';
		}
	}

	SCX_BUG_ON(scx_qmap__load(skel), "Failed to load skel");

	if (has_ops_exit_dump_len)
		link = bpf_map__attach_struct_ops(skel->maps.qmap_ops);
	else
		link = bpf_map__attach_struct_ops(skel->maps.qmap_ops___no_exit_dump_len);

	SCX_BUG_ON(!link, "Failed to attach struct_ops");

	while (!exit_req && !uei_exited(&skel->bss->uei)) {
		long nr_enqueued = skel->bss->nr_enqueued;
		long nr_dispatched = skel->bss->nr_dispatched;

		printf("enq=%lu, dsp=%lu, delta=%ld, reenq=%" PRIu64 ", deq=%" PRIu64 ", core=%" PRIu64 "\n",
		       nr_enqueued, nr_dispatched, nr_enqueued - nr_dispatched,
		       skel->bss->nr_reenqueued, skel->bss->nr_dequeued,
		       skel->bss->nr_core_sched_execed);
		fflush(stdout);
		sleep(1);
	}

	bpf_link__destroy(link);
	uei_print(&skel->bss->uei);
	scx_qmap__destroy(skel);
	return 0;
}
