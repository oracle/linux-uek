/*
 * FILE:	sdt_mod.c
 * DESCRIPTION:	Statically Defined Tracing: module handling
 *
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
 * Copyright 2010, 2011, 2012 Oracle, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <linux/module.h>

#include "dtrace.h"
#include "dtrace_dev.h"
#include "sdt_impl.h"

MODULE_AUTHOR("Kris Van Hees (kris.van.hees@oracle.com)");
MODULE_DESCRIPTION("Profile Interrupt Tracing");
MODULE_VERSION("v0.1");
MODULE_LICENSE("CDDL");

static dtrace_pattr_t vtrace_attr = {
{ DTRACE_STABILITY_UNSTABLE, DTRACE_STABILITY_UNSTABLE, DTRACE_CLASS_ISA },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_UNKNOWN },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_UNKNOWN },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_UNKNOWN },
{ DTRACE_STABILITY_UNSTABLE, DTRACE_STABILITY_UNSTABLE, DTRACE_CLASS_ISA },
};

static dtrace_pattr_t info_attr = {
{ DTRACE_STABILITY_EVOLVING, DTRACE_STABILITY_EVOLVING, DTRACE_CLASS_ISA },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_UNKNOWN },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_UNKNOWN },
{ DTRACE_STABILITY_EVOLVING, DTRACE_STABILITY_EVOLVING, DTRACE_CLASS_ISA },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_ISA },
};

static dtrace_pattr_t fc_attr = {
{ DTRACE_STABILITY_EVOLVING, DTRACE_STABILITY_EVOLVING, DTRACE_CLASS_ISA },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_UNKNOWN },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_UNKNOWN },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_ISA },
{ DTRACE_STABILITY_EVOLVING, DTRACE_STABILITY_EVOLVING, DTRACE_CLASS_ISA },
};

static dtrace_pattr_t fpu_attr = {
{ DTRACE_STABILITY_EVOLVING, DTRACE_STABILITY_EVOLVING, DTRACE_CLASS_ISA },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_UNKNOWN },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_UNKNOWN },
{ DTRACE_STABILITY_EVOLVING, DTRACE_STABILITY_EVOLVING, DTRACE_CLASS_CPU },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_ISA },
};

static dtrace_pattr_t fsinfo_attr = {
{ DTRACE_STABILITY_EVOLVING, DTRACE_STABILITY_EVOLVING, DTRACE_CLASS_ISA },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_UNKNOWN },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_UNKNOWN },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_UNKNOWN },
{ DTRACE_STABILITY_EVOLVING, DTRACE_STABILITY_EVOLVING, DTRACE_CLASS_ISA },
};

static dtrace_pattr_t stab_attr = {
{ DTRACE_STABILITY_EVOLVING, DTRACE_STABILITY_EVOLVING, DTRACE_CLASS_ISA },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_UNKNOWN },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_UNKNOWN },
{ DTRACE_STABILITY_EVOLVING, DTRACE_STABILITY_EVOLVING, DTRACE_CLASS_ISA },
{ DTRACE_STABILITY_EVOLVING, DTRACE_STABILITY_EVOLVING, DTRACE_CLASS_ISA },
};

static dtrace_pattr_t sdt_attr = {
{ DTRACE_STABILITY_EVOLVING, DTRACE_STABILITY_EVOLVING, DTRACE_CLASS_ISA },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_UNKNOWN },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_UNKNOWN },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_ISA },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_ISA },
};

static dtrace_pattr_t xpv_attr = {
{ DTRACE_STABILITY_EVOLVING, DTRACE_STABILITY_EVOLVING, DTRACE_CLASS_PLATFORM },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_UNKNOWN },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_UNKNOWN },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_PLATFORM },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_PLATFORM },
};

static dtrace_pattr_t iscsi_attr = {
{ DTRACE_STABILITY_EVOLVING, DTRACE_STABILITY_EVOLVING, DTRACE_CLASS_ISA },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_UNKNOWN },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_UNKNOWN },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_ISA },
{ DTRACE_STABILITY_EVOLVING, DTRACE_STABILITY_EVOLVING, DTRACE_CLASS_ISA },
};

DT_PROVIDER_POPS(sdt)

static dtrace_pops_t sdt_pops = {
	NULL,
	sdt_provide_module,
	sdt_enable,
	sdt_disable,
	NULL,
	NULL,
	sdt_getargdesc,
	sdt_getarg,
	NULL,
	sdt_destroy,
};

dtrace_mprovider_t sdt_providers[] = {
  { "vtrace", "__vtrace_", &vtrace_attr, DTRACE_PRIV_KERNEL, &sdt_pops, 0 },
  { "sysinfo", "__cpu_sysinfo_", &info_attr, DTRACE_PRIV_KERNEL, &sdt_pops, 0 },
  { "vminfo", "__cpu_vminfo_", &info_attr, DTRACE_PRIV_KERNEL, &sdt_pops, 0 },
  { "fpuinfo", "__fpuinfo_", &fpu_attr, DTRACE_PRIV_KERNEL, &sdt_pops, 0 },
  { "sched", "__sched_", &stab_attr, DTRACE_PRIV_KERNEL, &sdt_pops, 0 },
  { "proc", "__proc_", &stab_attr, DTRACE_PRIV_KERNEL, &sdt_pops, 0 },
  { "io", "__io_", &stab_attr, DTRACE_PRIV_KERNEL, &sdt_pops, 0 },
  { "ip", "__ip_", &stab_attr, DTRACE_PRIV_KERNEL, &sdt_pops, 0 },
  { "tcp", "__tcp_", &stab_attr, DTRACE_PRIV_KERNEL, &sdt_pops, 0 },
  { "udp", "__udp_", &stab_attr, DTRACE_PRIV_KERNEL, &sdt_pops, 0 },
  { "mib", "__mib_", &stab_attr, DTRACE_PRIV_KERNEL, &sdt_pops, 0 },
  { "fsinfo", "__fsinfo_", &fsinfo_attr, DTRACE_PRIV_KERNEL, &sdt_pops, 0 },
  { "iscsi", "__iscsi_", &iscsi_attr, DTRACE_PRIV_KERNEL, &sdt_pops, 0 },
  { "nfsv3", "__nfsv3_", &stab_attr, DTRACE_PRIV_KERNEL, &sdt_pops, 0 },
  { "nfsv4", "__nfsv4_", &stab_attr, DTRACE_PRIV_KERNEL, &sdt_pops, 0 },
  { "xpv", "__xpv_", &xpv_attr, DTRACE_PRIV_KERNEL, &sdt_pops, 0 },
  { "fc", "__fc_", &fc_attr, DTRACE_PRIV_KERNEL, &sdt_pops, 0 },
  { "srp", "__srp_", &fc_attr, DTRACE_PRIV_KERNEL, &sdt_pops, 0 },
  { "sysevent", "__sysevent_", &stab_attr, DTRACE_PRIV_KERNEL, &sdt_pops, 0 },
  { "sdt", NULL, &sdt_attr, DTRACE_PRIV_KERNEL, &sdt_pops, 0 },
  { NULL }
};

DT_MULTI_PROVIDER_MODULE(sdt, sdt_providers)
