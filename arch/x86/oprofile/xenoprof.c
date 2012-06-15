/**
 * @file xenoprof.c
 *
 * @remark Copyright 2002 OProfile authors
 * @remark Read the file COPYING
 *
 * @author John Levon <levon@xxxxxxxxxxxxxxxxx>
 *
 * Modified by Aravind Menon and Jose Renato Santos for Xen
 * These modifications are:
 * Copyright (C) 2005 Hewlett-Packard Co.
 *
 * x86-specific part
 * Copyright (c) 2006 Isaku Yamahata <yamahata at valinux co jp>
 *                    VA Linux Systems Japan K.K.
 */

#include <linux/init.h>
#include <linux/oprofile.h>
#include <linux/sched.h>
#include <linux/vmalloc.h>
#include <asm/pgtable.h>

#include <xen/interface/xen.h>
#include <asm/xen/hypercall.h>
#include <xen/xen-ops.h>
#include <xen/interface/xenoprof.h>
#include <xen/xenoprof.h>
#include "op_counter.h"

static unsigned int num_events = 0;
struct op_counter_config xen_counter_config[OP_MAX_COUNTER];

void __init xenoprof_arch_init_counter(struct xenoprof_init *init)
{
	num_events = init->num_events;
	/* just in case - make sure we do not overflow event list 
	   (i.e. xen_counter_config list) */
	if (num_events > OP_MAX_COUNTER) {
		num_events = OP_MAX_COUNTER;
		init->num_events = num_events;
	}
}

void xenoprof_arch_counter(void)
{
	int i;
	struct xenoprof_counter counter;

	for (i=0; i<num_events; i++) {
		counter.ind       = i;
		counter.count     = (uint64_t)xen_counter_config[i].count;
		counter.enabled   = (uint32_t)xen_counter_config[i].enabled;
		counter.event     = (uint32_t)xen_counter_config[i].event;
		counter.kernel    = (uint32_t)xen_counter_config[i].kernel;
		counter.user      = (uint32_t)xen_counter_config[i].user;
		counter.unit_mask = (uint64_t)xen_counter_config[i].unit_mask;
		WARN_ON(HYPERVISOR_xenoprof_op(XENOPROF_counter,
					       &counter));
	}
}

void xenoprof_arch_start(void) 
{
	/* nothing */
}

void xenoprof_arch_stop(void)
{
	/* nothing */
}

void xenoprof_arch_unmap_shared_buffer(struct xenoprof_shared_buffer * sbuf)
{
	if (sbuf->buffer) {
		vunmap(sbuf->buffer);
		sbuf->buffer = NULL;
	}
}

int xenoprof_arch_map_shared_buffer(struct xenoprof_get_buffer * get_buffer,
				    struct xenoprof_shared_buffer * sbuf)
{
	int npages, ret;
	struct vm_struct *area;

	sbuf->buffer = NULL;
	if ( (ret = HYPERVISOR_xenoprof_op(XENOPROF_get_buffer, get_buffer)) )
		return ret;

	npages = (get_buffer->bufsize * get_buffer->nbuf - 1) / PAGE_SIZE + 1;

	area = alloc_vm_area(npages * PAGE_SIZE, NULL);
	if (area == NULL)
		return -ENOMEM;

	if ( (ret = xen_remap_domain_kernel_mfn_range(
		      (unsigned long)area->addr,
		      get_buffer->buf_gmaddr >> PAGE_SHIFT,
		      npages, __pgprot(_KERNPG_TABLE),
		      DOMID_SELF)) ) {
		vunmap(area->addr);
		return ret;
	}

	sbuf->buffer = area->addr;
	return ret;
}

int xenoprof_arch_set_passive(struct xenoprof_passive * pdomain,
			      struct xenoprof_shared_buffer * sbuf)
{
	int ret;
	int npages;
	struct vm_struct *area;
	pgprot_t prot = __pgprot(_KERNPG_TABLE);

	sbuf->buffer = NULL;

	ret = HYPERVISOR_xenoprof_op(XENOPROF_set_passive, pdomain);
	if (ret)
		goto out;

	npages = (pdomain->bufsize * pdomain->nbuf - 1) / PAGE_SIZE + 1;

	area = alloc_vm_area(npages * PAGE_SIZE, NULL);
	if (area == NULL) {
		ret = -ENOMEM;
		goto out;
	}

	ret = xen_remap_domain_kernel_mfn_range(
		(unsigned long)area->addr & PAGE_MASK,
		pdomain->buf_gmaddr >> PAGE_SHIFT,
		npages, prot, DOMID_SELF);
	if (ret) {
		vunmap(area->addr);
		goto out;
	}
	sbuf->buffer = area->addr;

out:
	return ret;
}


int xenoprof_create_files(struct super_block * sb, struct dentry * root)
{
	unsigned int i;

	for (i = 0; i < num_events; ++i) {
		struct dentry * dir;
		char buf[2];
 
		snprintf(buf, 2, "%d", i);
		dir = oprofilefs_mkdir(sb, root, buf);
		oprofilefs_create_ulong(sb, dir, "enabled",
					&xen_counter_config[i].enabled);
		oprofilefs_create_ulong(sb, dir, "event",
					&xen_counter_config[i].event);
		oprofilefs_create_ulong(sb, dir, "count",
					&xen_counter_config[i].count);
		oprofilefs_create_ulong(sb, dir, "unit_mask",
					&xen_counter_config[i].unit_mask);
		oprofilefs_create_ulong(sb, dir, "kernel",
					&xen_counter_config[i].kernel);
		oprofilefs_create_ulong(sb, dir, "user",
					&xen_counter_config[i].user);
	}

	return 0;
}
