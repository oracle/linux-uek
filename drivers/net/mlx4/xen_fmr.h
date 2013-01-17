#ifndef _MLX4_XEN_FMR_GEN_H_
#define _MLX4_XEN_FMR_GEN_H_

#include <linux/mutex.h>
#include <linux/completion.h>

#include <xen/xenbus.h>

#include "fmr_api.h"

#define DRV_VERSION "2.0.0"

#if 0
	#define DPRINTK(format, args...) printk(KERN_INFO format, ##args)
#else
	#define DPRINTK(format, args...)
#endif

#define XENBUS_DEVID	"fmr"

typedef u64		addr_ref_t;
typedef __be64		addr_ref_be_t;
static inline addr_ref_be_t cpu_to_be_addr_ref(addr_ref_t cpu_var)
{
	return cpu_to_be64((addr_ref_t)cpu_var);
}
static inline addr_ref_t addr_ref_be_to_cpu(addr_ref_be_t be_var)
{
	return be64_to_cpu((addr_ref_be_t)be_var);
}

/**
 * Xen VPM
 */
struct xen_vpm {
	/* Base VPM */
	struct vpm	vpm;
	/* Used to map to page, initialize in slave */
	__be16		dom_id;
	/* This field holds diffrent value dependin on
	whether slave runs on domU or dom0
	In domU only 32 bits are used to hold gref of
	the shared page
	In dom0 the full 64 bits are used to hold the
	address of the shared page */
	addr_ref_be_t	addr_ref;
};

#define XEN_VPM_SZ	(sizeof(struct xen_vpm) - sizeof(struct vpm))

/**
 * Ref count: Structure
 */
struct ref_count {
	atomic_t		var;
	struct completion	comp;
};

/**
 * Ref count: Initialize
 */
static inline void ref_count_init(struct ref_count *rc)
{
	atomic_set(&(rc->var), 0);
	init_completion(&(rc->comp));
}

/**
 * Ref count: Increment reference
 */
static inline void ref_count_inc(struct ref_count *rc)
{
	atomic_inc(&(rc->var));
}

/**
 * Ref count: Decrement reference
 */
static inline void ref_count_dec(struct ref_count *rc)
{
	if (atomic_dec_and_test(&(rc->var)))
		complete(&(rc->comp));
}

/**
 * Ref count: Check if reference count is 0
 */
static inline int ref_count_is_zero(struct ref_count *rc)
{
	return (atomic_read(&(rc->var)) == 0);
}

/**
 * Ref count: Check if reference count is not 0
 */
static inline int ref_count_is_not_zero(struct ref_count *rc)
{
	return (atomic_read(&(rc->var)) != 0);
}

/**
 * Ref count: Decrement reference - block until 0
 */
static inline void ref_count_wait_for_zero(struct ref_count *rc)
{
	if (ref_count_is_not_zero(rc))
		wait_for_completion(&(rc->comp));
}

/**
 * Wrapper to xenbus_switch_state
 */
inline int mlx4_xen_fmr_switch_state(struct xenbus_device *dev,
				     enum xenbus_state state)
{
	int sts;
	DPRINTK("xen_fmr: Switching to state %s\n",
		xenbus_strstate(state));

	sts = xenbus_switch_state(dev, state);
	if (sts)
		printk("xen_fmr: Fail to switch state to %s\n",
		       xenbus_strstate(state));

	return sts;
}

#endif

