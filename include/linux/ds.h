/*
 * Copyright (C) 2015 Oracle Corporation
 */

#ifndef _DS_H
#define _DS_H

#include <uapi/linux/ds.h>

typedef u64	ds_svc_hdl_t;
typedef void	*ds_cb_arg_t;

typedef struct ds_ver {
	u64	major;
	u64	minor;
} ds_ver_t;

/*
 * Domain Services Capability
 *
 * A DS capability is exported by a provider using a unique service
 * identifier string. Along with this identifier the highest
 * version that the capability that the client supports. It is
 * assumed that the capability supports this specified version or
 * any lower version (down to 1.0). The service may be negotiated to
 * register at this specified version or at a lower version.
 */
typedef struct ds_capability {
	char		*svc_id;	/* service identifier */
	ds_ver_t	vers;		/* supported version */
} ds_capability_t;

/*
 * Domain Services Client Event Callbacks
 *
 * A client implementing a DS capability provides a set of callbacks
 * when it registers with the DS framework. The use of these callbacks
 * is described below:
 *
 *    ds_reg_cb()
 *
 *	    The ds_reg_cb() callback is invoked when the DS framework
 *	    has successfully completed version negotiation with the
 *	    remote endpoint for the capability. The cb also passes the
 *	    negotiated version of the service.
 *
 *    ds_unreg_cb()
 *
 *	    The ds_unreg_cb() callback is invoked when the DS framework
 *	    detects an event that causes the registered capability to
 *	    become unavailable. This includes an explicit unregister
 *	    message, a failure in the underlying communication transport,
 *	    etc. Any such event invalidates the service handle that was
 *	    received from the register callback. Once this callback has
 *	    been made, the client must re-register (unreg+reg) the service.
 *
 *    ds_data_cb()
 *
 *	    The ds_data_cb() callback is invoked whenever there is an
 *	    incoming data message for the client to process. It provides
 *	    the contents of the message along with the message length.
 */
typedef struct ds_ops {
	void (*ds_reg_cb)(ds_cb_arg_t arg, ds_svc_hdl_t hdl, ds_ver_t *ver);
	void (*ds_unreg_cb)(ds_cb_arg_t arg, ds_svc_hdl_t hdl);
	void (*ds_data_cb)(ds_cb_arg_t arg, ds_svc_hdl_t hdl,
	    void *buf, size_t buflen);
	ds_cb_arg_t	cb_arg; /* optional arg to ops - can be NULL */
} ds_ops_t;

/*
 * Domain Services Capability Interface
 */
extern int ds_cap_init(ds_capability_t *cap, ds_ops_t *ops, u32 flags,
	u64 domain_handle,  ds_svc_hdl_t *hdlp);
extern int ds_cap_fini(ds_svc_hdl_t hdl);
extern int ds_cap_send(ds_svc_hdl_t hdl, void *buf, size_t buflen);

#define DS_CAP_IS_CLIENT	0x0001 /* client service */
#define DS_CAP_IS_PROVIDER	0x0002 /* provider service */
#define DS_TARGET_IS_DOMAIN	0x0004 /* domain target */

#endif /* _DS_H */
