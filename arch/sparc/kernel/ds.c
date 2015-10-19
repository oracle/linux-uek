/*
 * ds.c: Sun4v LDOMs Domain Services Driver
 *
 * Copyright (C) 2007, 2008 David S. Miller <davem@davemloft.net>
 * Copyright (C) 2015 Oracle. All rights reserved.
 */
#include <linux/ds.h>
#include <linux/ioctl.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/delay.h>
#include <linux/spinlock.h>
#include <linux/mutex.h>
#include <linux/kthread.h>
#include <linux/completion.h>
#include <linux/reboot.h>
#include <linux/cpu.h>
#include <linux/miscdevice.h>
#include <linux/random.h>
#include <linux/init.h>
#include <linux/smp.h>

#include <asm/hypervisor.h>
#include <asm/ldc.h>
#include <asm/vio.h>
#include <asm/mdesc.h>
#include <asm/head.h>
#include <asm/irq.h>

#include "kernel.h"

/*
 * Def to enable kernel timer bug workaround.
 * See additional comments below.
 */
#define DS_KERNEL_TIMER_BUG_WAR 1

/*
 * Theory of operation:
 *
 * Domain Services provide a protocol for a logical domain (ldom) to provide
 * or use a service to/from another ldom or the SP. For a given service there is
 * a provider and a client. The provider and client can share a service across
 * a LDC or directly in the case of a "loopback" service on the same local
 * domain. For example, a guest ldom can provide a shutdown service to the
 * control domain (the client) to allow the control domain to use the service
 * to shutdown the guest. On the control domain, the kernel can provide
 * the shutdown service to the domain manager software in loopback mode to
 * allow the domain manager to shutdown the local control domain.
 * Several software entities can provide or use domain services: OBP, SP,
 * user-level logical domain manager and kernel driver (this module).
 * After establishing a domain service protocol link between two entities,
 * many services can be shared on the link. Services advertise
 * their availablility by sending a service registration request containing
 * a service id (a string identifying the service) and a generated numerical
 * handle (a value to use to identify the service connection after the
 * connection has been established). A service request is acknowledged
 * (ACK'd) by the other end of the link if the service is supported.
 * Once the service registration is ACK'd, the service connection is
 * established and service protocol packets can be exchanged by
 * both entities (client and provider) on either side of the link.
 * This driver can execute in the control domain, guest domains or both.
 * It contains a set of builtin services associated with the "primary" (or
 * control) domain. The driver also contains an API which allows external
 * domain services to be registered with the driver. This API can be utilized by
 * another kernel driver to provide/use services. The API can also be used by
 * another kernel driver (i.e. vlds) to provide user-level domain services.
 *
 */

static unsigned int dsdbg_level;
module_param(dsdbg_level, uint, S_IRUGO|S_IWUSR);

#define DRV_MODULE_NAME		"ds"
#define PFX DRV_MODULE_NAME	": "

#define XSTR(s) STR(s)
#define STR(s) #s
#define DRV_MODULE_VERSION XSTR(DS_MAJOR_VERSION) "." XSTR(DS_MINOR_VERSION)

static char version[] = DRV_MODULE_NAME ".c:v" DRV_MODULE_VERSION "\n";

#define dprintk(fmt, args...) do {\
if (dsdbg_level > 0)\
	printk(KERN_ERR "%s: %s: " fmt, DRV_MODULE_NAME, __func__, ##args);\
} while (0)

MODULE_AUTHOR("Oracle");
MODULE_DESCRIPTION("Sun4v LDOM domain services driver");
MODULE_LICENSE("GPL");
MODULE_VERSION(DRV_MODULE_VERSION);

#define LDC_IRQ_NAME_MAX	32

#define	DS_DEFAULT_BUF_SIZE	4096
#define	DS_DEFAULT_MTU		4096

#define	DS_PRIMARY_ID		0

#define DS_INVALID_HANDLE	0xFFFFFFFFFFFFFFFFUL

/*
 * The DS spec mentions that a DS handle is just any random number.
 * However, the Solaris code uses some conventions to identify server
 * and consumer handles, based on the setting of some bits in the
 * handle. We have to use the same convention to be compatible with
 * services from Solaris.
 */
#define	DS_HDL_ISCLIENT_BIT		0x80000000ull
#define	DS_HDL_ISCNTRLD_BIT		0x40000000ull

/* Globals to identify the local ldom handle */
u64 ds_local_ldom_handle;
bool ds_local_ldom_handle_set;

/* Global driver data struct for data common to all ds devices. */
struct ds_driver_data {

	/* list of all ds devices */
	struct list_head	ds_dev_list;
	int			num_ds_dev_list;

};
struct ds_driver_data ds_data;
static DEFINE_SPINLOCK(ds_data_lock); /* protect ds_data */

/*
 * For each DS port, a timer fires every DS_REG_TIMER_FREQ
 * milliseconds to attempt to register services on that DS port.
 */
#define	DS_REG_TIMER_FREQ	100	/* in ms */

/* Timeout to wait for responses for sp-token and var-config DS requests */
#define	DS_RESPONSE_TIMEOUT	10	/* in seconds */

#ifdef DS_KERNEL_TIMER_BUG_WAR
/*
 * Define a partial type for ldc_channel so the compiler knows
 * how to indirect ds->lp->lock. This must match the definition in ldc.c
 * (which should probably be moved to ldc.h).
 */
struct ldc_channel {
	/* Protects all operations that depend upon channel state.  */
	spinlock_t                      lock;
};
#endif /* DS_KERNEL_TIMER_BUG_WAR */

/*
 * DS device structure. There is one of these probed/created per
 * domain-services-port node in the MD.
 * On a guest ldom, there is typically just one primary ds device
 * for services provided from/to the "primary".
 * On the primary ldom, there can be several ds devices - typically
 * one for the SP, primary and each guest ldom.
 */
struct ds_dev {
	/* link into the global driver data dev list */
	struct list_head	list;

	/* protect this ds_dev */
	spinlock_t		ds_lock;

	/* number of references to this ds_dev on the callout queue */
	u64			co_ref_cnt;

	/* flag to indicate if this ds_dev is active */
	bool			active;

	/* flag to indicate if this is a domain DS (versus the SP DS) */
	bool			is_domain;

	/* LDC connection info for this ds_dev */
	struct ldc_channel	*lp;
	u8			hs_state;
	u64			id;
	u64			handle;

	/* negotiated DS version */
	ds_ver_t		neg_vers;

	/* LDC receive data buffer for this ds_dev */
	u8			*rcv_buf;
	int			rcv_buf_len;

	/* service registration timer */
	struct timer_list	ds_reg_tmr;

	u32			next_service_handle;

	/* list of local service providers registered with this ds_dev */
	struct list_head	service_provider_list;

	/* list of local service clients registered with this ds_dev */
	struct list_head	service_client_list;

	/* list of work items queued for processing (by callout thread) */
	struct list_head	callout_list;

};

/* ds_dev hs_state values */
#define DS_HS_LDC_DOWN		0x00
#define DS_HS_START		0x01
#define DS_HS_COMPLETE		0x02

/*
 * LDC interrupts are not blocked by spin_lock_irqsave(). So, for any
 * lock which the LDC interrupt handler (ds_event) obtains, we must
 * explicitly disable the LDC interrupt before grabbing the lock
 * throughout the driver (and re-enable the interrupt after releasing
 * the lock). This is to prevent a deadlock where the interrupt handler
 * waits indefinitely for a lock which is held by another thread on the
 * same CPU.
 *
 * The reason behind this is as follows:
 * spin_lock_irqsave() raises the PIL to level 14 which effectively
 * blocks interrupt_level_n traps (for n < 15). However, LDC
 * interrupts are not interrupt_level_n traps. They are dev_mondo traps,
 * so they are not impacted by the PIL.
 */

#define LOCK_DS_DEV(ds, flags) do {\
	ldc_disable_hv_intr((ds)->lp); \
	spin_lock_irqsave(&((ds)->ds_lock), (flags)); \
} while (0);

#define UNLOCK_DS_DEV(ds, flags)  do {\
	spin_unlock_irqrestore(&((ds)->ds_lock), flags); \
	ldc_enable_hv_intr((ds)->lp); \
} while (0);

/*
 * Generic service info structure used to describe
 * a provider service or local client service.
 */
struct ds_service_info {
	/* link into a ds_dev service list */
	struct list_head	list;

	/* id of the service */
	char			*id;

	/* supported max version */
	ds_ver_t		vers;

	/* callback ops for reg/unreg and data */
	ds_ops_t		ops;

	/* registration state */
	u64			reg_state;

	/* registration timeout */
	u64			svc_reg_timeout;

	/* connection negotiated version */
	ds_ver_t		neg_vers;

	/*
	 * Flag to indicate if the service is a
	 * a client or provider. This flag should always
	 * correspond to the list this service_info
	 * it is in (i.e. in the client or provider service
	 * list in the ds_dev).
	 */
	bool			is_client;

	/* Flag to indicate if the service is a builtin service */
	bool			is_builtin;

	/*
	 * Service is in loopback mode.
	 * Loopback mode allows a service provider and client
	 * which reside on the same/local host to connect directly
	 * (without using a LDC).
	 */
	bool			is_loopback;

	/* flag to indicate if this service is connected */
	bool			is_connected;

	/* Unique handle associated with this service */
	u64			handle;

	/* Handle used for service connection. */
	u64			con_handle;

};

/* service_info reg_states */
#define DS_REG_STATE_UNREG			0x00
#define DS_REG_STATE_REG_SENT			0x01
#define DS_REG_STATE_REGISTERED_LDC		0x02
#define DS_REG_STATE_REGISTERED_LOOPBACK	0x03

/*
 * DS service data structures
 */

struct ds_msg_tag {
	u32			type;
#define DS_INIT_REQ		0x00
#define DS_INIT_ACK		0x01
#define DS_INIT_NACK		0x02
#define DS_REG_REQ		0x03
#define DS_REG_ACK		0x04
#define DS_REG_NACK		0x05
#define DS_UNREG_REQ		0x06
#define DS_UNREG_ACK		0x07
#define DS_UNREG_NACK		0x08
#define DS_DATA			0x09
#define DS_NACK			0x0a

	u32			len;
};

struct ds_msg {
	struct ds_msg_tag	tag;
	char			payload[0];
};

/* Result codes */
#define DS_OK			0x00
#define DS_REG_VER_NACK		0x01
#define DS_REG_DUP		0x02
#define DS_INV_HDL		0x03
#define DS_TYPE_UNKNOWN		0x04

struct ds_version {
	u16				major;
	u16				minor;
};

struct ds_ver_req_payload {
	struct ds_version		ver;
};

struct ds_ver_req {
	struct ds_msg_tag		tag;
	struct ds_ver_req_payload	payload;
};

struct ds_ver_ack_payload {
	u16				minor;
};

struct ds_ver_ack {
	struct ds_msg_tag		tag;
	struct ds_ver_ack_payload	payload;
};

struct ds_ver_nack_payload {
	u16				major;
};

struct ds_ver_nack {
	struct ds_msg_tag		tag;
	struct ds_ver_nack_payload	payload;
};

struct ds_reg_req_payload {
	u64				handle;
	u16				major;
	u16				minor;
	char				svc_id[0];
};

struct ds_reg_req {
	struct ds_msg_tag		tag;
	struct ds_reg_req_payload	payload;
};

struct ds_reg_ack_payload {
	u64				handle;
	u16				minor;
};

struct ds_reg_ack {
	struct ds_msg_tag		tag;
	struct ds_reg_ack_payload	payload;
};

struct ds_reg_nack_payload {
	u64				handle;
	u64				result;
	u16				major;
};

struct ds_reg_nack {
	struct ds_msg_tag		tag;
	struct ds_reg_nack_payload	payload;
};

struct ds_unreg_req_payload {
	u64				handle;
};

struct ds_unreg_req {
	struct ds_msg_tag		tag;
	struct ds_unreg_req_payload	payload;
};

struct ds_unreg_ack_payload {
	u64				handle;
};

struct ds_unreg_ack {
	struct ds_msg_tag		tag;
	struct ds_unreg_ack_payload	payload;
};

struct ds_unreg_nack_payload {
	u64				handle;
};

struct ds_unreg_nack {
	struct ds_msg_tag		tag;
	struct ds_unreg_nack_payload	payload;
};

struct ds_data_req_payload {
	u64				handle;
	char				data[0];
};

struct ds_data_req {
	struct ds_msg_tag		tag;
	struct ds_data_req_payload	payload;
};

#define	DS_DATA_REQ_DSIZE(req) \
	((req)->tag.len - sizeof(struct ds_data_req_payload))

struct ds_data_nack_payload {
	u64				handle;
	u64				result;
};

struct ds_data_nack {
	struct ds_msg_tag		tag;
	struct ds_data_nack_payload	payload;
};

struct ds_unknown_msg_payload {
	u64				handle; /* ??? */
};

struct ds_unknown_msg {
	struct ds_msg_tag		tag;
	struct ds_unknown_msg_payload	payload;
};

struct ds_md_update_req {
	u64				req_num;
};

struct ds_md_update_res {
	u64				req_num;
	u32				result;
};

struct ds_shutdown_req {
	u64				req_num;
	u32				ms_delay;
};

struct ds_shutdown_res {
	u64				req_num;
	u32				result;
	char				reason[1];
};

struct ds_panic_req {
	u64				req_num;
};

struct ds_panic_res {
	u64				req_num;
	u32				result;
	char				reason[1];
};

struct ds_pri_msg {
	u64				req_num;
	u64				type;
#define DS_PRI_REQUEST			0x00
#define DS_PRI_DATA			0x01
#define DS_PRI_UPDATE			0x02
};

struct ds_var_hdr {
	u32				type;
#define DS_VAR_SET_REQ			0x00
#define DS_VAR_DELETE_REQ		0x01
#define DS_VAR_SET_RESP			0x02
#define DS_VAR_DELETE_RESP		0x03
};

struct ds_var_set_msg {
	struct ds_var_hdr		hdr;
	char				name_and_value[0];
};

struct ds_var_delete_msg {
	struct ds_var_hdr		hdr;
	char				name[0];
};

struct ds_var_resp {
	struct ds_var_hdr		hdr;
	u32				result;
#define DS_VAR_SUCCESS			0x00
#define DS_VAR_NO_SPACE			0x01
#define DS_VAR_INVALID_VAR		0x02
#define DS_VAR_INVALID_VAL		0x03
#define DS_VAR_NOT_PRESENT		0x04
};

struct ds_sp_token_msg {
	u64				req_num;
	u64				type;
	__u8				service[];
#define DS_SPTOK_REQUEST		0x01
};

struct ds_sp_token_resp {
	u64				req_num;
	u32				result;
	u32				ip_addr;
	u32				portid;
	__u8				token[DS_SPTOK_TOKEN_LEN];
#define DS_SP_TOKEN_RES_OK		0x00
#define DS_SP_TOKEN_RES_SVC_UNKNOWN	0x01
#define DS_SP_TOKEN_RES_SVC_UNAVAIL	0x02
#define DS_SP_TOKEN_RES_DOWN		0x03
};

#ifdef CONFIG_HOTPLUG_CPU
struct dr_cpu_tag {
	u64				req_num;
	u32				type;
#define DR_CPU_CONFIGURE		0x43
#define DR_CPU_UNCONFIGURE		0x55
#define DR_CPU_FORCE_UNCONFIGURE	0x46
#define DR_CPU_STATUS			0x53

/* Responses */
#define DR_CPU_OK			0x6f
#define DR_CPU_ERROR			0x65

	u32				num_records;
};

struct dr_cpu_resp_entry {
	u32				cpu;
	u32				result;
#define DR_CPU_RES_OK			0x00
#define DR_CPU_RES_FAILURE		0x01
#define DR_CPU_RES_BLOCKED		0x02
#define DR_CPU_RES_CPU_NOT_RESPONDING	0x03
#define DR_CPU_RES_NOT_IN_MD		0x04

	u32				stat;
#define DR_CPU_STAT_NOT_PRESENT		0x00
#define DR_CPU_STAT_UNCONFIGURED	0x01
#define DR_CPU_STAT_CONFIGURED		0x02

	u32				str_off;
};
#endif /* CONFIG_HOTPLUG_CPU */


/*
 * Builtin services provided directly by this module.
 */
struct ds_builtin_service {
	/* service id */
	char		*id;

	/* supported max version */
	ds_ver_t	vers;

	/* callback ops for this service */
	ds_ops_t	ops;
};

/* Prototypes for the builtin service callbacks */
static void ds_md_update_data_cb(ds_cb_arg_t arg,
	ds_svc_hdl_t hdl, void *buf, size_t len);
static void ds_dom_shutdown_data_cb(ds_cb_arg_t arg,
	ds_svc_hdl_t hdl, void *buf, size_t len);
static void ds_dom_panic_data_cb(ds_cb_arg_t arg,
	ds_svc_hdl_t hdl, void *buf, size_t len);
#ifdef CONFIG_HOTPLUG_CPU
static void ds_dr_cpu_data_cb(ds_cb_arg_t arg,
	ds_svc_hdl_t hdl, void *buf, size_t len);
#endif
static void ds_var_data_cb(ds_cb_arg_t arg,
	ds_svc_hdl_t hdl, void *buf, size_t len);
static void ds_sp_token_data_cb(ds_cb_arg_t arg,
	ds_svc_hdl_t hdl, void *buf, size_t len);
/*
 * Each service can have a unique supported maj/min version, but for
 * now we set them all to the same supported maj/min value below.
 */
#define	DS_CAP_MAJOR	1
#define	DS_CAP_MINOR	0

/*
 * Builtin service providers connected to the primary domain. These
 * service providers are started on any domain, and they are connected
 * and consumed by the primary domain.
 */
static struct ds_builtin_service ds_primary_builtin_template[] = {

	{
		.id		= "md-update",
		.vers		= {DS_CAP_MAJOR, DS_CAP_MINOR},
		.ops		= {NULL,
				   NULL,
				   ds_md_update_data_cb},
	},
	{
		.id		= "domain-shutdown",
		.vers		= {DS_CAP_MAJOR, DS_CAP_MINOR},
		.ops		= {NULL,
				   NULL,
				   ds_dom_shutdown_data_cb},
	},
	{
		.id		= "domain-panic",
		.vers		= {DS_CAP_MAJOR, DS_CAP_MINOR},
		.ops		= {NULL,
				   NULL,
				   ds_dom_panic_data_cb},
	},

#ifdef CONFIG_HOTPLUG_CPU
	{
		.id		= "dr-cpu",
		.vers		= {DS_CAP_MAJOR, DS_CAP_MINOR},
		.ops		= {NULL,
				   NULL,
				   ds_dr_cpu_data_cb},
	},
#endif

	/*
	 * var-config effectively behaves has a service client. But all kernel
	 * ds services are defined as providers, no matter if they actually
	 * behave as a server or as client.
	 */
	{
		.id		= "var-config",
		.vers		= {DS_CAP_MAJOR, DS_CAP_MINOR},
		.ops		= {NULL,
				   NULL,
				   ds_var_data_cb},
	},
};

/*
 * Builtin service clients connected to the SP. These service providers are
 * started only on the primary domain (which is the only domain connected
 * to the SP). They are connected to the SP which is the consumer of
 * these services.
 */
static struct ds_builtin_service ds_sp_builtin_template[] = {

	{
		.id		= "var-config-backup",
		.vers		= {DS_CAP_MAJOR, DS_CAP_MINOR},
		.ops		= {NULL,
				   NULL,
				   ds_var_data_cb},
	},
	{
		.id		= "sp-token",
		.vers		= {DS_CAP_MAJOR, DS_CAP_MINOR},
		.ops		= {NULL,
				   NULL,
				   ds_sp_token_data_cb},
	},
};

/* prototypes for local functions */
static void ds_unregister_ldc_services(struct ds_dev *ds);
static struct ds_service_info *ds_find_service_client_handle(
	struct ds_dev *ds, u64 handle);
static struct ds_service_info *ds_find_service_provider_handle(
	struct ds_dev *ds, u64 handle);
static struct ds_service_info *ds_find_service_client_con_handle(
	struct ds_dev *ds, u64 handle);
static struct ds_service_info *ds_find_service_provider_con_handle(
	struct ds_dev *ds, u64 handle);
static struct ds_service_info *ds_find_service_provider_id(struct ds_dev *ds,
	char *svc_id);
static void ds_remove_service_provider(struct ds_dev *ds,
	struct ds_service_info *provider_svc_info);
static struct ds_service_info *ds_add_service_provider(struct ds_dev *ds,
	char *id, ds_ver_t vers, ds_ops_t *ops, bool is_builtin);
static struct ds_service_info *ds_find_service_client_id(struct ds_dev *ds,
	char *svc_id);
static struct ds_service_info *ds_add_service_client(struct ds_dev *ds,
	char *id, ds_ver_t vers, ds_ops_t *ops, bool is_builtin);
static void ds_remove_service_client(struct ds_dev *ds,
	struct ds_service_info *client_svc_info);
static int ds_service_unreg(struct ds_dev *ds, u64 handle);
static void ds_disconnect_service_client(struct ds_dev *ds,
	struct ds_service_info *client_svc_info);
static void ds_disconnect_service_provider(struct ds_dev *ds,
	struct ds_service_info *provider_svc_info);

#define	LDOMS_DEBUG_LEVEL_SETUP		"ldoms_debug_level="
#define	LDOMS_MAX_DEBUG_LEVEL		7
unsigned int ldoms_debug_level;
EXPORT_SYMBOL(ldoms_debug_level);

module_param(ldoms_debug_level, uint, S_IRUGO|S_IWUSR);

static int __init ldoms_debug_level_setup(char *level_str)
{
	unsigned long level;

	if (!level_str)
		return -EINVAL;

	level = simple_strtoul(level_str, NULL, 0);

	if (level < LDOMS_MAX_DEBUG_LEVEL)
		ldoms_debug_level = level;

	return 1;

}
__setup(LDOMS_DEBUG_LEVEL_SETUP, ldoms_debug_level_setup);

static void ds_reset(struct ds_dev *ds)
{
	dprintk("entered.\n");

	ds->hs_state = DS_HS_LDC_DOWN;

	ds_unregister_ldc_services(ds);

	/* Disconnect the LDC */
	ldc_disconnect(ds->lp);

	/* clear the LDC RESET flag so that the LDC can reconnect */
	ldc_clr_reset(ds->lp);
}

static int ds_ldc_send_msg(struct ldc_channel *lp, void *data, int len)
{
	int rv, limit = 1000;

	rv = -EINVAL;
	while (limit-- > 0) {
		rv = ldc_write(lp, data, len);
		if (rv != -EAGAIN)
			break;
		udelay(1);
	}

	return rv;
}

static int ds_ldc_send_payload(struct ldc_channel *lp, u32 type,
	void *data, int len)
{
	struct ds_msg *msg;
	size_t msglen;
	gfp_t alloc_flags;
	int rv;

	/* This function can be called in either process or atomic mode */
	if (in_atomic())
		alloc_flags = GFP_ATOMIC;
	else
		alloc_flags = GFP_KERNEL;
	msglen = sizeof(struct ds_msg) + len;
	msg = kzalloc(msglen, alloc_flags);
	if (msg == NULL)
		return -ENOMEM;

	msg->tag.type = type;
	msg->tag.len = len;
	memcpy(msg->payload, data, len);

	rv = ds_ldc_send_msg(lp, msg, msglen);

	kfree(msg);

	return rv;
}

static void ds_send_data_nack(struct ds_dev *ds, u64 handle, u64 result)
{
	struct ds_data_nack_payload req;
	int rv;

	dprintk("entered.\n");

	req.handle = handle;
	req.result = result;

	rv = ds_ldc_send_payload(ds->lp, DS_NACK, &req, sizeof(req));
	if (rv <= 0)
		pr_err("ds-%llu: %s: ldc_send failed. (%d)\n ", ds->id,
		    __func__, rv);
}

struct ds_callout_entry_hdr {
	struct list_head		list;
	u8				type;
	struct ds_dev			*ds;
};
/* callout queue entry types */
#define	DS_QTYPE_DATA		0x1
#define	DS_QTYPE_REG		0x2
#define	DS_QTYPE_UNREG		0x3

/* callout queue entry for data cb */
struct ds_callout_data_entry {
	struct ds_callout_entry_hdr	hdr;
	u8				data_req_type;
	u64				req[0];
};
/* data_req_type field types */
#define	DS_DTYPE_CLIENT_REQ		0x1
#define	DS_DTYPE_PROVIDER_REQ		0x2
#define	DS_DTYPE_LDC_REQ		0x3

/* callout queue entry for reg or unreg cb */
struct ds_callout_reg_entry {
	struct ds_callout_entry_hdr	hdr;
	u64				hdl;
};

static struct ds_service_info *ds_callout_data_get_service(
	struct ds_dev *ds, u8 data_req_type, u64 hdl)
{
	struct ds_service_info *svc_info;

	/*
	 * Find the provider or client service to which
	 * a data message is intended to be sent.
	 * If the original request was from a client, find
	 * a provider handle. If the original request was
	 * from a provider, find a client handle. If the
	 * original request was from a LDC, look for either.
	 * This check is required to support a loopback
	 * connection where both a client and provider
	 * connected in loopback mode have the same con_handle.
	 */

	svc_info = NULL;

	if (data_req_type == DS_DTYPE_CLIENT_REQ ||
	    data_req_type == DS_DTYPE_LDC_REQ)
		svc_info = ds_find_service_provider_con_handle(ds, hdl);

	if (!svc_info &&
	    (data_req_type == DS_DTYPE_PROVIDER_REQ ||
	    data_req_type == DS_DTYPE_LDC_REQ))
		svc_info = ds_find_service_client_con_handle(ds, hdl);

	if (!svc_info || !svc_info->is_connected) {

		if (!svc_info)
			dprintk("ds-%llu: Data received for "
			    "unknown handle %llu\n", ds->id, hdl);
		else
			dprintk("ds-%llu: Data received for "
			    "unconnected handle %llu\n", ds->id, hdl);

		/*
		 * If this was a LDC data packet, nack it.
		 * NOTE: If this was a loopback data packet,
		 * we should always find a connected target
		 * service and never execute this code. In
		 * the unlikely event that the loopback
		 * connection has been disconnected while the
		 * data packet is "in-flight", the packet will
		 * just be ignored and ignoring the packet is
		 * probably appropriate in that case.
		 */
		if (data_req_type == DS_DTYPE_LDC_REQ)
			ds_send_data_nack(ds, hdl, DS_INV_HDL);

		return NULL;
	}

	return svc_info;

}

static struct ds_service_info *ds_callout_reg_get_service(
	struct ds_dev *ds, u8 type, u64 hdl)
{
	struct ds_service_info *svc_info;

	svc_info = ds_find_service_provider_handle(ds, hdl);
	if (svc_info == NULL) {

		svc_info = ds_find_service_client_handle(ds, hdl);
		if (svc_info == NULL) {
			dprintk("ds-%llu: %s cb request received for "
			    "unknown handle %llu\n", ds->id,
			    (type == DS_QTYPE_REG) ? "Reg" : "Unreg", hdl);
			return NULL;
		}
	}

	return svc_info;

}

static void ds_do_callout_processing(void)
{
	unsigned long flags;
	unsigned long ds_flags;
	struct ds_dev *ds;
	struct ds_callout_entry_hdr *qhdrp;
	struct ds_callout_entry_hdr *tmp;
	struct ds_callout_reg_entry *rentry;
	struct ds_callout_data_entry *dentry;
	struct ds_service_info *svc_info;
	struct ds_data_req *data_req;
	void (*reg_cb)(ds_cb_arg_t, ds_svc_hdl_t, ds_ver_t *);
	void (*unreg_cb)(ds_cb_arg_t, ds_svc_hdl_t);
	void (*data_cb)(ds_cb_arg_t, ds_svc_hdl_t, void *, size_t);
	ds_cb_arg_t cb_arg;
	ds_ver_t neg_vers;
	u64 hdl;
	LIST_HEAD(todo);

	dprintk("ds: CPU[%d]: callout processing START\n", smp_processor_id());

	/*
	 * Merge all the ds_dev callout lists into a
	 * single local todo list for processing. The
	 * ds_dev callout lists are re-initialized to empty.
	 * We do this because we cannot hold any driver locks
	 * while we process the entries (and make callbacks)
	 * because it's possible that the callbacks could
	 * call back into this driver and attempt to re-acquire
	 * the lock(s) resulting in deadlock.
	 */
	spin_lock_irqsave(&ds_data_lock, flags);
	list_for_each_entry(ds, &ds_data.ds_dev_list, list) {
		LOCK_DS_DEV(ds, ds_flags)
		list_splice_tail_init(&ds->callout_list, &todo);
		UNLOCK_DS_DEV(ds, ds_flags)
	}
	spin_unlock_irqrestore(&ds_data_lock, flags);

	list_for_each_entry_safe(qhdrp, tmp, &todo, list) {

		LOCK_DS_DEV(qhdrp->ds, ds_flags)
		/*
		 * If the ds this entry references
		 * has been deactivated, skip it.
		 * If this is the last reference to it,
		 * free the ds.
		 */
		qhdrp->ds->co_ref_cnt--;

		if (unlikely(!qhdrp->ds->active)) {

			UNLOCK_DS_DEV(qhdrp->ds, ds_flags)

			if (qhdrp->ds->co_ref_cnt == 0)
				kfree(qhdrp->ds);

			list_del(&qhdrp->list);
			kfree(qhdrp);

			continue;
		}

		if (qhdrp->type == DS_QTYPE_DATA) {
			/* process data entry */
			dentry = (struct ds_callout_data_entry *)qhdrp;
			data_req = (struct ds_data_req *) dentry->req;
			ds = dentry->hdr.ds;

			svc_info = ds_callout_data_get_service(ds,
			    dentry->data_req_type, data_req->payload.handle);

			if (unlikely(svc_info == NULL)) {
				UNLOCK_DS_DEV(ds, ds_flags)
				list_del(&qhdrp->list);
				kfree(qhdrp);
				continue;
			}

			/*
			 * We unlock the ds_dev before we make the data
			 * callback to enforce the rule that no locks be held
			 * when making callbacks. However, this opens a timing
			 * hole where a service unregistration could come in
			 * between releasing the lock and making the callback
			 * rendering the svc_info * stale/freed. So, copy
			 * over the svc_info fields into locals before we
			 * free the lock to close this very unlikely but
			 * possible hole.
			 */
			hdl = svc_info->handle;
			data_cb = svc_info->ops.ds_data_cb;
			cb_arg = svc_info->ops.cb_arg;

			UNLOCK_DS_DEV(ds, ds_flags)

			/*
			 * We strip off the DS protocol header (ds_data_req)
			 * portion of the data for the callback to receive.
			 * Since tag->len includes the handle (a u64) of the
			 * ds_data_req + the payload, we must subtract an extra
			 * u64 from the len. This is per spec.
			 */
			data_cb(cb_arg, hdl, data_req->payload.data,
			    DS_DATA_REQ_DSIZE(data_req));

		} else {
			/* process reg/ureg entry */
			rentry = (struct ds_callout_reg_entry *)qhdrp;
			ds = rentry->hdr.ds;

			svc_info = ds_callout_reg_get_service(ds,
			    rentry->hdr.type, rentry->hdl);

			if (unlikely(svc_info == NULL)) {
				UNLOCK_DS_DEV(ds, ds_flags)
				list_del(&qhdrp->list);
				kfree(qhdrp);
				continue;
			}

			/*
			 * We unlock the ds_dev before we make the reg/unreg
			 * callback to enforce the rule that no locks be held
			 * when making callbacks. However, this opens a timing
			 * hole where a service unregistration could come in
			 * between releasing the lock and making the callback
			 * rendering the svc_info * stale/freed. So, copy
			 * over the svc_info fields into locals before we
			 * free the lock to close this very unlikely but
			 * possible hole.
			 */
			hdl = svc_info->handle;
			reg_cb = svc_info->ops.ds_reg_cb;
			unreg_cb = svc_info->ops.ds_unreg_cb;
			cb_arg = svc_info->ops.cb_arg;
			neg_vers = svc_info->neg_vers;

			UNLOCK_DS_DEV(ds, ds_flags)

			if (rentry->hdr.type == DS_QTYPE_REG) {
				if (reg_cb != NULL)
					reg_cb(cb_arg, hdl, &neg_vers);
			} else {
				if (unreg_cb != NULL)
					unreg_cb(cb_arg, hdl);
			}

		}

		/* done processing the entry, remove it from the list */
		list_del(&qhdrp->list);
		kfree(qhdrp);
	}

	dprintk("ds: CPU[%d]: callout processing END\n", smp_processor_id());
}

static DECLARE_WAIT_QUEUE_HEAD(ds_wait);

static int ds_callout_thread(void *__unused)
{
	DEFINE_WAIT(wait);
	unsigned long flags;
	struct ds_dev *ds;
	bool work_to_do;

	while (1) {
		prepare_to_wait(&ds_wait, &wait, TASK_INTERRUPTIBLE);

		work_to_do = false;
		spin_lock_irqsave(&ds_data_lock, flags);
		list_for_each_entry(ds, &ds_data.ds_dev_list, list) {
			if (!list_empty(&ds->callout_list)) {
				work_to_do = true;
				break;
			}
		}
		spin_unlock_irqrestore(&ds_data_lock, flags);

		if (!work_to_do)
			schedule();

		finish_wait(&ds_wait, &wait);

		if (kthread_should_stop())
			break;

		ds_do_callout_processing();
	}

	return 0;
}

static int ds_submit_reg_cb(struct ds_dev *ds, u64 hdl, u8 type)
{
	struct ds_callout_reg_entry *rentry;
	gfp_t alloc_flags;

	/* This function can be called in either process or atomic mode */
	if (in_atomic())
		alloc_flags = GFP_ATOMIC;
	else
		alloc_flags = GFP_KERNEL;

	rentry = kzalloc(sizeof(struct ds_callout_reg_entry), alloc_flags);
	if (!rentry)
		return -ENOMEM;

	rentry->hdr.type = type;
	rentry->hdr.ds = ds;
	rentry->hdl = hdl;

	list_add_tail(&rentry->hdr.list, &ds->callout_list);
	ds->co_ref_cnt++;

	dprintk("ds-%llu: Added %s item to work queue "
	    "(co_ref_cnt=%llu)\n", ds->id,
	    (rentry->hdr.type == DS_QTYPE_REG) ? "Reg" : "Unreg",
	    ds->co_ref_cnt);

	wake_up(&ds_wait);

	return 0;
}

static int ds_submit_data_cb(struct ds_dev *ds, struct ds_msg_tag *pkt,
	u8 data_type)
{
	struct ds_callout_data_entry *dentry;
	u64 pktlen;
	gfp_t alloc_flags;

	pktlen = (sizeof(struct ds_msg_tag) + pkt->len);

	/*
	 * Data packets are added to our data thread's
	 * data work queue for later processing.
	 */

	/* This function can be called in either process or atomic mode */
	if (in_atomic())
		alloc_flags = GFP_ATOMIC;
	else
		alloc_flags = GFP_KERNEL;

	dentry = kzalloc(sizeof(struct ds_callout_data_entry) + pktlen,
	    alloc_flags);
	if (!dentry)
		return -ENOMEM;

	dentry->hdr.type = DS_QTYPE_DATA;
	dentry->hdr.ds = ds;
	dentry->data_req_type = data_type;
	memcpy(&dentry->req, pkt, pktlen);

	list_add_tail(&dentry->hdr.list, &ds->callout_list);
	ds->co_ref_cnt++;

	dprintk("ds-%llu: Added data item (type=%u) to work queue "
	    "(co_ref_cnt=%llu)\n", ds->id, pkt->type, ds->co_ref_cnt);

	wake_up(&ds_wait);

	return 0;
}

/*
 * External service registration interface functions
 */
int ds_cap_init(ds_capability_t *cap, ds_ops_t *ops, u32 flags,
	u64 domain_hdl,  ds_svc_hdl_t *hdlp)
{
	struct ds_dev *ds;
	struct ds_service_info *svc_info = NULL;
	unsigned long data_flags = 0;
	unsigned long ds_flags = 0;
	bool is_domain;

	dprintk("entered.\n");

	/* validate args */
	if (cap == NULL || ops == NULL) {
		pr_err("%s: Error: NULL argument(s) received\n", __func__);
		return -EINVAL;
	}

	/* flags must be set to PROVIDER or CLIENT but not both. */
	if (!(flags & DS_CAP_IS_PROVIDER || flags & DS_CAP_IS_CLIENT) ||
	    (flags & DS_CAP_IS_PROVIDER && flags & DS_CAP_IS_CLIENT)) {
		pr_err("%s: Error: Invalid flags argument received %u\n",
		    __func__, flags);
		return -EINVAL;
	}

	/* data callback must be specified, other ops callbacks can be NULL */
	if (ops->ds_data_cb == NULL) {
		pr_err("%s: Error: data callback op must be present\n",
		    __func__);
		return -EINVAL;
	}

	is_domain = ((flags & DS_TARGET_IS_DOMAIN) != 0);

	/* Find the ds_dev associated with domain_hdl. */
	spin_lock_irqsave(&ds_data_lock, data_flags);
	ds = NULL;
	list_for_each_entry(ds, &ds_data.ds_dev_list, list) {

		LOCK_DS_DEV(ds, ds_flags)

		if ((is_domain && ds->is_domain && ds->handle == domain_hdl) ||
		    (!is_domain && !ds->is_domain))
			break;

		UNLOCK_DS_DEV(ds, ds_flags)
	}
	spin_unlock_irqrestore(&ds_data_lock, data_flags);

	if (ds == NULL) {
		pr_err("%s: Error: dom_hdl %llu (domain=%d) DS "
		    "port not found\n", __func__, domain_hdl,
		    ((flags & DS_TARGET_IS_DOMAIN) != 0));
		return -ENODEV;
	}

	if (flags & DS_CAP_IS_PROVIDER) {

		/* Check if there is already a registered service provider */
		svc_info = ds_find_service_provider_id(ds, cap->svc_id);
		if (svc_info != NULL) {
			if (svc_info->is_connected && !svc_info->is_builtin) {
				pr_err("%s: Error: service provider %s "
				    "already registered\n", __func__,
				    cap->svc_id);
				UNLOCK_DS_DEV(ds, ds_flags)
				return -EBUSY;
			} else {
				/*
				 * Existing service is not connected or is
				 * a builtin (i.e. allow external to override
				 * builtin). Remove the service.
				 */
				ds_remove_service_provider(ds, svc_info);
			}
		}

		svc_info = ds_add_service_provider(ds, cap->svc_id, cap->vers,
		    ops, false);

		if (svc_info == NULL) {
			pr_err("ds-%llu: %s: Failed to add service "
			    "provider %s", ds->id, __func__, cap->svc_id);
			UNLOCK_DS_DEV(ds, ds_flags)
			return -ENOMEM;
		}

	} else if (flags & DS_CAP_IS_CLIENT) {

		/* Check if there is already a registered service client */
		svc_info = ds_find_service_client_id(ds, cap->svc_id);
		if (svc_info != NULL) {
			if (svc_info->is_connected && !svc_info->is_builtin) {
				pr_err("%s: Error: service client %s "
				    "already registered\n", __func__,
				    cap->svc_id);
				UNLOCK_DS_DEV(ds, ds_flags)
				return -EBUSY;
			} else {
				/*
				 * Existing service is not connected or is
				 * a builtin (i.e. allow external to override
				 * builtin). Remove the service.
				 */
				ds_remove_service_client(ds, svc_info);
			}
		}

		svc_info = ds_add_service_client(ds, cap->svc_id, cap->vers,
		    ops, false);

		if (svc_info == NULL) {
			pr_err("ds-%llu: %s: Failed to add service "
			    "client %s", ds->id, __func__, cap->svc_id);
			UNLOCK_DS_DEV(ds, ds_flags)
			return -ENOMEM;
		}
	}

	/* populate the unique handle to passed in hdlp argument */
	*hdlp = (ds_svc_hdl_t)svc_info->handle;

	dprintk("ds-%llu: Registered %s service (%llx), client=%d\n",
	    ds->id, svc_info->id, svc_info->handle, svc_info->is_client);

	UNLOCK_DS_DEV(ds, ds_flags)

	return 0;

}
EXPORT_SYMBOL(ds_cap_init);

int ds_cap_fini(ds_svc_hdl_t hdl)
{
	struct ds_dev *ds;
	struct ds_service_info *svc_info, *tmp;
	unsigned long flags = 0;
	unsigned long ds_flags = 0;

	dprintk("entered.\n");

	/* validate args */
	if (hdl == 0) {
		pr_err("%s: Error: hdl argument received is 0\n", __func__);
		return -EINVAL;
	}

	/* Find and remove all services associated with hdl. */

	spin_lock_irqsave(&ds_data_lock, flags);

	list_for_each_entry(ds, &ds_data.ds_dev_list, list) {

		LOCK_DS_DEV(ds, ds_flags)

		list_for_each_entry_safe(svc_info, tmp,
		    &ds->service_provider_list, list) {
			if (svc_info->handle == (u64)hdl)
				ds_remove_service_provider(ds, svc_info);
		}

		list_for_each_entry_safe(svc_info, tmp,
		    &ds->service_client_list, list) {
			if (svc_info->handle == (u64)hdl)
				ds_remove_service_client(ds, svc_info);
		}

		UNLOCK_DS_DEV(ds, ds_flags)
	}

	spin_unlock_irqrestore(&ds_data_lock, flags);

	return 0;

}
EXPORT_SYMBOL(ds_cap_fini);

int ds_cap_send(ds_svc_hdl_t hdl, void *buf, size_t buflen)
{
	struct ds_dev *ds;
	struct ds_service_info *svc_info;
	unsigned long flags = 0;
	unsigned long ds_flags = 0;
	struct ds_data_req *hdr;
	int msglen;
	u8 type;
	int rv;

	dprintk("entered.\n");

	/* validate args */
	if (hdl == 0) {
		pr_err("%s: Error: hdl argument received is 0\n", __func__);
		return -EINVAL;
	}

	if (buf == NULL) {
		pr_err("%s: Error: Invalid NULL buffer argument\n", __func__);
		return -EINVAL;
	}

	if (buflen == 0)
		return 0;

	/* Find the service uniquely identified by hdl */

	svc_info = NULL;

	spin_lock_irqsave(&ds_data_lock, flags);
	list_for_each_entry(ds, &ds_data.ds_dev_list, list) {

		LOCK_DS_DEV(ds, ds_flags)

		svc_info = ds_find_service_provider_handle(ds, (u64)hdl);
		if (svc_info == NULL)
			svc_info = ds_find_service_client_handle(ds,
			    (u64)hdl);

		/* if we found the hdl, break but do not release the ds_lock */
		if (svc_info != NULL)
			break;

		UNLOCK_DS_DEV(ds, ds_flags)
	}

	spin_unlock_irqrestore(&ds_data_lock, flags);

	if (svc_info == NULL) {
		pr_err("%s: Error: no service found "
		    "for handle %llx\n", __func__, hdl);
		return -ENODEV;
	}

	if (!svc_info->is_connected) {
		pr_err("%s: Error: Service %s not connected.\n", __func__,
		    svc_info->id);
		UNLOCK_DS_DEV(ds, ds_flags)
		return -ENODEV;
	}

	/* build the data packet containing the data */
	msglen = sizeof(struct ds_data_req) + buflen;
	hdr = kzalloc(msglen, GFP_KERNEL);
	if (hdr == NULL) {
		pr_err("ds-%llu: %s: failed to alloc mem for data msg.\n",
		    ds->id, __func__);
		UNLOCK_DS_DEV(ds, ds_flags)
		return -ENOMEM;
	}
	hdr->tag.type = DS_DATA;
	hdr->tag.len = sizeof(struct ds_data_req_payload) + buflen;
	hdr->payload.handle = svc_info->con_handle;
	(void) memcpy(hdr->payload.data, buf, buflen);

	if (svc_info->is_loopback) {
		/*
		 * If the service is connected via loopback, submit the
		 * packet to our local work queue.
		 */
		type = (svc_info->is_client) ? DS_DTYPE_CLIENT_REQ
		    : DS_DTYPE_PROVIDER_REQ;
		rv = ds_submit_data_cb(ds, (struct ds_msg_tag *)hdr, type);
		if (rv < 0)
			pr_err("ds-%llu: %s: ds_submit_data_cb failed.\n ",
			    ds->id, __func__);
	} else {
		/* send the data out to the LDC */
		rv = ds_ldc_send_msg(ds->lp, (void *)hdr, msglen);
		if (rv <= 0) {
			pr_err("ds-%llu: %s: ldc_send failed.(%d)\n ",
			    ds->id, __func__, rv);
			rv = -EIO;
		} else {
			rv = 0;
		}
	}

	kfree(hdr);

	UNLOCK_DS_DEV(ds, ds_flags)

	return rv;
}
EXPORT_SYMBOL(ds_cap_send);

/*
 * Builtin service callback routines
 */

static void ds_md_update_data_cb(ds_cb_arg_t arg,
		   ds_svc_hdl_t handle, void *buf, size_t len)
{
	struct ds_dev *ds = (struct ds_dev *)arg;
	struct ds_md_update_req *rp;
	struct ds_md_update_res	res;

	dprintk("entered.\n");

	rp = (struct ds_md_update_req *)buf;

	pr_alert("ds-%llu: Machine description update.\n", ds->id);

	mdesc_update();

	res.req_num = rp->req_num;
	res.result = DS_OK;

	ds_cap_send(handle, &res, sizeof(struct ds_md_update_res));
}

static void ds_dom_shutdown_data_cb(ds_cb_arg_t arg,
		ds_svc_hdl_t handle, void *buf, size_t len)
{
	struct ds_dev *ds = (struct ds_dev *)arg;
	struct ds_shutdown_req *rp;
	struct ds_shutdown_res res;

	dprintk("entered.\n");

	rp = (struct ds_shutdown_req *)buf;

	pr_alert("ds-%llu: Shutdown request received.\n", ds->id);

	res.req_num = rp->req_num;
	res.result = DS_OK;
	res.reason[0] = 0;

	ds_cap_send(handle, &res, sizeof(struct ds_shutdown_res));

	/* give a message to the console if the delay is greater than 1 sec. */
	if (rp->ms_delay > 1000) {
		pr_alert("ds-%llu: Shutting down in %u seconds.\n",
		    ds->id, rp->ms_delay/1000);
		/* delay for specified ms before shutdown */
		mdelay(rp->ms_delay);
	}


	orderly_poweroff(true);
}

static void ds_dom_panic_data_cb(ds_cb_arg_t arg,
		ds_svc_hdl_t handle, void *buf, size_t len)
{
	struct ds_dev *ds = (struct ds_dev *)arg;
	struct ds_panic_req *rp;
	struct ds_panic_res res;

	dprintk("entered.\n");

	rp = (struct ds_panic_req *)buf;

	pr_alert("ds-%llu: Panic request received.\n", ds->id);

	res.req_num = rp->req_num;
	res.result = DS_OK;
	res.reason[0] = 0;

	ds_cap_send(handle, &res, sizeof(struct ds_panic_res));

	panic("PANIC requested.\n");
}

#ifdef CONFIG_HOTPLUG_CPU

static void __dr_cpu_send_error(struct ds_dev *ds,
	u64 handle, struct dr_cpu_tag *tag)
{
	struct dr_cpu_tag	resp_tag;

	dprintk("entered.\n");

	resp_tag.req_num = tag->req_num;
	resp_tag.type = DR_CPU_ERROR;
	resp_tag.num_records = 0;

	ds_cap_send(handle, &resp_tag, sizeof(struct dr_cpu_tag));
}

#define CPU_SENTINEL	0xffffffff

static void purge_dups(u32 *list, u32 num_ents)
{
	unsigned int i;

	dprintk("entered.\n");

	for (i = 0; i < num_ents; i++) {
		u32 cpu = list[i];
		unsigned int j;

		if (cpu == CPU_SENTINEL)
			continue;

		for (j = i + 1; j < num_ents; j++) {
			if (list[j] == cpu)
				list[j] = CPU_SENTINEL;
		}
	}
}

static int dr_cpu_size_response(int ncpus)
{
	return sizeof(struct dr_cpu_tag) +
		(sizeof(struct dr_cpu_resp_entry) * ncpus);
}

static void dr_cpu_init_response(struct dr_cpu_tag *tag, u64 req_num,
				 u64 handle, int resp_len, int ncpus,
				 cpumask_t *mask, u32 default_stat)
{
	struct dr_cpu_resp_entry *ent;
	int i, cpu;

	ent = (struct dr_cpu_resp_entry *) (tag + 1);

	tag->req_num = req_num;
	tag->type = DR_CPU_OK;
	tag->num_records = ncpus;

	i = 0;
	for_each_cpu(cpu, mask) {
		ent[i].cpu = cpu;
		ent[i].result = DR_CPU_RES_OK;
		ent[i].stat = default_stat;
		i++;
	}
	BUG_ON(i != ncpus);
}

static void dr_cpu_mark(struct dr_cpu_tag *tag, int cpu, int ncpus,
			u32 res, u32 stat)
{
	struct dr_cpu_resp_entry *ent;
	int i;

	ent = (struct dr_cpu_resp_entry *) (tag + 1);

	for (i = 0; i < ncpus; i++) {
		if (ent[i].cpu != cpu)
			continue;
		ent[i].result = res;
		ent[i].stat = stat;
		break;
	}
}

static int __cpuinit dr_cpu_configure(struct ds_dev *ds,
	u64 handle, u64 req_num, cpumask_t *mask)
{
	struct dr_cpu_tag *resp;
	int resp_len, ncpus, cpu;

	dprintk("entered.\n");

	ncpus = cpumask_weight(mask);
	resp_len = dr_cpu_size_response(ncpus);
	resp = kzalloc(resp_len, GFP_KERNEL);
	if (!resp)
		return -ENOMEM;

	dr_cpu_init_response(resp, req_num, handle,
			     resp_len, ncpus, mask,
			     DR_CPU_STAT_CONFIGURED);

	mdesc_populate_present_mask(mask);
	mdesc_fill_in_cpu_data(mask);

	for_each_cpu(cpu, mask) {
		int err;

		dprintk("ds-%llu: Starting cpu %d...\n", ds->id, cpu);
		err = cpu_up(cpu);
		if (err) {
			u32 res = DR_CPU_RES_FAILURE;
			u32 stat = DR_CPU_STAT_UNCONFIGURED;

			if (!cpu_present(cpu)) {
				/* CPU not present in MD */
				stat = DR_CPU_STAT_NOT_PRESENT;
			} else if (err == -ENODEV) {
				/* CPU did not call in successfully */
				res = DR_CPU_RES_CPU_NOT_RESPONDING;
			}

			pr_err("ds-%llu: CPU startup failed err=%d\n", ds->id,
				err);
			dr_cpu_mark(resp, cpu, ncpus, res, stat);
		}
	}

	ds_cap_send(handle, resp, resp_len);

	kfree(resp);

	/* Redistribute IRQs, taking into account the new cpus.  */
	fixup_irqs();

	return 0;
}

static int dr_cpu_unconfigure(struct ds_dev *ds,
	u64 handle, u64 req_num, cpumask_t *mask)
{
	struct dr_cpu_tag *resp;
	int resp_len, ncpus, cpu;

	dprintk("entered.\n");

	ncpus = cpumask_weight(mask);
	resp_len = dr_cpu_size_response(ncpus);
	resp = kzalloc(resp_len, GFP_KERNEL);
	if (!resp)
		return -ENOMEM;

	dr_cpu_init_response(resp, req_num, handle,
			     resp_len, ncpus, mask,
			     DR_CPU_STAT_UNCONFIGURED);

	for_each_cpu(cpu, mask) {
		int err;

		pr_info("ds-%llu: Shutting down cpu %d...\n", ds->id, cpu);
		err = cpu_down(cpu);
		if (err)
			dr_cpu_mark(resp, cpu, ncpus,
				    DR_CPU_RES_FAILURE,
				    DR_CPU_STAT_CONFIGURED);
	}

	ds_cap_send(handle, resp, resp_len);

	kfree(resp);

	return 0;
}

static void __cpuinit ds_dr_cpu_data_cb(ds_cb_arg_t arg,
		ds_svc_hdl_t handle, void *buf, size_t len)
{
	struct ds_dev *ds = (struct ds_dev *)arg;
	struct dr_cpu_tag *tag = (struct dr_cpu_tag *)buf;
	u32 *cpu_list = (u32 *) (tag + 1);
	u64 req_num = tag->req_num;
	cpumask_t mask;
	unsigned int i;
	int err;

	dprintk("entered.\n");

	switch (tag->type) {
	case DR_CPU_CONFIGURE:
	case DR_CPU_UNCONFIGURE:
	case DR_CPU_FORCE_UNCONFIGURE:
		break;

	default:
		__dr_cpu_send_error(ds, handle, tag);
		return;
	}

	purge_dups(cpu_list, tag->num_records);

	cpumask_clear(&mask);
	for (i = 0; i < tag->num_records; i++) {
		if (cpu_list[i] == CPU_SENTINEL)
			continue;

		if (cpu_list[i] < nr_cpu_ids)
			cpumask_set_cpu(cpu_list[i], &mask);
	}

	if (tag->type == DR_CPU_CONFIGURE)
		err = dr_cpu_configure(ds, handle, req_num, &mask);
	else
		err = dr_cpu_unconfigure(ds, handle, req_num, &mask);

	if (err)
		__dr_cpu_send_error(ds, handle, tag);
}
#endif /* CONFIG_HOTPLUG_CPU */

static DEFINE_MUTEX(ds_var_mutex);
static DECLARE_COMPLETION(ds_var_config_cb_complete);
static DEFINE_MUTEX(ds_var_complete_mutex);
static int ds_var_response;

static void ds_var_data_cb(ds_cb_arg_t arg,
	ds_svc_hdl_t handle, void *buf, size_t len)
{
	struct ds_var_resp *rp;

	dprintk("entered.\n");

	rp = (struct ds_var_resp *)buf;

	dprintk("hdr.type = %u\n", rp->hdr.type);
	dprintk("result = %u\n", rp->result);

	if (rp->hdr.type != DS_VAR_SET_RESP &&
	    rp->hdr.type != DS_VAR_DELETE_RESP)
		return;

	ds_var_response = rp->result;
	wmb();

	mutex_lock(&ds_var_complete_mutex);
	complete(&ds_var_config_cb_complete);
	mutex_unlock(&ds_var_complete_mutex);
}

static DEFINE_MUTEX(ds_sp_token_mutex);
static DECLARE_COMPLETION(ds_sp_token_cb_complete);
static DEFINE_MUTEX(ds_sp_token_complete_mutex);
static u32		ds_sp_token_resp_result;
static u64		ds_sp_token_resp_req_num;
static u64		ds_sp_token_next_req_num;
static ds_sptok_t	ds_sp_token_data;

static void ds_sp_token_data_cb(ds_cb_arg_t arg,
	ds_svc_hdl_t handle, void *buf, size_t len)
{
	struct ds_dev *ds = (struct ds_dev *)arg;
	struct ds_sp_token_resp *rp;

	dprintk("entered.\n");

	rp = (struct ds_sp_token_resp *)buf;

	dprintk("ds-%llu: SP TOKEN REQ [%llx:%x], len=%lu ip_addr=%x (%d.%d)"
	    "portid=%d\n", ds->id, rp->req_num, rp->result, len, rp->ip_addr,
	    (rp->ip_addr & 0xFF00) >> 8, rp->ip_addr & 0xFF, rp->portid);

	dprintk("[%x:%x...0x%x...:%x].\n", (__u8)rp->token[0],
	    (__u8)rp->token[1], (__u8)rp->token[11], (__u8)rp->token[19]);

	(void) memcpy(&ds_sp_token_data, &(rp->ip_addr), sizeof(ds_sptok_t));
	ds_sp_token_resp_result = rp->result;
	ds_sp_token_resp_req_num = rp->req_num;
	wmb();

	mutex_lock(&ds_sp_token_complete_mutex);
	complete(&ds_sp_token_cb_complete);
	mutex_unlock(&ds_sp_token_complete_mutex);

}

/*
 * Helper functions
 */

static u64 ds_get_service_timeout(void)
{
	u8 random_byte;
	u64 timeout_cnt;

	/*
	 * Return a random number of jiffies that is
	 * between 3000 and 9000ms in the future.
	 * XXX - make these values configurable.
	 */
	get_random_bytes(&random_byte, 1);
	timeout_cnt = (((random_byte % 7) + 3));

	return jiffies + msecs_to_jiffies(timeout_cnt * 1000);

}

static struct ds_service_info *ds_find_connected_prov_service(char *svc_id)
{
	struct ds_dev *ds;
	unsigned long flags;
	unsigned long ds_flags = 0;
	struct ds_service_info *svc_info;

	spin_lock_irqsave(&ds_data_lock, flags);

	list_for_each_entry(ds, &ds_data.ds_dev_list, list) {

		LOCK_DS_DEV(ds, ds_flags)

		svc_info = ds_find_service_provider_id(ds, svc_id);
		if (svc_info != NULL && svc_info->is_connected) {
			UNLOCK_DS_DEV(ds, ds_flags)
			spin_unlock_irqrestore(&ds_data_lock, flags);
			return svc_info;
		}

		UNLOCK_DS_DEV(ds, ds_flags)
	}

	spin_unlock_irqrestore(&ds_data_lock, flags);

	return NULL;

}

static struct ds_service_info *ds_find_service_provider_id(struct ds_dev *ds,
	char *svc_id)
{
	struct ds_service_info *svc_info;

	list_for_each_entry(svc_info, &ds->service_provider_list, list) {
		if (strncmp(svc_info->id, svc_id, DS_MAX_SVC_NAME_LEN) == 0)
			return svc_info;
	}

	return NULL;
}

static struct ds_service_info *ds_find_service_provider_handle(
	struct ds_dev *ds, u64 handle)
{
	struct ds_service_info *svc_info;

	list_for_each_entry(svc_info, &ds->service_provider_list, list) {
		if (svc_info->handle == handle)
			return svc_info;
	}

	return NULL;
}

static struct ds_service_info *ds_find_service_provider_con_handle(
	struct ds_dev *ds, u64 handle)
{
	struct ds_service_info *svc_info;

	list_for_each_entry(svc_info, &ds->service_provider_list, list) {
		if (svc_info->con_handle == handle)
			return svc_info;
	}

	return NULL;
}

static struct ds_service_info *ds_find_service_client_id(struct ds_dev *ds,
	char *svc_id)
{
	struct ds_service_info *svc_info;

	list_for_each_entry(svc_info, &ds->service_client_list, list) {
		if (strncmp(svc_info->id, svc_id, DS_MAX_SVC_NAME_LEN) == 0)
			return svc_info;
	}

	return NULL;
}

static struct ds_service_info *ds_find_service_client_handle(
	struct ds_dev *ds, u64 handle)
{
	struct ds_service_info *svc_info;

	list_for_each_entry(svc_info, &ds->service_client_list, list) {
		if (svc_info->handle == handle)
			return svc_info;
	}

	return NULL;
}

static struct ds_service_info *ds_find_service_client_con_handle(
	struct ds_dev *ds, u64 handle)
{
	struct ds_service_info *svc_info;

	list_for_each_entry(svc_info, &ds->service_client_list, list) {
		if (svc_info->con_handle == handle)
			return svc_info;
	}

	return NULL;
}

static struct ds_service_info *ds_find_lb_service_peer(struct ds_dev *ds,
	struct ds_service_info *svc_info)
{
	struct ds_service_info *peer_svc_info;

	/* if the service is a client, find a provider with the same id */
	if (svc_info->is_client) {
		peer_svc_info = ds_find_service_provider_id(ds, svc_info->id);
		if (peer_svc_info && peer_svc_info->reg_state ==
		    DS_REG_STATE_REGISTERED_LOOPBACK)
			return peer_svc_info;
	} else {
		peer_svc_info = ds_find_service_client_id(ds, svc_info->id);
		if (peer_svc_info && peer_svc_info->reg_state ==
		    DS_REG_STATE_REGISTERED_LOOPBACK)
			return peer_svc_info;
	}

	return NULL;
}


static u64 ds_get_new_service_handle(struct ds_dev *ds, bool is_client)
{

	u64 handle;

	/*
	 * Solaris uses a couple of bits in the handle as flags.
	 * See, DS_HDL_ISCLIENT_BIT, DS_HDL_ISCNTRLD_BIT.
	 * So, to avoid using these bits in a handle we only use the
	 * bottom 30 bits. This will help avoid issues on mixed
	 * systems running both Linux and Solaris domains.
	 */

	/* handle wrap at DS_HDL_ISCNTRLD_BIT - don't use 0 */
	if (ds->next_service_handle == DS_HDL_ISCNTRLD_BIT)
		ds->next_service_handle = 1;

	handle = (ds->id << 32) | ds->next_service_handle++;

	/*
	 * If the service is a client service, set the ISLCLIENT
	 * bit which is an indication (or "ping") to the other end
	 * to send a REG_REQ for the provider service.
	 */
	if (is_client)
		handle |= DS_HDL_ISCLIENT_BIT;

	return handle;

}

static struct ds_service_info *ds_add_service_provider(struct ds_dev *ds,
	char *id, ds_ver_t vers, ds_ops_t *ops, bool is_builtin)
{
	struct ds_service_info *svc_info;

	dprintk("entered.\n");

	svc_info = kzalloc(sizeof(struct ds_service_info), GFP_KERNEL);
	if (unlikely(svc_info == NULL))
		return NULL;

	svc_info->id = kmemdup(id, (strlen(id) + 1), GFP_KERNEL);
	svc_info->vers = vers;
	svc_info->ops = *ops;
	svc_info->is_client = false;
	svc_info->is_builtin = is_builtin;
	svc_info->is_loopback = false;
	svc_info->is_connected = false;
	svc_info->reg_state = DS_REG_STATE_UNREG;
	svc_info->svc_reg_timeout = ds_get_service_timeout();

	/*
	 * Get a service handle to use to reference this svc_info.
	 * This handle is also used to send a REG_REQ for this service.
	 */
	svc_info->handle = ds_get_new_service_handle(ds, false);
	svc_info->con_handle = 0;

	/* init the the ops arg for builtin services to the ds */
	if (is_builtin)
		svc_info->ops.cb_arg = ds;

	list_add_tail(&svc_info->list, &ds->service_provider_list);

	return svc_info;
}

static void ds_remove_service_provider(struct ds_dev *ds,
	struct ds_service_info *provider_svc_info)
{
	dprintk("entered.\n");

	if (provider_svc_info->is_connected)
		ds_disconnect_service_provider(ds, provider_svc_info);

	kfree(provider_svc_info->id);
	list_del(&provider_svc_info->list);
	kfree(provider_svc_info);

}

static struct ds_service_info *ds_add_service_client(struct ds_dev *ds,
	char *id, ds_ver_t vers, ds_ops_t *ops, bool is_builtin)
{
	struct ds_service_info *svc_info;

	dprintk("entered.\n");

	svc_info = kzalloc(sizeof(struct ds_service_info), GFP_KERNEL);
	if (unlikely(svc_info == NULL))
		return NULL;

	svc_info->id = kmemdup(id, (strlen(id) + 1), GFP_KERNEL);
	svc_info->vers = vers;
	svc_info->ops = *ops;
	svc_info->is_client = true;
	svc_info->is_builtin = is_builtin;
	svc_info->is_loopback = false;
	svc_info->is_connected = false;
	svc_info->reg_state = DS_REG_STATE_UNREG;
	svc_info->svc_reg_timeout = ds_get_service_timeout();

	/* Get a service handle to use to reference this svc_info. */
	svc_info->handle = ds_get_new_service_handle(ds, true);
	svc_info->con_handle = 0;

	/* init the the ops arg for builtin services to the ds */
	if (is_builtin)
		svc_info->ops.cb_arg = ds;

	list_add_tail(&svc_info->list, &ds->service_client_list);

	return svc_info;
}

static void ds_remove_service_client(struct ds_dev *ds,
	struct ds_service_info *client_svc_info)
{
	dprintk("entered.\n");

	 /* If the service is connected, send a unreg message */
	if (client_svc_info->is_connected)
		ds_disconnect_service_client(ds, client_svc_info);

	kfree(client_svc_info->id);
	list_del(&client_svc_info->list);
	kfree(client_svc_info);

}

static void ds_connect_service_client(struct ds_dev *ds, u64 handle,
	u16 major, u16 minor, struct ds_service_info *client_svc_info)
{
	dprintk("entered.\n");

	/* assign the client to the service */
	client_svc_info->is_loopback = false;
	client_svc_info->con_handle = handle;
	client_svc_info->neg_vers.major = major;
	client_svc_info->neg_vers.minor = minor;
	client_svc_info->reg_state = DS_REG_STATE_REGISTERED_LDC;
	client_svc_info->is_connected = true;

	/* submit the register callback */
	(void) ds_submit_reg_cb(ds, client_svc_info->handle, DS_QTYPE_REG);
}

static void ds_disconnect_service_client(struct ds_dev *ds,
	struct ds_service_info *client_svc_info)
{
	struct ds_service_info *peer_svc_info;
	int rv;

	dprintk("entered.\n");

	peer_svc_info = NULL;

	if (client_svc_info->reg_state == DS_REG_STATE_REGISTERED_LOOPBACK) {
		peer_svc_info = ds_find_lb_service_peer(ds, client_svc_info);
	} else if (client_svc_info->reg_state == DS_REG_STATE_REGISTERED_LDC) {
		rv = ds_service_unreg(ds, client_svc_info->con_handle);
		if (rv != 0) {
			pr_err("ds-%llu: %s: failed to send UNREG_REQ for "
			    "handle %llx (%d)\n", ds->id, __func__,
			    client_svc_info->con_handle, rv);
		}
	}
	client_svc_info->is_loopback = false;
	client_svc_info->con_handle = 0;
	client_svc_info->neg_vers.major = 0;
	client_svc_info->neg_vers.minor = 0;
	client_svc_info->reg_state = DS_REG_STATE_UNREG;
	client_svc_info->is_connected = false;
	client_svc_info->svc_reg_timeout = ds_get_service_timeout();

	/* submit the unregister callback */
	(void) ds_submit_reg_cb(ds, client_svc_info->handle, DS_QTYPE_UNREG);

	/* if it was a loopback connection, disconnect the peer */
	if (peer_svc_info)
		ds_disconnect_service_provider(ds, peer_svc_info);
}

static void ds_connect_service_provider(struct ds_dev *ds, u64 handle,
	u16 major, u16 minor, struct ds_service_info *provider_svc_info)
{
	dprintk("entered.\n");

	/* register the provider */
	provider_svc_info->is_loopback = false;
	provider_svc_info->con_handle = handle;
	provider_svc_info->neg_vers.major = major;
	provider_svc_info->neg_vers.minor = minor;
	provider_svc_info->reg_state = DS_REG_STATE_REGISTERED_LDC;
	provider_svc_info->is_connected = true;

	/* submit the register callback */
	(void) ds_submit_reg_cb(ds, provider_svc_info->handle, DS_QTYPE_REG);

}

static void ds_disconnect_service_provider(struct ds_dev *ds,
	struct ds_service_info *provider_svc_info)
{
	struct ds_service_info *peer_svc_info;
	int rv;

	dprintk("entered.\n");

	peer_svc_info = NULL;
	if (provider_svc_info->reg_state == DS_REG_STATE_REGISTERED_LOOPBACK) {
		peer_svc_info = ds_find_lb_service_peer(ds, provider_svc_info);
	} else if (provider_svc_info->reg_state ==
	    DS_REG_STATE_REGISTERED_LDC) {
		rv = ds_service_unreg(ds, provider_svc_info->con_handle);
		if (rv != 0) {
			pr_err("ds-%llu: %s: failed to send UNREG_REQ for "
			    "handle %llx (%d)\n", ds->id, __func__,
			    provider_svc_info->con_handle, rv);
		}
	}
	provider_svc_info->is_loopback = false;
	provider_svc_info->con_handle = 0;
	provider_svc_info->neg_vers.major = 0;
	provider_svc_info->neg_vers.minor = 0;
	provider_svc_info->reg_state = DS_REG_STATE_UNREG;
	provider_svc_info->is_connected = false;
	provider_svc_info->svc_reg_timeout = ds_get_service_timeout();

	/* submit the unregister callback */
	(void) ds_submit_reg_cb(ds, provider_svc_info->handle, DS_QTYPE_UNREG);

	/* if it was a loopback connection, disconnect the peer */
	if (peer_svc_info)
		ds_disconnect_service_client(ds, peer_svc_info);
}

static int ds_connect_loopback_service(struct ds_dev *ds,
	struct ds_service_info *svc_info,
	struct ds_service_info *peer_svc_info)
{
	ds_ver_t neg_vers;

	dprintk("entered.\n");

	/* First check to make sure the versions are compatible */
	if (svc_info->vers.major != peer_svc_info->vers.major) {
		pr_err("ds-%llu: failed to connect loopback service %s due "
		    "version incompatibilty (%llu, %llu)\n", ds->id,
		    svc_info->id, svc_info->vers.major,
		    peer_svc_info->vers.major);
		return -EINVAL;
	}

	/* create the negotiated version */
	neg_vers.minor = min_t(u64, svc_info->vers.minor,
	    peer_svc_info->vers.minor);
	neg_vers.major = svc_info->vers.major;

	/* establish the loopback connection */
	svc_info->is_loopback = true;
	svc_info->neg_vers = neg_vers;
	svc_info->reg_state = DS_REG_STATE_REGISTERED_LOOPBACK;
	svc_info->con_handle = svc_info->handle;
	svc_info->is_connected = true;
	peer_svc_info->is_loopback = true;
	peer_svc_info->neg_vers = neg_vers;
	peer_svc_info->reg_state = DS_REG_STATE_REGISTERED_LOOPBACK;
	peer_svc_info->con_handle = svc_info->handle;
	peer_svc_info->is_connected = true;

	/* submit the register callbacks */
	(void) ds_submit_reg_cb(ds, svc_info->handle, DS_QTYPE_REG);
	(void) ds_submit_reg_cb(ds, peer_svc_info->handle, DS_QTYPE_REG);

	return 0;
}

static void ds_unregister_ldc_services(struct ds_dev *ds)
{
	struct ds_service_info *svc_info;

	dprintk("entered.\n");

	list_for_each_entry(svc_info, &ds->service_provider_list, list) {
		if (svc_info->reg_state == DS_REG_STATE_REGISTERED_LDC)
			ds_disconnect_service_provider(ds, svc_info);
	}

	list_for_each_entry(svc_info, &ds->service_client_list, list) {
		if (svc_info->reg_state == DS_REG_STATE_REGISTERED_LDC)
			ds_disconnect_service_client(ds, svc_info);
	}

}

static void ds_reregister_ldc_services(struct ds_dev *ds)
{
	struct ds_service_info *svc_info;

	dprintk("entered.\n");

	list_for_each_entry(svc_info, &ds->service_provider_list, list) {
		if (svc_info->reg_state == DS_REG_STATE_REG_SENT) {
			svc_info->reg_state = DS_REG_STATE_UNREG;
			svc_info->svc_reg_timeout = ds_get_service_timeout();
		}
	}

	list_for_each_entry(svc_info, &ds->service_client_list, list) {
		if (svc_info->reg_state == DS_REG_STATE_REG_SENT) {
			svc_info->reg_state = DS_REG_STATE_UNREG;
			svc_info->svc_reg_timeout = ds_get_service_timeout();
		}
	}

}

static void ds_remove_services(struct ds_dev *ds)
{
	struct ds_service_info *svc_info, *tmp;

	dprintk("entered.\n");

	list_for_each_entry_safe(svc_info, tmp,
	    &ds->service_provider_list, list) {
		ds_remove_service_provider(ds, svc_info);
	}

	list_for_each_entry_safe(svc_info, tmp,
	    &ds->service_client_list, list) {
		ds_remove_service_client(ds, svc_info);
	}

}

/*
 * DS Kernel Interface functions
 */
void ldom_set_var(const char *var, const char *value)
{
	struct ds_service_info *svc_info;
	union {
		struct ds_var_set_msg	msg;
		char			all[512];
	} payload;
	char  *base, *p;
	int msg_len;
	int rv;

	dprintk("entered.\n");

	if (var == NULL) {
		pr_err("%s: Invalid NULL variable name argument.\n", __func__);
		return;
	}

	if (value == NULL) {
		pr_err("%s: Invalid NULL variable value argument.\n", __func__);
		return;
	}

	if (strlen(var) > 254) {
		pr_err("%s: Variable name too long.\n", __func__);
		return;
	}

	if (strlen(value) > 254) {
		pr_err("%s: Variable value too long.\n", __func__);
		return;
	}

	svc_info = ds_find_connected_prov_service("var-config");
	if (svc_info == NULL)
		svc_info = ds_find_connected_prov_service("var-config-backup");

	if (svc_info == NULL) {
		pr_err("%s: var-config and var-config-backup service "
		    "not registered. Failed to set (%s) variable "
		    "to (%s).\n", __func__, var, value);
		return;
	}

	dprintk("%s: found %s client service\n", __func__, svc_info->id);

	memset(&payload, 0, sizeof(payload));
	payload.msg.hdr.type = DS_VAR_SET_REQ;
	base = p = &payload.msg.name_and_value[0];
	strcpy(p, var);
	p += strlen(var) + 1;
	strcpy(p, value);
	p += strlen(value) + 1;

	msg_len = (sizeof(struct ds_var_set_msg) + (p - base));
	msg_len = (msg_len + 3) & ~3;

	mutex_lock(&ds_var_mutex);

	ds_var_response = -1;
	wmb();

	/*
	 * (re)init the completion var to help guarantee
	 * responses are for this request (and not an older
	 * request which came in late). Use a mutex to protect
	 * against the possibility of re-initializing at the same time
	 * as the callout thread calling complete() in the callback.
	 */
	mutex_lock(&ds_var_complete_mutex);
	init_completion(&ds_var_config_cb_complete);
	mutex_unlock(&ds_var_complete_mutex);

	rv = ds_cap_send(svc_info->handle, &payload, msg_len);

	if (!rv) {
		/* wait for response here */
		wait_for_completion_timeout(&ds_var_config_cb_complete,
		    (DS_RESPONSE_TIMEOUT * HZ));
	}

	if (ds_var_response != DS_VAR_SUCCESS)
		pr_err("%s: var-config [%s:%s] failed, response(%d).\n",
		    __func__, var, value, ds_var_response);

	mutex_unlock(&ds_var_mutex);

	return;

}

static int ldom_req_sp_token(const char *service_name, u32 *sp_token_result,
	ds_sptok_t *sp_token_data)
{
	struct ds_service_info *svc_info;
	struct ds_sp_token_msg	*payload;
	int	svc_len;	/* length of service_name string */
	int	payload_len;	/* length of ds_sp_token_msg payload */
	int rv;

	dprintk("entered.\n");

	if (service_name == NULL) {
		pr_err("%s: Invalid NULL service name argument.\n", __func__);
		return -EINVAL;
	}

	svc_info = ds_find_connected_prov_service("sp-token");
	if (svc_info == NULL) {
		pr_err("%s: sp-token service not registered.\n", __func__);
		return -EIO;
	}

	svc_len = (service_name == NULL || *service_name == '\0') ? 0 :
	    strlen(service_name) + 1;
	if (svc_len > DS_MAX_SVC_NAME_LEN) {
		pr_err("%s: service name '%s' too long.\n",
		    __func__, service_name);
		return -EINVAL;
	}

	payload_len = sizeof(struct ds_sp_token_msg) + svc_len;
	payload = kzalloc(payload_len, GFP_KERNEL);
	if (payload == NULL) {
		pr_err("%s: failed to alloc mem for msg.\n", __func__);
		return -ENOMEM;
	}

	payload->type = DS_SPTOK_REQUEST;
	(void) memcpy(payload->service, service_name, svc_len);

	mutex_lock(&ds_sp_token_mutex);

	payload->req_num = ds_sp_token_next_req_num;

	dprintk("%s: sizeof ds_sp_token_msg=%lu svclen=%d.\n",
	    __func__, sizeof(struct ds_sp_token_msg), svc_len);
	dprintk("req_num %llu: payload(%p): type[0x%llx] svc[%s].\n",
	    payload->req_num, payload, payload->type, payload->service);

	/* set init values */
	ds_sp_token_resp_req_num = ~0;
	ds_sp_token_resp_result = ~0;
	wmb();

	/*
	 * (re)init the completion var to help guarantee
	 * responses are for this request (and not an older
	 * request which came in late). Use a mutex to protect
	 * against the possibility of re-initializing at the same time
	 * as the callout thread calling complete() in the callback.
	 */
	mutex_lock(&ds_sp_token_complete_mutex);
	init_completion(&ds_sp_token_cb_complete);
	mutex_unlock(&ds_sp_token_complete_mutex);

	rv = ds_cap_send(svc_info->handle, payload, payload_len);

	kfree(payload);

	if (!rv) {

		while (1) {
			/* wait for response here */
			rv = wait_for_completion_timeout(
			    &ds_sp_token_cb_complete,
			    (DS_RESPONSE_TIMEOUT * HZ));

			if (!rv) {
				pr_err("%s: set-token failed: no reply.\n",
				    __func__);
				rv = -ETIMEDOUT;
				break;
			}

			/* got a reply, validate it */

			/* If the response wasn't for this request, try again */
			if (ds_sp_token_resp_req_num !=
			    ds_sp_token_next_req_num) {
				continue;
			}

			/* if we didn't get a valid reply, abort */
			if (ds_sp_token_resp_result != DS_SP_TOKEN_RES_OK) {
				pr_err("%s: set-token failed [%d].\n", __func__,
				    ds_sp_token_resp_result);
				rv = -EIO;
				break;
			} else {
				/*
				 * Got a valid response.
				 * Copy the response/result to caller.
				 */
				*sp_token_result = ds_sp_token_resp_result;
				*sp_token_data = ds_sp_token_data;
				rv = 0;
				break;
			}
		}
	}

	/* increment sequence number for next caller - wrap at ~0 */
	if (++ds_sp_token_next_req_num == ~0)
		ds_sp_token_next_req_num = 0;

	mutex_unlock(&ds_sp_token_mutex);

	return rv;
}

static char full_boot_str[256] __aligned(32);
static int reboot_data_supported;

void ldom_reboot(const char *boot_command)
{
	dprintk("entered.\n");

	/*
	 * Don't bother with any of this if the boot_command
	 * is empty.
	 */
	if (boot_command && strlen(boot_command)) {
		unsigned long len;

		strcpy(full_boot_str, "boot ");
		strcpy(full_boot_str + strlen("boot "), boot_command);
		len = strlen(full_boot_str);

		if (reboot_data_supported) {
			unsigned long ra = kimage_addr_to_ra(full_boot_str);
			unsigned long hv_ret;

			hv_ret = sun4v_reboot_data_set(ra, len);
			if (hv_ret != HV_EOK)
				pr_err("%s: Unable to set reboot "
				    "data hv_ret=%lu\n", __func__, hv_ret);
		} else {
			ldom_set_var("reboot-command", full_boot_str);
		}
	}
	sun4v_mach_sir();
}

void ldom_power_off(void)
{
	dprintk("entered.\n");

	sun4v_mach_exit(0);
}

static int ds_handle_data_nack(struct ds_dev *ds, struct ds_msg_tag *pkt)
{
	int rv;
	struct ds_data_nack *data_nack;

	dprintk("entered.\n");

	data_nack = (struct ds_data_nack *)pkt;

	switch (data_nack->payload.result) {
	case DS_INV_HDL:

		pr_err("ds-%llu: received INV_HDL data NACK for "
			"handle %llx\n", ds->id, data_nack->payload.handle);

		/*
		 * If we got back an DS_INV_HDL data nack, it means
		 * the other side could not find a handle associated
		 * with a data pack we sent to it. So, we interpret this
		 * to mean the other side's client has gone away, so we
		 * send an unregister request to clean things up.
		 */
		rv = ds_service_unreg(ds, data_nack->payload.handle);
		if (rv != 0) {
			pr_err("ds-%llu: failed to send UNREG_REQ for "
			    "handle %llx on data NACK (%d)\n", ds->id,
			    data_nack->payload.handle, rv);
		}

		break;

	case DS_TYPE_UNKNOWN:

		/*
		 * If we got back a TYPE_UNKNOWN, it means the other side
		 * got an unknown msg_type from a pkt we sent to it. Maybe
		 * it's an older/buggy driver? What to do?
		 */
		pr_err("ds-%llu: received UNKNOWN data NACK for "
			"handle %llx\n", ds->id, data_nack->payload.handle);
		rv = 0;

		break;
	};

	return rv;
}

static int ds_data_msg(struct ds_dev *ds, struct ds_msg_tag *pkt)
{
	int rv;
	struct ds_unknown_msg *unknown_msg;

	dprintk("entered.\n");

	switch (pkt->type) {
	case DS_DATA:
		rv = ds_submit_data_cb(ds, pkt, DS_DTYPE_LDC_REQ);
		break;
	case DS_NACK:
		rv = ds_handle_data_nack(ds, pkt);
		break;
	default:
		/*
		 * XXX - If we receive an unknown msg_type, per spec,
		 * we are supposed to send back a nack with the handle
		 * However, since this is an unknown msg_type,
		 * we don't know how to retrieve the handle from the msg!
		 * (a deficiency with the protocol). Let's just hope
		 * the handle is the first 8 bytes of the payload...?
		 */
		unknown_msg = (struct ds_unknown_msg *)pkt;
		ds_send_data_nack(ds, unknown_msg->payload.handle,
		    DS_TYPE_UNKNOWN);
		rv = 0;
	};

	return rv;
}

static int ds_service_reg(struct ds_dev *ds, struct ds_service_info *svc_info)
{
	int rv;
	int payload_len;
	struct {
		struct ds_reg_req_payload req;
		u8 id_buf[256];
	} pbuf;

	dprintk("entered.\n");

	payload_len = (sizeof(struct ds_reg_req_payload) +
		   strlen(svc_info->id) + 1);

	/* adjust for 4 bytes of default padding of ds_reg_req_payload */
	payload_len -= 4;

	memset(&pbuf, 0, sizeof(pbuf));
	pbuf.req.handle = svc_info->handle; /* use the unique handle */
	pbuf.req.major = svc_info->vers.major;
	pbuf.req.minor = svc_info->vers.minor;
	strcpy(pbuf.req.svc_id, svc_info->id);

	rv = ds_ldc_send_payload(ds->lp, DS_REG_REQ, &pbuf, payload_len);

	if (rv > 0)
		dprintk("ds-%llu: DS_REG_REQ sent for %s service (%llu.%llu), "
		    "hdl=(%llx)\n", ds->id, svc_info->id, svc_info->vers.major,
		    svc_info->vers.minor, svc_info->handle);

	return (rv <= 0);
}

static int ds_service_unreg(struct ds_dev *ds, u64 handle)
{
	struct ds_unreg_req_payload req;
	int rv;

	dprintk("entered.\n");

	req.handle = handle;

	rv = ds_ldc_send_payload(ds->lp, DS_UNREG_REQ, &req, sizeof(req));

	return (rv <= 0);
}

static void ds_service_ack(struct ds_dev *ds, u64 handle, u16 minor)
{
	struct ds_reg_ack_payload req;
	int rv;

	dprintk("entered.\n");

	req.handle = handle;
	req.minor = minor;

	rv = ds_ldc_send_payload(ds->lp, DS_REG_ACK, &req, sizeof(req));
	if (rv <= 0)
		pr_err("ds-%llu: %s: ldc_send failed. (%d)\n ", ds->id,
		    __func__, rv);
}

static void ds_service_nack(struct ds_dev *ds, u64 handle, u64 result,
	u16 major)
{
	struct ds_reg_nack_payload req;
	int rv;

	dprintk("entered.\n");

	req.handle = handle;
	req.result = result;
	req.major = major;

	rv = ds_ldc_send_payload(ds->lp, DS_REG_NACK, &req, sizeof(req));
	if (rv <= 0)
		pr_err("ds-%llu: %s: ldc_send failed. (%d)\n ", ds->id,
		    __func__, rv);

}

static void ds_service_unreg_ack(struct ds_dev *ds, u64 handle)
{
	struct ds_unreg_ack_payload req;
	int rv;

	dprintk("entered.\n");

	req.handle = handle;

	rv = ds_ldc_send_payload(ds->lp, DS_UNREG_ACK, &req, sizeof(req));
	if (rv <= 0)
		pr_err("ds-%llu: %s: ldc_send failed. (%d)\n ", ds->id,
		    __func__, rv);

}

/*
 * Process DS service registration packets received from LDC.
 */
static int ds_handshake_reg(struct ds_dev *ds, struct ds_msg_tag *pkt)
{
	int rv;
	u16 neg_svc_minor;
	struct ds_reg_req *reg_req = NULL;
	struct ds_reg_ack *reg_ack = NULL;
	struct ds_reg_nack *reg_nack = NULL;
	struct ds_unreg_req *unreg_req = NULL;
	struct ds_unreg_ack *unreg_ack = NULL;
	struct ds_unreg_nack *unreg_nack = NULL;
	struct ds_service_info *svc_info;

	dprintk("entered.\n");

	rv = 0;

	if (ds->hs_state != DS_HS_COMPLETE) {
		/*
		 * We should not be getting service registration type
		 * packets unless the HS has been established, so reset
		 * to get back to a sane state.
		 */
		pr_err("ds-%llu: ds_handshake_reg: received REG packet "
		    "but HS is not complete!\n", ds->id);
		goto conn_reset;
	}

	/*
	 * In HS_COMPLETE state, we expect only the following service
	 * registration packets:
	 * DS_REG_REQ: The other end of the LDC is requesting registration
	 *             of a service.
	 *             Action:
	 *             If we have a provider or client registered for
	 *             this service, ACK with the supported minor and
	 *             connect the service.
	 *             Use major sent in request and lowest minor.
	 *             If we don't have a registered service, NACK it.
	 * DS_REG_ACK: The other end of the LDC has ACK'd our request to
	 *             register a service.
	 *             Action:
	 *             Use the handle sent in the ACK.
	 *             Use the major sent with the original request and
	 *             lowest minor.
	 * DS_REG_NACK: The other end of the LDC has NACK'd our request
	 *             to register a service.
	 *
	 * DS_UNREG_REQ:
	 * DS_UNREG_ACK:
	 * DS_UNREG_NACK: Behave according to the spec.
	 */

	if (pkt->type == DS_REG_REQ) {

		/* Other end has sent a register request */

		reg_req = (struct ds_reg_req *)pkt;

		/*
		 * For compatibility with Solaris ldoms on mixed
		 * systems, if we receive a REG_REQ with the
		 * DS_HDL_ISCLIENT_BIT, it is an indication (or "ping")
		 * to send a REG_REQ for any provider services for this
		 * svc_id.
		 */

		if (reg_req->payload.handle & DS_HDL_ISCLIENT_BIT) {

			dprintk("ds-%llu: Received REG_REQ 'ping' "
			    "for %s service", ds->id,
			    reg_req->payload.svc_id);

			/*
			 * If there is a provider service in SENT
			 * state (which means the service never got
			 * connected), put it back into UNREG state
			 * so it will be registered again.
			 */
			svc_info = ds_find_service_provider_id(ds,
			    reg_req->payload.svc_id);
			if (svc_info != NULL &&
			    svc_info->reg_state == DS_REG_STATE_REG_SENT) {
				svc_info->reg_state = DS_REG_STATE_UNREG;
				svc_info->svc_reg_timeout =
				    ds_get_service_timeout();
			}

			goto done;

		}

		/* check if there is a registered service for this request */
		svc_info = ds_find_service_client_id(ds,
		    reg_req->payload.svc_id);
		if (svc_info == NULL) {
			svc_info = ds_find_service_provider_id(ds,
			    reg_req->payload.svc_id);
			if (svc_info == NULL) {
				/* There is no registered service */
				dprintk("ds-%llu: no service registered for "
				    "REG_REQ service %s (%llx)\n", ds->id,
				    reg_req->payload.svc_id,
				    reg_req->payload.handle);

				/* NACK it */
				ds_service_nack(ds, reg_req->payload.handle,
				    DS_INV_HDL, 0);

				goto done;
			}
		}

		/* Found a registered service */

		if (svc_info->is_connected) {
			/* service is already registered */
			ds_service_nack(ds, reg_req->payload.handle,
			    DS_REG_DUP, 0);
			goto done;
		}

		if (reg_req->payload.major != svc_info->vers.major) {
			/* service version is incompatible */
			ds_service_nack(ds, reg_req->payload.handle,
			    DS_REG_VER_NACK, 0);
			goto done;
		}

		neg_svc_minor = min_t(u16, (u16)svc_info->vers.minor,
		    reg_req->payload.minor);

		if (svc_info->is_client)
			ds_connect_service_client(ds, reg_req->payload.handle,
			    reg_req->payload.major, neg_svc_minor, svc_info);
		else
			ds_connect_service_provider(ds, reg_req->payload.handle,
			    reg_req->payload.major, neg_svc_minor, svc_info);

		/* ACK the init request */
		ds_service_ack(ds, reg_req->payload.handle,
		    (u16)svc_info->vers.minor);

		dprintk("ds-%llu: Registered %s %s service (%llx) "
		    "version %llu.%llu  to (%llx).\n", ds->id,
		    (svc_info->is_client ? "Client" : "Provider"),
		    svc_info->id, svc_info->handle,
		    svc_info->neg_vers.major,
		    svc_info->neg_vers.minor,
		    svc_info->con_handle);

	} else if (pkt->type == DS_REG_ACK) {

		/* other end has ACK'd our reg request */

		reg_ack = (struct ds_reg_ack *)pkt;

		svc_info = ds_find_service_provider_handle(ds,
		    reg_ack->payload.handle);
		if (svc_info == NULL) {
			svc_info = ds_find_service_client_handle(ds,
			    reg_ack->payload.handle);

			if (svc_info == NULL) {
				/* no service for this handle */
				pr_err("ds-%llu: REG ACK for unknown "
				    "handle %llx\n", ds->id,
				    reg_ack->payload.handle);
				goto done;
			}
		}

		if (svc_info->reg_state != DS_REG_STATE_REG_SENT) {
			pr_err("ds-%llu: REG ACK for %s service in "
			    "%llu state (%llx)\n", ds->id, svc_info->id,
			    svc_info->reg_state, reg_ack->payload.handle);
			goto done;
		}

		/* Use the lowest negotiated DS minor version */
		neg_svc_minor = min_t(u16, reg_ack->payload.minor,
		    svc_info->vers.minor);

		if (svc_info->is_client)
			ds_connect_service_client(ds, reg_ack->payload.handle,
			    svc_info->vers.major, neg_svc_minor, svc_info);
		else
			ds_connect_service_provider(ds, reg_ack->payload.handle,
			    svc_info->vers.major, neg_svc_minor, svc_info);


		dprintk("ds-%llu: Registered %s service "
		    "version %llu.%llu (%llx).\n", ds->id,
		    svc_info->id, svc_info->neg_vers.major,
		    svc_info->neg_vers.minor, svc_info->handle);

	} else if (pkt->type == DS_REG_NACK) {

		/* other end has NACK'd our reg request */

		reg_nack = (struct ds_reg_nack *)pkt;

		svc_info = ds_find_service_provider_handle(ds,
		    reg_nack->payload.handle);
		if (svc_info == NULL) {
			svc_info = ds_find_service_client_handle(ds,
			    reg_nack->payload.handle);
			if (svc_info == NULL) {
				/* No service for this handle */
				pr_err("ds-%llu: REG NACK for "
				    "unknown handle %llx\n",
				    ds->id, reg_nack->payload.handle);
				goto done;
			}
		}

		if (svc_info->reg_state != DS_REG_STATE_REG_SENT) {
			pr_err("ds-%llu: REG NACK for %s service in "
			    "%llu state (%llx)\n", ds->id, svc_info->id,
			    svc_info->reg_state, reg_nack->payload.handle);
			goto done;
		}

		/*
		 * If a service is NACK'd for any reason we simply put
		 * the service into UNREG state. At some point in the
		 * future, the service registration will be re-tried
		 * by the timer thread.
		 */
		svc_info->reg_state = DS_REG_STATE_UNREG;
		svc_info->svc_reg_timeout = ds_get_service_timeout();

		dprintk("ds-%llu: Registration nack'd for %s service "
		    "(%llx). Result=%llu. Major=%u\n", ds->id, svc_info->id,
		    reg_nack->payload.handle, reg_nack->payload.result,
		    reg_nack->payload.major);

	} else if (pkt->type == DS_UNREG_REQ) {

		/* other end has sent a unregister request */

		unreg_req = (struct ds_unreg_req *)pkt;

		/* unregister any service associated with the handle */

		/* see if service registered */
		svc_info = ds_find_service_client_con_handle(ds,
		    unreg_req->payload.handle);
		if (svc_info == NULL) {
			svc_info = ds_find_service_provider_con_handle(ds,
			    unreg_req->payload.handle);

			if (svc_info == NULL) {
				/* There is no service */

				pr_err("ds-%llu: no service registered for "
				    "UNREG_REQ handle %llx\n", ds->id,
				   unreg_req->payload.handle);

				/*
				 * Our service could have been unregistered and
				 * removed. Go ahead and ACK it. This allows
				 * the other side to still clean up properly.
				 */
				ds_service_unreg_ack(ds,
				    unreg_req->payload.handle);

				goto done;
			}
		}


		if (svc_info->reg_state != DS_REG_STATE_REGISTERED_LDC) {
			pr_err("ds-%llu: UNREG_REQ for %s service in "
			    "%llu state (%llx)\n", ds->id, svc_info->id,
			    svc_info->reg_state, unreg_req->payload.handle);
			goto done;
		}

		dprintk("ds-%llu: Unregistered %s service (%llx) "
		    "from (%llx).\n", ds->id, svc_info->id,
		    svc_info->con_handle, unreg_req->payload.handle);

		if (svc_info->is_client)
			ds_disconnect_service_client(ds, svc_info);
		else
			ds_disconnect_service_provider(ds, svc_info);

		/* ACK the unreg request */
		ds_service_unreg_ack(ds, unreg_req->payload.handle);

	} else if (pkt->type == DS_UNREG_ACK) {

		/* Got an ACK to our UNREG_REQ */

		unreg_ack = (struct ds_unreg_ack *)pkt;

		svc_info = ds_find_service_client_con_handle(ds,
		    unreg_ack->payload.handle);
		if (svc_info == NULL) {
			svc_info = ds_find_service_provider_con_handle(ds,
			    unreg_ack->payload.handle);
			if (svc_info == NULL) {
				/*
				 * There is no service for this handle.
				 * It's possible the service was
				 * unregistered and removed.
				 */
				dprintk("ds-%llu: UNREG ACK for unknown "
				    "handle %llx\n", ds->id,
				    unreg_ack->payload.handle);
				goto done;
			}
		}

		dprintk("ds-%llu: Unregistered %s service (%llx).\n",
		    ds->id, svc_info->id, unreg_ack->payload.handle);

		if (svc_info->is_client)
			ds_disconnect_service_client(ds, svc_info);
		else
			ds_disconnect_service_provider(ds, svc_info);

	} else if (pkt->type == DS_UNREG_NACK) {

		/* Got a NACK to our UNREG_REQ */

		unreg_nack = (struct ds_unreg_nack *)pkt;

		/* XXX - what to do on an unreg NACK??? */

		dprintk("ds-%llu: Received UNREG_NACK for (%llx).\n",
		    ds->id, unreg_nack->payload.handle);

	} else {
		/* Unexpected packet type. Reset to get back to a sane state. */
		goto conn_reset;
	}

done:
	return 0;

conn_reset:

	ds_reset(ds);

	return -ECONNRESET;
}

static int ds_is_local_ds(struct ds_dev *ds)
{
	struct mdesc_handle *hp;
	u64 cd_node;
	u64 anode;
	u64 target;
	const u64 *local_handle;

	if (!ds_local_ldom_handle_set) {
		/*
		 * Find the virtual-domain-service node under the
		 * channel-devices node in the MD which
		 * contains the vlds-domain-handle property.
		 * This is the "local" ldom handle.
		 * Cache it in ds_local_ldom_handle global var.
		 */
		hp = mdesc_grab();
		if (hp) {
			/* get the channel-devices ndoe in the MD */
			cd_node = mdesc_node_by_name(hp, MDESC_NODE_NULL,
			    "channel-devices");
			if (cd_node != MDESC_NODE_NULL) {
				/*
				 * For each node under look for the
				 * virtual-device node which contains the
				 * vlds-domain-handle property.
				 */
				mdesc_for_each_arc(anode, hp, cd_node,
				    MDESC_ARC_TYPE_FWD) {

					target = mdesc_arc_target(hp, anode);

					local_handle = mdesc_get_property(hp,
					    target, "vlds-domain-handle", NULL);
					if (local_handle != NULL) {
						ds_local_ldom_handle =
						    *local_handle;
						ds_local_ldom_handle_set = true;
					}
				}
			}

			mdesc_release(hp);
		}
	}

	if (ds_local_ldom_handle_set &&
	    ds->handle == ds_local_ldom_handle) {
		return 1;
	}

	return 0;
}

static void ds_timer_register_service(struct ds_dev *ds,
		struct ds_service_info *svc_info)
{
	struct ds_service_info *peer_svc_info;
	int rv;

	/* Check if the service is allowed to register yet */
	if (jiffies < svc_info->svc_reg_timeout)
		return;

	if (svc_info->reg_state != DS_REG_STATE_UNREG)
		return;

	/* We have a service ready to be registered. */

	/*
	 * First check to see if there is a local unconnected loopback peer
	 * for this service id and if so, connect it in loopback mode.
	 * NOTE: we only allow loopback connections on the "local" DS port.
	 */
	if (ds_is_local_ds(ds)) {
		if (svc_info->is_client)
			peer_svc_info = ds_find_service_provider_id(ds,
			    svc_info->id);
		else
			peer_svc_info = ds_find_service_client_id(ds,
			    svc_info->id);

		if (peer_svc_info && !peer_svc_info->is_connected) {
			rv = ds_connect_loopback_service(ds, svc_info,
			    peer_svc_info);
			if (rv == 0) {
				dprintk("ds-%llu: Registered loopback "
				    "service %s (%llu)\n", ds->id,
				    svc_info->id, svc_info->con_handle);
				return;
			} else {
				pr_err("ds-%llu: failed to connect "
				    "loopback %s service\n", ds->id,
					svc_info->id);
			}
			/* fallthrough and attempt LDC registration? */
		}
	}

	/* Only attempt LDC registration if the HS is complete */
	if (ds->hs_state == DS_HS_COMPLETE) {
		rv = ds_service_reg(ds, svc_info);
		if (rv == 0) {
			svc_info->reg_state = DS_REG_STATE_REG_SENT;
			/*
			 * Clear the reg SENT timeout.
			 * We don't retry unless the LDC is reconnected.
			 * Or if we receive a client "ping" for the service.
			 */
			svc_info->svc_reg_timeout = 0;
			return;
		} else {
			dprintk("ds-%llu: failed to send REG_REQ for "
				" \"%s\" service (%d)\n", ds->id,
				svc_info->id, rv);
		}
	}

	/*
	 * We failed to register the service.
	 * Try again in the future.
	 */
	svc_info->svc_reg_timeout = ds_get_service_timeout();
}

static void ds_exec_reg_timer(unsigned long data)
{
	struct ds_dev *ds = (struct ds_dev *)data;
	unsigned long flags;
	struct ds_service_info *svc_info;
	int rv;

#ifdef DS_KERNEL_TIMER_BUG_WAR
	/*
	 * There appears to be a bug in the UEK kernel where
	 * timers can execute on a CPU where local interrupts
	 * have been disabled. Deadlocks have been observed
	 * where the DS registration timer (ds_reg_tmr) can
	 * execute on a CPU, interrupting a thread on the CPU
	 * which is holding the ds->ds_lock or the ds->lp->lock
	 * resulting in a deadlock when the timer attempts
	 * to grab the lock. As a workaround, the timer handler will
	 * first check if the locks are held and if so, simply
	 * reschedule the timer and exit (without grabbing the
	 * locks - thus avoiding the deadlock). the kernel needs
	 * to be fixed at some point since executing timers
	 * on CPUs with local interrupts disabled is a violation
	 * of spin_lock_irqsave() semantics.
	 */
	if (spin_is_locked(&ds->ds_lock) || spin_is_locked(&ds->lp->lock)) {
		mod_timer(&ds->ds_reg_tmr,
		    jiffies + msecs_to_jiffies(DS_REG_TIMER_FREQ));
		return;
	}
#endif /* DS_KERNEL_TIMER_BUG_WAR */

	LOCK_DS_DEV(ds, flags)

	/*
	 * Walk through the services for this ds and for those
	 * which are not yet registered, (re)send a REG_REQ.
	 */
	list_for_each_entry(svc_info, &ds->service_provider_list, list)
		ds_timer_register_service(ds, svc_info);

	list_for_each_entry(svc_info, &ds->service_client_list, list)
		ds_timer_register_service(ds, svc_info);

	/* reset the timer to fire again in DS_REG_TIMER_FREQ ms */
	rv = mod_timer(&ds->ds_reg_tmr,
	    jiffies + msecs_to_jiffies(DS_REG_TIMER_FREQ));

	UNLOCK_DS_DEV(ds, flags)

}

static void ds_start_service_reg_timer(struct ds_dev *ds)
{
	int rv;

	dprintk("entered.\n");

	setup_timer(&ds->ds_reg_tmr, ds_exec_reg_timer,
	    (unsigned long)ds);

	/* kick off the first timer in DS_REG_TIMER_FREQ ms */
	rv = mod_timer(&ds->ds_reg_tmr,
	    jiffies + msecs_to_jiffies(DS_REG_TIMER_FREQ));

	if (rv)
		pr_err("ds-%llu: Error setting ds registration timer",
			ds->id);
}


/*
 * NOTE: All kernel ds services are defined as providers, no matter if
 * they actually behave as a server or as client.
 */
static void ds_add_builtin_services(struct ds_dev *ds,
	struct ds_builtin_service *ds_builtin_service_template,
	int num_template_services)
{

	struct ds_service_info	*svc_info;
	int i;

	dprintk("entered.\n");

	/* walk the builtin service provider array and add to the ds */
	for (i = 0; i < num_template_services; i++) {

		/*
		 * If there is already a registered service provider
		 * for this id, skip it since there can only be 1
		 * service provider per ds/service id.
		 */
		svc_info = ds_find_service_provider_id(ds,
		    ds_builtin_service_template[i].id);

		if (svc_info != NULL)
			continue;

		/* if no existing service provider, add the builtin */
		svc_info = ds_add_service_provider(ds,
		    ds_builtin_service_template[i].id,
		    ds_builtin_service_template[i].vers,
		    &ds_builtin_service_template[i].ops,
		    true);

		if (svc_info == NULL)
			pr_err("ds-%llu: Failed to add builtin "
			    "provider service %s", ds->id,
			    ds_builtin_service_template[i].id);
	}

}

static int ds_init_req(struct ds_dev *ds)
{
	struct ds_ver_req_payload req;
	int rv;

	dprintk("entered.\n");

	/* send a DS version init request */
	req.ver.major = DS_MAJOR_VERSION;
	req.ver.minor = DS_MINOR_VERSION;

	rv = ds_ldc_send_payload(ds->lp, DS_INIT_REQ, &req, sizeof(req));

	return (rv <= 0);
}

static void ds_init_ack(struct ds_dev *ds)
{
	struct ds_ver_ack_payload req;
	int rv;

	dprintk("entered.\n");

	req.minor = DS_MINOR_VERSION;

	rv = ds_ldc_send_payload(ds->lp, DS_INIT_ACK, &req, sizeof(req));
	if (rv <= 0)
		pr_err("ds-%llu: %s: ldc_send failed. (%d)\n ", ds->id,
		    __func__, rv);

}

static void ds_init_nack(struct ds_dev *ds, u16 major)
{
	struct ds_ver_nack_payload req;
	int rv;

	dprintk("entered.\n");

	req.major = major;

	rv = ds_ldc_send_payload(ds->lp, DS_INIT_NACK, &req, sizeof(req));
	if (rv <= 0)
		pr_err("ds-%llu: %s: ldc_send failed. (%d)\n ", ds->id,
		    __func__, rv);

}

/* Process DS init packets received from LDC. */
static int ds_handshake_init(struct ds_dev *ds, struct ds_msg_tag *pkt)
{
	struct ds_ver_req *init_req;
	struct ds_ver_ack *init_ack;
	u16 neg_ds_major;
	u16 neg_ds_minor;

	dprintk("entered.\n");

	if (ds->hs_state != DS_HS_START) {

		if (ds->hs_state == DS_HS_COMPLETE) {
			/*
			 * If an INIT type pkt comes through while in
			 * HS_COMPLETE state, it could be a extraneuous packet
			 * left over from a (simultaneous) handshake. So, we
			 * will just ignore it since the connection has already
			 * been established. No need to error out.
			 */
			goto done;
		}

		/* Invalid state, reset to get sane again */
		goto conn_reset;
	}

	/*
	 * In the DS_HS_START state, only valid pkt types are:
	 * DS_INIT_REQ: Other end of LDC is requesting INIT of DS.
	 *              Action:
	 *              If the sent major is compatible, ACK
	 *              with supported minor.
	 *             	Use major sent in request and lowest minor.
	 * DS_INIT_ACK: Other end of LDC has ack'd our DS INIT request.
	 *              Action:
	 *             	Use major sent in original INIT_REQ and
	 *             	lowest minor.
	 * DS_INIT_NACK: Other end of LDC nack'd our DS INIT request.
	 *              Action:
	 *              Remiain in HS_START state. Other side could try to
	 *              init the DS (with an acceptable major #).
	 */

	if (pkt->type == DS_INIT_REQ) {

		init_req = (struct ds_ver_req *)pkt;

		/* Check if the major is compatible */

		/* NOTE - we currently only support DS_MAJOR_VERSION.  */
		if (init_req->payload.ver.major != DS_MAJOR_VERSION) {
			/*
			 * Incompatible major, NACK it. But remain in
			 * HS_START state since it's possible our
			 * INIT_REQ will still be successfully ACK'd.
			 */
			ds_init_nack(ds, 0);
			goto done;
		}

		/* Use the requested DS major version */
		neg_ds_major = init_req->payload.ver.major;

		/* Use the lowest negotiated DS minor version */
		neg_ds_minor = min_t(u16, init_req->payload.ver.minor,
		    DS_MINOR_VERSION);

		/* ACK the init request */
		ds_init_ack(ds);

	} else if (pkt->type == DS_INIT_ACK) {

		init_ack = (struct ds_ver_ack *)pkt;

		/* Use the major version we sent in the INIT request */
		neg_ds_major = DS_MAJOR_VERSION;

		/* Use the lowest negotiated DS minor version */
		neg_ds_minor = min_t(u16, init_ack->payload.minor,
		    DS_MINOR_VERSION);

	} else if (pkt->type == DS_INIT_NACK) {
		/*
		 * If we get a NACK, per spec, we could try another
		 * request with an alternate major number. However, for now,
		 * we do not and we just remain in HS_START state.
		 * We remain in START state so the other end could
		 * still potentially make/complete a HS init request.
		 * If code is ever added in the future to retry the INIT_REQ
		 * with an alternate major, per spec, the code should use the
		 * major returned in the NACK.
		 */
		goto done;

	} else {

		/* Unexpected packet type. Reset to get back to a sane state. */
		goto conn_reset;
	}

	/* assign the negotiated maj/min for the DS connection */
	ds->neg_vers.major = (u64)neg_ds_major;
	ds->neg_vers.minor = (u64)neg_ds_minor;

	/* Handshake established, move to complete state */
	ds->hs_state = DS_HS_COMPLETE;

	/*
	 * If there were any services which failed to
	 * register before, then try to re-register them.
	 */
	ds_reregister_ldc_services(ds);

	dprintk("ds-%llu: DS INIT HS Complete Version=%llu.%llu.\n", ds->id,
	    ds->neg_vers.major, ds->neg_vers.minor);

done:
	return 0;

conn_reset:

	ds_reset(ds);

	return -ECONNRESET;

}

static int ds_handshake_msg(struct ds_dev *ds, struct ds_msg_tag *pkt)
{

	dprintk("entered.\n");

	dprintk("ds-%llu: ds_handshake: hs_state=%d, pkt_type = %d\n", ds->id,
	    ds->hs_state, pkt->type);

	if (ds->hs_state == DS_HS_LDC_DOWN) {

		/* We should not be getting HS packets until the LDC is UP */

		pr_err("ds-%llu: ds_handshake: received HS packet "
		    "but LDC is down!\n", ds->id);

		/* reset the connection to get back to a sane state */
		goto conn_reset;
	}

	switch (pkt->type) {
	case DS_INIT_REQ:
	case DS_INIT_ACK:
	case DS_INIT_NACK:

		/* handle ds initialization packets */
		return ds_handshake_init(ds, pkt);

	case DS_REG_REQ:
	case DS_REG_ACK:
	case DS_REG_NACK:
	case DS_UNREG_REQ:
	case DS_UNREG_ACK:
	case DS_UNREG_NACK:

		/* handle service registration packets */
		return ds_handshake_reg(ds, pkt);

	default:
		/* Invalid pkt type */
		pr_err("ds-%llu: Invalid pkt received %d\n", ds->id, pkt->type);
		return -EINVAL;
	}

conn_reset:

	ds_reset(ds);

	return -ECONNRESET;
}

static void ds_up(struct ds_dev *ds)
{
	int rv;

	dprintk("entered.\n");

	/* reset the HS state machine */
	ds->hs_state = DS_HS_START;

	/* send a DS init request */
	rv = ds_init_req(ds);

	if (rv != 0)
		pr_err("ds-%llu: failed to send DS_INIT_REQ (%d)\n",
		    ds->id, rv);
}

static void ds_event(void *arg, int event)
{
	struct ds_dev *ds = arg;
	unsigned long flags;
	int rv;

	dprintk("ds-%llu: CPU[%d] event received = %d\n", ds->id,
	    smp_processor_id(), event);

	/*
	 * NOTE - we don't use the UN/LOCK_DS_DEV macros here
	 * since we do not need to disable the HV interrupt - since
	 * we are in the interrupt handler.
	 */
	spin_lock_irqsave(&ds->ds_lock, flags);

	if (event == LDC_EVENT_UP) {
		ds_up(ds);
		spin_unlock_irqrestore(&ds->ds_lock, flags);
		return;
	}

	if (event == LDC_EVENT_RESET) {
		ds_reset(ds);
		spin_unlock_irqrestore(&ds->ds_lock, flags);
		return;
	}

	if (event != LDC_EVENT_DATA_READY) {
		pr_err("ds-%llu: Unexpected LDC event %d\n", ds->id, event);
		spin_unlock_irqrestore(&ds->ds_lock, flags);
		return;
	}

	rv = 0;
	while (1) {
		struct ds_msg_tag *tag;

		rv = ldc_read(ds->lp, ds->rcv_buf, sizeof(*tag));

		if (unlikely(rv < 0)) {
			if (rv == -ECONNRESET)
				ds_reset(ds);
			break;
		}

		if (rv == 0)
			break;

		tag = (struct ds_msg_tag *)ds->rcv_buf;

		/* Make sure the read won't overrun our buffer */
		if (tag->len > (DS_DEFAULT_BUF_SIZE -
		    sizeof(struct ds_msg_tag))) {
			pr_err("ds-%llu: %s: msg tag length too big.\n",
			    ds->id, __func__);
			ds_reset(ds);
			break;
		}

		rv = ldc_read(ds->lp, tag + 1, tag->len);

		if (unlikely(rv < 0)) {
			if (rv == -ECONNRESET)
				ds_reset(ds);
			break;
		}

		if (rv < tag->len)
			break;

		if (tag->type < DS_DATA) {
			dprintk("ds-%llu: hs data received (%d bytes)\n",
			    ds->id, rv);
			rv = ds_handshake_msg(ds,
			    (struct ds_msg_tag *)ds->rcv_buf);
		} else {
			dprintk("ds-%llu: data received (%d bytes)\n",
			    ds->id, rv);
			/* only process data if the HS is complete */
			if (ds->hs_state == DS_HS_COMPLETE) {
				rv = ds_data_msg(ds,
				    (struct ds_msg_tag *)ds->rcv_buf);
			} else {
				/* just eat the data packet */
				pr_err("ds-%llu: %s: received data for "
				    "unconnected DS - ignored.\n",
				    ds->id, __func__);
				rv = 0;
			}
		}

		if (unlikely(rv < 0)) {

			if (rv == -ECONNRESET)
				break;

			pr_err("ds-%llu: %s: failed process data "
				"packet rv = %d\n", ds->id, __func__, rv);
		}
	}

	spin_unlock_irqrestore(&ds->ds_lock, flags);
}

static long ds_fops_ioctl(struct file *filp, unsigned int cmd,
		unsigned long arg)
{
	ds_ioctl_sptok_data_t __user *uarg;
	u32			major_version;
	u32			minor_version;
	u32			sp_token_result;
	ds_sptok_t		sp_token_data;
	char			service_name[DS_MAX_SVC_NAME_LEN];
	int rv;

	dprintk("entered.\n");

	rv = 0;

	switch (cmd) {
	case DS_SPTOK_GET:
		pr_info("%s Getting sp-token\n", __func__);
		uarg = (ds_ioctl_sptok_data_t __user *)arg;
		if (get_user(major_version, &uarg->major_version) != 0 ||
		    get_user(minor_version, &uarg->minor_version) != 0 ||
		    copy_from_user(service_name, &uarg->service_name,
			    DS_MAX_SVC_NAME_LEN)) {
			return -EFAULT;
		}
		if ((major_version > DS_MAJOR_VERSION) ||
		    (major_version == DS_MAJOR_VERSION &&
		     minor_version > DS_MINOR_VERSION)) {
			pr_err("%s Invalid version number %u.%u\n",
			    __func__, major_version, minor_version);
			return -EINVAL;
		}
		rv = ldom_req_sp_token(service_name, &sp_token_result,
		    &sp_token_data);
		if (!rv && sp_token_result == DS_SP_TOKEN_RES_OK) {
			dprintk("Copying sp token to userland\n");
			if (copy_to_user(&uarg->sp_tok,
			    (void *)&sp_token_data,
			    sizeof(struct ds_sptok))) {
				rv = -EFAULT;
			}
		}
		break;
	default:
		pr_err("%s Invalid cmd (%d)\n", __func__, cmd);
		rv = -EINVAL;
	}

	return rv;
}

static int ds_probe(struct vio_dev *vdev, const struct vio_device_id *id)
{
	struct ldc_channel_config ds_cfg = {
		.event		= ds_event,
		.mtu		= DS_DEFAULT_MTU,
		.mode		= LDC_MODE_STREAM,
	};
	struct mdesc_handle *hp;
	struct ldc_channel *lp;
	struct ds_dev *ds;
	const u64 *val;
	char ds_irq_name[LDC_IRQ_NAME_MAX];
	unsigned long flags;
	unsigned long ds_flags = 0;
	bool is_sp;
	u64 node;
	int rv;

	dprintk("entered.\n");

	ds = kzalloc(sizeof(struct ds_dev), GFP_KERNEL);
	rv = -ENOMEM;
	if (unlikely(!ds))
		goto out_err;

	spin_lock_init(&ds->ds_lock);

	INIT_LIST_HEAD(&ds->service_provider_list);
	INIT_LIST_HEAD(&ds->service_client_list);
	INIT_LIST_HEAD(&ds->callout_list);

	ds->co_ref_cnt = 0;
	ds->active = true;

	hp = mdesc_grab();

	node = vio_vdev_node(hp, vdev);
	if (node == MDESC_NODE_NULL) {
		dprintk("ds: Failed to get vdev MD node.\n");
		mdesc_release(hp);
		rv = -ENXIO;
		goto out_free_ds;
	}

	val = mdesc_get_property(hp, node, "id", NULL);
	if (val == NULL) {
		mdesc_release(hp);
		rv = -ENXIO;
		goto out_free_ds;
	} else {
		ds->id = *val;
	}

	/* The SP DS port is identified by a unique ldc-ids property */
	val = mdesc_get_property(hp, node, "ldc-ids", NULL);
	is_sp = (val != NULL);

	val = mdesc_get_property(hp, node, "vlds-remote-domain-handle",
	    NULL);
	if (val == NULL) {
		/* Not all DS ports have a handle (such as the SP DS port). */
		ds->handle = DS_INVALID_HANDLE;
	} else {
		ds->handle = *val;
	}

	mdesc_release(hp);

	/* If this is not the SP DS, then this is a domain DS */
	ds->is_domain = !is_sp;

	ds->rcv_buf = kzalloc(DS_DEFAULT_BUF_SIZE, GFP_KERNEL);
	if (unlikely(!ds->rcv_buf))
		goto out_free_ds;

	ds->rcv_buf_len = DS_DEFAULT_BUF_SIZE;

	ds->hs_state = DS_HS_LDC_DOWN;

	ds_cfg.debug = 0;
	ds_cfg.tx_irq = vdev->tx_irq;
	ds_cfg.rx_irq = vdev->rx_irq;
	ds_cfg.rx_ino = vdev->rx_ino;
	ds_cfg.tx_ino = vdev->tx_ino;
	ds_cfg.dev_handle = vdev->dev_handle;

	/* create the irq name for the ldc */
	(void) scnprintf(ds_irq_name, LDC_IRQ_NAME_MAX, "DS-%llu", ds->handle);

	lp = ldc_alloc(vdev->channel_id, &ds_cfg, ds, ds_irq_name);
	if (IS_ERR(lp)) {
		rv = PTR_ERR(lp);
		goto out_free_rcv_buf;
	}
	ds->lp = lp;

	/*
	 * As soon as we bind the LDC, we can start getting
	 * events. So grab the ds_lock here and hold it
	 * until we are done initializing the ds.
	 */
	LOCK_DS_DEV(ds, ds_flags)

	rv = ldc_bind(lp);
	if (rv) {
		UNLOCK_DS_DEV(ds, ds_flags)
		goto out_free_ldc;
	}

	(void) ldc_connect(ds->lp);

	dev_set_drvdata(&vdev->dev, ds);

	ds->next_service_handle = 1; /* start assigning handles from 1 */

	/* add primary builtin services */
	if (ds->id == DS_PRIMARY_ID)
		ds_add_builtin_services(ds, ds_primary_builtin_template,
		    ARRAY_SIZE(ds_primary_builtin_template));

	/* add SP builtin services */
	if (is_sp)
		ds_add_builtin_services(ds, ds_sp_builtin_template,
		    ARRAY_SIZE(ds_sp_builtin_template));

	/* add the ds_dev to the global ds_data device list */
	spin_lock_irqsave(&ds_data_lock, flags);
	list_add_tail(&ds->list, &ds_data.ds_dev_list);
	ds_data.num_ds_dev_list++;
	spin_unlock_irqrestore(&ds_data_lock, flags);

	/*
	 * begin the process of registering services.
	 * Note - we do this here to allow loopback services
	 * even if the DS LDC connection/handshake fails to establish.
	 */
	ds_start_service_reg_timer(ds);

	dprintk("ds-%llu: probe successful for domain %llu (channel_id=%lu).\n",
	    ds->id, ds->handle, vdev->channel_id);

	UNLOCK_DS_DEV(ds, ds_flags)

	return rv;

out_free_ldc:
	ldc_free(ds->lp);

out_free_rcv_buf:
	kfree(ds->rcv_buf);

out_free_ds:
	kfree(ds);

out_err:
	return rv;
}

static int ds_remove(struct vio_dev *vdev)
{
	struct ds_dev *ds;
	struct ds_callout_entry_hdr *qhdrp;
	struct ds_callout_entry_hdr *tmp;
	unsigned long flags;
	unsigned long ds_flags;

	dprintk("entered.\n");

	ds = dev_get_drvdata(&vdev->dev);

	if (ds == NULL)
		return 0;

	/*
	 * Lock the global ds_dev list to prevent another thread
	 * from finding the ds in the list while we are removing it.
	 */
	spin_lock_irqsave(&ds_data_lock, flags);

	/*
	 * Lock down the ds_dev to prevent removing it
	 * while being used by another thread.
	 */
	LOCK_DS_DEV(ds, ds_flags)

	/* remove the ds_dev from the global ds_data device list */
	list_del(&ds->list);
	ds_data.num_ds_dev_list--;

	del_timer(&ds->ds_reg_tmr);

	ds_remove_services(ds);

	ds->hs_state = DS_HS_LDC_DOWN;

	ldc_disconnect(ds->lp);

	ldc_unbind(ds->lp);

	ldc_free(ds->lp);

	kfree(ds->rcv_buf);

	/* free any entries left on the callout list */
	list_for_each_entry_safe(qhdrp, tmp, &ds->callout_list, list) {
		list_del(&qhdrp->list);
		kfree(qhdrp);
		ds->co_ref_cnt--;
	}

	dprintk("ds-%llu: removing domain %llu (co_ref_cnt=%llu)\n",
	    ds->id, ds->handle, ds->co_ref_cnt);

	/*
	 * When the callout thread processes work entries, it
	 * creates a local list of entries which can contain
	 * references to this ds. So, we maintain
	 * a ds reference count for entries on the callout todo list.
	 * If there are no outstanding references to this ds, free
	 * the ds now (it's safely locked down). If there are outstanding
	 * references (because the callout thread is currently processing them),
	 * allow the callout thread to clean things up - we do not want to
	 * remove the ds here since the callout thread will reference it.
	 */
	if (ds->co_ref_cnt == 0) {
		UNLOCK_DS_DEV(ds, ds_flags);
		kfree(ds);
	} else {
		/*
		 * Mark the ds_dev as inactive.
		 * ds_dev will be cleaned up by the
		 * callout processing.
		 */
		ds->active = false;
		UNLOCK_DS_DEV(ds, ds_flags)
	}

	spin_unlock_irqrestore(&ds_data_lock, flags);

	return 0;
}

static const struct vio_device_id ds_match[] = {
	{
		.type = "domain-services-port",
	},
	{},
};

static struct vio_driver ds_driver = {
	.id_table	= ds_match,
	.probe		= ds_probe,
	.remove		= ds_remove,
	.name		= DRV_MODULE_NAME,
};

static struct file_operations ds_fops = {
	.owner			= THIS_MODULE,
	.unlocked_ioctl		= ds_fops_ioctl
};

static struct miscdevice ds_miscdev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = DRV_MODULE_NAME,
	.fops = &ds_fops
};

static int __init ds_init(void)
{
	unsigned long hv_ret, major, minor;
	struct task_struct *callout_task;
	int		err;

	/* set the default ldoms debug level */
	dsdbg_level = ldoms_debug_level;

	dprintk("%s", version);

	INIT_LIST_HEAD(&ds_data.ds_dev_list);
	ds_data.num_ds_dev_list = 0;

	err = misc_register(&ds_miscdev);
	if (err)
		return err;

	dprintk("minor is %d.\n", ds_miscdev.minor);

	if (tlb_type == hypervisor) {
		hv_ret = sun4v_get_version(HV_GRP_REBOOT_DATA, &major, &minor);
		if (hv_ret == HV_EOK) {
			dprintk("SUN4V: Reboot data supported "
			    "(maj=%lu,min=%lu).\n", major, minor);
			reboot_data_supported = 1;
		}
	}

	callout_task = kthread_run(ds_callout_thread, NULL, "ldoms-ds");
	if (IS_ERR(callout_task)) {
		misc_deregister(&ds_miscdev);
		return PTR_ERR(callout_task);
	}

	return vio_register_driver(&ds_driver);
}

fs_initcall(ds_init);
