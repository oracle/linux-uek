/*
 * vlds.c: Sun4v LDOMs Virtual Domain Services Driver
 *
 * Copyright (C) 2015 Oracle. All rights reserved.
 */
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/poll.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/wait.h>
#include <linux/sched.h>
#include <linux/delay.h>
#include <linux/sysfs.h>
#include <linux/ioctl.h>
#include <linux/vlds.h>
#include <linux/atomic.h>
#include <linux/uaccess.h>
#include <linux/pid.h>
#include <linux/fdtable.h>
#include <linux/rcupdate.h>
#include <linux/eventfd.h>
#include <linux/ds.h>
#include <asm/mdesc.h>
#include <asm/vio.h>

extern unsigned int ldoms_debug_level;
static unsigned int vldsdbg_level;
module_param(vldsdbg_level, uint, S_IRUGO|S_IWUSR);

#define DRV_NAME		"vlds"
#define DRV_VERSION		"1.0"
#define VLDS_DEVICE_NAME DRV_NAME

#define VLDS_MINOR_BASE 0
#define VLDS_MAX_DEVS	65535 /* need one per guest domain - max is 2^20 */
#define VLDS_MAX_MSG_SIZE (256 * 1024)

#define	VLDS_SP_INT_NAME	DS_SP_NAME /* SP DS internal name */
#define	VLDS_SP_DEV_NAME	"sp" /* SP DS device name */
#define VLDS_PATH_MAX		256

#define VLDS_INVALID_HANDLE	0xFFFFFFFFFFFFFFFFUL

static char driver_version[] = DRV_NAME ".c:v" DRV_VERSION "\n";

#define dprintk(fmt, args...) do {\
if (vldsdbg_level > 0)\
	printk(KERN_ERR "%s: %s: " fmt, DRV_NAME, __func__, ##args);\
} while (0)

/* Global driver data struct for data common to all devices */
struct vlds_driver_data {
	struct list_head	vlds_dev_list; /* list of all vlds devices */
	int			num_vlds_dev_list;
	struct class		*chrdev_class;
	dev_t			devt;
};
struct vlds_driver_data vlds_data;
static DEFINE_MUTEX(vlds_data_mutex); /* protect vlds_data */

struct vlds_dev {
	/* link into the global driver data dev list */
	struct list_head	list;

	struct mutex            vlds_mutex; /* protect this vlds_dev */
	struct cdev		cdev;
	dev_t			devt;
	char			*int_name; /* internal name for device */
	struct device		*device;
	u64			domain_handle; /* only valid for domain dev */

	/* list of all services for this vlds device */
	struct list_head	service_info_list;

};

/* we maintain a global vlds_dev for the SP device */
struct vlds_dev *sp_vlds;

struct vlds_service_info {
	/* link into the vlds_dev service info list */
	struct list_head	list;

	/* name/id of the service */
	char			*name;

	u64			state;

	u64			flags;

	/* the thread group id which is using this service */
	pid_t			tgid;

	/* unique handle assigned to this service */
	u64			handle;

	/* version that was negotiated */
	vlds_ver_t		neg_vers;

	/* Queue of received data messages for this service */
	struct list_head	msg_queue;
	u64			msg_queue_size;

};
#define VLDS_SVC_IS_CLIENT(svc) ((svc)->flags & VLDS_REG_CLIENT)
#define VLDS_SVC_IS_EVENT(svc) ((svc)->flags & VLDS_REG_EVENT)

struct vlds_msg_data {
	/* link into the vlds_service_info message queue */
	struct list_head	list;

	size_t			size;  /* message data size */
	u8			data[0]; /* message data */
};
#define VLDS_MAX_MSG_LIST_NUM		16

/*
 * If a process registers an event fd, we create an
 * event_info to track events for the process.
 */
struct vlds_event_info {
	/* link into the vlds_event_info_list */
	struct list_head	list;

	/* the thread group id (i.e. pid) to which this event_info belongs */
	pid_t			tgid;

	/* fd to signal process of received event - See eventfd(2) */
	int			fd;

	/* List of received events */
	struct list_head	event_list;
};

struct list_head	vlds_event_info_list;
static DEFINE_MUTEX(vlds_event_info_list_mutex);

struct vlds_event {
	/* link into the vlds_event_info event_list */
	struct list_head	list;

	/* service associated with the event */
	struct vlds_service_info *svc_info;

	/* type of event - reg/unreg/data */
	u64			type;

	/* negotiated version (for reg events) */
	vlds_ver_t		neg_vers;
};

/*
 * When holding multiple locks in this driver, locking
 * MUST be consistently performed in this order:
 * vlds_data_mutex
 * vlds_dev->vlds_mutex
 * vlds_event_info_list_mutex
 */

/* vlds_event_info_list_mutex must be held */
static int vlds_add_event_info(pid_t tgid, int fd)
{
	struct vlds_event_info *event_info;

	dprintk("called\n");

	event_info = kzalloc(sizeof(struct vlds_event_info), GFP_KERNEL);
	if (unlikely(event_info == NULL)) {
		dprintk("failed to allocate event_info\n");
		return -ENOMEM;
	}

	event_info->tgid = tgid;
	event_info->fd = fd;
	INIT_LIST_HEAD(&event_info->event_list);

	list_add_tail(&event_info->list, &vlds_event_info_list);

	return 0;

}

/* vlds_event_info_list_mutex must be held */
static int vlds_get_event_info(pid_t tgid,
	struct vlds_event_info **ret_event_info)
{
	struct vlds_event_info *event_info;
	bool found;

	found = false;
	list_for_each_entry(event_info, &vlds_event_info_list, list) {
		if (event_info->tgid == tgid) {
			found = true;
			break;
		}
	}

	if (!found)
		return -ENODEV;

	*ret_event_info = event_info;

	return 0;

}

/* vlds_event_info_list_mutex must be held */
static void vlds_remove_event_info(pid_t tgid)
{
	struct vlds_event_info *event_info;
	struct vlds_event *event;
	struct vlds_event *next;
	bool found;

	dprintk("called\n");

	found = false;
	list_for_each_entry(event_info, &vlds_event_info_list, list) {
		if (event_info->tgid == tgid) {
			found = true;
			break;
		}
	}

	if (found) {
		/* Remove all events queued on this event_info */
		list_for_each_entry_safe(event, next, &event_info->event_list,
		    list) {
			list_del(&event->list);
			kfree(event);
		}

		list_del(&event_info->list);
		kfree(event_info);
	}

}

static int vlds_add_event(pid_t tgid, struct vlds_service_info *svc_info,
	u64 type, vlds_ver_t *neg_vers)
{
	struct vlds_event_info *event_info;
	struct vlds_event *event;
	struct task_struct *utask;
	struct file *efd_file;
	struct eventfd_ctx *efd_ctx;
	int rv;

	mutex_lock(&vlds_event_info_list_mutex);

	event_info = NULL;
	rv = vlds_get_event_info(tgid, &event_info);
	if (rv || event_info == NULL) {
		/*
		 * If we failed to find an event_info, it probably just
		 * means the process did not register for events in favor
		 * of using polling - which is valid.
		 */
		mutex_unlock(&vlds_event_info_list_mutex);
		return 0;
	}

	event = kzalloc(sizeof(struct vlds_event), GFP_KERNEL);
	if (unlikely(event == NULL)) {
		dprintk("failed to allocate event for "
		    "service %llx\n", svc_info->handle);
		mutex_unlock(&vlds_event_info_list_mutex);
		return -ENOMEM;
	} else {
		event->type = type;
		event->svc_info = svc_info;
		if (neg_vers != NULL)
			event->neg_vers = *neg_vers;

		list_add_tail(&event->list,
		    &event_info->event_list);
	}

	mutex_unlock(&vlds_event_info_list_mutex);

	/*
	 * Signal the process that there is an event pending
	 * This is tricky as it requires searching the task's
	 * file table for the entry corresponding to the event fd
	 * to get the event fd context.
	 */

	rcu_read_lock();

	/* Get the task struct */
	utask = pid_task(find_vpid(tgid), PIDTYPE_PID);
	if (!utask) {
		rcu_read_unlock();
		return -EIO;
	}

	/* Get the file corresponding to event_info->fd */
	efd_file = fcheck_files(utask->files, event_info->fd);
	if (!efd_file) {
		rcu_read_unlock();
		return -EIO;
	}

	/* Get the eventfd context associated with the file */
	efd_ctx = eventfd_ctx_fileget(efd_file);
	if (!efd_ctx) {
		rcu_read_unlock();
		return -EIO;
	}

	/* signal the task by incrementing the counter by 1 */
	eventfd_signal(efd_ctx, 1);

	/* release the eventfd context */
	eventfd_ctx_put(efd_ctx);

	rcu_read_unlock();

	return rv;

}

static struct vlds_event *vlds_get_event(struct vlds_event_info *event_info)
{

	struct vlds_event *event;

	if (list_empty(&event_info->event_list))
		return NULL;

	event = list_first_entry(&event_info->event_list,
	    struct vlds_event, list);

	BUG_ON(event == NULL);

	return event;

}

static void vlds_remove_event(struct vlds_event_info *event_info,
	struct vlds_event *event)
{
	if (event == NULL || list_empty(&event_info->event_list))
		return;

	/* Check here that the event is actually on the list? TBD */

	list_del(&event->list);

	kfree(event);
}

static void vlds_remove_svc_events(struct vlds_service_info *svc_info)
{
	struct vlds_event_info *event_info;
	struct vlds_event *event;
	struct vlds_event *next;

	mutex_lock(&vlds_event_info_list_mutex);

	list_for_each_entry(event_info, &vlds_event_info_list, list) {

		list_for_each_entry_safe(event, next, &event_info->event_list,
		    list) {
			if (event->svc_info == svc_info) {
				list_del(&event->list);
				kfree(event);
			}
		}
	}

	mutex_unlock(&vlds_event_info_list_mutex);
}

static struct vlds_service_info *vlds_get_svc_info(struct vlds_dev *vlds,
	char *svc_str, bool is_client)
{
	struct vlds_service_info *svc_info;

	list_for_each_entry(svc_info, &vlds->service_info_list, list) {
		if (!strncmp(svc_info->name, svc_str, VLDS_MAX_NAMELEN) &&
		    VLDS_SVC_IS_CLIENT(svc_info) == is_client) {
			return svc_info;
		}
	}

	return NULL;
}

static struct vlds_service_info *vlds_get_svc_info_hdl(struct vlds_dev *vlds,
	u64 hdl)
{
	struct vlds_service_info *svc_info;

	list_for_each_entry(svc_info, &vlds->service_info_list, list) {
		if (svc_info->handle == hdl)
			return svc_info;
	}

	return NULL;
}

/* Add a message to a service message queue */
static int vlds_add_msg(struct vlds_service_info *svc_info, void *buf,
	size_t buflen)
{
	struct vlds_msg_data *msg_data;

	/* check if we've reached the max num of queued messages */
	if (svc_info->msg_queue_size > VLDS_MAX_MSG_LIST_NUM)
		return -ENOSPC;

	/* make sure the message size isn't too large */
	if (buflen > VLDS_MAX_MSG_SIZE)
		return -EFBIG;

	/* we don't allow enqueing zero length messages */
	if (buflen == 0)
		return -EINVAL;

	/* allocate/copy a buffer for the message */
	msg_data = kzalloc(sizeof(struct vlds_msg_data) + buflen, GFP_KERNEL);
	if (unlikely(msg_data == NULL))
		return -ENOMEM;

	/* copy the message/size */
	memcpy(msg_data->data, buf, buflen);
	msg_data->size = buflen;

	/* add it to the queue */
	list_add_tail(&msg_data->list, &svc_info->msg_queue);

	svc_info->msg_queue_size++;

	return 0;
}

/*
 * Get a message (data and size) from a service message queue.
 * NOTE: the message remains on the queue.
 */
static struct vlds_msg_data *vlds_get_msg(struct vlds_service_info *svc_info)
{
	struct vlds_msg_data *msg_data;

	if (list_empty(&svc_info->msg_queue)) {
		/*
		 * TBD: Block instead of return here
		 * (unless NONBLOCK flag specified).
		 */
		return NULL;
	}

	msg_data = list_first_entry(&svc_info->msg_queue, struct vlds_msg_data,
	    list);

	BUG_ON(msg_data == NULL);

	return msg_data;
}

/* Dequeue a message from a service message queue. */
static void vlds_dequeue_msg(struct vlds_service_info *svc_info,
	struct vlds_msg_data *msg_data)
{
	if (msg_data == NULL || list_empty(&svc_info->msg_queue))
		return;

	/* Check here that the message is actually on the queue? TBD */

	list_del(&msg_data->list);

	kfree(msg_data);

	svc_info->msg_queue_size--;
}

static void vlds_free_msg_queue(struct vlds_service_info *svc_info)
{
	struct vlds_msg_data *msg_data;
	struct vlds_msg_data *next;

	list_for_each_entry_safe(msg_data, next, &svc_info->msg_queue,
	    list) {

		list_del(&msg_data->list);

		kfree(msg_data);

		svc_info->msg_queue_size--;
	}

}

/*
 * Callback ops
 */
static void
vlds_ds_reg_cb(ds_cb_arg_t arg, ds_svc_hdl_t hdl, ds_ver_t *ver)
{
	struct vlds_dev *vlds;
	struct vlds_service_info *svc_info;
	int rv;

	dprintk("entered.\n");

	vlds = (struct vlds_dev *)arg;

	mutex_lock(&vlds->vlds_mutex);

	svc_info = vlds_get_svc_info_hdl(vlds, hdl);
	if (svc_info == NULL) {
		dprintk("%s: received invalid handle (%llx)\n",
		    vlds->int_name, hdl);
		mutex_unlock(&vlds->vlds_mutex);
		return;
	}

	svc_info->neg_vers.vlds_major = (u16)ver->major;
	svc_info->neg_vers.vlds_minor = (u16)ver->minor;
	svc_info->state = VLDS_HDL_STATE_CONNECTED;

	/*
	 * if the service requires events,
	 * add an event to the process's event_info queue
	 */
	if (VLDS_SVC_IS_EVENT(svc_info)) {
		rv = vlds_add_event(svc_info->tgid, svc_info,
		    VLDS_EVENT_TYPE_REG, &svc_info->neg_vers);
		if (rv) {
			/* just give an error if we failed to add the event */
			pr_err("%s: failed to create registration event "
			    "(%llx)\n", vlds->int_name, hdl);
		}
	}

	dprintk("%s: service %s registered version (%u.%u) hdl=%llx\n",
	    vlds->int_name, svc_info->name, svc_info->neg_vers.vlds_major,
	    svc_info->neg_vers.vlds_minor, hdl);

	mutex_unlock(&vlds->vlds_mutex);

}

static void
vlds_ds_unreg_cb(ds_cb_arg_t arg, ds_svc_hdl_t hdl)
{
	struct vlds_dev *vlds;
	struct vlds_service_info *svc_info;
	int rv;

	dprintk("entered.\n");

	vlds = (struct vlds_dev *)arg;

	mutex_lock(&vlds->vlds_mutex);

	svc_info = vlds_get_svc_info_hdl(vlds, hdl);
	if (svc_info == NULL) {
		dprintk("%s: recevied invalid handle (%llx)\n",
		    vlds->int_name, hdl);
		mutex_unlock(&vlds->vlds_mutex);
		return;
	}

	svc_info->neg_vers.vlds_major = 0;
	svc_info->neg_vers.vlds_minor = 0;
	svc_info->state = VLDS_HDL_STATE_DISCONNECTED;

	/*
	 * if the service requires events,
	 * add an event to the process's event_info queue
	 */
	if (VLDS_SVC_IS_EVENT(svc_info)) {
		rv = vlds_add_event(svc_info->tgid, svc_info,
		    VLDS_EVENT_TYPE_UNREG, NULL);
		if (rv) {
			/* just give an error if we failed to add the event */
			pr_err("%s: failed to create unregistration event "
			    "(%llx)\n", vlds->int_name, hdl);
		}
	}

	dprintk("%s: service %s unregistered hdl=%llx\n",
	    vlds->int_name, svc_info->name, hdl);

	mutex_unlock(&vlds->vlds_mutex);

}

static void
vlds_ds_data_cb(ds_cb_arg_t arg, ds_svc_hdl_t hdl, void *buf, size_t buflen)
{
	struct vlds_dev *vlds;
	struct vlds_service_info *svc_info;
	int rv;

	dprintk("entered.\n");

	vlds = (struct vlds_dev *)arg;

	mutex_lock(&vlds->vlds_mutex);

	svc_info = vlds_get_svc_info_hdl(vlds, hdl);
	if (svc_info == NULL) {
		dprintk("%s: recevied invalid handle (%llx)\n",
		    vlds->int_name, hdl);
		mutex_unlock(&vlds->vlds_mutex);
		return;
	}

	/* received data is assumed to be 1 complete message */
	rv = vlds_add_msg(svc_info, buf, buflen);
	if (rv) {
		if (rv == -ENOSPC)
			dprintk("%s: service %s: message queue overflow!\n",
			    vlds->int_name, svc_info->name);
		else if (rv == -EFBIG)
			dprintk("%s: service %s: message too large "
			    "(%lu bytes)!\n", vlds->int_name, svc_info->name,
			    buflen);
		else
			dprintk("%s: service %s: failed to add message "
			    "(err = %d)!\n", vlds->int_name,
			    svc_info->name, rv);

		mutex_unlock(&vlds->vlds_mutex);

		return;
	}

	/*
	 * if the service requires events,
	 * add an event to the process's event_info queue
	 */
	if (VLDS_SVC_IS_EVENT(svc_info)) {
		rv = vlds_add_event(svc_info->tgid, svc_info,
		    VLDS_EVENT_TYPE_DATA, NULL);
		if (rv) {
			/* just give an error if we failed to add the event */
			pr_err("%s: failed to create data event (%llx)\n",
			    vlds->int_name, hdl);
		}
	}

	dprintk("%s: %s service: Received %lu bytes hdl=%llx\n",
	    vlds->int_name, svc_info->name, buflen, hdl);

	mutex_unlock(&vlds->vlds_mutex);

}

static ds_ops_t vlds_ds_ops = {
	vlds_ds_reg_cb,		/* register */
	vlds_ds_unreg_cb,	/* unregister */
	vlds_ds_data_cb,	/* data */
	NULL			/* optional arg to ops */
};

static int vlds_svc_reg(struct vlds_dev *vlds, const void __user *uarg)
{

	vlds_svc_reg_arg_t svc_reg;
	vlds_cap_t cap;
	char *svc_str;
	bool is_client_reg;
	ds_capability_t dscap;
	u32 flags;
	ds_svc_hdl_t ds_hdl;
	int rv;
	struct vlds_service_info *svc_info;

	dprintk("entered.\n");

	svc_str = NULL;
	svc_info = NULL;

	/* Get (and validate) userland args */
	if (uarg == NULL || copy_from_user(&svc_reg, uarg,
	    sizeof(vlds_svc_reg_arg_t)) != 0) {
		rv = -EFAULT;
		goto error_out1;
	}

	/* Validate svc_reg.vlds_hdlp is present/accessible */
	if (!access_ok(VERIFY_WRITE, (void __user *)svc_reg.vlds_hdlp,
	    sizeof(u64))) {
		rv = -EFAULT;
		goto error_out1;
	}

	if (copy_from_user(&cap, (const void __user *)svc_reg.vlds_capp,
	    sizeof(vlds_cap_t)) != 0) {
		rv = -EFAULT;
		goto error_out1;
	}

	/* make sure the service strlen is sane */
	if (cap.vlds_service.vlds_strlen == 0 ||
	    cap.vlds_service.vlds_strlen > VLDS_MAX_NAMELEN) {
		rv = -EINVAL;
		goto error_out1;
	}

	/* get the service string from userland */
	svc_str = kzalloc(cap.vlds_service.vlds_strlen + 1, GFP_KERNEL);
	if (unlikely(svc_str == NULL)) {
		rv = -ENOMEM;
		goto error_out1;
	}

	if (copy_from_user(svc_str,
	    (const void __user *)cap.vlds_service.vlds_strp,
	    cap.vlds_service.vlds_strlen) != 0) {
		rv = -EFAULT;
		goto error_out1;
	}

	is_client_reg = (svc_reg.vlds_reg_flags & VLDS_REG_CLIENT);

	mutex_lock(&vlds->vlds_mutex);

	/* Check if the service is already being used */
	svc_info = vlds_get_svc_info(vlds, svc_str, is_client_reg);
	if (svc_info != NULL) {
		/* This service is already in use */
		rv = -EBUSY;
		svc_info = NULL;
		goto error_out2;
	}

	/* init the ds capability structure */
	dscap.svc_id = svc_str;
	dscap.vers.major = (u64)cap.vlds_vers.vlds_major;
	dscap.vers.minor = (u64)cap.vlds_vers.vlds_minor;

	/* The svc_info will be passed back as an arg to the cb */
	vlds_ds_ops.cb_arg = (void *)vlds;

	flags = 0x0;
	if (is_client_reg)
		flags |= DS_CAP_IS_CLIENT;
	else
		flags |= DS_CAP_IS_PROVIDER;

	if (vlds != sp_vlds)
		flags |= DS_TARGET_IS_DOMAIN;

	ds_hdl = 0;
	rv = ds_cap_init(&dscap, &vlds_ds_ops, flags, vlds->domain_handle,
	    &ds_hdl);
	if (rv || ds_hdl == 0) {
		dprintk("%s: ds_cap_init failed for %s service\n",
		    vlds->int_name, svc_str);
		goto error_out2;
	}

	if (copy_to_user((void __user *)(svc_reg.vlds_hdlp), (u64 *)&ds_hdl,
	    sizeof(u64)) != 0) {
		(void) ds_cap_fini(ds_hdl);
		rv = -EFAULT;
		goto error_out2;
	}

	/* create a service info for the new service */
	svc_info = kzalloc(sizeof(struct vlds_service_info), GFP_KERNEL);
	if (unlikely(svc_str == NULL)) {
		(void) ds_cap_fini(ds_hdl);
		rv = -ENOMEM;
		goto error_out2;
	}

	svc_info->name = svc_str;
	svc_info->state = VLDS_HDL_STATE_NOT_YET_CONNECTED;
	svc_info->flags = svc_reg.vlds_reg_flags;
	svc_info->tgid = task_tgid_vnr(current);
	svc_info->handle = (u64)ds_hdl;
	INIT_LIST_HEAD(&svc_info->msg_queue);
	svc_info->msg_queue_size = 0;

	/* add the service_info to the vlds device */
	list_add_tail(&svc_info->list, &vlds->service_info_list);

	dprintk("%s: registered %s service (client = %llu) "
	    "(hdl = %llx) (tgid = %u) with ds\n", vlds->int_name, svc_str,
	    VLDS_SVC_IS_CLIENT(svc_info), svc_info->handle, svc_info->tgid);

	mutex_unlock(&vlds->vlds_mutex);

	return 0;

error_out2:

	mutex_unlock(&vlds->vlds_mutex);

error_out1:

	dprintk("%s: failed to register service rv = %d\n", vlds->int_name, rv);

	if (svc_info)
		kfree(svc_info);

	if (svc_str)
		kfree(svc_str);

	return rv;
}

static int vlds_unreg_hdl(struct vlds_dev *vlds, const void __user *uarg)
{
	vlds_unreg_hdl_arg_t unreg;
	struct vlds_service_info *svc_info;
	int rv;

	dprintk("entered.\n");

	/* Get (and validate) userland args */
	if (uarg == NULL || copy_from_user(&unreg, uarg,
	    sizeof(vlds_unreg_hdl_arg_t)) != 0) {
		rv = -EFAULT;
		goto error_out1;
	}

	mutex_lock(&vlds->vlds_mutex);

	svc_info = vlds_get_svc_info_hdl(vlds, unreg.vlds_hdl);
	if (svc_info == NULL) {
		rv = -ENODEV;
		goto error_out2;
	}

	/* unregister the service from ds */
	rv = ds_cap_fini(unreg.vlds_hdl);
	if (rv) {
		dprintk("%s: ds_cap_fini failed for %s service ",
		    vlds->int_name, svc_info->name);
		goto error_out2;
	}

	dprintk("%s: unregistered %s service (client = %llu) "
	    "(hdl = %llx) with ds\n", vlds->int_name, svc_info->name,
	    VLDS_SVC_IS_CLIENT(svc_info), unreg.vlds_hdl);

	list_del(&svc_info->list);

	/* remove any events referencing this svc_info */
	vlds_remove_svc_events(svc_info);

	kfree(svc_info->name);
	vlds_free_msg_queue(svc_info);
	kfree(svc_info);

	mutex_unlock(&vlds->vlds_mutex);

	return 0;

error_out2:

	mutex_unlock(&vlds->vlds_mutex);

error_out1:

	dprintk("%s: failed to unregister service rv = %d\n",
	    vlds->int_name, rv);

	return rv;
}

static int vlds_hdl_lookup(struct vlds_dev *vlds, const void __user *uarg)
{
	vlds_hdl_lookup_arg_t hdl_lookup;
	struct vlds_service_info *svc_info;
	char *svc_str;
	u64 num_hdls;
	int rv;

	dprintk("entered.\n");

	svc_str = NULL;

	/* Get (and validate) userland args */
	if (uarg == NULL || copy_from_user(&hdl_lookup, uarg,
	    sizeof(vlds_hdl_lookup_arg_t)) != 0) {
		rv = -EFAULT;
		goto error_out1;
	}

	/* we only support 1 return handle */
	if (hdl_lookup.vlds_maxhdls != 1) {
		rv = -EINVAL;
		goto error_out1;
	}

	/* get the service string */

	/* make sure the service strlen is sane */
	if (hdl_lookup.vlds_service.vlds_strlen == 0 ||
	    hdl_lookup.vlds_service.vlds_strlen > VLDS_MAX_NAMELEN) {
		rv = -EINVAL;
		goto error_out1;
	}

	/* get the service string from userland */
	svc_str = kzalloc(hdl_lookup.vlds_service.vlds_strlen + 1, GFP_KERNEL);
	if (unlikely(svc_str == NULL)) {
		rv = -ENOMEM;
		goto error_out1;
	}

	if (copy_from_user(svc_str,
	    (const void __user *)hdl_lookup.vlds_service.vlds_strp,
	    hdl_lookup.vlds_service.vlds_strlen) != 0) {
		rv = -EFAULT;
		goto error_out1;
	}

	mutex_lock(&vlds->vlds_mutex);

	svc_info = vlds_get_svc_info(vlds, svc_str, hdl_lookup.vlds_isclient);
	if (svc_info == NULL) {
		rv = -ENODEV;
		goto error_out2;
	}

	if (copy_to_user((void __user *)(hdl_lookup.vlds_hdlsp),
	    &svc_info->handle, sizeof(u64)) != 0) {
		rv = -EFAULT;
		goto error_out2;
	}

	num_hdls = 1;
	if (put_user(num_hdls, (u64 __user *)(hdl_lookup.vlds_nhdlsp)) != 0) {
		rv = -EFAULT;
		goto error_out2;
	}

	dprintk("%s: handle lookup for  %s service (client = %llu) "
	    "returned (hdl = %llx)\n", vlds->int_name, svc_str,
	    hdl_lookup.vlds_isclient, svc_info->handle);

	mutex_unlock(&vlds->vlds_mutex);

	return 0;

error_out2:

	mutex_unlock(&vlds->vlds_mutex);

error_out1:

	dprintk("%s: failed to lookup handle rv = %d\n", vlds->int_name, rv);

	if (svc_str)
		kfree(svc_str);

	return rv;

}

static int vlds_dmn_lookup(struct vlds_dev *vlds, const void __user *uarg)
{
	vlds_dmn_lookup_arg_t dmn_lookup;
	int rv;

	/* Get (and validate) userland args */
	if (uarg == NULL || copy_from_user(&dmn_lookup, uarg,
	    sizeof(vlds_dmn_lookup_arg_t)) != 0) {
		rv = -EFAULT;
		goto error_out1;
	}

	/* make sure the string buffer size is sane */
	if (dmn_lookup.vlds_dname.vlds_strlen < (strlen(vlds->int_name) + 1)) {
		rv = -EINVAL;
		goto error_out1;
	}

	if (put_user(vlds->domain_handle,
	    (u64 __user *)(dmn_lookup.vlds_dhdlp)) != 0) {
		rv = -EFAULT;
		goto error_out1;
	}

	if (copy_to_user((void __user *)(dmn_lookup.vlds_dname.vlds_strp),
	    vlds->int_name, (strlen(vlds->int_name) + 1)) != 0) {
		rv = -EFAULT;
		goto error_out1;
	}

	return 0;

error_out1:

	dprintk("%s: failed to lookup domain info. rv = %d\n",
	    vlds->int_name, rv);

	return rv;
}

static int vlds_hdl_get_state(struct vlds_dev *vlds, const void __user *uarg)
{
	vlds_hdl_get_state_arg_t hdl_get_state;
	struct vlds_service_info *svc_info;
	vlds_hdl_state_t hdl_state;
	int rv;

	/* Get (and validate) userland args */
	if (uarg == NULL || copy_from_user(&hdl_get_state, uarg,
	    sizeof(vlds_hdl_get_state_arg_t)) != 0) {
		rv = -EFAULT;
		goto error_out1;
	}

	mutex_lock(&vlds->vlds_mutex);

	svc_info = vlds_get_svc_info_hdl(vlds, hdl_get_state.vlds_hdl);
	if (svc_info == NULL) {
		rv = -ENODEV;
		goto error_out2;
	}

	memset(&hdl_state, 0, sizeof(hdl_state));
	hdl_state.state = svc_info->state;
	/* if the state is connected, return the negotiated version */
	if (svc_info->state == VLDS_HDL_STATE_CONNECTED) {
		hdl_state.vlds_vers.vlds_major = svc_info->neg_vers.vlds_major;
		hdl_state.vlds_vers.vlds_minor = svc_info->neg_vers.vlds_minor;
	}

	if (copy_to_user((void __user *)(hdl_get_state.vlds_statep),
	    &hdl_state, sizeof(vlds_hdl_state_t)) != 0) {
		rv = -EFAULT;
		goto error_out2;
	}

	mutex_unlock(&vlds->vlds_mutex);

	return 0;

error_out2:

	mutex_unlock(&vlds->vlds_mutex);

error_out1:

	dprintk("%s: failed to get handle state rv = %d\n", vlds->int_name, rv);

	return rv;

}

static int vlds_send_msg(struct vlds_dev *vlds, const void __user *uarg)
{
	vlds_send_msg_arg_t send_msg;
	struct vlds_service_info *svc_info;
	u8 *send_buf;
	int rv;

	dprintk("entered.\n");

	send_buf = NULL;

	/* Get (and validate) userland args */
	if (uarg == NULL || copy_from_user(&send_msg, uarg,
	    sizeof(vlds_send_msg_arg_t)) != 0) {
		rv = -EFAULT;
		goto error_out1;
	}

	if (send_msg.vlds_buflen == 0 ||
	    send_msg.vlds_buflen > VLDS_MAX_SENDBUF_LEN) {
		rv = -EINVAL;
		goto error_out1;
	}

	mutex_lock(&vlds->vlds_mutex);

	svc_info = vlds_get_svc_info_hdl(vlds, send_msg.vlds_hdl);
	if (svc_info == NULL) {
		rv = -ENODEV;
		goto error_out2;
	}

	/* make sure we are in connected state before sending the data */
	if (svc_info->state != VLDS_HDL_STATE_CONNECTED) {
		rv = -EIO;
		goto error_out2;
	}

	send_buf = kzalloc(send_msg.vlds_buflen, GFP_KERNEL);
	if (unlikely(send_buf == NULL)) {
		rv = -ENOMEM;
		goto error_out2;
	}

	if (copy_from_user(send_buf, (const void __user *)send_msg.vlds_bufp,
	    send_msg.vlds_buflen) != 0) {
		rv = -EFAULT;
		goto error_out2;
	}

	rv = ds_cap_send(send_msg.vlds_hdl, send_buf, send_msg.vlds_buflen);
	if (rv) {

		/*
		 * TBD: If rv == -EAGAIN, block here trying again in loop
		 * (unless NONBLOCK flag specified).
		 */
		dprintk("%s: ds_cap_send failed for %s service (rv=%d)\n",
		    vlds->int_name, svc_info->name, rv);
		goto error_out2;
	}

	kfree(send_buf);

	dprintk("%s: send msg hdl = %llx (buflen=%llu) SUCCESS\n",
	    vlds->int_name, send_msg.vlds_hdl, send_msg.vlds_buflen);

	mutex_unlock(&vlds->vlds_mutex);

	return 0;

error_out2:

	mutex_unlock(&vlds->vlds_mutex);

error_out1:

	dprintk("%s: failed to send msg rv = %d\n", vlds->int_name, rv);

	if (send_buf != NULL)
		kfree(send_buf);

	return rv;

}

static int vlds_recv_msg(struct vlds_dev *vlds, const void __user *uarg)
{
	vlds_recv_msg_arg_t recv_msg;
	struct vlds_service_info *svc_info;
	u8 *msg;
	size_t msglen;
	int rv;
	struct vlds_msg_data *msg_data;

	/* Get (and validate) userland args */
	if (uarg == NULL || copy_from_user(&recv_msg, uarg,
	    sizeof(vlds_recv_msg_arg_t)) != 0) {
		rv = -EFAULT;
		goto error_out1;
	}

	if (recv_msg.vlds_buflen > VLDS_MAX_SENDBUF_LEN) {
		rv = -EINVAL;
		goto error_out1;
	}

	mutex_lock(&vlds->vlds_mutex);

	svc_info = vlds_get_svc_info_hdl(vlds, recv_msg.vlds_hdl);
	if (svc_info == NULL) {
		rv = -ENODEV;
		goto error_out2;
	}

	msg_data =  vlds_get_msg(svc_info);
	if (msg_data == NULL) {
		msg = NULL;
		msglen = 0;
	} else {
		msg = msg_data->data;
		msglen = msg_data->size;
	}

	if (put_user(msglen, (u64 __user *)(recv_msg.vlds_msglenp)) != 0) {
		rv = -EFAULT;
		goto error_out2;
	}

	/*
	 * Special handling for a buflen of 0: if buflen is 0, we return
	 * the number of bytes for the next message in the queue.
	 *
	 * This is a mechanism for the caller to use to poll the queue
	 * to detect if a msg is ready to be received and to get the
	 * size of the next message so the appropriate sized buffer can
	 * be allocated to receive the msg.
	 */
	if (recv_msg.vlds_buflen == 0) {

		if (msglen > 0)
			dprintk("%s: service %s: buflen==0 poll "
			    "returned %zu bytes\n",
			    vlds->int_name, svc_info->name, msglen);

		mutex_unlock(&vlds->vlds_mutex);

		return 0;
	}

	/*
	 * We do not return truncated data. Return EFBIG error if
	 * supplied buffer is too small to hold the next message.
	 */
	if (msglen > 0 && recv_msg.vlds_buflen < msglen) {
		dprintk("%s: service %s: recv buffer too small for "
		    "next message (supplied buffer = %llu bytes, "
		    "next message = %lu bytes)\n",
		    vlds->int_name, svc_info->name, recv_msg.vlds_buflen,
		    msglen);

		rv = -EFBIG;
		goto error_out2;
	}

	if (msglen > 0) {

		if (copy_to_user((void __user *)(recv_msg.vlds_bufp),
		    msg, msglen) != 0) {
			rv = -EFAULT;
			goto error_out2;
		}

		/*
		 * We successfully copied the data to user,
		 * so dequeue the message
		 */
		vlds_dequeue_msg(svc_info, msg_data);

		dprintk("%s: recv msg hdl = %llx (len=%lu) SUCCESS\n",
		    vlds->int_name, recv_msg.vlds_hdl, msglen);
	}

	mutex_unlock(&vlds->vlds_mutex);

	return 0;

error_out2:

	mutex_unlock(&vlds->vlds_mutex);

error_out1:

	dprintk("%s: failed to recv msg rv = %d\n",
	    vlds->int_name, rv);

	return rv;
}

static int vlds_set_event_fd(struct vlds_dev *vlds, const void __user *uarg)
{
	vlds_set_event_fd_arg_t set_event_fd;
	int rv;
	pid_t tgid;

	/* Get (and validate) userland args */
	if (uarg == NULL || copy_from_user(&set_event_fd, uarg,
	    sizeof(vlds_set_event_fd_arg_t)) != 0) {
		rv = -EFAULT;
		goto error_out1;
	}

	tgid = task_tgid_vnr(current);

	mutex_lock(&vlds_event_info_list_mutex);

	/*
	 * If there is already an event fd
	 * registered for this process, remove it.
	 */
	vlds_remove_event_info(tgid);

	rv = vlds_add_event_info(tgid, set_event_fd.fd);

	mutex_unlock(&vlds_event_info_list_mutex);

	if (rv)
		goto error_out1;

	dprintk("%s: vlds_set_event_fd: SUCCESS\n", vlds->int_name);

	return 0;


error_out1:

	dprintk("%s: failed to set event fd: rv = %d\n",
	    vlds->int_name, rv);

	return rv;
}

static int vlds_unset_event_fd(struct vlds_dev *vlds, const void __user *uarg)
{
	pid_t tgid;

	tgid = task_tgid_vnr(current);

	mutex_lock(&vlds_event_info_list_mutex);

	vlds_remove_event_info(tgid);

	mutex_unlock(&vlds_event_info_list_mutex);

	dprintk("%s: vlds_unset_event_fd: SUCCESS\n", vlds->int_name);

	return 0;

}

static int vlds_get_next_event(struct vlds_dev *vlds, const void __user *uarg)
{
	vlds_get_next_event_arg_t next_event;
	struct vlds_event_info *event_info;
	struct vlds_event *event;
	struct vlds_msg_data *msg_data;
	u8 *msg;
	size_t msglen;
	int rv;

	dprintk("called\n");

	/* Get (and validate) userland args */
	if (uarg == NULL || copy_from_user(&next_event, uarg,
	    sizeof(vlds_get_next_event_arg_t)) != 0) {
		rv = -EFAULT;
		goto error_out1;
	}

	/* Validate next_event.vlds_hdlp is present/accessible */
	if (!access_ok(VERIFY_WRITE, (void __user *)next_event.vlds_hdlp,
	    sizeof(u64))) {
		rv = -EFAULT;
		goto error_out1;
	}

	/* Validate next_event.vlds_event_typep is present/accessible */
	if (!access_ok(VERIFY_WRITE, (void __user *)next_event.vlds_event_typep,
	    sizeof(u64))) {
		rv = -EFAULT;
		goto error_out1;
	}

	/* Validate next_event.neg_versp is present/accessible */
	if (!access_ok(VERIFY_WRITE, (void __user *)next_event.neg_versp,
	    sizeof(u64))) {
		rv = -EFAULT;
		goto error_out1;
	}

	/* Validate next_event.vlds_buflen is valid */
	if (next_event.vlds_buflen == 0 ||
	    next_event.vlds_buflen > VLDS_MAX_SENDBUF_LEN) {
		rv = -EINVAL;
		goto error_out1;
	}

	/* Validate next_event.vlds_bufp is present/accessible */
	if (!access_ok(VERIFY_WRITE, (void __user *)next_event.vlds_bufp,
	    next_event.vlds_buflen)) {
		rv = -EFAULT;
		goto error_out1;
	}

	/* Validate next_event.vlds_msglenp is present/accessible */
	if (!access_ok(VERIFY_WRITE, (void __user *)next_event.vlds_msglenp,
	    sizeof(u64))) {
		rv = -EFAULT;
		goto error_out1;
	}

	/* user arg is valid, get the next event */

	mutex_lock(&vlds->vlds_mutex);

	mutex_lock(&vlds_event_info_list_mutex);


	event_info = NULL;
	rv = vlds_get_event_info(task_tgid_vnr(current), &event_info);
	if (rv || event_info == NULL) {
		/*
		 * Process didn't register an event fd!
		 * This is required to start receiving events.
		 */
		rv = -EIO;
		goto error_out2;
	}

	event = vlds_get_event(event_info);
	if (event == NULL) {
		/*
		 * No events left outstanding. Return -ENOENT (-2)
		 * to indicate no more events to process.
		 */
		rv = -ENOENT;
		goto error_out2;
	}

	/* populate the return event handle */
	if (put_user(event->svc_info->handle,
	    (u64 __user *)(next_event.vlds_hdlp)) != 0) {
		rv = -EFAULT;
		goto error_out2;
	}

	/* populate the return event type */
	if (put_user(event->type, (u64 __user *)(next_event.vlds_event_typep)) != 0) {
		rv = -EFAULT;
		goto error_out2;
	}

	/* if it's a reg type event, populate the negotiated version */
	if (event->type == VLDS_EVENT_TYPE_REG) {
		if (copy_to_user((void __user *)(next_event.neg_versp),
		    &event->neg_vers, sizeof(vlds_ver_t)) != 0) {
			rv = -EFAULT;
			goto error_out2;
		}
	}

	/*
	 * if it's a data type event, populate the data buffer
	 * with next message from the service
	 */
	if (event->type == VLDS_EVENT_TYPE_DATA) {
		msg_data =  vlds_get_msg(event->svc_info);
		if (msg_data == NULL || msg_data->size == 0) {
			rv = -EIO;
			goto error_out2;
		}

		msg = msg_data->data;
		msglen = msg_data->size;

		if (next_event.vlds_buflen < msglen) {
			dprintk("%s: service %s: recv buffer too small for "
			    "next message (supplied buffer = %llu bytes, "
			    "next message = %lu bytes)\n",
			    vlds->int_name, event->svc_info->name,
			    next_event.vlds_buflen, msglen);

			rv = -EFBIG;
			goto error_out2;
		}

		if (put_user(msglen, (u64 __user *)(next_event.vlds_msglenp))
		    != 0) {
			rv = -EFAULT;
			goto error_out2;
		}

		if (copy_to_user((void __user *)(next_event.vlds_bufp),
		    msg, msglen) != 0) {
			rv = -EFAULT;
			goto error_out2;
		}

		/* we copied the data to user, so dequeue the message */
		vlds_dequeue_msg(event->svc_info, msg_data);
	}

	/* We successfully transferred the event, remove it from the list */
	vlds_remove_event(event_info, event);

	mutex_unlock(&vlds_event_info_list_mutex);

	mutex_unlock(&vlds->vlds_mutex);

	return 0;

error_out2:

	mutex_unlock(&vlds_event_info_list_mutex);

	mutex_unlock(&vlds->vlds_mutex);

error_out1:

	if (rv != -ENOENT)
		dprintk("%s: failed to get next event: rv = %d\n",
		    vlds->int_name, rv);

	return rv;
}

static int vlds_fops_open(struct inode *inode, struct file *filp)
{

	struct vlds_dev *vlds;

	dprintk("entered.\n");

	/*
	 * We allow all opens on the device. We just need to
	 * tuck away the vlds device for subsequent fops.
	 */
	vlds = container_of(inode->i_cdev, struct vlds_dev, cdev);

	filp->private_data = vlds;

	return 0;
}

static void vlds_unreg_all(struct vlds_dev *vlds)
{

	struct vlds_service_info *svc_info;
	struct vlds_service_info *next;

	if (vlds == NULL)
		return;

	mutex_lock(&vlds->vlds_mutex);

	list_for_each_entry_safe(svc_info, next, &vlds->service_info_list,
	    list) {

		(void) ds_cap_fini(svc_info->handle);

		dprintk("%s: unregistered %s service (client = %llu) "
		    "(hdl = %llx) with ds\n", vlds->int_name,
		    svc_info->name, VLDS_SVC_IS_CLIENT(svc_info),
		    svc_info->handle);

		list_del(&svc_info->list);
		vlds_remove_svc_events(svc_info);
		kfree(svc_info->name);
		vlds_free_msg_queue(svc_info);
		kfree(svc_info);

	}

	mutex_unlock(&vlds->vlds_mutex);

}

static void vlds_unreg_all_tgid(struct vlds_dev *vlds, pid_t tgid)
{

	struct vlds_service_info *svc_info;
	struct vlds_service_info *next;

	mutex_lock(&vlds->vlds_mutex);

	list_for_each_entry_safe(svc_info, next, &vlds->service_info_list,
	    list) {

		if (svc_info->tgid == tgid) {

			(void) ds_cap_fini(svc_info->handle);

			dprintk("%s: unregistered %s service "
			    "(client = %llu) (hdl = %llx) with ds\n",
			    vlds->int_name, svc_info->name,
			    VLDS_SVC_IS_CLIENT(svc_info), svc_info->handle);

			list_del(&svc_info->list);

			kfree(svc_info->name);
			vlds_free_msg_queue(svc_info);
			kfree(svc_info);
		}

	}

	mutex_unlock(&vlds->vlds_mutex);

}

static int vlds_fops_release(struct inode *inode, struct file *filp)
{
	struct vlds_dev *vlds;
	pid_t tgid;

	dprintk("entered.\n");

	if (filp == NULL)
		return -EINVAL;

	vlds = filp->private_data;

	if (vlds == NULL) {
		/* This should not happen, but... */
		pr_err("vlds_fops_release: ERROR- failed to get "
		    "associated vlds_dev\n");
		return 0;
	}

	tgid = task_tgid_vnr(current);

	dprintk("%s: unregistering all events and services for tgid = %u\n",
	    vlds->int_name, tgid);

	/* Remove all events queued for this tgid */
	mutex_lock(&vlds_event_info_list_mutex);

	vlds_remove_event_info(tgid);

	mutex_unlock(&vlds_event_info_list_mutex);

	/* Close all services used by this process */
	vlds_unreg_all_tgid(vlds, tgid);

	return 0;
}

static long vlds_fops_ioctl(struct file *filp, unsigned int cmd,
			    unsigned long arg)
{
	struct vlds_dev *vlds;
	int rv;

	rv = 0;

	vlds = filp->private_data;

	switch (cmd) {

	case VLDS_IOCTL_SVC_REG:

		rv = vlds_svc_reg(vlds, (const void __user *)arg);

		break;

	case VLDS_IOCTL_UNREG_HDL:

		rv = vlds_unreg_hdl(vlds, (const void __user *)arg);

		break;

	case VLDS_IOCTL_HDL_LOOKUP:

		rv = vlds_hdl_lookup(vlds, (const void __user *)arg);

		break;

	case VLDS_IOCTL_DMN_LOOKUP:

		rv = vlds_dmn_lookup(vlds, (const void __user *)arg);

		break;

	case VLDS_IOCTL_SEND_MSG:

		rv = vlds_send_msg(vlds, (const void __user *)arg);

		break;

	case VLDS_IOCTL_RECV_MSG:

		rv = vlds_recv_msg(vlds, (const void __user *)arg);

		break;

	case VLDS_IOCTL_HDL_GET_STATE:

		rv = vlds_hdl_get_state(vlds, (const void __user *)arg);

		break;

	case VLDS_IOCTL_SET_EVENT_FD:

		rv = vlds_set_event_fd(vlds, (const void __user *)arg);

		break;

	case VLDS_IOCTL_UNSET_EVENT_FD:

		rv = vlds_unset_event_fd(vlds, (const void __user *)arg);

		break;

	case VLDS_IOCTL_GET_NEXT_EVENT:

		rv = vlds_get_next_event(vlds, (const void __user *)arg);

		break;

	default:

		return -EINVAL;
	}

	return rv;
}

static const struct file_operations vlds_fops = {
	.owner		= THIS_MODULE,
	.open		= vlds_fops_open,
	.release	= vlds_fops_release,
	.unlocked_ioctl	= vlds_fops_ioctl,
};

static int vlds_get_next_avail_minor(void)
{
	struct vlds_dev *vlds;
	bool found;
	int i;

	/*
	 * walk the vlds_dev_list list to find the next
	 * lowest available minor.
	 */
	mutex_lock(&vlds_data_mutex);
	for (i = VLDS_MINOR_BASE; i < VLDS_MAX_DEVS; i++) {
		found = false;
		list_for_each_entry(vlds, &vlds_data.vlds_dev_list, list) {
			if (i == MINOR(vlds->devt)) {
				found = true;
				break;
			}
		}
		if (!found) {
			/* found a free minor, use it */
			break;
		}
	}
	mutex_unlock(&vlds_data_mutex);

	if (i == VLDS_MAX_DEVS) {
		dprintk("no more minors left for allocation!\n");
		return -1;
	}

	return i;
}

static int vlds_alloc_vlds_dev(char *int_name, char *dev_name,
	struct device *vdev_dev, const u64 domain_handle,
	struct vlds_dev **vldsp)
{
	struct vlds_dev *vlds;
	int rv;
	dev_t devt;
	struct device *device;
	int next_minor;
	unsigned char devt_buf[32];

	dprintk("entered.\n");

	devt = 0;
	device = NULL;

	vlds = kzalloc(sizeof(struct vlds_dev), GFP_KERNEL);
	if (unlikely(vlds == NULL)) {
		dprintk("failed to allocate vlds_dev\n");
		rv = -ENOMEM;
		goto error;
	}

	vlds->domain_handle = domain_handle;

	mutex_init(&vlds->vlds_mutex);

	INIT_LIST_HEAD(&vlds->service_info_list);

	vlds->int_name = kmemdup(int_name, (strlen(int_name) + 1), GFP_KERNEL);
	if (unlikely(vlds->int_name == NULL)) {
		dprintk("failed to alloc vlds int name.\n");
		rv = -ENOMEM;
		goto error;
	}

	/* create the devt for this device */
	next_minor = vlds_get_next_avail_minor();
	if (next_minor == -1) {
		dprintk("vlds_get_next_avail_minor() failed.\n");
		rv = -ENXIO;
		goto error;
	}
	devt = MKDEV(MAJOR(vlds_data.devt), next_minor);
	vlds->devt = devt;

	dprintk("%s: dev_t=%s\n", vlds->int_name, format_dev_t(devt_buf,
		vlds->devt));
	dprintk("%s: domain_handle = %llu\n", vlds->int_name, domain_handle);

	/* create/add the associated cdev */
	cdev_init(&vlds->cdev, &vlds_fops);
	vlds->cdev.owner = THIS_MODULE;
	rv = cdev_add(&vlds->cdev, devt, 1);
	if (rv != 0) {
		dprintk("cdev_add() failed.\n");
		devt = 0;
		goto error;
	}

	/* create the associated /sys and /dev entries */
	device = device_create(vlds_data.chrdev_class, vdev_dev, devt,
		       vlds, "%s", dev_name);
	if (IS_ERR(device)) {
		dprintk("device_create() failed.\n");
		rv = PTR_ERR(device);
		device = NULL;
		goto error;
	}

	vlds->device = device;

	/* add the vlds to the global vlds_data device list */
	mutex_lock(&vlds_data_mutex);
	list_add_tail(&vlds->list, &vlds_data.vlds_dev_list);
	vlds_data.num_vlds_dev_list++;
	mutex_unlock(&vlds_data_mutex);

	if (vldsp != NULL)
		*vldsp = vlds;

	return 0;

error:

	if (device)
		device_destroy(vlds_data.chrdev_class, devt);

	if (devt)
		cdev_del(&vlds->cdev);

	if (vlds->int_name)
		kfree(vlds->int_name);

	if (vlds != NULL) {
		mutex_destroy(&vlds->vlds_mutex);
		kfree(vlds);
	}

	dprintk("dev alloc failed (rv=%d)\n", rv);

	return rv;
}

static int vlds_probe(struct vio_dev *vdev, const struct vio_device_id *vio_did)
{
	struct vlds_dev *vlds;
	struct mdesc_handle *hp;
	const u64 *id;
	const char *name;
	const u64 *dom_handle;
	int name_len;
	char int_name_buf[DS_MAX_DOM_NAME_LEN + 1];
	char dev_name_buf[VLDS_PATH_MAX];
	u64 node;
	int rv;

	dprintk("entered.\n");

	rv = 0;

	hp = mdesc_grab();

	node = vio_vdev_node(hp, vdev);
	if (node == MDESC_NODE_NULL) {
		dprintk("Failed to get vdev MD node.\n");
		mdesc_release(hp);
		rv = -ENXIO;
		goto error;
	}

	id = mdesc_get_property(hp, node, "id", NULL);
	if (id == NULL) {
		dprintk("failed to get id property.\n");
		mdesc_release(hp);
		rv = -ENXIO;
		goto error;
	}

	dom_handle = mdesc_get_property(hp, node,
	    "vlds-remote-domain-handle", NULL);
	if (dom_handle == NULL) {
		dprintk("failed to get vlds-remote-domain-handle property.\n");
		mdesc_release(hp);
		rv = -ENXIO;
		goto error;
	}

	/* get the name of the ldom this vlds-port refers to */
	name = mdesc_get_property(hp, node, "vlds-remote-domain-name",
	    &name_len);
	if (name == NULL) {
		dprintk("failed to get vlds-remote-domain-name property.\n");
		mdesc_release(hp);
		rv = -ENXIO;
		goto error;
	}

	mdesc_release(hp);

	/* sanity check - should never happen */
	if (name_len > DS_MAX_DOM_NAME_LEN)
		goto error;

	/* create the (NULL-terminated) internal name */
	memcpy(int_name_buf, name, name_len);
	int_name_buf[name_len] = '\0';

	/* create the /dev name */
	(void) scnprintf(dev_name_buf, VLDS_PATH_MAX, "%s%llu",
	    VLDS_DEV_DOMAIN_FILENAME_TAG, *dom_handle);

	rv = vlds_alloc_vlds_dev(int_name_buf, dev_name_buf, &vdev->dev,
	    *dom_handle, &vlds);
	if (rv != 0)
		goto error;

	dev_set_drvdata(&vdev->dev, vlds);

	dprintk("%s: Probe successfful: cfg_handle=%llu, id=%llu\n",
	    vlds->int_name, vdev->dev_no, *id);

	return 0;

error:

	dprintk("probe failed (rv=%d)\n", rv);

	return rv;
}

static int vlds_free_vlds_dev(struct vlds_dev *vlds)
{

	dprintk("entered. (%s)\n", vlds->int_name);

	/* Unregister all the services associated with this vlds. */
	vlds_unreg_all(vlds);

	mutex_lock(&vlds_data_mutex);
	list_del(&vlds->list);
	vlds_data.num_vlds_dev_list--;
	mutex_unlock(&vlds_data_mutex);

	device_destroy(vlds_data.chrdev_class, vlds->devt);
	cdev_del(&vlds->cdev);
	kfree(vlds->int_name);
	mutex_destroy(&vlds->vlds_mutex);
	kfree(vlds);

	return 0;
}

static int vlds_remove(struct vio_dev *vdev)
{
	int rv;
	struct vlds_dev *vlds;

	dprintk("entered.\n");

	vlds = dev_get_drvdata(&vdev->dev);

	if (vlds == NULL) {
		dprintk("failed to get vlds_dev from vio_dev.\n");
		rv = -ENXIO;
	} else {
		dprintk("removing (%s)\n", vlds->int_name);
		rv = vlds_free_vlds_dev(vlds);
	}

	return rv;
}

static const struct vio_device_id vlds_match[] = {
	{
		.type = "vlds-port",
	},
	{},
};

static char *vlds_devnode(struct device *dev, umode_t *mode)
{
	if (mode != NULL)
		*mode = 0600;

	return kasprintf(GFP_KERNEL, "vlds/%s", dev_name(dev));
}

static struct vio_driver vlds_driver = {
	.id_table	= vlds_match,
	.probe		= vlds_probe,
	.remove		= vlds_remove,
	.name		= VLDS_DEVICE_NAME,
	.no_irq		= true,
};

static int __init vlds_init(void)
{
	int rv;
	unsigned char devt_buf[32];

	/* set the default ldoms debug level */
	vldsdbg_level = ldoms_debug_level;

	dprintk("entered. (DEBUG enabled)\n");

	dprintk("%s", driver_version);

	INIT_LIST_HEAD(&vlds_data.vlds_dev_list);
	vlds_data.num_vlds_dev_list = 0;

	INIT_LIST_HEAD(&vlds_event_info_list);

	rv = alloc_chrdev_region(&vlds_data.devt, VLDS_MINOR_BASE,
				 VLDS_MAX_DEVS, VLDS_DEVICE_NAME);
	if (rv < 0) {
		dprintk("alloc_chrdev_region failed: %d\n", rv);
		return rv;
	}

	if (vlds_data.devt == (dev_t)0) {
		dprintk("alloc_chrdev_region failed: (vlds_data.devt == 0)\n");
		rv = -ENXIO;
		return rv;
	}

	dprintk("dev_t allocated = %s\n",
		format_dev_t(devt_buf, vlds_data.devt));

	vlds_data.chrdev_class = class_create(THIS_MODULE, VLDS_DEVICE_NAME);
	if (IS_ERR(vlds_data.chrdev_class)) {
		rv = PTR_ERR(vlds_data.chrdev_class);
		dprintk("class_create() failed: %d\n", rv);
		vlds_data.chrdev_class = NULL;
		goto error;
	}

	/* set callback to create devices under /dev/ds directory */
	vlds_data.chrdev_class->devnode = vlds_devnode;

	/*
	 * Add a device for the SP directly since there is no
	 * vlds-port MD node for the SP and we need one to provide
	 * access to SP domain services.
	 */
	rv = vlds_alloc_vlds_dev(VLDS_SP_INT_NAME, VLDS_SP_DEV_NAME,
	    NULL, VLDS_INVALID_HANDLE, &sp_vlds);
	if (rv != 0)
		dprintk("Failed to create SP vlds device (%d)\n", rv);

	rv = vio_register_driver(&vlds_driver);
	if (rv != 0) {
		dprintk("vio_register_driver() failed: %d\n", rv);
		goto error;
	}

	return 0;

error:
	if (vlds_data.chrdev_class)
		class_destroy(vlds_data.chrdev_class);

	if (vlds_data.devt)
		unregister_chrdev_region(vlds_data.devt, VLDS_MAX_DEVS);

	return rv;
}

static void __exit vlds_exit(void)
{

	dprintk("entered.\n");

	/* remove the SP vlds */
	vlds_free_vlds_dev(sp_vlds);

	/*
	 * Note - vio_unregister_driver() will invoke a call to
	 * vlds_remove() for every successfully probed device.
	 */
	vio_unregister_driver(&vlds_driver);

	if (vlds_data.chrdev_class)
		class_destroy(vlds_data.chrdev_class);

	if (vlds_data.devt)
		unregister_chrdev_region(vlds_data.devt, VLDS_MAX_DEVS);
}

module_init(vlds_init);
module_exit(vlds_exit);

MODULE_AUTHOR("Oracle");
MODULE_DESCRIPTION("Sun4v LDOMs Virtual Domain Services Driver");
MODULE_LICENSE("GPL");
MODULE_VERSION(DRV_VERSION);
