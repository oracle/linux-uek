/*
 * vlds.c: Sun4v LDOMs Virtual Domain Services Driver
 *
 * Copyright (C) 2015, 2016 Oracle. All rights reserved.
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

#define	VLDS_SP_INT_NAME	DS_SP_NAME /* SP DS internal name */
#define VLDS_PATH_MAX		256

static char driver_version[] = DRV_NAME ".c:v" DRV_VERSION "\n";

#define dprintk(fmt, args...) do {\
if (vldsdbg_level > 0)\
	printk(KERN_ERR "%s: %s: " fmt, DRV_NAME, __func__, ##args);\
} while (0)

/* Global driver data struct for common data */
struct vlds_driver_data {
	struct list_head	vlds_dev_list; /* list of all vlds devices */
	int			num_vlds_dev_list;
	struct class		*chrdev_class;
	dev_t			devt;
};
struct vlds_driver_data vlds_data;
static DEFINE_MUTEX(vlds_data_mutex); /* protect vlds_data */

/* VLDS device */
struct vlds_dev {
	/* link into the global driver data dev list */
	struct list_head	list;

	struct mutex            vlds_mutex; /* protect this vlds_dev */
	struct cdev		cdev;
	dev_t			devt;
	char			*int_name; /* internal name for device */
	struct device		*device;
	u64			domain_handle;

	/* open reference count */
	u64			ref_cnt;

	/* flag to indicate that the device has been removed */
	bool			removed;

	/* list of all services for this vlds device */
	struct list_head	service_info_list;

	/* set as cdev parent kobject */
	struct kobject		kobj;
};

/* for convenience, alias to the vlds_dev for the SP device */
struct vlds_dev *sp_vlds;
#define	IS_SP_VLDS(vlds_dev)	((vlds_dev) == sp_vlds)

/* Control device to provide non-device specific operations */
struct vlds_dev *ctrl_vlds;
#define	IS_CTRL_VLDS(vlds_dev)	((vlds_dev) == ctrl_vlds)

/*
 * Service info to describe a service and process(es) using the service.
 * Services can be regsitered as shared (the default) or exclusive.
 * Exclusive services can only be registered by the initial
 * process which registers it. Multiple processes can
 * register a shared service.  Data received for a service in
 * shared mode will be multiplexed to all the processes that are registered
 * for the service. Therefore, processes could receive data messages which
 * are responses to requests from other processes. Therefore, processes using
 * shared services must be careful to only process messages intended for them
 * (by using/checking sequence numbers encoded in the message for example).
 */
struct vlds_service_info {
	/* link into the vlds_dev service info list */
	struct list_head	list;

	/* name/id of the service */
	char			*name;

	/* state of the service connection with ds */
	u64			state;

	/* client service (or provider) */
	bool			is_client;

	/* exclusive service? */
	bool			is_exclusive;

	/* unique handle assigned to this service */
	u64			handle;

	/* version that was registered */
	vlds_ver_t		reg_vers;

	/* version that was negotiated */
	vlds_ver_t		neg_vers;

	/* next service registration ID to use */
	u32			next_svc_reg_id;

	/* the list of processes (thread group ids) using this service */
	struct list_head	tgid_list;

};
#define VLDS_SVC_IS_CLIENT(svc) ((svc)->is_client)
#define VLDS_SVC_IS_EXCL(svc) ((svc)->is_exclusive)

struct vlds_tgid_info {
	/* link into the vlds_service_info tgid list */
	struct list_head	list;

	/* thread group id for associated process */
	pid_t			tgid;

	/* service reg ID assigned to this process/svc */
	u32			svc_reg_id;

	/* does the process expect events for this service? */
	bool			event_reg;

	/* Queue of received data messages for this service/process */
	struct list_head	msg_queue;

	/* number of messages on the queue - used to limit the # of messages */
	u64			msg_queue_size;
};
#define VLDS_MAX_MSG_LIST_NUM		32

struct vlds_msg_data {
	/* link into the vlds_tgid_info message queue */
	struct list_head	list;

	size_t			size;  /* message data size */
	u8			data[0]; /* message data */
};

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

	dprintk("entered\n");

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

	dprintk("entered\n");

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

static int vlds_signal_event(pid_t tgid, int fd)
{
	struct file *efd_file;
	struct eventfd_ctx *efd_ctx;
	struct task_struct *utask;
	struct pid *pid;

	/*
	 * Signal the process that there is an event pending
	 * This is tricky as it requires searching the task's
	 * file table for the entry corresponding to the event fd
	 * to get the event fd context.
	 */

	rcu_read_lock();

	/* Get the pid */
	pid = find_vpid(tgid);
	if (pid == NULL) {
		rcu_read_unlock();
		return -ESRCH;
	}

	/* Get the task struct */
	utask = pid_task(pid, PIDTYPE_PID);
	if (!utask || !utask->files) {
		rcu_read_unlock();
		return -EIO;
	}

	/* Get the file corresponding to fd */
	efd_file = fcheck_files(utask->files, fd);
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

	return 0;
}

/* vlds_dev_mutex must be held */
static void vlds_add_event_all(struct vlds_dev *vlds, u64 type)
{
	struct vlds_event_info *event_info;
	struct vlds_event_info *nxt;
	struct vlds_event *event;
	int rv;

	mutex_lock(&vlds_event_info_list_mutex);

	list_for_each_entry_safe(event_info, nxt, &vlds_event_info_list, list) {

		event = kzalloc(sizeof(struct vlds_event), GFP_KERNEL);
		if (unlikely(event == NULL)) {
			dprintk("failed to allocate event %llu for tgid=%u\n",
			    type, event_info->tgid);
		} else {
			event->type = type;
			list_add_tail(&event->list,
			    &event_info->event_list);
		}

		rv = vlds_signal_event(event_info->tgid, event_info->fd);
		if (rv) {
			/* just give an error if we failed to add the event */
			pr_err("%s: Failed to create %llu event for tgid=%u\n",
			    vlds->int_name, type, event_info->tgid);

			/*
			 * If the event failed to signal because the
			 * process no longer exists, we will prune the
			 * stale event_info from the list. This can happen
			 * if a process registers an eventfd but fails to
			 * unregister it before exiting.
			 */
			if (rv == -ESRCH) {
				pr_err("%s: Removing stale event_info for "
				       "tgid=%u\n", vlds->int_name,
				       event_info->tgid);
				vlds_remove_event_info(event_info->tgid);
			}
		}
	}

	mutex_unlock(&vlds_event_info_list_mutex);
}

static void vlds_add_svc_event(struct vlds_dev *vlds, pid_t tgid,
			       struct vlds_service_info *svc_info, u64 type,
			       vlds_ver_t *neg_vers)
{
	struct vlds_event_info *event_info;
	struct vlds_event *event;
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
		return;
	}

	event = kzalloc(sizeof(struct vlds_event), GFP_KERNEL);
	if (unlikely(event == NULL)) {
		if (svc_info)
			dprintk("failed to allocate event for "
			    "service %llx\n", svc_info->handle);
		mutex_unlock(&vlds_event_info_list_mutex);
		return;
	}

	event->type = type;
	event->svc_info = svc_info;
	if (neg_vers != NULL)
		event->neg_vers = *neg_vers;

	list_add_tail(&event->list,
	    &event_info->event_list);

	rv = vlds_signal_event(tgid, event_info->fd);
	if (rv) {
		/* just give an error if we failed to add the event */
		pr_err("%s: Failed to create event (type = %llu) for tgid=%u\n",
		    vlds->int_name, type, tgid);

		/*
		 * If the event failed to signal because the
		 * process no longer exists, we will prune the
		 * stale event_info from the list. This can happen
		 * if a process registers an eventfd but fails to
		 * unregister it before exiting.
		 */
		if (rv == -ESRCH) {
			pr_err("%s: Removing stale event_info for "
			       "tgid=%u\n", vlds->int_name, tgid);
			vlds_remove_event_info(tgid);
		}
	}

	mutex_unlock(&vlds_event_info_list_mutex);

}

/* vlds_dev_mutex must be held */
static void vlds_add_event_svc_all(struct vlds_dev *vlds,
	struct vlds_service_info *svc_info, u64 type, vlds_ver_t *neg_vers)
{
	struct vlds_tgid_info *tgid_info;

	list_for_each_entry(tgid_info, &svc_info->tgid_list, list) {

		/* Only add an event if it's an event registration */
		if (!tgid_info->event_reg)
			continue;

		vlds_add_svc_event(vlds, tgid_info->tgid, svc_info,
		    type, neg_vers);
	}
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

/* remove all events for a tgid/service */
static void vlds_remove_svc_events_tgid(struct vlds_service_info *svc_info,
	struct vlds_tgid_info *tgid_info)
{
	struct vlds_event_info *event_info;
	struct vlds_event *event;
	struct vlds_event *next;
	int rv;

	if (!tgid_info->event_reg)
		return;

	mutex_lock(&vlds_event_info_list_mutex);

	event_info = NULL;
	rv = vlds_get_event_info(tgid_info->tgid, &event_info);
	if (rv == 0 && event_info != NULL) {
		list_for_each_entry_safe(event, next, &event_info->event_list,
		    list) {
			if (event->svc_info && event->svc_info == svc_info)
				vlds_remove_event(event_info, event);
		}
	}

	mutex_unlock(&vlds_event_info_list_mutex);
}

/* vlds_dev_mutex must be held */
static void vlds_free_msg_queue(struct vlds_tgid_info *tgid_info)
{
	struct vlds_msg_data *msg_data;
	struct vlds_msg_data *next;

	list_for_each_entry_safe(msg_data, next, &tgid_info->msg_queue,
	    list) {

		list_del(&msg_data->list);

		kfree(msg_data);

		tgid_info->msg_queue_size--;
	}
}


/* vlds_dev_mutex must be held */
static struct vlds_tgid_info *vlds_get_tgid_info(
	struct vlds_service_info *svc_info, pid_t tgid)
{
	struct vlds_tgid_info *tgid_info;

	list_for_each_entry(tgid_info, &svc_info->tgid_list, list)
		if (tgid_info->tgid == tgid)
			return tgid_info;

	return NULL;
}

/* vlds_dev_mutex must be held */
static int vlds_get_primary_tgid(struct vlds_service_info *svc_info,
	pid_t *tgid)
{
	struct vlds_tgid_info *tgid_info;

	tgid_info = list_first_entry(&svc_info->tgid_list,
	    struct vlds_tgid_info, list);

	if (tgid_info == NULL)
		return -ENODEV;

	*tgid = tgid_info->tgid;

	return 0;
}

/* vlds_dev_mutex must be held */
static int vlds_add_tgid_info(struct vlds_service_info *svc_info,
	pid_t tgid, bool event_reg, struct vlds_tgid_info **tgid_info)
{
	struct vlds_tgid_info *new_tgid_info;

	new_tgid_info = kzalloc(sizeof(struct vlds_tgid_info), GFP_KERNEL);
	if (unlikely(new_tgid_info == NULL))
		return -ENOMEM;

	new_tgid_info->tgid = tgid;
	new_tgid_info->svc_reg_id = svc_info->next_svc_reg_id++;
	new_tgid_info->event_reg = event_reg;
	INIT_LIST_HEAD(&new_tgid_info->msg_queue);
	new_tgid_info->msg_queue_size = 0;

	list_add_tail(&new_tgid_info->list, &svc_info->tgid_list);

	*tgid_info = new_tgid_info;

	return 0;

}

/* vlds_dev_mutex must be held */
static void vlds_remove_tgid_info(struct vlds_tgid_info *tgid_info)
{
	/* remove all the messages queued on this tgid_info */
	vlds_free_msg_queue(tgid_info);

	list_del(&tgid_info->list);

	kfree(tgid_info);
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

static void vlds_remove_svc_info(struct vlds_service_info *svc_info)
{
	list_del(&svc_info->list);
	kfree(svc_info->name);
	kfree(svc_info);
}

static int vlds_add_msg(struct vlds_tgid_info *tgid_info,
	void *buf, size_t buflen)
{
	struct vlds_msg_data *msg_data;

	/* check if we've reached the max num of queued messages */
	if (tgid_info->msg_queue_size > VLDS_MAX_MSG_LIST_NUM)
		return -ENOSPC;

	/* make sure the message size isn't too large */
	if (buflen > VLDS_MAX_SENDBUF_LEN)
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
	list_add_tail(&msg_data->list, &tgid_info->msg_queue);

	tgid_info->msg_queue_size++;

	return 0;
}

/* vlds_dev_mutex must be held */
static void vlds_add_msg_all(struct vlds_dev *vlds,
	struct vlds_service_info *svc_info, void *buf, size_t buflen)
{
	struct vlds_tgid_info *tgid_info;
	int rv;

	list_for_each_entry(tgid_info, &svc_info->tgid_list, list) {

		rv = vlds_add_msg(tgid_info, buf, buflen);
		if (rv) {
			if (rv == -ENOSPC)
				dprintk("%s: service %s: message queue "
				    "overflow! (tgid=%u)\n", vlds->int_name,
				    svc_info->name, tgid_info->tgid);
			else if (rv == -EFBIG)
				dprintk("%s: service %s: message too large "
				    "(%lu bytes)! (tgid=%u)\n",
				    vlds->int_name, svc_info->name, buflen,
				    tgid_info->tgid);
			else
				dprintk("%s: service %s: failed to add message "
				    "(err = %d)! (tgid=%u)\n", vlds->int_name,
				    svc_info->name, rv, tgid_info->tgid);
		}
	}
}

/*
 * Get a message (data and size) from a service/tgid message queue.
 * NOTE: the message remains on the queue.
 */
static struct vlds_msg_data *vlds_get_msg(struct vlds_service_info *svc_info,
	pid_t tgid)
{
	struct vlds_tgid_info *tgid_info;
	struct vlds_msg_data *msg_data;
	bool found;

	/* find the tgid_info associated with the process */
	found = false;
	list_for_each_entry(tgid_info, &svc_info->tgid_list, list) {
		if (tgid_info->tgid == tgid) {
			found = true;
			break;
		}
	}

	if (!found)
		return NULL;

	if (list_empty(&tgid_info->msg_queue))
		return NULL;

	msg_data = list_first_entry(&tgid_info->msg_queue, struct vlds_msg_data,
	    list);

	BUG_ON(msg_data == NULL);

	return msg_data;
}

/* Dequeue a message from a service/tgid message queue. */
static void vlds_dequeue_msg(struct vlds_service_info *svc_info,
	pid_t tgid, struct vlds_msg_data *msg_data)
{
	struct vlds_tgid_info *tgid_info;
	bool found;

	if (msg_data == NULL)
		return;

	/* find the tgid_info associated with the process */
	found = false;
	list_for_each_entry(tgid_info, &svc_info->tgid_list, list) {
		if (tgid_info->tgid == tgid) {
			found = true;
			break;
		}
	}

	if (!found)
		return;

	if (list_empty(&tgid_info->msg_queue))
		return;

	/* Check here that the message is actually on the queue? TBD */

	list_del(&msg_data->list);

	kfree(msg_data);

	tgid_info->msg_queue_size--;
}

/*
 * Service callback ops
 */
static void
vlds_ds_reg_cb(ds_cb_arg_t arg, ds_svc_hdl_t hdl, ds_ver_t *ver)
{
	struct vlds_dev *vlds;
	struct vlds_service_info *svc_info;

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
	 * For every process that has registered this service
	 * in EVENT mode, register an event.
	 */
	vlds_add_event_svc_all(vlds, svc_info, VLDS_EVENT_TYPE_REG,
	    &svc_info->neg_vers);

	dprintk("%s: service %s register version (%u.%u) hdl=%llx\n",
	    vlds->int_name, svc_info->name, svc_info->neg_vers.vlds_major,
	    svc_info->neg_vers.vlds_minor, hdl);

	mutex_unlock(&vlds->vlds_mutex);
}

static void
vlds_ds_unreg_cb(ds_cb_arg_t arg, ds_svc_hdl_t hdl)
{
	struct vlds_dev *vlds;
	struct vlds_service_info *svc_info;

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
	 * For every process that has registered this service
	 * in EVENT mode, register an event.
	 */
	vlds_add_event_svc_all(vlds, svc_info, VLDS_EVENT_TYPE_UNREG, NULL);

	dprintk("%s: service %s unregister hdl=%llx\n",
	    vlds->int_name, svc_info->name, hdl);

	mutex_unlock(&vlds->vlds_mutex);
}

static void
vlds_ds_data_cb(ds_cb_arg_t arg, ds_svc_hdl_t hdl, void *buf, size_t buflen)
{
	struct vlds_dev *vlds;
	struct vlds_service_info *svc_info;

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

	/*
	 * For every process that has registered this service
	 * populate the message into the msg queue.
	 * NOTE - received data is assumed to be 1 complete message.
	 * No partial message support.
	 */
	vlds_add_msg_all(vlds, svc_info, buf, buflen);

	/*
	 * For every process that has registered this service
	 * in EVENT mode, register an event.
	 */
	vlds_add_event_svc_all(vlds, svc_info, VLDS_EVENT_TYPE_DATA, NULL);

	dprintk("%s: service %s: Received %lu bytes hdl=%llx\n",
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
	char svc_str[VLDS_MAX_NAMELEN + 1];
	bool is_client_reg;
	bool is_excl_reg;
	bool is_event_reg;
	ds_capability_t dscap;
	u32 flags;
	ds_svc_hdl_t ds_hdl;
	pid_t tgid;
	struct vlds_service_info *svc_info;
	struct vlds_tgid_info *tgid_info;
	int rv;

	dprintk("entered.\n");

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

	/* If present, validate svc reg id */
	if (svc_reg.vlds_svc_reg_idp) {
		if (!access_ok(VERIFY_WRITE,
		    (void __user *)svc_reg.vlds_svc_reg_idp, sizeof(u32))) {
			rv = -EFAULT;
			goto error_out1;
		}
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
	if (copy_from_user(svc_str,
	    (const void __user *)cap.vlds_service.vlds_strp,
	    cap.vlds_service.vlds_strlen) != 0) {
		rv = -EFAULT;
		goto error_out1;
	}
	svc_str[cap.vlds_service.vlds_strlen] = '\0';

	is_client_reg = (svc_reg.vlds_reg_flags & VLDS_REG_CLIENT);
	is_excl_reg = (svc_reg.vlds_reg_flags & VLDS_REG_EXCLUSIVE);
	is_event_reg = (svc_reg.vlds_reg_flags & VLDS_REG_EVENT);
	tgid = task_tgid_vnr(current);

	mutex_lock(&vlds->vlds_mutex);

	/* Check if the service is already registered */
	svc_info = vlds_get_svc_info(vlds, svc_str, is_client_reg);
	if (svc_info != NULL) {

		/* make sure this process didn't already register it */
		if (vlds_get_tgid_info(svc_info, tgid)) {
			rv = -EBUSY;
			svc_info = NULL;
			goto error_out2;
		}

		/*
		 * Enforce exclusive registration here:
		 * Another process has already registered this service.
		 * If this process is attempting to register it exclusive
		 * or the service is already registered exclusive, deny
		 * the request.
		 */
		if (is_excl_reg || VLDS_SVC_IS_EXCL(svc_info)) {
			rv = -EBUSY;
			svc_info = NULL;
			goto error_out2;
		}

		/*
		 * Make sure the registration versions match.
		 * i.e. cannot register shared service with different
		 * versions.
		 */
		if (svc_info->reg_vers.vlds_major !=
		    cap.vlds_vers.vlds_major || svc_info->reg_vers.vlds_minor !=
		    cap.vlds_vers.vlds_minor) {
			rv = -EINVAL;
			svc_info = NULL;
			goto error_out2;
		}

		/* populate the service handle to the user */
		if (put_user(svc_info->handle,
		    (u64 __user *)(svc_reg.vlds_hdlp)) != 0) {
			rv = -EFAULT;
			svc_info = NULL;
			goto error_out2;
		}

		/*
		 * The service is already registered in shared mode,
		 * just add another tgid to the service.
		 */
		rv = vlds_add_tgid_info(svc_info, tgid, is_event_reg,
		    &tgid_info);
		if (unlikely(rv != 0)) {
			svc_info = NULL;
			goto error_out2;
		}

		/* Populate (optional) svc reg ID to the user */
		if (svc_reg.vlds_svc_reg_idp) {
			if (put_user(tgid_info->svc_reg_id,
			    (u32 __user *)(svc_reg.vlds_svc_reg_idp)) != 0) {
				vlds_remove_tgid_info(tgid_info);
				rv = -EFAULT;
				svc_info = NULL;
				goto error_out2;
			}
		}

		/*
		 * If it's an event based registration and the service has
		 * already been connected/registered with ds, enqueue a reg
		 * event for the process - since it will probably expect one.
		 */
		if (is_event_reg &&
		    svc_info->state == VLDS_HDL_STATE_CONNECTED)
			vlds_add_svc_event(vlds, tgid, svc_info,
			    VLDS_EVENT_TYPE_REG, &svc_info->neg_vers);

		dprintk("%s: registered tgid %u with service %s (client = %u) "
		    "(hdl = %llx)\n", vlds->int_name, tgid, svc_str,
		    VLDS_SVC_IS_CLIENT(svc_info), svc_info->handle);

		mutex_unlock(&vlds->vlds_mutex);

		return 0;
	}

	/*
	 * This is a new service registration.
	 */

	/* init the ds capability structure */
	dscap.svc_id = svc_str;
	dscap.vers.major = (u64)cap.vlds_vers.vlds_major;
	dscap.vers.minor = (u64)cap.vlds_vers.vlds_minor;

	/* The vlds_dev will be passed back as an arg to the callbacks */
	vlds_ds_ops.cb_arg = (void *)vlds;

	flags = 0x0;
	if (is_client_reg)
		flags |= DS_CAP_IS_CLIENT;
	else
		flags |= DS_CAP_IS_PROVIDER;

	ds_hdl = 0;
	rv = ds_cap_init(&dscap, &vlds_ds_ops, flags, vlds->domain_handle,
	    &ds_hdl);
	if (rv || ds_hdl == 0) {
		dprintk("%s: ds_cap_init failed for service %s\n",
		    vlds->int_name, svc_str);
		goto error_out2;
	}

	if (put_user(ds_hdl, (u64 __user *)(svc_reg.vlds_hdlp)) != 0) {
		(void) ds_cap_fini(ds_hdl);
		rv = -EFAULT;
		goto error_out2;
	}

	/* create a service info for the new service */
	svc_info = kzalloc(sizeof(struct vlds_service_info), GFP_KERNEL);
	if (unlikely(svc_info == NULL)) {
		(void) ds_cap_fini(ds_hdl);
		rv = -ENOMEM;
		goto error_out2;
	}

	svc_info->name = kmemdup(svc_str, (strlen(svc_str) + 1), GFP_KERNEL);
	if (unlikely(svc_info->name == NULL)) {
		(void) ds_cap_fini(ds_hdl);
		rv = -ENOMEM;
		goto error_out2;
	}
	svc_info->state = VLDS_HDL_STATE_NOT_YET_CONNECTED;
	svc_info->is_client = is_client_reg;
	svc_info->is_exclusive = is_excl_reg;
	svc_info->next_svc_reg_id = 1;  /* start at 1 */
	INIT_LIST_HEAD(&svc_info->tgid_list);
	svc_info->handle = (u64)ds_hdl;
	svc_info->reg_vers = cap.vlds_vers;

	rv = vlds_add_tgid_info(svc_info, tgid, is_event_reg,
	    &tgid_info);
	if (unlikely(rv != 0)) {
		(void) ds_cap_fini(ds_hdl);
		goto error_out2;
	}

	/* Populate (optional) svc reg ID to the user */
	if (svc_reg.vlds_svc_reg_idp) {
		if (put_user(tgid_info->svc_reg_id,
		    (u32 __user *)(svc_reg.vlds_svc_reg_idp)) != 0) {
			vlds_remove_tgid_info(tgid_info);
			rv = -EFAULT;
			goto error_out2;
		}
	}

	/* add the service_info to the vlds device */
	list_add_tail(&svc_info->list, &vlds->service_info_list);

	dprintk("%s: registered new service %s (client = %u) "
	    "(hdl = %llx) (tgid = %u)\n", vlds->int_name, svc_str,
	    VLDS_SVC_IS_CLIENT(svc_info), svc_info->handle, tgid);

	mutex_unlock(&vlds->vlds_mutex);

	return 0;

error_out2:

	mutex_unlock(&vlds->vlds_mutex);

error_out1:

	dprintk("Failed to register service rv = %d\n", rv);

	if (svc_info)
		kfree(svc_info);

	return rv;
}

static int vlds_unreg_hdl(struct vlds_dev *vlds, const void __user *uarg)
{
	vlds_unreg_hdl_arg_t unreg;
	struct vlds_service_info *svc_info;
	struct vlds_tgid_info *tgid_info;
	pid_t tgid;
	int rv;

	dprintk("entered.\n");

	/* Get (and validate) userland args */
	if (uarg == NULL || copy_from_user(&unreg, uarg,
	    sizeof(vlds_unreg_hdl_arg_t)) != 0) {
		rv = -EFAULT;
		goto error_out1;
	}

	tgid = task_tgid_vnr(current);

	mutex_lock(&vlds->vlds_mutex);

	svc_info = vlds_get_svc_info_hdl(vlds, unreg.vlds_hdl);
	if (svc_info == NULL) {
		rv = -ENODEV;
		goto error_out2;
	}

	tgid_info = vlds_get_tgid_info(svc_info, tgid);
	if (tgid_info == NULL) {
		/* This process doesn't have the service registered */
		rv = -ENODEV;
		goto error_out2;
	}

	/*
	 * There may be more than one process that has the
	 * service registered. So, remove the tgid_info for this
	 * process (which is unregistering the hdl) and if the
	 * number of processes using the service goes to zero,
	 * then unregister the service with ds and remove the
	 * service_info entirely.
	 */
	vlds_remove_svc_events_tgid(svc_info, tgid_info);
	vlds_remove_tgid_info(tgid_info);

	if (!list_empty(&svc_info->tgid_list)) {

		/* there are still other process(es) using the service */
		dprintk("%s: unregistered tgid %u from service %s "
		    "(client = %u) (hdl = %llx)\n", vlds->int_name, tgid,
		    svc_info->name, VLDS_SVC_IS_CLIENT(svc_info),
		    unreg.vlds_hdl);

		mutex_unlock(&vlds->vlds_mutex);

		return 0;
	}

	/* this was the last process using the service */

	/*
	 * Unregister the service from ds.
	 * NOTE - once we call ds_cap_fini(), we should NOT get
	 * any more callbacks for the service (including an unreg
	 * event)!
	 */
	rv = ds_cap_fini(unreg.vlds_hdl);
	if (rv) {
		dprintk("%s: ds_cap_fini failed for service %s\n",
		    vlds->int_name, svc_info->name);
		goto error_out2;
	}

	dprintk("%s: unregistered service %s (client = %u) "
	    "(hdl = %llx)\n", vlds->int_name, svc_info->name,
	    VLDS_SVC_IS_CLIENT(svc_info), unreg.vlds_hdl);

	vlds_remove_svc_info(svc_info);

	mutex_unlock(&vlds->vlds_mutex);

	return 0;

error_out2:

	mutex_unlock(&vlds->vlds_mutex);

error_out1:

	dprintk("Failed to unregister service rv = %d\n", rv);

	return rv;
}

static int vlds_hdl_lookup(struct vlds_dev *vlds, const void __user *uarg)
{
	vlds_hdl_lookup_arg_t hdl_lookup;
	struct vlds_service_info *svc_info;
	char svc_str[VLDS_MAX_NAMELEN + 1];
	u64 num_hdls;
	pid_t tgid;
	int rv;

	dprintk("entered.\n");

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

	/* make sure the service strlen is sane */
	if (hdl_lookup.vlds_service.vlds_strlen == 0 ||
	    hdl_lookup.vlds_service.vlds_strlen > VLDS_MAX_NAMELEN) {
		rv = -EINVAL;
		goto error_out1;
	}

	/* get the service string from userland */
	if (copy_from_user(svc_str,
	    (const void __user *)hdl_lookup.vlds_service.vlds_strp,
	    hdl_lookup.vlds_service.vlds_strlen) != 0) {
		rv = -EFAULT;
		goto error_out1;
	}

	tgid = task_tgid_vnr(current);

	mutex_lock(&vlds->vlds_mutex);

	svc_info = vlds_get_svc_info(vlds, svc_str, hdl_lookup.vlds_isclient);
	if (svc_info == NULL) {
		rv = -ENODEV;
		goto error_out2;
	}

	if (!vlds_get_tgid_info(svc_info, tgid)) {
		/* This process doesn't have the service registered */
		rv = -ENODEV;
		goto error_out2;
	}

	if (put_user(svc_info->handle,
	    (u64 __user *)(hdl_lookup.vlds_hdlsp)) != 0) {
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

	dprintk("Failed to lookup handle rv = %d\n", rv);

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

	mutex_lock(&vlds->vlds_mutex);

	/* make sure the string buffer size is sane */
	if (dmn_lookup.vlds_dname.vlds_strlen < (strlen(vlds->int_name) + 1)) {
		rv = -EINVAL;
		goto error_out2;
	}

	if (put_user(vlds->domain_handle,
	    (u64 __user *)(dmn_lookup.vlds_dhdlp)) != 0) {
		rv = -EFAULT;
		goto error_out2;
	}

	if (copy_to_user((void __user *)(dmn_lookup.vlds_dname.vlds_strp),
	    vlds->int_name, (strlen(vlds->int_name) + 1)) != 0) {
		rv = -EFAULT;
		goto error_out2;
	}

	mutex_unlock(&vlds->vlds_mutex);

	return 0;

error_out2:

	mutex_unlock(&vlds->vlds_mutex);

error_out1:

	dprintk("Failed to lookup domain info. rv = %d\n", rv);

	return rv;
}

static int vlds_hdl_get_state(struct vlds_dev *vlds, const void __user *uarg)
{
	vlds_hdl_get_state_arg_t hdl_get_state;
	struct vlds_service_info *svc_info;
	vlds_hdl_state_t hdl_state;
	pid_t tgid;
	int rv;

	/* Get (and validate) userland args */
	if (uarg == NULL || copy_from_user(&hdl_get_state, uarg,
	    sizeof(vlds_hdl_get_state_arg_t)) != 0) {
		rv = -EFAULT;
		goto error_out1;
	}

	tgid = task_tgid_vnr(current);

	mutex_lock(&vlds->vlds_mutex);

	svc_info = vlds_get_svc_info_hdl(vlds, hdl_get_state.vlds_hdl);
	if (svc_info == NULL) {
		rv = -ENODEV;
		goto error_out2;
	}

	if (!vlds_get_tgid_info(svc_info, tgid)) {
		/* This process doesn't have the service registered */
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

	dprintk("Failed to get handle state rv = %d\n", rv);

	return rv;

}

static int vlds_send_msg(struct vlds_dev *vlds, const void __user *uarg)
{
	vlds_send_msg_arg_t send_msg;
	struct vlds_service_info *svc_info;
	u8 *send_buf;
	pid_t tgid;
	pid_t primary_tgid;
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

	tgid = task_tgid_vnr(current);

	mutex_lock(&vlds->vlds_mutex);

	svc_info = vlds_get_svc_info_hdl(vlds, send_msg.vlds_hdl);
	if (svc_info == NULL) {
		rv = -ENODEV;
		goto error_out2;
	}

	/* make sure this process has the service registered */
	if (!vlds_get_tgid_info(svc_info, tgid)) {
		rv = -ENODEV;
		goto error_out2;
	}

	/* make sure we are in connected state before sending the data */
	if (svc_info->state != VLDS_HDL_STATE_CONNECTED) {
		rv = -EIO;
		goto error_out2;
	}

	/*
	 * The SP DS does not handle multiple outstanding messages
	 * in the LDC tx queue. So, as a workaround, we only allow
	 * the primary process (i.e. the process which first registered
	 * the service) to send messages. Non-primary proceses are in
	 * "read-only" mode - i.e. they can receive messages only. This
	 * is basically a workaround for libpri and prevents the situation
	 * where multiple processes are using libpri and attempt to
	 * send a PRI request message at the same time. We return a -EPERM
	 * to read-only processes - which libpri knows how to handle.
	 */
	if (IS_SP_VLDS(vlds)) {

		rv = vlds_get_primary_tgid(svc_info, &primary_tgid);

		if (rv != 0 || primary_tgid != tgid) {
			rv = -EPERM;
			goto error_out2;
		}
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
		dprintk("%s: ds_cap_send failed for service %s (rv=%d)\n",
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

	dprintk("Failed to send msg rv = %d\n", rv);

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
	pid_t tgid;
	struct vlds_msg_data *msg_data;
	int rv;

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

	tgid = task_tgid_vnr(current);

	mutex_lock(&vlds->vlds_mutex);

	svc_info = vlds_get_svc_info_hdl(vlds, recv_msg.vlds_hdl);
	if (svc_info == NULL) {
		rv = -ENODEV;
		goto error_out2;
	}

	/* make sure this process has the service registered */
	if (!vlds_get_tgid_info(svc_info, tgid)) {
		rv = -ENODEV;
		goto error_out2;
	}

	msg_data =  vlds_get_msg(svc_info, tgid);
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
		vlds_dequeue_msg(svc_info, tgid, msg_data);

		dprintk("%s: recv msg hdl = %llx (len=%lu) SUCCESS\n",
		    vlds->int_name, recv_msg.vlds_hdl, msglen);
	}

	mutex_unlock(&vlds->vlds_mutex);

	return 0;

error_out2:

	mutex_unlock(&vlds->vlds_mutex);

error_out1:

	dprintk("Failed to recv msg rv = %d\n", rv);

	return rv;
}

static int vlds_set_event_fd(struct vlds_dev *vlds, const void __user *uarg)
{
	vlds_set_event_fd_arg_t set_event_fd;
	int rv;
	pid_t tgid;

	dprintk("entered.\n");

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

	return 0;

error_out1:

	dprintk("Failed to set event fd: rv = %d\n", rv);

	return rv;
}

static int vlds_unset_event_fd(struct vlds_dev *vlds, const void __user *uarg)
{
	pid_t tgid;

	dprintk("entered.\n");

	tgid = task_tgid_vnr(current);

	mutex_lock(&vlds_event_info_list_mutex);

	vlds_remove_event_info(tgid);

	mutex_unlock(&vlds_event_info_list_mutex);

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
	pid_t tgid;
	int rv;

	dprintk("entered\n");

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

	tgid = task_tgid_vnr(current);

	mutex_lock(&vlds->vlds_mutex);

	mutex_lock(&vlds_event_info_list_mutex);

	event_info = NULL;
	rv = vlds_get_event_info(tgid, &event_info);
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
	if (event->svc_info) {
		if (put_user(event->svc_info->handle,
		    (u64 __user *)(next_event.vlds_hdlp)) != 0) {
			rv = -EFAULT;
			goto error_out2;
		}
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
	 * with next queued message from the service
	 */
	if (event->type == VLDS_EVENT_TYPE_DATA) {
		msg_data =  vlds_get_msg(event->svc_info, tgid);
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
		vlds_dequeue_msg(event->svc_info, tgid, msg_data);
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
		dprintk("Failed to get next event: rv = %d\n", rv);

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

	if (vlds == NULL)
		return -ENXIO;

	mutex_lock(&vlds->vlds_mutex);

	if (vlds->removed) {
		mutex_unlock(&vlds->vlds_mutex);
		return -ENXIO;
	}

	vlds->ref_cnt++;

	/* tuck away the vlds_dev for other fops to use */
	filp->private_data = vlds;

	mutex_unlock(&vlds->vlds_mutex);

	return 0;
}

/* vlds_dev mutex must be held here! */
static void vlds_unreg_all(struct vlds_dev *vlds)
{

	struct vlds_service_info *svc_info;
	struct vlds_service_info *next;
	struct vlds_tgid_info *tgid_info;
	struct vlds_tgid_info *tgid_next;

	if (vlds == NULL)
		return;

	list_for_each_entry_safe(svc_info, next, &vlds->service_info_list,
	    list) {

		list_for_each_entry_safe(tgid_info, tgid_next,
		    &svc_info->tgid_list, list) {

			vlds_remove_svc_events_tgid(svc_info, tgid_info);
			vlds_remove_tgid_info(tgid_info);

		}

		/*
		 * Unregister the service from ds.
		 * NOTE - once we call ds_cap_fini(), we should NOT get
		 * any more callbacks for the service (including an unreg
		 * event)!
		 */
		(void) ds_cap_fini(svc_info->handle);

		dprintk("%s: unregistered service %s (client = %u) "
		    "(hdl = %llx)\n", vlds->int_name,
		    svc_info->name, VLDS_SVC_IS_CLIENT(svc_info),
		    svc_info->handle);

		vlds_remove_svc_info(svc_info);
	}

}

/* vlds_dev mutex must be held! */
static void vlds_unreg_all_tgid(struct vlds_dev *vlds, pid_t tgid)
{

	struct vlds_service_info *svc_info;
	struct vlds_service_info *next;
	struct vlds_tgid_info *tgid_info;
	struct vlds_tgid_info *tgid_next;

	list_for_each_entry_safe(svc_info, next, &vlds->service_info_list,
	    list) {

		/*
		 * Check if the tgid is registered for this service and if
		 * so, remove the tgid from the list. The the tgid list becomes
		 * empty, it was the last process using the service, so remove
		 * the service.
		 */
		list_for_each_entry_safe(tgid_info, tgid_next,
		    &svc_info->tgid_list, list) {

			if (tgid_info->tgid != tgid)
				continue;

			vlds_remove_svc_events_tgid(svc_info, tgid_info);
			vlds_remove_tgid_info(tgid_info);
		}

		/* If no more processes using the service, remove it */
		if (list_empty(&svc_info->tgid_list)) {

			(void) ds_cap_fini(svc_info->handle);

			dprintk("%s: unregistered service %s "
			    "(client = %u) (hdl = %llx)\n",
			    vlds->int_name, svc_info->name,
			    VLDS_SVC_IS_CLIENT(svc_info),
			    svc_info->handle);

			vlds_remove_svc_info(svc_info);
		}
	}

}

/* data_mutex and vlds_dev mutex must be held here! */
static void vlds_free_vlds_dev(struct vlds_dev *vlds)
{
	if (vlds == NULL)
		return;

	pr_info("Removing (%s)\n", vlds->int_name);

	/*
	 * Unregister all the services associated with this vlds.
	 * NOTE - once we call ds_cap_fini() out of vlds_unreg_all,
	 * we should NOT get any more callbacks for the services
	 * (including an unreg event) - which is required since
	 * the vlds_dev is the callback arg and we are about to
	 * free it below!
	 */
	vlds_unreg_all(vlds);

	/* remove vlds_dev from the global list */
	list_del(&vlds->list);
	vlds_data.num_vlds_dev_list--;

	/* free memory when kobject's reference count is 0 */
	mutex_destroy(&vlds->vlds_mutex);
	kobject_put(&vlds->kobj);

	return;
}

static int vlds_fops_release(struct inode *inode, struct file *filp)
{
	struct vlds_dev *vlds;
	pid_t tgid;

	dprintk("entered.\n");

	if (filp == NULL)
		return -EINVAL;

	vlds = filp->private_data;

	if (vlds == NULL)
		return -ENXIO;

	tgid = task_tgid_vnr(current);

	/*
	 * Since we may have to remove the vlds_dev
	 * if this is the last release/close, we need
	 * to lock down the vlds_data and the vlds_dev.
	 */
	mutex_lock(&vlds_data_mutex);

	mutex_lock(&vlds->vlds_mutex);

	dprintk("%s: unregistering all events and services for tgid = %u\n",
	    vlds->int_name, tgid);

	/*
	 * Unreg all services used by this process on this vlds_dev.
	 * Also, remove any events queued for these services.
	 */
	vlds_unreg_all_tgid(vlds, tgid);

	vlds->ref_cnt--;

	/*
	 * If this is the last reference to the removed
	 * vlds device, remove the vlds_dev completely.
	 */
	if (vlds->removed && vlds->ref_cnt == 0) {
		vlds_free_vlds_dev(vlds);
		/* vlds is freed at this point. Don't access it! */
	} else {
		mutex_unlock(&vlds->vlds_mutex);
	}

	mutex_unlock(&vlds_data_mutex);

	return 0;
}

static long vlds_fops_ioctl(struct file *filp, unsigned int cmd,
			    unsigned long arg)
{
	struct vlds_dev *vlds;
	int rv;

	rv = 0;

	vlds = filp->private_data;

	if (vlds == NULL)
		return -ENXIO;

	mutex_lock(&vlds->vlds_mutex);

	if (vlds->removed) {
		mutex_unlock(&vlds->vlds_mutex);
		return -ENXIO;
	}

	if (IS_CTRL_VLDS(vlds)) {
		/*
		 * For the control device,
		 * we only allow the following operations.
		 */
		if (cmd != VLDS_IOCTL_SET_EVENT_FD &&
		    cmd != VLDS_IOCTL_UNSET_EVENT_FD &&
		    cmd != VLDS_IOCTL_GET_NEXT_EVENT) {
			mutex_unlock(&vlds->vlds_mutex);
			return -EINVAL;
		}
	}

	mutex_unlock(&vlds->vlds_mutex);

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

/*
 * Return whether there is a SP DS port present in the MD.
 * A domain-services-port MD node with a ldc-ids property indicates
 * the presence of a SP DS.
 */
static bool vlds_sp_ds_present(void)
{
	struct mdesc_handle *hp;
	u64 node;
	const u64 *val;
	bool sp_present;

	hp = mdesc_grab();

	sp_present = false;
	mdesc_for_each_node_by_name(hp, node, "domain-services-port") {
		val = mdesc_get_property(hp, node, "ldc-ids", NULL);
		if (val != NULL) {
			sp_present = true;
			break;
		}
	}

	mdesc_release(hp);

	return sp_present;
}

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

static void vlds_free_kobject(struct kobject *kobj)
{
	struct vlds_dev *vlds =
		container_of(kobj, struct vlds_dev, kobj);

	dprintk("Deallocating (%s)\n", vlds->int_name);
	kfree(vlds->int_name);
	kfree(vlds);
}

static struct kobj_type vlds_ktype = {
	.release = vlds_free_kobject,
};

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

	vlds->ref_cnt = 0;
	vlds->removed = false;

	/* setup kobj to free vlds, it will be the parent of cdev */
	kobject_init(&vlds->kobj, &vlds_ktype);

	/* create/add the associated cdev */
	cdev_init(&vlds->cdev, &vlds_fops);
	vlds->cdev.owner = THIS_MODULE;
	vlds->cdev.kobj.parent = &vlds->kobj;
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

	if (vlds != NULL) {
		kfree(vlds->int_name);
		mutex_destroy(&vlds->vlds_mutex);
		if (vlds->kobj.state_initialized)
			kobject_put(&vlds->kobj);
		else
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

	mutex_lock(&vlds->vlds_mutex);
	/* Register a device update event */
	vlds_add_event_all(vlds, VLDS_EVENT_TYPE_DEVICE_UPDATE);
	mutex_unlock(&vlds->vlds_mutex);

	dprintk("%s: Probe successfful: cfg_handle=%llu, id=%llu\n",
	    vlds->int_name, vdev->dev_no, *id);

	return 0;

error:

	dprintk("probe failed (rv=%d)\n", rv);

	return rv;
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
	}

	/* lock things down while we try to remove the vlds device */
	mutex_lock(&vlds_data_mutex);
	mutex_lock(&vlds->vlds_mutex);

	/* Cleanup the associated cdev, /sys and /dev entry */
	device_destroy(vlds_data.chrdev_class, vlds->devt);
	cdev_del(&vlds->cdev);

	/* Register a device update event */
	vlds_add_event_all(vlds, VLDS_EVENT_TYPE_DEVICE_UPDATE);

	/*
	 * If there are still outstanding references (opens)
	 * on this device, then set a flag and remove it on
	 * last close/release.
	 */
	if (vlds->ref_cnt > 0) {
		vlds->removed = true;
		mutex_unlock(&vlds->vlds_mutex);
	} else {
		vlds_free_vlds_dev(vlds);
		/* vlds is freed at this point. Don't access it! */
	}

	mutex_unlock(&vlds_data_mutex);

	return 0;
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

	/* set callback to create devices under /dev/vlds directory */
	vlds_data.chrdev_class->devnode = vlds_devnode;

	/* Create the control device */
	rv = vlds_alloc_vlds_dev(VLDS_CTRL_DEV_NAME, VLDS_CTRL_DEV_NAME,
	    NULL, VLDS_INVALID_HANDLE, &ctrl_vlds);
	if (rv != 0)
		dprintk("Failed to create control vlds device (%d)\n", rv);

	/*
	 * If there is a SP DS present on the system (in the MD),
	 * add a device for the SP directly since there is no
	 * vlds-port MD node for the SP and this driver provides
	 * access to SP domain services.
	 */
	if (vlds_sp_ds_present()) {
		rv = vlds_alloc_vlds_dev(VLDS_SP_INT_NAME, VLDS_SP_DEV_NAME,
		    NULL, DS_SP_DMN_HANDLE, &sp_vlds);
		if (rv != 0)
			dprintk("Failed to create SP vlds device (%d)\n", rv);
	}

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
	if (sp_vlds) {

		mutex_lock(&vlds_data_mutex);
		mutex_lock(&sp_vlds->vlds_mutex);

		/* Cleanup the associated cdev, /sys and /dev entry */
		device_destroy(vlds_data.chrdev_class, sp_vlds->devt);
		cdev_del(&sp_vlds->cdev);

		vlds_free_vlds_dev(sp_vlds);
		sp_vlds = NULL;

		mutex_unlock(&vlds_data_mutex);
	}

	if (ctrl_vlds) {

		mutex_lock(&vlds_data_mutex);
		mutex_lock(&ctrl_vlds->vlds_mutex);

		/* Cleanup the associated cdev, /sys and /dev entry */
		device_destroy(vlds_data.chrdev_class, ctrl_vlds->devt);
		cdev_del(&ctrl_vlds->cdev);

		vlds_free_vlds_dev(ctrl_vlds);
		ctrl_vlds = NULL;

		mutex_unlock(&vlds_data_mutex);
	}

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
