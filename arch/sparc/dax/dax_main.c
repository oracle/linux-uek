/*
 * Copyright (c) 2017, Oracle and/or its affiliates. All rights reserved.
 *
 * This work is licensed under the terms of the GNU GPL, version 2.
 */

#include "dax_impl.h"

int dax_ccb_wait_usec = DAX_CCB_WAIT_USEC;
int dax_ccb_wait_retries_max = DAX_CCB_WAIT_RETRIES_MAX;
LIST_HEAD(dax_mm_list);
DEFINE_SPINLOCK(dm_list_lock);

atomic_t dax_alloc_counter = ATOMIC_INIT(0);
atomic_t dax_requested_mem = ATOMIC_INIT(0);

int dax_debug;
bool dax_no_flow_ctl, dax_no_ra_pgsz;

/* driver public entry points */
static long dax_ioctl(struct file *f, unsigned int cmd, unsigned long arg);
static int dax_close(struct inode *i, struct file *f);

/* internal */
static struct dax_ctx *dax_ctx_alloc(void);
static int dax_ioctl_ccb_thr_init(void *, struct file *);
static int dax_ioctl_ccb_thr_fini(struct file *f);
static int dax_ioctl_ccb_exec(void *, struct file *);
static int dax_ioctl_ca_dequeue(void *, struct file *f);
static int dax_ioctl_ccb_kill(void *arg, struct file *f);
static int dax_ioctl_ccb_info(void *arg, struct file *f);
static int dax_validate_ca_dequeue_args(struct dax_ctx *,
					struct dax_ca_dequeue_arg *);
static int dax_ccb_hv_submit(struct dax_ctx *, union ccb *, size_t,
			     struct dax_ccb_exec_arg *);
static int dax_validate_ccb(union ccb *);
static int dax_preprocess_usr_ccbs(struct dax_ctx *, union ccb *, size_t);
static void dax_ctx_fini(struct dax_ctx *);
static void dax_ctx_flush_decommit_ccbs(struct dax_ctx *);
static int dax_ccb_flush_contig(struct dax_ctx *, int, int, bool, bool);
static void dax_ccb_wait(struct dax_ctx *, int);
static void dax_state_destroy(struct file *f);

static int dax_type;
static long dax_version = DAX_DRIVER_VERSION;
static u32 dax_hv_ccb_submit_maxlen;
static dev_t first;
static struct cdev c_dev;
static struct class *cl;
static int force;
module_param(force, int, 0644);
MODULE_PARM_DESC(force, "Forces module loading if no device present");
module_param(dax_debug, int, 0644);
MODULE_PARM_DESC(dax_debug, "Debug flags");
static int flow_enable = 0;
module_param(flow_enable, int, 0644);
MODULE_PARM_DESC(flow_enable, "Enables flow control if hardware supports it");

static const struct file_operations dax_fops = {
	.owner =    THIS_MODULE,
	.mmap =     dax_devmap,
	.release =  dax_close,
	.unlocked_ioctl = dax_ioctl
};

static int hv_get_hwqueue_size(unsigned long *qsize)
{
	long dummy;

	/* ccb = NULL, length = 0, Q type = query, VQ token = 0 */
	return sun4v_dax_ccb_submit(0, 0, HV_DAX_QUERY_CMD, 0, qsize, &dummy);
}

static int __init dax_attach(void)
{
	unsigned long minor = DAX_MINOR;
	unsigned long max_ccbs;
	int ret = 0, found_dax = 0;
	struct mdesc_handle *hp = mdesc_grab();
	u64 pn;
	char *msg;

	if (hp == NULL) {
		dax_err("Unable to grab mdesc");
		return -ENODEV;
	}

	mdesc_for_each_node_by_name(hp, pn, "virtual-device") {
		int len;
		char *prop;

		prop = (char *) mdesc_get_property(hp, pn, "name", &len);
		if (prop == NULL)
			continue;
		if (strncmp(prop, "dax", strlen("dax")))
			continue;
		dax_dbg("Found node 0x%llx = %s",  pn, prop);

		prop = (char *) mdesc_get_property(hp, pn, "compatible", &len);
		if (prop == NULL)
			continue;
		if (strncmp(prop, DAX1_STR, strlen(DAX1_STR)))
			continue;
		dax_dbg("Found node 0x%llx = %s",  pn, prop);

		if (!strncmp(prop, DAX1_FC_STR, strlen(DAX1_FC_STR))) {
			msg = "dax1-flow-control";
			dax_type = DAX1;
		} else if (!strncmp(prop, DAX2_STR, strlen(DAX2_STR))) {
			msg = "dax2";
			dax_type = DAX2;
		} else if (!strncmp(prop, DAX1_STR, strlen(DAX1_STR))) {
			msg = "dax1-no-flow-control";
			dax_no_flow_ctl = true;
			dax_type = DAX1;
		} else {
			break;
		}
		found_dax = 1;
		dax_dbg("MD indicates %s chip",  msg);
		break;
	}

	if (found_dax == 0) {
		dax_err("No DAX device found");
		if ((force & FORCE_LOAD_ON_ERROR) == 0) {
			ret = -ENODEV;
			goto done;
		}
	}

	dax_dbg("Registering DAX HV api with minor %ld", minor);
	if (sun4v_hvapi_register(HV_GRP_M7_DAX, DAX_MAJOR, &minor)) {
		dax_err("hvapi_register failed");
		if ((force & FORCE_LOAD_ON_ERROR) == 0) {
			ret = -ENODEV;
			goto done;
		}
	} else {
		dax_dbg("Max minor supported by HV = %ld", minor);
		minor = min(minor, DAX_MINOR);
		dax_dbg("registered DAX major %ld minor %ld ",
				 DAX_MAJOR, minor);
	}

	dax_no_ra_pgsz = (DAX_MAJOR == 1) && (minor == 0) && !dax_has_ra_pgsz();
	dax_dbg("RA pagesize feature %spresent", dax_no_ra_pgsz ? "not " : "");

	ret = hv_get_hwqueue_size(&max_ccbs);
	if (ret != 0) {
		dax_err("get_hwqueue_size failed with status=%d and max_ccbs=%ld",
			ret, max_ccbs);
		if (force & FORCE_LOAD_ON_ERROR) {
			max_ccbs = DAX_DEFAULT_MAX_CCB;
		} else {
			ret = -ENODEV;
			goto done;
		}
	}

	dax_hv_ccb_submit_maxlen = (u32)NCCB_TO_CCB_BYTE(max_ccbs);
	if (max_ccbs == 0 || max_ccbs > U16_MAX) {
		dax_err("Hypervisor reports nonsensical max_ccbs");
		if ((force & FORCE_LOAD_ON_ERROR) == 0) {
			ret = -ENODEV;
			goto done;
		}
	}

	/* Older M7 CPUs (pre-3.0) has bug in the flow control feature.  Since
	 * MD does not report it in old versions of HV, we need to explicitly
	 * check for flow control feature.
	 */
	if (!flow_enable) {
		dax_dbg("Flow control disabled by software, dax_alloc restricted to 4M");
		dax_no_flow_ctl = true;
	} else if ((dax_type == DAX1) && !dax_has_flow_ctl_numa()) {
		dax_dbg("Flow control disabled by hardware, dax_alloc (if available) restricted to 4M");
		dax_no_flow_ctl = true;
	} else {
		dax_dbg("Flow control enabled");
		dax_no_flow_ctl = false;
	}

	if (force & FORCE_LOAD_ON_NO_FLOW_CTL) {
		dax_no_flow_ctl = !dax_no_flow_ctl;
		dax_info("Force option %d. dax_no_flow_ctl %s",
			 force, dax_no_flow_ctl ? "true" : "false");
	}

	if (alloc_chrdev_region(&first, 0, 1, "dax") < 0) {
		ret = -ENXIO;
		goto done;
	}

	cl = class_create(THIS_MODULE, "dax");
	if (cl == NULL) {
		dax_err("class_create failed");
		ret = -ENXIO;
		goto class_error;
	}

	if (device_create(cl, NULL, first, NULL, "dax") == NULL) {
		dax_err("device_create failed");
		ret = -ENXIO;
		goto device_error;
	}

	cdev_init(&c_dev, &dax_fops);
	if (cdev_add(&c_dev, first, 1) == -1) {
		dax_err("cdev_add failed");
		ret = -ENXIO;
		goto cdev_error;
	}

	dax_debugfs_init();
	dax_info("Attached DAX module");
	goto done;

cdev_error:
	device_destroy(cl, first);
device_error:
	class_destroy(cl);
class_error:
	unregister_chrdev_region(first, 1);
done:
	mdesc_release(hp);
	return ret;
}

static void __exit dax_detach(void)
{
	dax_info("Cleaning up DAX module");
	if (!list_empty(&dax_mm_list))
		dax_warn("dax_mm_list is not empty");
	dax_info("dax_alloc_counter = %d",  atomic_read(&dax_alloc_counter));
	dax_info("dax_requested_mem = %dk",  atomic_read(&dax_requested_mem));
	cdev_del(&c_dev);
	device_destroy(cl, first);
	class_destroy(cl);
	unregister_chrdev_region(first, 1);
	dax_debugfs_clean();
}
module_init(dax_attach);
module_exit(dax_detach);
MODULE_LICENSE("GPL");

/*
 * Logic of opens, closes, threads, contexts:
 *
 * open()/close()
 *
 * A thread may open the dax device as many times as it likes, but
 * each open must be bound to a separate thread before it can be used
 * to submit a transaction.
 *
 * The DAX_CCB_THR_INIT ioctl is called to create a context for the
 * calling thread and bind it to the file descriptor associated with
 * the ioctl. A thread must always use the fd to which it is bound.
 * A thread cannot bind to more than one fd, and one fd cannot be
 * bound to more than one thread.
 *
 * When a thread is finished, it should call the DAX_CCB_THR_FINI
 * ioctl to inform us that its context is no longer needed. This is
 * optional since close() will have the same effect for the context
 * associated with the fd being closed. However, if the thread dies
 * with its context still associated with the fd, then the fd cannot
 * ever be used again by another thread.
 *
 * The DAX_CA_DEQUEUE ioctl informs the driver that one or more
 * (contiguous) chunks of completion area buffers are no longer needed
 * and can be reused.
 *
 * The DAX_CCB_EXEC submits a coprocessor transaction using the
 * calling thread's context, which must match the context associated
 * with the associated fd.
 *
 */

static int dax_close(struct inode *i, struct file *f)
{
	dax_state_destroy(f);
	return 0;
}

static long dax_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
	dax_dbg("cmd=0x%x, f=%p, priv=%p",  cmd, f, f->private_data);
	switch (cmd) {
	case DAXIOC_CCB_THR_INIT:
		return dax_ioctl_ccb_thr_init((void *)arg, f);
	case DAXIOC_CCB_THR_FINI:
		return dax_ioctl_ccb_thr_fini(f);
	case DAXIOC_CA_DEQUEUE:
		return dax_ioctl_ca_dequeue((void *)arg, f);
	case DAXIOC_CCB_EXEC:
		return dax_ioctl_ccb_exec((void *)arg, f);
	case DAXIOC_CCB_KILL:
		return dax_ioctl_ccb_kill((void *)arg, f);
	case DAXIOC_CCB_INFO:
		return dax_ioctl_ccb_info((void *)arg, f);
	case DAXIOC_VERSION:
		if (copy_to_user((void __user *)arg, &dax_version,
				 sizeof(dax_version)))
			return -EFAULT;
		return 0;
	case DAXIOC_CCB_THR_INIT_OLD:
	case DAXIOC_CA_DEQUEUE_OLD:
	case DAXIOC_CCB_EXEC_OLD:
	case PERFCOUNT_GET_NODE_COUNT_OLD:
	case PERFCOUNT_DAX_SET_COUNTERS_OLD:
	case PERFCOUNT_DAX_GET_COUNTERS_OLD:
	case PERFCOUNT_DAX_CLEAR_COUNTERS_OLD:
		dax_err("Old driver API not supported");
		return -ENOTTY;
	default:
		return dax_perfcount_ioctl(f, cmd, arg);
	}
}

static void dax_state_destroy(struct file *f)
{
	struct dax_ctx *ctx = (struct dax_ctx *) f->private_data;

	if (ctx != NULL) {
		dax_ctx_flush_decommit_ccbs(ctx);
		f->private_data = NULL;
		dax_ctx_fini(ctx);
	}
}

static int dax_ioctl_ccb_thr_init(void *arg, struct file *f)
{
	struct dax_ccb_thr_init_arg usr_args;
	struct dax_ctx *ctx;

	ctx = (struct dax_ctx *) f->private_data;

	/* Only one thread per open can create a context */
	if (ctx != NULL) {
		if (ctx->owner != current) {
			dax_err("This open already has an associated thread");
			return -EUSERS;
		}
		dax_err("duplicate CCB_THR_INIT ioctl");
		return -EINVAL;
	}

	if (copy_from_user(&usr_args, (void __user *)arg, sizeof(usr_args))) {
		dax_err("invalid user args\n");
		return -EFAULT;
	}

	dax_dbg("pid=%d, ccb_maxlen = %d",  current->pid,
		usr_args.dcti_ccb_buf_maxlen);

	usr_args.dcti_compl_maplen = DAX_MMAP_SZ;
	usr_args.dcti_compl_mapoff = DAX_MMAP_OFF;
	usr_args.dcti_ccb_buf_maxlen = dax_hv_ccb_submit_maxlen;

	if (copy_to_user((void __user *)arg, &usr_args,
			 sizeof(usr_args))) {
		dax_err("copyout dax_ccb_thr_init_arg failed");
		return -EFAULT;
	}

	ctx = dax_ctx_alloc();

	if (ctx == NULL) {
		dax_err("dax_ctx_alloc failed.");
		return -ENOMEM;
	}
	ctx->owner = current;
	f->private_data = ctx;
	return 0;
}

static int dax_ioctl_ccb_thr_fini(struct file *f)
{
	struct dax_ctx *ctx = (struct dax_ctx *) f->private_data;

	if (ctx == NULL) {
		dax_err("CCB_THR_FINI ioctl called without previous CCB_THR_INIT ioctl");
		return -EINVAL;
	}

	if (ctx->owner != current) {
		dax_err("CCB_THR_FINI ioctl called from wrong thread");
		return -EINVAL;
	}

	dax_state_destroy(f);
	return 0;
}

int dax_ccb_kill_info_hv(u64 ca, unsigned long ret, char *ok_str)
{
	switch (ret) {
	case HV_EOK:
		dax_kill_info_dbg("HV returned HV_EOK for ca_ra 0x%llx, %s", ca,
				  ok_str);
		return 0;

	case HV_EBADALIGN:
		dax_err("HV returned HV_EBADALIGN for ca_ra 0x%llx", ca);
		return -EFAULT;

	case HV_ENORADDR:
		dax_err("HV returned HV_ENORADDR for ca_ra 0x%llx", ca);
		return -EFAULT;

	case HV_EINVAL:
		dax_err("HV returned HV_EINVAL for ca_ra 0x%llx", ca);
		return -EINVAL;

	case HV_EWOULDBLOCK:
		dax_err("HV returned HV_EWOULDBLOCK for ca_ra 0x%llx", ca);
		return -EAGAIN;

	case HV_ENOACCESS:
		dax_err("HV returned HV_ENOACCESS for ca_ra 0x%llx", ca);
		return -EPERM;

	default:
		dax_err("HV returned unknown (%ld) for ca_ra 0x%llx", ret, ca);
		return -EIO;
	}
}

int dax_ccb_kill(u64 ca, u16 *kill_res)
{
	unsigned long hv_ret;
	char res_str[80];
	int count;
	int ret;

	/* confirm dax drv and hv api constants the same */
	BUILD_BUG_ON(DAX_KILL_COMPLETED != HV_DAX_KILL_COMPLETED);
	BUILD_BUG_ON(DAX_KILL_DEQUEUED != HV_DAX_KILL_DEQUEUED);
	BUILD_BUG_ON(DAX_KILL_KILLED != HV_DAX_KILL_KILLED);
	BUILD_BUG_ON(DAX_KILL_NOTFOUND != HV_DAX_KILL_NOTFOUND);

	for (count = 0; count < DAX_KILL_RETRIES_MAX; count++) {
		dax_dbg("attempting kill on ca_ra 0x%llx", ca);
		hv_ret = sun4v_dax_ccb_kill(ca, kill_res);

		if (*kill_res == DAX_KILL_COMPLETED)
			snprintf(res_str, sizeof(res_str), "COMPLETED");
		else if (*kill_res == DAX_KILL_DEQUEUED)
			snprintf(res_str, sizeof(res_str), "DEQUEUED");
		else if (*kill_res == DAX_KILL_KILLED)
			snprintf(res_str, sizeof(res_str), "KILLED");
		else if (*kill_res == DAX_KILL_NOTFOUND)
			snprintf(res_str, sizeof(res_str), "NOTFOUND");
		else
			snprintf(res_str, sizeof(res_str), "??? (%d)",
				 *kill_res);

		ret = dax_ccb_kill_info_hv(ca, hv_ret, res_str);
		if (ret != -EAGAIN)
			return ret;
		dax_kill_info_dbg("ccb_kill count = %d", count);
		udelay(DAX_KILL_WAIT_USEC);
	}

	return -EAGAIN;
}

static int dax_ccb_info(u64 ca, struct dax_ccb_info_arg *info)
{
	u16 *info_arr = &info->dax_ccb_state;
	unsigned long hv_ret;
	char info_str[80];
	int count;
	int ret;

	/* confirm dax drv and hv api constants the same */
	BUILD_BUG_ON(DAX_CCB_COMPLETED != HV_CCB_STATE_COMPLETED);
	BUILD_BUG_ON(DAX_CCB_ENQUEUED != HV_CCB_STATE_ENQUEUED);
	BUILD_BUG_ON(DAX_CCB_INPROGRESS != HV_CCB_STATE_INPROGRESS);
	BUILD_BUG_ON(DAX_CCB_NOTFOUND != HV_CCB_STATE_NOTFOUND);

	for (count = 0; count < DAX_INFO_RETRIES_MAX; count++) {
		dax_dbg("attempting info on ca_ra 0x%llx", ca);
		hv_ret = sun4v_dax_ccb_info(ca, info_arr);

		if (info->dax_ccb_state == DAX_CCB_COMPLETED) {
			snprintf(info_str, sizeof(info_str),
				 "ccb_state COMPLETED");
		} else if (info->dax_ccb_state == DAX_CCB_ENQUEUED) {
			snprintf(info_str, sizeof(info_str),
				 "ccb_state ENQUEUED (dax_unit %d, queue_num %d, queue_pos %d)",
				 info->dax_inst_num, info->dax_q_num,
				 info->dax_q_pos);
		} else if (info->dax_ccb_state == DAX_CCB_INPROGRESS) {
			snprintf(info_str, sizeof(info_str),
				 "ccb_state INPROGRESS");
		} else if (info->dax_ccb_state == DAX_CCB_NOTFOUND) {
			snprintf(info_str, sizeof(info_str),
				 "ccb_state NOTFOUND");
		} else {
			snprintf(info_str, sizeof(info_str),
				 "ccb_state ??? (%d)", info->dax_ccb_state);
		}

		ret = dax_ccb_kill_info_hv(ca, hv_ret, info_str);
		if (ret != -EAGAIN)
			return ret;
		dax_kill_info_dbg("ccb_info count = %d", count);
		udelay(DAX_INFO_WAIT_USEC);
	}

	return -EAGAIN;
}

static int dax_ioctl_ccb_kill(void *arg, struct file *f)
{
	struct dax_ctx *dax_ctx = (struct dax_ctx *) f->private_data;
	struct dax_ccb_kill_arg kill_arg;
	int ret;
	u64 ca;

	if (dax_ctx == NULL) {
		dax_err("CCB_INIT ioctl not previously called");
		return -ENOENT;
	}

	if (dax_ctx->owner != current) {
		dax_err("wrong thread");
		return -EUSERS;
	}

	if (copy_from_user(&kill_arg, (void __user *)arg, sizeof(kill_arg))) {
		dax_err("copy_from_user failed");
		return -EFAULT;
	}

	dax_dbg("ca_offset=%d", kill_arg.dax_ca_offset);

	if (kill_arg.dax_ca_offset >= dax_ctx->ca_buflen) {
		dax_err("invalid dax_ca_offset (%d) >= ca_buflen (%d)",
			kill_arg.dax_ca_offset, dax_ctx->ca_buflen);
		return -EINVAL;
	}

	ca = dax_ctx->ca_buf_ra + kill_arg.dax_ca_offset;

	ret = dax_ccb_kill(ca, &kill_arg.dax_kill_res);
	if (ret != 0) {
		dax_err("dax_ccb_kill failed (ret=%d)", ret);
		return ret;
	}

	dax_kill_info_dbg("kill succeeded on ca_offset %d",
			  kill_arg.dax_ca_offset);

	if (copy_to_user((void __user *)arg, &kill_arg, sizeof(kill_arg))) {
		dax_err("copy_to_user failed");
		return -EFAULT;
	}

	return 0;
}

static int dax_ioctl_ccb_info(void *arg, struct file *f)
{
	struct dax_ctx *dax_ctx = (struct dax_ctx *) f->private_data;
	struct dax_ccb_info_arg info_arg;
	int ret;
	u64 ca;

	if (dax_ctx == NULL) {
		dax_err("CCB_INIT ioctl not previously called");
		return -ENOENT;
	}

	if (dax_ctx->owner != current) {
		dax_err("wrong thread");
		return -EUSERS;
	}

	if (copy_from_user(&info_arg, (void __user *)arg, sizeof(info_arg))) {
		dax_err("copy_from_user failed");
		return -EFAULT;
	}

	dax_dbg("ca_offset=%d", info_arg.dax_ca_offset);

	if (info_arg.dax_ca_offset >= dax_ctx->ca_buflen) {
		dax_err("invalid dax_ca_offset (%d) >= ca_buflen (%d)",
			info_arg.dax_ca_offset, dax_ctx->ca_buflen);
		return -EINVAL;
	}

	ca = dax_ctx->ca_buf_ra + info_arg.dax_ca_offset;

	ret = dax_ccb_info(ca, &info_arg);
	if (ret != 0) {
		dax_err("dax_ccb_info failed (ret=%d)", ret);
		return ret;
	}

	dax_kill_info_dbg("info succeeded on ca_offset %d",
			  info_arg.dax_ca_offset);

	if (copy_to_user((void __user *)arg, &info_arg, sizeof(info_arg))) {
		dax_err("copy_to_user failed");
		return -EFAULT;
	}

	return 0;
}

static int dax_ioctl_ca_dequeue(void *arg, struct file *f)
{
	struct dax_ctx *dax_ctx = (struct dax_ctx *) f->private_data;
	struct dax_ca_dequeue_arg usr_args;
	int n_remain, n_avail, n_dq;
	int start_idx, end_idx;
	int rv = 0;
	int i;

	if (dax_ctx == NULL) {
		dax_err("CCB_INIT ioctl not previously called");
		rv = -ENOENT;
		goto ca_dequeue_error;
	}

	if (dax_ctx->owner != current) {
		dax_err("wrong thread");
		rv = -EUSERS;
		goto ca_dequeue_error;
	}

	if (copy_from_user(&usr_args, (void __user *)arg, sizeof(usr_args))) {
		rv = -EFAULT;
		goto ca_dequeue_error;
	}

	dax_dbg("dcd_len_requested=%d", usr_args.dcd_len_requested);

	if (dax_validate_ca_dequeue_args(dax_ctx, &usr_args)) {
		rv = -EINVAL;
		goto ca_dequeue_end;
	}

	/* The user length has been validated.  If the kernel queue is empty,
	 * return EINVAL.  Else, check that each CCB CA has completed in HW.
	 * If any CCB CA has not completed, return EBUSY.
	 *
	 * The user expects the length to be deqeueued in terms of CAs starting
	 * from the last dequeued CA. The driver keeps track of CCBs in terms
	 * of CCBs itself.
	 */
	n_remain = CA_BYTE_TO_NCCB(usr_args.dcd_len_requested);
	dax_dbg("number of CCBs to dequeue = %d", n_remain);
	usr_args.dcd_len_dequeued = 0;

	for (i = 0; i < DAX_BIP_MAX_CONTIG_BLOCKS && n_remain > 0; i++) {
		start_idx = dax_ccb_buffer_get_contig_ccbs(dax_ctx, &n_avail);

		dax_dbg("%d number of contig CCBs available starting from idx = %d",
			 n_avail, start_idx);
		if (start_idx < 0 || n_avail == 0) {
			dax_err("cannot get contiguous buffer start = %d, n_avail = %d",
				 start_idx, n_avail);
			rv = -EIO;
			goto ca_dequeue_end;
		}

		n_dq = min(n_remain, n_avail);
		end_idx = start_idx + n_dq;

		rv = dax_ccb_flush_contig(dax_ctx, start_idx, end_idx,
					  false, true);
		if (rv != 0) {
			/* Attempted to dequeue single CA for long CCB.  All
			 * the CCBs till then are dequeued, So release their
			 * backing BIP buffer
			 */
			if (rv == -EINVAL) {
				n_dq--;
				dax_ccb_buffer_decommit(dax_ctx, n_dq);
				usr_args.dcd_len_dequeued += NCCB_TO_CA_BYTE(n_dq);
			}
			goto ca_dequeue_end;
		}

		/* Free buffer. Update accounting. */
		dax_ccb_buffer_decommit(dax_ctx, n_dq);

		usr_args.dcd_len_dequeued += NCCB_TO_CA_BYTE(n_dq);
		n_remain -= n_dq;

		if (n_remain > 0)
			dax_dbg("checking additional ccb_buffer contig block, n_remain=%d",
				 n_remain);
	}

ca_dequeue_end:
	dax_dbg("copyout CA's dequeued in bytes =%d",
		usr_args.dcd_len_dequeued);

	if (copy_to_user((void __user *)arg, &usr_args, sizeof(usr_args))) {
		dax_err("copyout dax_ca_dequeue_arg failed");
		rv = -EFAULT;
		goto ca_dequeue_error;
	}

ca_dequeue_error:
	return rv;
}

static int dax_validate_ca_dequeue_args(struct dax_ctx *dax_ctx,
			     struct dax_ca_dequeue_arg *usr_args)
{
	/* requested len must be multiple of completion area size */
	if ((usr_args->dcd_len_requested % sizeof(struct ccb_completion_area))
	    != 0) {
		dax_err("dequeue len (%d) not a muliple of %ldB",
			 usr_args->dcd_len_requested,
			 sizeof(struct ccb_completion_area));
		return -1;
	}

	/* and not more than current buffer entry count */
	if (CA_BYTE_TO_NCCB(usr_args->dcd_len_requested) >
			    CCB_BYTE_TO_NCCB(dax_ctx->bufcnt)) {
		dax_err("dequeue len (%d bytes, %ld CAs) more than current CA buffer count (%ld CAs)",
			usr_args->dcd_len_requested,
			CA_BYTE_TO_NCCB(usr_args->dcd_len_requested),
			CCB_BYTE_TO_NCCB(dax_ctx->bufcnt));
		return -1;
	}

	/* reject zero length */
	if (usr_args->dcd_len_requested == 0)
		return -1;

	return 0;
}

static struct dax_ctx *
dax_ctx_alloc(void)
{
	struct dax_ctx *dax_ctx;
	struct dax_mm *dm = NULL;
	struct list_head *p;

	dax_ctx = kzalloc(sizeof(struct dax_ctx), GFP_KERNEL);
	if (dax_ctx == NULL)
		goto done;

	BUILD_BUG_ON(((DAX_CCB_BUF_SZ) & ((DAX_CCB_BUF_SZ) - 1)) != 0);
	/* allocate CCB buffer */
	dax_ctx->ccb_buf = kmalloc(DAX_CCB_BUF_SZ, GFP_KERNEL);
	if (dax_ctx->ccb_buf == NULL)
		goto ccb_buf_error;

	dax_ctx->ccb_buf_ra = virt_to_phys(dax_ctx->ccb_buf);
	dax_ctx->ccb_buflen = DAX_CCB_BUF_SZ;
	dax_ctx->ccb_submit_maxlen = dax_hv_ccb_submit_maxlen;

	dax_dbg("dax_ctx->ccb_buf=0x%p, ccb_buf_ra=0x%llx, ccb_buflen=%d",
		(void *)dax_ctx->ccb_buf, dax_ctx->ccb_buf_ra,
		dax_ctx->ccb_buflen);

	BUILD_BUG_ON(((DAX_CA_BUF_SZ) & ((DAX_CA_BUF_SZ) - 1)) != 0);
	/* allocate CCB completion area buffer */
	dax_ctx->ca_buf = kzalloc(DAX_CA_BUF_SZ, GFP_KERNEL);
	if (dax_ctx->ca_buf == NULL)
		goto ca_buf_error;

	dax_ctx->ca_buflen = DAX_CA_BUF_SZ;
	dax_ctx->ca_buf_ra = virt_to_phys(dax_ctx->ca_buf);
	dax_dbg("allocated 0x%x bytes for ca_buf", dax_ctx->ca_buflen);

	/* allocate page array */
	if (dax_alloc_page_arrays(dax_ctx))
		goto ctx_pages_error;

	/* initialize buffer accounting */
	dax_ctx->a_start = 0;
	dax_ctx->a_end = 0;
	dax_ctx->b_end = 0;
	dax_ctx->resv_start = 0;
	dax_ctx->resv_end = 0;
	dax_ctx->bufcnt = 0;
	dax_ctx->ccb_count = 0;
	dax_ctx->fail_count = 0;

	dax_dbg("dax_ctx=0x%p, dax_ctx->ca_buf=0x%p, ca_buf_ra=0x%llx, ca_buflen=%d",
		(void *)dax_ctx, (void *)dax_ctx->ca_buf,
		dax_ctx->ca_buf_ra, dax_ctx->ca_buflen);

	/* look for existing mm context */
	spin_lock(&dm_list_lock);
	list_for_each(p, &dax_mm_list) {
		dm = list_entry(p, struct dax_mm, mm_list);
		if (dm->this_mm == current->mm) {
			dax_ctx->dax_mm = dm;
			dax_map_dbg("existing dax_mm found: %p", dm);
			break;
		}
	}

	/* did not find an existing one, must create it */
	if (dax_ctx->dax_mm == NULL) {
		dm = kmalloc(sizeof(*dm), GFP_KERNEL);
		if (dm == NULL) {
			spin_unlock(&dm_list_lock);
			goto dm_error;
		}

		INIT_LIST_HEAD(&dm->mm_list);
		INIT_LIST_HEAD(&dm->ctx_list);
		spin_lock_init(&dm->lock);
		dm->this_mm = current->mm;
		dm->vma_count = 0;
		dm->ctx_count = 0;
		list_add(&dm->mm_list, &dax_mm_list);
		dax_ctx->dax_mm = dm;
		dax_map_dbg("no dax_mm found, creating and adding to dax_mm_list: %p",
			    dm);
	}
	spin_unlock(&dm_list_lock);
	/* now add this ctx to the list of threads for this mm context */
	INIT_LIST_HEAD(&dax_ctx->ctx_list);
	spin_lock(&dm->lock);
	list_add(&dax_ctx->ctx_list, &dax_ctx->dax_mm->ctx_list);
	dax_ctx->dax_mm->ctx_count++;
	spin_unlock(&dm->lock);

	dax_dbg("allocated ctx %p", dax_ctx);
	goto done;

dm_error:
	dax_dealloc_page_arrays(dax_ctx);
ctx_pages_error:
	kfree(dax_ctx->ca_buf);
ca_buf_error:
	kfree(dax_ctx->ccb_buf);
ccb_buf_error:
	kfree(dax_ctx);
	dax_ctx = NULL;
done:
	return dax_ctx;
}

static void dax_ctx_fini(struct dax_ctx *ctx)
{
	int i, j;
	struct dax_mm *dm;

	kfree(ctx->ccb_buf);
	ctx->ccb_buf = NULL;

	kfree(ctx->ca_buf);
	ctx->ca_buf = NULL;

	for (i = 0; i < DAX_CCB_BUF_NELEMS; i++)
		for (j = 0; j < AT_MAX ; j++)
			if (ctx->pages[j][i] != NULL)
				dax_err("still not freed pages[%d] = %p",
					     j, ctx->pages[j][i]);

	dax_dealloc_page_arrays(ctx);

	dm = ctx->dax_mm;
	if (dm == NULL) {
		dax_err("dm is NULL");
	} else {
		spin_lock(&dm->lock);
		list_del(&ctx->ctx_list);
		/*
		 * dm is deallocated here. So no need to unlock dm->lock if the
		 * function succeeds
		 */
		if (dax_clean_dm(dm))
			spin_unlock(&dm->lock);
	}

	dax_drv_dbg("CCB count: %d good, %d failed", ctx->ccb_count,
		    ctx->fail_count);
	kfree(ctx);
}

static int dax_validate_ccb(union ccb *ccb)
{
	struct ccb_hdr *hdr = CCB_HDR(ccb);
	int ret = -EINVAL;

	/*
	 * The user is not allowed to specify real address types
	 * in the CCB header.  This must be enforced by the kernel
	 * before submitting the CCBs to HV.
	 *
	 * The allowed values are:
	 *	hdr->at_dst	VA/IMM only
	 *	hdr->at_src0	VA/IMM only
	 *	hdr->at_src1	VA/IMM only
	 *	hdr->at_tbl	VA/IMM only
	 *
	 * Note: IMM is only valid for certain opcodes, but the kernel is not
	 * validating at this level of granularity.  The HW will flag invalid
	 * address types.  The required check is that the user must not be
	 * allowed to specify real address types.
	 */

	DAX_VALIDATE_AT(hdr, dst, done);
	DAX_VALIDATE_AT(hdr, src0, done);
	DAX_VALIDATE_AT(hdr, src1, done);
	DAX_VALIDATE_AT(hdr, tbl, done);
	ret = 0;
done:
	return ret;
}

void dax_prt_ccbs(union ccb *ccb, u64 len)
{
	int nelem = CCB_BYTE_TO_NCCB(len);
	int i, j;

	dax_dbg("ccb buffer (processed):");
	for (i = 0; i < nelem; i++) {
		dax_dbg("%sccb[%d]", IS_LONG_CCB(&ccb[i]) ? "long " : "",  i);
		for (j = 0; j < DWORDS_PER_CCB; j++)
			dax_dbg("\tccb[%d].dwords[%d]=0x%llx",
				i, j, ccb[i].dwords[j]);
	}
}

static int dax_ioctl_ccb_exec(void *arg, struct file *f)
{
	struct dax_ccb_exec_arg usr_args;
	struct dax_ctx *dax_ctx = (struct dax_ctx *) f->private_data;
	union ccb *ccb_buf;
	size_t nreserved;
	int rv, hv_rv;

	if (dax_ctx == NULL) {
		dax_err("CCB_INIT ioctl not previously called");
		return -ENOENT;
	}

	if (dax_ctx->owner != current) {
		dax_err("wrong thread");
		return -EUSERS;
	}

	if (dax_ctx->dax_mm == NULL) {
		dax_err("dax_ctx initialized incorrectly");
		return -ENOENT;
	}

	if (copy_from_user(&usr_args, (void __user *)arg, sizeof(usr_args))) {
		dax_err("copyin of user args failed");
		return -EFAULT;
	}

	if (usr_args.dce_ccb_buf_len > dax_hv_ccb_submit_maxlen ||
	    (usr_args.dce_ccb_buf_len % sizeof(union ccb)) != 0 ||
	    usr_args.dce_ccb_buf_len == 0) {
		dax_err("invalid usr_args.dce_ccb_len(%d)",
			usr_args.dce_ccb_buf_len);
		return -ERANGE;
	}

	dax_dbg("args: ccb_buf_len=%d, buf_addr=%p",
		usr_args.dce_ccb_buf_len, usr_args.dce_ccb_buf_addr);

	/* Check for available buffer space. */
	ccb_buf = dax_ccb_buffer_reserve(dax_ctx, usr_args.dce_ccb_buf_len,
					 &nreserved);
	dax_dbg("reserved address %p for ccb_buf", ccb_buf);

	/*
	 * We don't attempt a partial submission since that would require extra
	 * logic to not split a long CCB at the end.  This would be an
	 * enhancement.
	 */
	if (ccb_buf == NULL || nreserved != usr_args.dce_ccb_buf_len) {
		dax_dbg("insufficient kernel CCB resources: user needs to free completion area space and retry");
		return -ENOBUFS;
	}

	/*
	 * Copy user CCBs.  Here we copy the entire user buffer and later
	 * validate the contents by running the buffer.
	 */
	if (copy_from_user(ccb_buf, (void __user *)usr_args.dce_ccb_buf_addr,
			   usr_args.dce_ccb_buf_len)) {
		dax_err("copyin of user CCB buffer failed");
		return -EFAULT;
	}

	rv = dax_preprocess_usr_ccbs(dax_ctx, ccb_buf,
				     usr_args.dce_ccb_buf_len);

	if (rv != 0)
		return rv;

	rv = dax_map_segment(dax_ctx, ccb_buf, usr_args.dce_ccb_buf_len);
	if (rv != 0)
		return -EFAULT;

	hv_rv = dax_ccb_hv_submit(dax_ctx, ccb_buf, usr_args.dce_ccb_buf_len,
				  &usr_args);

	/* Update based on actual number of submitted CCBs. */
	if (hv_rv == 0) {
		dax_ccb_buffer_commit(dax_ctx,
				      usr_args.dce_submitted_ccb_buf_len);
		dax_ctx->ccb_count++;
	} else {
		dax_ctx->fail_count++;
		dax_dbg("submit failed, status=%d, nomap=0x%llx",
			 usr_args.dce_ccb_status, usr_args.dce_nomap_va);
		dax_unlock_pages(dax_ctx, ccb_buf, usr_args.dce_ccb_buf_len);
	}

	dax_dbg("copyout dce_submitted_ccb_buf_len=%d, dce_ca_region_off=%lld, dce_ccb_status=%d",
		usr_args.dce_submitted_ccb_buf_len, usr_args.dce_ca_region_off,
		usr_args.dce_ccb_status);

	if (copy_to_user((void __user *)arg, &usr_args, sizeof(usr_args))) {
		dax_err("copyout of dax_ccb_exec_arg failed");
		return -EFAULT;
	}

	return 0;
}


/*
 * Validates user CCB content.  Also sets completion address and address types
 * for all addresses contained in CCB.
 */
static int dax_preprocess_usr_ccbs(struct dax_ctx *dax_ctx, union ccb *ccb,
				   size_t ccb_len)
{
	int i;
	int nelem = CCB_BYTE_TO_NCCB(ccb_len);

	for (i = 0; i < nelem; i++) {
		struct ccb_hdr *hdr = CCB_HDR(&ccb[i]);
		u32 idx;
		ptrdiff_t ca_offset;

		/* enforce validation checks */
		if (dax_validate_ccb(&ccb[i])) {
			dax_dbg("ccb[%d] invalid ccb", i);
			return -ENOKEY;
		}

		/* change all virtual address types to virtual alternate */
		if (hdr->at_src0 == CCB_AT_VA)
			hdr->at_src0 = CCB_AT_VA_ALT;
		if (hdr->at_src1 == CCB_AT_VA)
			hdr->at_src1 = CCB_AT_VA_ALT;
		if (hdr->at_dst == CCB_AT_VA)
			hdr->at_dst = CCB_AT_VA_ALT;
		if (hdr->at_tbl == CCB_AT_VA)
			hdr->at_tbl = CCB_AT_VA_ALT;

		/* set completion (real) address and address type */
		hdr->at_cmpl = CCB_AT_RA;

		idx = &ccb[i] - dax_ctx->ccb_buf;
		ca_offset = (uintptr_t)&dax_ctx->ca_buf[idx] -
				(uintptr_t)dax_ctx->ca_buf;

		dax_dbg("ccb[%d]=0x%p, ccb_buf=0x%p, idx=%d, ca_offset=0x%lx, ca_buf_ra=0x%llx",
			i, (void *)&ccb[i], (void *)dax_ctx->ccb_buf, idx,
			ca_offset, dax_ctx->ca_buf_ra);

		dax_dbg("ccb[%d] setting completion RA=0x%llx",
			i, dax_ctx->ca_buf_ra + ca_offset);

		CCB_SET_COMPL_PA(dax_ctx->ca_buf_ra + ca_offset,
		    ccb[i].dwords[CCB_DWORD_COMPL]);
		memset((void *)((unsigned long)dax_ctx->ca_buf + ca_offset),
		       0, sizeof(struct ccb_completion_area));

		/* skip over 2nd 64 bytes of long CCB */
		if (IS_LONG_CCB(&ccb[i]))
			i++;
	}

	return 0;
}

static int dax_ccb_hv_submit(struct dax_ctx *dax_ctx, union ccb *ccb_buf,
			     size_t buflen, struct dax_ccb_exec_arg *exec_arg)
{
	unsigned long submitted_ccb_buf_len = 0;
	unsigned long status_data = 0;
	unsigned long hv_rv = HV_ENOMAP;
	int rv = -EIO;
	ptrdiff_t offset;

	offset = (uintptr_t)ccb_buf - (uintptr_t)dax_ctx->ccb_buf;

	dax_dbg("ccb_buf=0x%p, buflen=%ld, offset=0x%lx, ccb_buf_ra=0x%llx ",
		(void *)ccb_buf, buflen, offset,
		dax_ctx->ccb_buf_ra + offset);

	if (dax_debug & DAX_DBG_FLG_BASIC)
		dax_prt_ccbs(ccb_buf, buflen);

	/* hypercall */
	hv_rv = sun4v_dax_ccb_submit((void *) dax_ctx->ccb_buf_ra +
				     offset, buflen,
				     HV_DAX_QUERY_CMD |
				     HV_DAX_CCB_VA_SECONDARY, 0,
				     &submitted_ccb_buf_len, &status_data);

	if (dax_debug & DAX_DBG_FLG_BASIC)
		dax_prt_ccbs(ccb_buf, buflen);

	exec_arg->dce_ccb_status = DAX_SUBMIT_ERR_INTERNAL;
	exec_arg->dce_submitted_ccb_buf_len = 0;
	exec_arg->dce_ca_region_off = 0;

	dax_dbg("hcall rv=%ld, submitted_ccb_buf_len=%ld, status_data=0x%lx",
		hv_rv, submitted_ccb_buf_len, status_data);

	if (submitted_ccb_buf_len % sizeof(union ccb) != 0) {
		dax_err("submitted_ccb_buf_len %ld not multiple of ccb size %ld",
			submitted_ccb_buf_len, sizeof(union ccb));
		return rv;
	}

	switch (hv_rv) {
	case HV_EOK:
		/*
		 * Hcall succeeded with no errors but the submitted length may
		 * be less than the requested length.  The only way the kernel
		 * can resubmit the remainder is to wait for completion of the
		 * submitted CCBs since there is no way to guarantee the
		 * ordering semantics required by the client applications.
		 * Therefore we let the user library deal with retransmissions.
		 */
		rv = 0;
		exec_arg->dce_ccb_status = DAX_SUBMIT_OK;
		exec_arg->dce_submitted_ccb_buf_len = submitted_ccb_buf_len;
		exec_arg->dce_ca_region_off =
			NCCB_TO_CA_BYTE(CCB_BYTE_TO_NCCB(offset));
		break;
	case HV_EWOULDBLOCK:
		/*
		 * This is a transient HV API error that we may eventually want
		 * to hide from the user. For now return
		 * DAX_SUBMIT_ERR_WOULDBLOCK and let the user library retry.
		 */
		dax_err("hcall returned HV_EWOULDBLOCK");
		exec_arg->dce_ccb_status = DAX_SUBMIT_ERR_WOULDBLOCK;
		break;
	case HV_ENOMAP:
		/*
		 * HV was unable to translate a VA.  The VA it could not
		 * translate is returned in the nomap_va param.
		 */
		dax_err("hcall returned HV_ENOMAP nomap_va=0x%lx", status_data);
		exec_arg->dce_nomap_va = status_data;
		exec_arg->dce_ccb_status = DAX_SUBMIT_ERR_NOMAP;
		break;
	case HV_EINVAL:
		/*
		 * This is the result of an invalid user CCB as HV is validating
		 * some of the user CCB fields.  Pass this error back to the
		 * user. There is no supporting info to isolate the invalid
		 * field
		 */
		dax_err("hcall returned HV_EINVAL");
		exec_arg->dce_ccb_status = DAX_SUBMIT_ERR_CCB_INVAL;
		break;
	case HV_ENOACCESS:
		/*
		 * HV found a VA that did not have the appropriate permissions
		 * (such as the w bit). The VA in question is returned in
		 * nomap_va param, but there is no specific indication which
		 * CCB had the error.  There is no remedy for the kernel to
		 * correct the failure, so return an appropriate error to the
		 * user.
		 */
		dax_err("hcall returned HV_ENOACCESS");
		exec_arg->dce_ccb_status = DAX_SUBMIT_ERR_NOACCESS;
		exec_arg->dce_nomap_va = status_data;
		break;
	case HV_EUNAVAILABLE:
		/*
		 * The requested CCB operation could not be performed at this
		 * time. The restrict-ed operation availability may apply only
		 * to the first unsuccessfully submitted CCB, or may apply to a
		 * larger scope. Return the specific unavailable code in the
		 * nomap_va field.
		 */
		dax_err("hcall returned HV_EUNAVAILABLE code=%ld", status_data);
		exec_arg->dce_ccb_status = DAX_SUBMIT_ERR_UNAVAIL;
		exec_arg->dce_nomap_va = status_data;
		break;
	default:
		exec_arg->dce_ccb_status = DAX_SUBMIT_ERR_INTERNAL;
		dax_err("unknown hcall return value (%ld)", hv_rv);
		break;
	}

	return rv;
}

/*
 * Wait for all CCBs to complete and remove from CCB buffer.
 */
static void dax_ctx_flush_decommit_ccbs(struct dax_ctx *dax_ctx)
{
	int n_contig_ccbs;

	dax_dbg("");

	/* Wait for all CCBs to complete.  Do not remove from CCB buffer */
	dax_ccb_flush_contig(dax_ctx, CCB_BYTE_TO_NCCB(dax_ctx->a_start),
			     CCB_BYTE_TO_NCCB(dax_ctx->a_end), true, false);

	if (dax_ctx->b_end > 0)
		dax_ccb_flush_contig(dax_ctx, 0,
				     CCB_BYTE_TO_NCCB(dax_ctx->b_end),
				     true, false);

	/* decommit all */
	while (dax_ccb_buffer_get_contig_ccbs(dax_ctx, &n_contig_ccbs) >= 0) {
		if (n_contig_ccbs == 0)
			break;
		dax_ccb_buffer_decommit(dax_ctx, n_contig_ccbs);
	}
}

static int dax_ccb_flush_contig(struct dax_ctx *dax_ctx, int start_idx,
				int end_idx, bool wait,
				bool check_long_ccb_error)
{
	int i;

	dax_dbg("start_idx=%d, end_idx=%d", start_idx, end_idx);

	for (i = start_idx; i < end_idx; i++) {
		u8 status;
		union ccb *ccb = &dax_ctx->ccb_buf[i];

		if (check_long_ccb_error && IS_LONG_CCB(ccb) &&
		   (i == (end_idx - 1))) {
			/*
			 * Validate that the user must dequeue 2 CAs for a long
			 * CCB.  In other words, the last entry in a contig
			 * block cannot be a long CCB.
			 */
			dax_err("invalid attempt to dequeue single CA for long CCB, index=%d",
				i);
			return -EINVAL;
		}

		if (wait) {
			dax_ccb_wait(dax_ctx, i);
		} else {
			status = dax_ctx->ca_buf[i].cmd_status;

			if (status == CCB_CMD_STAT_NOT_COMPLETED) {
				dax_err("CCB completion area status == CCB_CMD_STAT_NOT_COMPLETED: fail request to free completion index=%d",
					i);
				return -EBUSY;
			}
		}

		dax_overflow_check(dax_ctx, i);
		/* free any locked pages associated with this ccb */
		dax_unlock_pages_ccb(dax_ctx, i, ccb);

		/* skip over 64B data of long CCB */
		if (IS_LONG_CCB(ccb))
			i++;
	}
	return 0;
}

static void dax_ccb_wait(struct dax_ctx *dax_ctx, int idx)
{
	int nretries = 0;
	u16 kill_res;
	int ret;
	u64 ca;

	dax_dbg("idx=%d", idx);

	while (dax_ctx->ca_buf[idx].cmd_status == CCB_CMD_STAT_NOT_COMPLETED) {
		udelay(dax_ccb_wait_usec);

		if (++nretries >= dax_ccb_wait_retries_max) {
			dax_alert("dax_ctx (0x%p): CCB[%d] did not complete (timed out, wait usec=%d retries=%d). Killing ccb",
				  (void *)dax_ctx, idx, dax_ccb_wait_usec,
				  dax_ccb_wait_retries_max);
			ca = dax_ctx->ca_buf_ra + NCCB_TO_CA_BYTE(idx);
			ret = dax_ccb_kill(ca, &kill_res);
			if (ret != 0)
				dax_alert("Killing CCB[%d] failed", idx);
			else
				dax_alert("CCB[%d] killed", idx);

			return;
		}
	}
}

static void dax_ccb_drain(struct dax_ctx *ctx, int idx, struct dax_vma *dv)
{
	union ccb *ccb;
	struct ccb_hdr *hdr;

	if (ctx->ca_buf[idx].cmd_status != CCB_CMD_STAT_NOT_COMPLETED)
		return;

	ccb = &ctx->ccb_buf[idx];
	hdr = CCB_HDR(ccb);

	if (dax_address_in_use(dv, hdr->at_dst,
			       ccb->dwords[QUERY_DWORD_OUTPUT])
		|| dax_address_in_use(dv, hdr->at_src0,
				      ccb->dwords[QUERY_DWORD_INPUT])
		|| dax_address_in_use(dv, hdr->at_src1,
				      ccb->dwords[QUERY_DWORD_SEC_INPUT])
		|| dax_address_in_use(dv, hdr->at_tbl,
				      ccb->dwords[QUERY_DWORD_TBL])) {
		dax_ccb_wait(ctx, idx);
	}
}

static void dax_ccbs_drain_contig(struct dax_ctx *ctx, struct dax_vma *dv,
				  int start_bytes, int end_bytes)
{
	int start_idx = CCB_BYTE_TO_NCCB(start_bytes);
	int end_idx = CCB_BYTE_TO_NCCB(end_bytes);
	int i;

	dax_dbg("start_idx=%d, end_idx=%d", start_idx, end_idx);

	for (i = start_idx; i < end_idx; i++) {
		dax_ccb_drain(ctx, i, dv);
		if (IS_LONG_CCB(&ctx->ccb_buf[i])) {
			/* skip over 64B data of long CCB */
			i++;
		}
	}
}

void dax_ccbs_drain(struct dax_ctx *ctx, struct dax_vma *dv)
{
	dax_ccbs_drain_contig(ctx, dv, ctx->a_start, ctx->a_end);
	if (ctx->b_end > 0)
		dax_ccbs_drain_contig(ctx, dv, 0, ctx->b_end);
}
