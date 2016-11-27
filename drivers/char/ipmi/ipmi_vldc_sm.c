/*
 * IPMI Driver for Sparc T4/T5/T7 Platforms
 *
 * Copyright (C) 2013 Oracle, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	 See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Author:
 *	Rob Gardner <rob.gardner@oracle.com
 */


#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/ipmi_msgdefs.h>
#include <linux/workqueue.h>
#include <linux/wait.h>
#include <linux/delay.h>
#include <linux/vldc.h>
#include <linux/sched.h>
#include "ipmi_si_sm.h"
#include <asm/ldc.h>

#define VLDC_DEBUG_OFF		0 /* Used in production */
#define VLDC_DEBUG_ENABLE	1 /* Generic messages */
#define VLDC_DEBUG_MSG		2 /* Prints all request/response buffers */
#define VLDC_DEBUG_STATES	4 /* Verbose look at state changes */
#define VLDC_RESET_RETRY_STIME (15 * HZ) /* 15 seconds retry time */
#define VLDC_RESET_RETRY_LTIME (60 * HZ) /* 60 seconds retry time */
#define VLDC_RESET_RETRY_SCOUNT 25
#define INVALID_IPMI_DEV -1

static int vldc_debug = VLDC_DEBUG_OFF;
static struct workqueue_struct *vldc_reset_wq;

#define dprintk(LEVEL, ...) \
	if (vldc_debug & LEVEL) \
		printk(KERN_DEBUG __VA_ARGS__)

#define dprint_hex_dump(LEVEL, BUF, LEN) \
	if (vldc_debug & LEVEL) \
		print_hex_dump(KERN_DEBUG, "", DUMP_PREFIX_NONE, 16, 1, BUF, LEN, 0);

module_param(vldc_debug, int, 0600);
MODULE_PARM_DESC(vldc_debug, "debug bitmask, 1=enable, 2=messages, 4=states");

enum vldc_states {
	VLDC_STATE_IDLE = 0,
	VLDC_STATE_XACTION_START,
	VLDC_STATE_READ_WAIT,
	VLDC_STATE_RESETTING,
	VLDC_STATE_RESET,
	VLDC_STATE_CLEANUP,
	VLDC_STATE_PRINTME,
};

/*
 * Default Data limits for the virtual channel interface
 */
#define	BMC_VC_MAX_REQUEST_SIZE		263 /* 263 to allow the payload */
					    /* to be the full 255 bytes */
#define	VC_SEND_NONDATA_SIZE		8
#define	VC_SEND_MAX_PAYLOAD_SIZE	(BMC_VC_MAX_REQUEST_SIZE - VC_SEND_NONDATA_SIZE)
#define	BMC_VC_MAX_RESPONSE_SIZE	266 /* Max-out receive payload */
#define	VC_RECV_NONDATA_SIZE		11
#define	VC_RECV_MAX_PAYLOAD_SIZE	(BMC_VC_MAX_RESPONSE_SIZE - VC_RECV_NONDATA_SIZE)

#define VLDC_IPMI_DEV "ipmi"

#define VLDC_NORMAL_TIMEOUT	5	/* seconds */
#define	VC_MAGIC_NUM	0x4B59554E

/*
 * data structure to send a message to BMC.
 */
typedef struct bmc_vc_send {
	uint32_t magic_num;	/* magic number */
	uint16_t datalen;	/* data length */
	uint8_t  fn_lun;	/* Network Function and LUN */
	uint8_t  cmd;		/* command */
	uint8_t  data[1];	/* Variable-length, see vc_max_send_payload */
} bmc_vc_send_t;

/*
 * data structure to receive a message from BMC.
 */
typedef struct bmc_vc_recv {
	uint32_t magic_num;	/* magic number */
	uint16_t datalen;	/* data length */
	uint16_t reserved;	/* reserved */
	uint8_t  fn_lun;	/* Network Function and LUN */
	uint8_t  cmd;		/* command */
	uint8_t  ccode;		/* completion code */
	uint8_t  data[VC_RECV_MAX_PAYLOAD_SIZE];
} bmc_vc_recv_t;

struct si_sm_data {
	struct work_struct reset_work;
	wait_queue_head_t cleanup_waitq;
	enum vldc_states state;
	unsigned char	write_data[IPMI_MAX_MSG_LENGTH + sizeof(bmc_vc_send_t)];
	int		write_count;
	unsigned char	read_data[IPMI_MAX_MSG_LENGTH];
	int		read_count;
	long		timeout;
	int		vldc_handle;
};

static void vldc_cleanup(struct si_sm_data *v);
static int vldc_detect(struct si_sm_data *v);
static void vldc_reset_work(struct work_struct *w);

static unsigned int vldc_init_data(struct si_sm_data *v, struct si_sm_io *io)
{
	pr_info("%s\n", __func__);
	memset(v, 0, sizeof(struct si_sm_data));
	v->state = VLDC_STATE_IDLE;
	v->vldc_handle = INVALID_IPMI_DEV;

	return 0;
}

static int vldc_start_transaction(struct si_sm_data *vldc,
				  unsigned char *data,
				  unsigned int size)
{
	bmc_vc_send_t *send_bmc = (bmc_vc_send_t *) vldc->write_data;

	if (size < 2)
		return IPMI_REQ_LEN_INVALID_ERR;
	if (size > IPMI_MAX_MSG_LENGTH)
		return IPMI_REQ_LEN_EXCEEDED_ERR;

	if (vldc->state != VLDC_STATE_IDLE)
		return IPMI_NOT_IN_MY_STATE_ERR;

	dprintk(VLDC_DEBUG_ENABLE, "VLDC: +++++++++++++++++ New command\n");
	dprintk(VLDC_DEBUG_ENABLE, "VLDC: NetFn/LUN CMD [%d data]:", size - 2);
	dprint_hex_dump(VLDC_DEBUG_ENABLE, data, size);

	memset(vldc->write_data, 0, IPMI_MAX_MSG_LENGTH + sizeof(bmc_vc_send_t));
	send_bmc->magic_num = VC_MAGIC_NUM;
	send_bmc->fn_lun = *data;
	send_bmc->cmd = *(data+1);
	send_bmc->datalen = size - 2;
	if (send_bmc->datalen > 0)
		memcpy(send_bmc->data, data+2, send_bmc->datalen);
	vldc->write_count = send_bmc->datalen + VC_SEND_NONDATA_SIZE;
	vldc->read_count = 0;
	vldc->state = VLDC_STATE_XACTION_START;
	vldc->timeout = VLDC_NORMAL_TIMEOUT * 1000000; /* convert to microseconds */

	return 0;
}

static int vldc_get_result(struct si_sm_data *vldc,
			 unsigned char *data,
			 unsigned int length)
{
	ssize_t msg_len;
	bmc_vc_recv_t *rcv;

	rcv = (bmc_vc_recv_t *) vldc->read_data;
	dprintk(VLDC_DEBUG_ENABLE, "%s: rcv->datalen=%d, fn_lun=0x%x, cmd=0x%x, ccode=0x%x, read_count=%d\n",
		__func__, rcv->datalen, rcv->fn_lun, rcv->cmd, rcv->ccode, vldc->read_count);

	msg_len = vldc->read_count - 8;

	/* msg_len must be at least 3 to account for fn_lun, cmd, and completion code */
	if (msg_len < 3 || msg_len > IPMI_MAX_MSG_LENGTH) {
		dprintk(VLDC_DEBUG_MSG, "%s: bad msg_len: %ld\n", __func__, msg_len);
		return 0;
	}
	if (rcv->datalen+3 > length) {
		dprintk(VLDC_DEBUG_MSG, "%s: datalen(%d)+3 > length(%d)\n", __func__, rcv->datalen, length);
		return 0;
	}
	memcpy(data, &rcv->fn_lun, rcv->datalen+3);

	dprintk(VLDC_DEBUG_MSG, "VLDC: result %ld bytes:", msg_len);
	dprint_hex_dump(VLDC_DEBUG_MSG, data, msg_len);

	vldc->read_count = 0;

	return msg_len;
}

static enum si_sm_result vldc_event(struct si_sm_data *vldc, long time)
{
	int ret;
	static enum vldc_states last_printed = VLDC_STATE_PRINTME;
	bmc_vc_recv_t *rcv;

	if ((vldc_debug & VLDC_DEBUG_STATES) && (vldc->state != last_printed)) {
		dprintk(VLDC_DEBUG_STATES, "VLDC: state %d TO=%ld - %ld\n",
		       vldc->state, vldc->timeout, time);
		last_printed = vldc->state;
	}

	if (vldc->state != VLDC_STATE_IDLE && vldc->state < VLDC_STATE_PRINTME) {
		vldc->timeout -= time;
		if (vldc->timeout <= 0 && vldc->state < VLDC_STATE_RESETTING) {
			vldc->state = VLDC_STATE_IDLE;
			return SI_SM_HOSED;
		}
	}

	switch (vldc->state) {
	case VLDC_STATE_IDLE:
		if (vldc->read_count > 0) {
			/* already got data, don't know why they're asking again */
			rcv = (bmc_vc_recv_t *) vldc->read_data;
			if (rcv->magic_num != VC_MAGIC_NUM) {
				dprintk(VLDC_DEBUG_MSG, "%s: bad magic in idle, read_count=%d\n", __func__, vldc->read_count);
				return SI_SM_HOSED;
			}
			dprintk(VLDC_DEBUG_MSG, "%s: state idle, read_count=%d\n", __func__, vldc->read_count);
			return SI_SM_TRANSACTION_COMPLETE;
		}

		/* try to purge any residual data in the channel */
		ret = vldc_read(vldc->vldc_handle, vldc->read_data,
			       IPMI_MAX_MSG_LENGTH, NULL);
		if (ret > 0) {
			/* huh, some leftover crud? */
			rcv = (bmc_vc_recv_t *) vldc->read_data;
			if (rcv->magic_num != VC_MAGIC_NUM) {
				dprintk(VLDC_DEBUG_MSG, "%s: bad magic in idle crud, ret=%d\n", __func__, ret);
				vldc->state = VLDC_STATE_IDLE;
				return SI_SM_HOSED;
			}

			vldc->read_count = ret;
			vldc->state = VLDC_STATE_IDLE;
			dprintk(VLDC_DEBUG_STATES, "%s: state idle, ret=%d\n", __func__, ret);
			return SI_SM_TRANSACTION_COMPLETE;
		}

		return SI_SM_IDLE;

	case VLDC_STATE_XACTION_START:
		ret = vldc_write(vldc->vldc_handle, vldc->write_data,
				vldc->write_count, NULL);
		if (ret == -EAGAIN) {
			last_printed = VLDC_STATE_PRINTME;
			return SI_SM_CALL_WITH_TICK_DELAY;
		}
		dprintk(VLDC_DEBUG_MSG, "%s: start xaction, ret=%d\n", __func__, ret);
		if (ret == -EIO || ret == -EBADF) {
			pr_debug("%s: state xaction, LOST CONTACT WITH MC?\n",
				 __func__);
			vldc->state = VLDC_STATE_RESETTING;
			if (vldc->vldc_handle >= 0) {
				vldc_close(vldc->vldc_handle);
				vldc->vldc_handle = INVALID_IPMI_DEV;
			}
			queue_work(vldc_reset_wq, &(vldc->reset_work));
			return SI_SM_CALL_WITHOUT_DELAY;
		}
		if (ret <= 0) {
			vldc->state = VLDC_STATE_IDLE;
			return SI_SM_HOSED;
		}
		vldc->state = VLDC_STATE_READ_WAIT;
		return SI_SM_CALL_WITH_TICK_DELAY;

	case VLDC_STATE_READ_WAIT:
		ret = vldc_read(vldc->vldc_handle, vldc->read_data,
			       IPMI_MAX_MSG_LENGTH, NULL);
		if (ret == -EAGAIN || ret == 0) {
			last_printed = VLDC_STATE_PRINTME;
			return SI_SM_CALL_WITH_TICK_DELAY;
		}
		dprintk(VLDC_DEBUG_MSG, "%s: state read, ret=%d\n", __func__, ret);
		if (ret == -EIO || ret == -EBADF) {
			pr_debug("%s: state read, LOST CONTACT WITH MC?\n",
				 __func__);
			vldc->state = VLDC_STATE_RESETTING;
			if (vldc->vldc_handle >= 0) {
				vldc_close(vldc->vldc_handle);
				vldc->vldc_handle = INVALID_IPMI_DEV;
			}
			queue_work(vldc_reset_wq, &(vldc->reset_work));
			return SI_SM_CALL_WITHOUT_DELAY;
		}
		if (ret < 0) {
			vldc->state = VLDC_STATE_IDLE;
			return SI_SM_HOSED;
		}
		rcv = (bmc_vc_recv_t *) vldc->read_data;
		if (rcv->magic_num != VC_MAGIC_NUM) {
			dprintk(VLDC_DEBUG_MSG, "%s: bad magic in read, ret=%d\n", __func__, ret);
			vldc->state = VLDC_STATE_IDLE;
			return SI_SM_HOSED;
		}

		vldc->read_count = ret;
		vldc->state = VLDC_STATE_IDLE;
		return SI_SM_TRANSACTION_COMPLETE;

	case VLDC_STATE_RESETTING:
		return SI_SM_HOSED;

	case VLDC_STATE_RESET:
		vldc->state = VLDC_STATE_IDLE;
		return SI_SM_CALL_WITHOUT_DELAY;

	default:
		dprintk(VLDC_DEBUG_MSG, "unknown state %d", vldc->state);
		vldc->state = VLDC_STATE_IDLE;
		break;
	}

	return SI_SM_HOSED;
}

static void vldc_cleanup(struct si_sm_data *v)
{
	if (!v)
		return;

	v->state = VLDC_STATE_CLEANUP;
	if (vldc_reset_wq) {
		wake_up(&v->cleanup_waitq);
		flush_workqueue(vldc_reset_wq);
		destroy_workqueue(vldc_reset_wq);
		vldc_reset_wq = NULL;
	}
	vldc_close(v->vldc_handle);
	v->vldc_handle = INVALID_IPMI_DEV;
}

static int vldc_size(void)
{
	return sizeof(struct si_sm_data);
}

static int vldc_detect(struct si_sm_data *v)
{
	int dev_handle;

	if (v->vldc_handle >= 0) {
		pr_warn("%s: vldc_handle already present = %d\n",
		       __func__, v->vldc_handle);
		vldc_close(v->vldc_handle);
		v->vldc_handle = INVALID_IPMI_DEV;
	}

	dev_handle = vldc_open(VLDC_IPMI_DEV, VLDC_MODE_STREAM);
	if (dev_handle < 0) {
		pr_err("%s: vldc device open failed, vldc module may not be loaded\n",
		      __func__);
		return dev_handle;
	}

	v->vldc_handle = dev_handle;
	pr_info("%s: Successfully opened %s\n", __func__, VLDC_IPMI_DEV);

	if (vldc_reset_wq)
		return 0;
	vldc_reset_wq = alloc_workqueue("ipmi-vldc-reset-wq", WQ_UNBOUND, 1);
	if (vldc_reset_wq == NULL) {
		pr_err("%s: Reset workqueue creation failed\n", __func__);
		return -ENOMEM;
	}
	INIT_WORK(&(v->reset_work), vldc_reset_work);
	init_waitqueue_head(&v->cleanup_waitq);

	return 0;
}

static void vldc_reset_work(struct work_struct *work)
{
	struct si_sm_data *vldc;
	int reset_tries = 0;
	int ret;
	int reset_retry_time = VLDC_RESET_RETRY_STIME;

	vldc = container_of(work, struct si_sm_data, reset_work);

	if (vldc->state != VLDC_STATE_RESETTING) {
		pr_err("%s: Invalid state [%d]\n", __func__, vldc->state);
		return;
	}

	/* Try in each 15 seconds for reconnection for 25 times.
	 * If it is unsuccessful, then there is a good chance that something is
	 * horribly wrong with the ILOM. Increase the timeout to 1 minute
	 * afterwards.
	 */
	while (vldc_detect(vldc) != 0) {
		ret = wait_event_timeout(vldc->cleanup_waitq,
					 vldc->state == VLDC_STATE_CLEANUP,
					 reset_retry_time);
		if (ret > 0) {
			pr_info(
			"%s: clean up requested. Exit the retry process\n",
			__func__);
			break;
		}
		reset_tries++;
		if (reset_tries == VLDC_RESET_RETRY_SCOUNT)
			reset_retry_time = VLDC_RESET_RETRY_LTIME;
		pr_info("%s: Retry count [%d]\n", __func__, reset_tries);
	}
	pr_info("%s: VLDC reset completed\n", __func__);
	vldc->state = VLDC_STATE_RESET;
}

struct si_sm_handlers vldc_smi_handlers = {
	.version                = "ipmi_vldc v1.0",
	.init_data		= vldc_init_data,
	.start_transaction	= vldc_start_transaction,
	.get_result		= vldc_get_result,
	.event			= vldc_event,
	.detect			= vldc_detect,
	.cleanup		= vldc_cleanup,
	.size			= vldc_size,
};
