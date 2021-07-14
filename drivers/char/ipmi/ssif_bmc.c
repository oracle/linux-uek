// SPDX-License-Identifier: GPL-2.0+
/*
 * The driver for BMC side of SSIF interface
 *
 * Copyright (c) 2021, Ampere Computing LLC
 *
 */

#include <linux/i2c.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/platform_device.h>
#include <linux/poll.h>
#include <linux/sched.h>
#include <linux/mutex.h>
#include <linux/spinlock.h>

#include "ssif_bmc.h"

static const char *state_to_string(enum ssif_state state)
{
	switch (state) {
	case SSIF_READY:
		return "SSIF_READY";
	case SSIF_START:
		return "SSIF_START";
	case SSIF_SMBUS_CMD:
		return "SSIF_SMBUS_CMD";
	case SSIF_REQ_RECVING:
		return "SSIF_REQ_RECVING";
	case SSIF_RES_SENDING:
		return "SSIF_RES_SENDING";
	case SSIF_BAD_SMBUS:
		return "SSIF_BAD_SMBUS";
	default:
		return "SSIF_STATE_UNKNOWN";
	}
}

/* Handle SSIF message that will be sent to user */
static ssize_t ssif_bmc_read(struct file *file, char __user *buf, size_t count, loff_t *ppos)
{
	struct ssif_bmc_ctx *ssif_bmc = to_ssif_bmc(file);
	struct ssif_msg msg;
	unsigned long flags;
	ssize_t ret;

	spin_lock_irqsave(&ssif_bmc->lock, flags);
	while (!ssif_bmc->request_available) {
		spin_unlock_irqrestore(&ssif_bmc->lock, flags);
		if (file->f_flags & O_NONBLOCK)
			return -EAGAIN;
		ret = wait_event_interruptible(ssif_bmc->wait_queue,
					       ssif_bmc->request_available);
		if (ret)
			return ret;
		spin_lock_irqsave(&ssif_bmc->lock, flags);
	}

	if (count < min_t(ssize_t, ssif_msg_len(&ssif_bmc->request), sizeof(struct ssif_msg))) {
		spin_unlock_irqrestore(&ssif_bmc->lock, flags);
		ret = -EINVAL;
	} else {
		count = min_t(ssize_t, ssif_msg_len(&ssif_bmc->request), sizeof(struct ssif_msg));
		memcpy(&msg, &ssif_bmc->request, count);
		ssif_bmc->request_available = false;
		spin_unlock_irqrestore(&ssif_bmc->lock, flags);

		ret = copy_to_user(buf, &msg, count);
	}

	return (ret < 0) ? ret : count;
}

/* Handle SSIF message that is written by user */
static ssize_t ssif_bmc_write(struct file *file, const char __user *buf, size_t count,
			      loff_t *ppos)
{
	struct ssif_bmc_ctx *ssif_bmc = to_ssif_bmc(file);
	struct ssif_msg msg;
	unsigned long flags;
	ssize_t ret;

	if (count > sizeof(struct ssif_msg))
		return -EINVAL;

	ret = copy_from_user(&msg, buf, count);
	if (ret)
		return ret;

	if (!msg.len || count < ssif_msg_len(&msg))
		return -EINVAL;

	spin_lock_irqsave(&ssif_bmc->lock, flags);
	while (ssif_bmc->response_in_progress) {
		spin_unlock_irqrestore(&ssif_bmc->lock, flags);
		if (file->f_flags & O_NONBLOCK)
			return -EAGAIN;
		ret = wait_event_interruptible(ssif_bmc->wait_queue,
					       !ssif_bmc->response_in_progress);
		if (ret)
			return ret;
		spin_lock_irqsave(&ssif_bmc->lock, flags);
	}

	memcpy(&ssif_bmc->response, &msg, count);
	ssif_bmc->is_singlepart_read = (ssif_msg_len(&msg) <= MAX_PAYLOAD_PER_TRANSACTION + 1);
	ssif_bmc->response_in_progress = true;

	if (ssif_bmc->client->adapter->algo->slave_enable)
		ret = ssif_bmc->client->adapter->algo->slave_enable(ssif_bmc->client, true);

	spin_unlock_irqrestore(&ssif_bmc->lock, flags);

	return (ret < 0) ? ret : count;
}

static int ssif_bmc_open(struct inode *inode, struct file *file)
{
	struct ssif_bmc_ctx *ssif_bmc = to_ssif_bmc(file);
	int ret = 0;

	spin_lock_irq(&ssif_bmc->lock);
	if (!ssif_bmc->running)
		ssif_bmc->running = 1;
	else
		ret = -EBUSY;
	spin_unlock_irq(&ssif_bmc->lock);

	return ret;
}

static unsigned int ssif_bmc_poll(struct file *file, poll_table *wait)
{
	struct ssif_bmc_ctx *ssif_bmc = to_ssif_bmc(file);
	unsigned int mask = 0;

	poll_wait(file, &ssif_bmc->wait_queue, wait);

	spin_lock_irq(&ssif_bmc->lock);
	/* The request is available, userspace application can get the request */
	if (ssif_bmc->request_available)
		mask |= POLLIN;

	spin_unlock_irq(&ssif_bmc->lock);

	return mask;
}

static int ssif_bmc_release(struct inode *inode, struct file *file)
{
	struct ssif_bmc_ctx *ssif_bmc = to_ssif_bmc(file);

	spin_lock_irq(&ssif_bmc->lock);
	ssif_bmc->running = 0;
	spin_unlock_irq(&ssif_bmc->lock);

	return 0;
}

/*
 * System calls to device interface for user apps
 */
static const struct file_operations ssif_bmc_fops = {
	.owner		= THIS_MODULE,
	.open		= ssif_bmc_open,
	.read		= ssif_bmc_read,
	.write		= ssif_bmc_write,
	.release	= ssif_bmc_release,
	.poll		= ssif_bmc_poll,
};

/* Called with ssif_bmc->lock held. */
static void complete_response(struct ssif_bmc_ctx *ssif_bmc)
{
	/* Invalidate response in buffer to denote it having been sent. */
	ssif_bmc->response.len = 0;
	ssif_bmc->response_in_progress = false;
	ssif_bmc->nbytes_processed = 0;
	ssif_bmc->remain_len = 0;
	wake_up_all(&ssif_bmc->wait_queue);
}

/* Called with ssif_bmc->lock held. */
static void handle_request(struct ssif_bmc_ctx *ssif_bmc)
{
	if (ssif_bmc->client->adapter->algo->slave_enable)
		ssif_bmc->client->adapter->algo->slave_enable(ssif_bmc->client, false);

	/* Request message is available to process */
	ssif_bmc->request_available = true;
	/*
	 * This is the new READ request.
	 */
	wake_up_all(&ssif_bmc->wait_queue);
}

static void set_multipart_response_buffer(struct ssif_bmc_ctx *ssif_bmc, u8 *val)
{
	u8 response_len = 0;
	int idx = 0;
	u8 data_len;

	data_len = ssif_bmc->response.len;
	switch (ssif_bmc->smbus_cmd) {
	case SSIF_IPMI_MULTIPART_READ_START:
		/*
		 * Read Start length is 32 bytes.
		 * Read Start transfer first 30 bytes of IPMI response
		 * and 2 special code 0x00, 0x01.
		 */
		*val = MAX_PAYLOAD_PER_TRANSACTION;
		ssif_bmc->remain_len = data_len - MAX_IPMI_DATA_PER_START_TRANSACTION;
		ssif_bmc->block_num = 0;

		ssif_bmc->response_buf[idx++] = 0x00; /* Start Flag */
		ssif_bmc->response_buf[idx++] = 0x01; /* Start Flag */
		ssif_bmc->response_buf[idx++] = ssif_bmc->response.netfn_lun;
		ssif_bmc->response_buf[idx++] = ssif_bmc->response.cmd;
		ssif_bmc->response_buf[idx++] = ssif_bmc->response.payload[0];

		response_len = MAX_PAYLOAD_PER_TRANSACTION - idx;

		memcpy(&ssif_bmc->response_buf[idx], &ssif_bmc->response.payload[1],
		       response_len);
		break;

	case SSIF_IPMI_MULTIPART_READ_MIDDLE:
		/*
		 * IPMI READ Middle or READ End messages can carry up to 31 bytes
		 * IPMI data plus block number byte.
		 */
		if (ssif_bmc->remain_len < MAX_IPMI_DATA_PER_MIDDLE_TRANSACTION) {
			/*
			 * This is READ End message
			 *  Return length is the remaining response data length
			 *  plus block number
			 *  Block number 0xFF is to indicate this is last message
			 *
			 */
			*val = ssif_bmc->remain_len + 1;
			ssif_bmc->block_num = 0xFF;
			ssif_bmc->response_buf[idx++] = ssif_bmc->block_num;
			response_len = ssif_bmc->remain_len;
			/* Clean the buffer */
			memset(&ssif_bmc->response_buf[idx], 0, MAX_PAYLOAD_PER_TRANSACTION - idx);
		} else {
			/*
			 * This is READ Middle message
			 *  Response length is the maximum SMBUS transfer length
			 *  Block number byte is incremented
			 * Return length is maximum SMBUS transfer length
			 */
			*val = MAX_PAYLOAD_PER_TRANSACTION;
			ssif_bmc->remain_len -= MAX_IPMI_DATA_PER_MIDDLE_TRANSACTION;
			response_len = MAX_IPMI_DATA_PER_MIDDLE_TRANSACTION;
			ssif_bmc->response_buf[idx++] = ssif_bmc->block_num;
			ssif_bmc->block_num++;
		}

		memcpy(&ssif_bmc->response_buf[idx],
		       ssif_bmc->response.payload + 1 + ssif_bmc->nbytes_processed,
		       response_len);
		break;

	default:
		/* Do not expect to go to this case */
		dev_err(&ssif_bmc->client->dev,
			"%s: Unexpected SMBus command 0x%x, aborting ...\n",
			__func__, ssif_bmc->smbus_cmd);
		ssif_bmc->aborting = true;
		break;
	}

	ssif_bmc->nbytes_processed += response_len;
}

/* Process the IPMI response that will be read by master */
static void handle_read_processed(struct ssif_bmc_ctx *ssif_bmc, u8 *val)
{
	u8 *buf;
	u8 pec_len, addr, len;
	u8 pec = 0;

	pec_len = ssif_bmc->pec_support ? 1 : 0;
	/* PEC - Start Read Address */
	addr = GET_8BIT_ADDR(ssif_bmc->client->addr);
	pec = i2c_smbus_pec(pec, &addr, 1);
	/* PEC - SSIF Command */
	pec = i2c_smbus_pec(pec, &ssif_bmc->smbus_cmd, 1);
	/* PEC - Restart Write Address */
	addr = addr | 0x01;
	pec = i2c_smbus_pec(pec, &addr, 1);

	if (ssif_bmc->is_singlepart_read) {
		/* Single-part Read processing */
		buf = (u8 *)&ssif_bmc->response;

		if (ssif_bmc->response.len && ssif_bmc->msg_idx < ssif_bmc->response.len) {
			ssif_bmc->msg_idx++;
			*val = buf[ssif_bmc->msg_idx];
		} else if (ssif_bmc->response.len && ssif_bmc->msg_idx == ssif_bmc->response.len) {
			ssif_bmc->msg_idx++;
			*val = i2c_smbus_pec(pec, buf, ssif_msg_len(&ssif_bmc->response));
		} else {
			*val = 0;
		}
		/* Invalidate response buffer to denote it is sent */
		if (ssif_bmc->msg_idx + 1 >= (ssif_msg_len(&ssif_bmc->response) + pec_len))
			complete_response(ssif_bmc);
	} else {
		/* Multi-part Read processing */
		switch (ssif_bmc->smbus_cmd) {
		case SSIF_IPMI_MULTIPART_READ_START:
		case SSIF_IPMI_MULTIPART_READ_MIDDLE:
			buf = (u8 *)&ssif_bmc->response_buf;
			*val = buf[ssif_bmc->msg_idx];
			ssif_bmc->msg_idx++;
			break;
		default:
			/* Do not expect to go to this case */
			dev_err(&ssif_bmc->client->dev,
				"%s: Unexpected SMBus command 0x%x, aborting ...\n",
				__func__, ssif_bmc->smbus_cmd);
			ssif_bmc->aborting = true;
			break;
		}

		len = (ssif_bmc->block_num == 0xFF) ?
		       ssif_bmc->remain_len + 1 : MAX_PAYLOAD_PER_TRANSACTION;
		if (ssif_bmc->msg_idx == (len + 1)) {
			pec = i2c_smbus_pec(pec, &len, 1);
			*val = i2c_smbus_pec(pec, ssif_bmc->response_buf, len);
		}
		/* Invalidate response buffer to denote last response is sent */
		if (ssif_bmc->block_num == 0xFF &&
		    ssif_bmc->msg_idx > (ssif_bmc->remain_len + pec_len)) {
			complete_response(ssif_bmc);
		}
	}
}

static void handle_write_received(struct ssif_bmc_ctx *ssif_bmc, u8 *val)
{
	u8 *buf = (u8 *)&ssif_bmc->request;

	if (ssif_bmc->msg_idx >= sizeof(struct ssif_msg))
		return;

	switch (ssif_bmc->smbus_cmd) {
	case SSIF_IPMI_SINGLEPART_WRITE:
		buf[ssif_bmc->msg_idx - 1] = *val;
		ssif_bmc->msg_idx++;

		break;
	case SSIF_IPMI_MULTIPART_WRITE_START:
		if (ssif_bmc->msg_idx == 1)
			ssif_bmc->request.len = 0;

		fallthrough;
	case SSIF_IPMI_MULTIPART_WRITE_MIDDLE:
		/* The len should always be 32 */
		if (ssif_bmc->msg_idx == 1 && *val != MAX_PAYLOAD_PER_TRANSACTION) {
			dev_warn(&ssif_bmc->client->dev,
				 "Warn: Invalid Multipart Write len, aborting ...");
			ssif_bmc->aborting = true;
		}

		fallthrough;
	case SSIF_IPMI_MULTIPART_WRITE_END:
		/* Multi-part write, 2nd byte received is length */
		if (ssif_bmc->msg_idx == 1) {
			if (*val > MAX_PAYLOAD_PER_TRANSACTION) {
				dev_warn(&ssif_bmc->client->dev,
					 "Warn: Invalid Multipart Write End len, aborting ...");
				ssif_bmc->aborting = true;
			}

			ssif_bmc->request.len += *val;
			ssif_bmc->recv_len = *val;

			/* request len should never exceeded 255 bytes */
			if (ssif_bmc->request.len > 255) {
				dev_warn(&ssif_bmc->client->dev,
					 "Warn: Invalid request len, aborting ...");
				ssif_bmc->aborting = true;
			}

		} else {
			buf[ssif_bmc->msg_idx - 1 +
			    ssif_bmc->request.len - ssif_bmc->recv_len]	= *val;
		}

		ssif_bmc->msg_idx++;

		break;
	default:
		/* Do not expect to go to this case */
		dev_err(&ssif_bmc->client->dev,
			"%s: Unexpected SMBus command 0x%x, aborting ...\n",
			__func__, ssif_bmc->smbus_cmd);
		ssif_bmc->aborting = true;
		break;
	}
}

static bool validate_request(struct ssif_bmc_ctx *ssif_bmc)
{
	u8 rpec = 0, cpec = 0;
	bool ret = true;
	u8 addr, index;
	u8 *buf;

	buf = (u8 *)&ssif_bmc->request;
	switch (ssif_bmc->smbus_cmd) {
	case SSIF_IPMI_SINGLEPART_WRITE:
		if ((ssif_bmc->msg_idx - 1) == ssif_msg_len(&ssif_bmc->request)) {
			/* PEC is not included */
			ssif_bmc->pec_support = false;
			ret = true;
			goto exit;
		}

		if ((ssif_bmc->msg_idx - 1) != (ssif_msg_len(&ssif_bmc->request) + 1)) {
			dev_err(&ssif_bmc->client->dev, "Error: Unexpected length received %d\n",
				ssif_msg_len(&ssif_bmc->request));
			ret = false;
			goto exit;
		}

		/* PEC is included */
		ssif_bmc->pec_support = true;
		rpec = buf[ssif_bmc->msg_idx - 2];
		addr = GET_8BIT_ADDR(ssif_bmc->client->addr);
		cpec = i2c_smbus_pec(cpec, &addr, 1);
		cpec = i2c_smbus_pec(cpec, &ssif_bmc->smbus_cmd, 1);
		cpec = i2c_smbus_pec(cpec, buf, ssif_msg_len(&ssif_bmc->request));
		if (rpec != cpec) {
			dev_err(&ssif_bmc->client->dev, "Bad PEC 0x%02x vs. 0x%02x\n", rpec, cpec);
			ret = false;
		}

		break;
	case SSIF_IPMI_MULTIPART_WRITE_START:
	case SSIF_IPMI_MULTIPART_WRITE_MIDDLE:
	case SSIF_IPMI_MULTIPART_WRITE_END:
		index = ssif_bmc->request.len - ssif_bmc->recv_len;
		if ((ssif_bmc->msg_idx - 1 + index) == ssif_msg_len(&ssif_bmc->request)) {
			/* PEC is not included */
			ssif_bmc->pec_support = false;
			ret = true;
			goto exit;
		}

		if ((ssif_bmc->msg_idx - 1 + index) != (ssif_msg_len(&ssif_bmc->request) + 1)) {
			dev_err(&ssif_bmc->client->dev, "Error: Unexpected length received %d\n",
				ssif_msg_len(&ssif_bmc->request));
			ret = false;
			goto exit;
		}

		/* PEC is included */
		ssif_bmc->pec_support = true;
		rpec = buf[ssif_bmc->msg_idx - 2 + index];
		addr = GET_8BIT_ADDR(ssif_bmc->client->addr);
		cpec = i2c_smbus_pec(cpec, &addr, 1);
		cpec = i2c_smbus_pec(cpec, &ssif_bmc->smbus_cmd, 1);
		cpec = i2c_smbus_pec(cpec, &ssif_bmc->recv_len, 1);
		/* As SMBus specification does not allow the length
		 * (byte count) in the Write-Block protocol to be zero.
		 * Therefore, it is illegal to have the last Middle
		 * transaction in the sequence carry 32-byte and have
		 * a length of ‘0’ in the End transaction.
		 * But some users may try to use this way and we should
		 * prevent ssif_bmc driver broken in this case.
		 */
		if (ssif_bmc->recv_len != 0)
			cpec = i2c_smbus_pec(cpec, buf + 1 + index, ssif_bmc->recv_len);

		if (rpec != cpec) {
			dev_err(&ssif_bmc->client->dev, "Bad PEC 0x%02x vs. 0x%02x\n", rpec, cpec);
			ret = false;
		}

		break;
	default:
		/* Do not expect to go to this case */
		dev_err(&ssif_bmc->client->dev, "%s: Unexpected SMBus command 0x%x, aborting ...\n",
			__func__, ssif_bmc->smbus_cmd);
		ret = false;
		break;
	}

exit:
	return ret;
}

static bool unsupported_smbus_cmd(u8 cmd)
{
	if (cmd == SSIF_IPMI_SINGLEPART_READ ||
	    cmd == SSIF_IPMI_SINGLEPART_WRITE ||
	    cmd == SSIF_IPMI_MULTIPART_WRITE_START ||
	    cmd == SSIF_IPMI_MULTIPART_WRITE_MIDDLE ||
	    cmd == SSIF_IPMI_MULTIPART_WRITE_END ||
	    cmd == SSIF_IPMI_MULTIPART_READ_START ||
	    cmd == SSIF_IPMI_MULTIPART_READ_MIDDLE)
		return false;

	return true;
}

static void process_smbus_cmd(struct ssif_bmc_ctx *ssif_bmc, u8 *val)
{
	/* SMBUS command can vary (single or multi-part) */
	ssif_bmc->smbus_cmd = *val;
	ssif_bmc->msg_idx++;

	if (unsupported_smbus_cmd(*val)) {
		dev_warn(&ssif_bmc->client->dev, "Warn: Unknown SMBus command, aborting ...");
		ssif_bmc->aborting = true;
	} else if (ssif_bmc->aborting &&
		   (*val == SSIF_IPMI_SINGLEPART_WRITE ||
		    *val == SSIF_IPMI_MULTIPART_WRITE_START)) {
		/* New request */
		dev_warn(&ssif_bmc->client->dev, "Warn: New request found, stop aborting ...");
		ssif_bmc->aborting = false;
	}
}

static void on_read_requested_event(struct ssif_bmc_ctx *ssif_bmc, u8 *val)
{
	if (ssif_bmc->state == SSIF_READY ||
	    ssif_bmc->state == SSIF_START ||
	    ssif_bmc->state == SSIF_REQ_RECVING ||
	    ssif_bmc->state == SSIF_RES_SENDING) {
		ssif_bmc->state = SSIF_BAD_SMBUS;
		dev_warn(&ssif_bmc->client->dev,
			 "Warn: %s unexpected READ REQUESTED in state=%s, aborting ...\n",
			 __func__, state_to_string(ssif_bmc->state));
		ssif_bmc->aborting = true;

	} else if (ssif_bmc->state == SSIF_SMBUS_CMD) {
		ssif_bmc->state = SSIF_RES_SENDING;
	}

	if (ssif_bmc->aborting || ssif_bmc->state != SSIF_RES_SENDING) {
		/* Abort by returning the last request with 0xFF as completion code */
		ssif_bmc->is_singlepart_read = true;
		ssif_bmc->response.len = 0x03;
		ssif_bmc->response.netfn_lun = ssif_bmc->request.netfn_lun | 4;
		ssif_bmc->response.cmd = ssif_bmc->request.cmd;
		memset(&ssif_bmc->response.payload[0], 0xFF, MAX_PAYLOAD_PER_TRANSACTION);
	}

	ssif_bmc->msg_idx = 0;
	if (ssif_bmc->is_singlepart_read)
		*val = ssif_bmc->response.len;
	else
		set_multipart_response_buffer(ssif_bmc, val);
}

static void on_read_processed_event(struct ssif_bmc_ctx *ssif_bmc, u8 *val)
{
	if (ssif_bmc->state == SSIF_READY ||
	    ssif_bmc->state == SSIF_START ||
	    ssif_bmc->state == SSIF_REQ_RECVING ||
	    ssif_bmc->state == SSIF_SMBUS_CMD) {
		dev_warn(&ssif_bmc->client->dev,
			 "Warn: %s unexpected READ PROCESSED in state=%s\n",
			 __func__, state_to_string(ssif_bmc->state));
		ssif_bmc->state = SSIF_BAD_SMBUS;
	}

	handle_read_processed(ssif_bmc, val);
}

static void on_write_requested_event(struct ssif_bmc_ctx *ssif_bmc, u8 *val)
{
	ssif_bmc->msg_idx = 0;

	if (ssif_bmc->state == SSIF_READY || ssif_bmc->state == SSIF_SMBUS_CMD) {
		ssif_bmc->state = SSIF_START;

	} else if (ssif_bmc->state == SSIF_START ||
		   ssif_bmc->state == SSIF_REQ_RECVING ||
		   ssif_bmc->state == SSIF_RES_SENDING) {
		dev_warn(&ssif_bmc->client->dev,
			 "Warn: %s unexpected WRITE REQUEST in state=%s\n",
			 __func__, state_to_string(ssif_bmc->state));
		ssif_bmc->state = SSIF_BAD_SMBUS;
	}
}

static void on_write_received_event(struct ssif_bmc_ctx *ssif_bmc, u8 *val)
{
	if (ssif_bmc->state == SSIF_READY || ssif_bmc->state == SSIF_RES_SENDING) {
		dev_warn(&ssif_bmc->client->dev,
			 "Warn: %s unexpected WRITE RECEIVED in state=%s\n",
			 __func__, state_to_string(ssif_bmc->state));
		ssif_bmc->state = SSIF_BAD_SMBUS;
	} else if (ssif_bmc->state == SSIF_START) {
		ssif_bmc->state = SSIF_SMBUS_CMD;
	} else if (ssif_bmc->state == SSIF_SMBUS_CMD) {
		ssif_bmc->state = SSIF_REQ_RECVING;
	}

	/* This is response sending state */
	if (ssif_bmc->state == SSIF_REQ_RECVING) {
		if (ssif_bmc->response_in_progress) {
			/*
			 * As per spec, it is generic management software or SSIF drivers to take
			 * care of issuing new request before the prior requests completed.
			 * So just abort everything here and wait for next new request
			 */
			dev_warn(&ssif_bmc->client->dev,
				 "Warn: SSIF new request with pending response, aborting ...");
			ssif_bmc->aborting = true;
			complete_response(ssif_bmc);
		}

		handle_write_received(ssif_bmc, val);
	} else if (ssif_bmc->state == SSIF_SMBUS_CMD) {
		process_smbus_cmd(ssif_bmc, val);
	}
}

static void on_stop_event(struct ssif_bmc_ctx *ssif_bmc, u8 *val)
{
	if (ssif_bmc->state == SSIF_READY ||
	    ssif_bmc->state == SSIF_START ||
	    ssif_bmc->state == SSIF_SMBUS_CMD) {
		dev_warn(&ssif_bmc->client->dev,
			 "Warn: %s unexpected SLAVE STOP in state=%s\n",
			 __func__, state_to_string(ssif_bmc->state));

	} else if (ssif_bmc->state == SSIF_BAD_SMBUS) {
		dev_warn(&ssif_bmc->client->dev,
			 "Warn: %s received SLAVE STOP from bad state=%s\n",
			 __func__, state_to_string(ssif_bmc->state));

	} else if (ssif_bmc->state == SSIF_REQ_RECVING) {
		/* A BMC that receives an invalid request drop the data for the write
		 * transaction and any further transactions (read or write) until
		 * the next valid read or write Start transaction is received
		 */
		if (!validate_request(ssif_bmc))
			ssif_bmc->aborting = true;

		if (!ssif_bmc->aborting &&
		    (ssif_bmc->smbus_cmd == SSIF_IPMI_SINGLEPART_WRITE ||
		     ssif_bmc->smbus_cmd == SSIF_IPMI_MULTIPART_WRITE_END))
			handle_request(ssif_bmc);
	}

	ssif_bmc->state = SSIF_READY;
	/* Reset message index */
	ssif_bmc->msg_idx = 0;
}

/*
 * Callback function to handle I2C slave events
 */
static int ssif_bmc_cb(struct i2c_client *client, enum i2c_slave_event event, u8 *val)
{
	unsigned long flags;
	struct ssif_bmc_ctx *ssif_bmc = i2c_get_clientdata(client);

	spin_lock_irqsave(&ssif_bmc->lock, flags);

	switch (event) {
	case I2C_SLAVE_READ_REQUESTED:
		on_read_requested_event(ssif_bmc, val);
		break;

	case I2C_SLAVE_WRITE_REQUESTED:
		on_write_requested_event(ssif_bmc, val);
		break;

	case I2C_SLAVE_READ_PROCESSED:
		on_read_processed_event(ssif_bmc, val);
		break;

	case I2C_SLAVE_WRITE_RECEIVED:
		on_write_received_event(ssif_bmc, val);
		break;

	case I2C_SLAVE_STOP:
		on_stop_event(ssif_bmc, val);
		break;

	default:
		dev_warn(&ssif_bmc->client->dev, "Warn: Unknown i2c slave event, aborting ...\n");
		ssif_bmc->aborting = true;
		break;
	}

	spin_unlock_irqrestore(&ssif_bmc->lock, flags);

	return 0;
}

static int ssif_bmc_probe(struct i2c_client *client, const struct i2c_device_id *id)
{
	struct ssif_bmc_ctx *ssif_bmc;
	int ret;

	ssif_bmc = devm_kzalloc(&client->dev, sizeof(*ssif_bmc), GFP_KERNEL);
	if (!ssif_bmc)
		return -ENOMEM;

	spin_lock_init(&ssif_bmc->lock);

	init_waitqueue_head(&ssif_bmc->wait_queue);
	ssif_bmc->request_available = false;
	ssif_bmc->response_in_progress = false;

	/* Register misc device interface */
	ssif_bmc->miscdev.minor = MISC_DYNAMIC_MINOR;
	ssif_bmc->miscdev.name = DEVICE_NAME;
	ssif_bmc->miscdev.fops = &ssif_bmc_fops;
	ssif_bmc->miscdev.parent = &client->dev;
	ret = misc_register(&ssif_bmc->miscdev);
	if (ret)
		goto out;

	ssif_bmc->client = client;
	ssif_bmc->client->flags |= I2C_CLIENT_SLAVE;

	/* Register I2C slave */
	i2c_set_clientdata(client, ssif_bmc);
	ret = i2c_slave_register(client, ssif_bmc_cb);
	if (ret) {
		misc_deregister(&ssif_bmc->miscdev);
		goto out;
	}

	return 0;
out:
	devm_kfree(&client->dev, ssif_bmc);
	return ret;
}

static int ssif_bmc_remove(struct i2c_client *client)
{
	struct ssif_bmc_ctx *ssif_bmc = i2c_get_clientdata(client);

	i2c_slave_unregister(client);
	misc_deregister(&ssif_bmc->miscdev);

	return 0;
}

static const struct of_device_id ssif_bmc_match[] = {
	{ .compatible = "ampere,ssif-bmc" },
	{ },
};

static const struct i2c_device_id ssif_bmc_id[] = {
	{ DEVICE_NAME, 0 },
	{ },
};

MODULE_DEVICE_TABLE(i2c, ssif_bmc_id);

static struct i2c_driver ssif_bmc_driver = {
	.driver         = {
		.name           = DEVICE_NAME,
		.of_match_table = ssif_bmc_match,
	},
	.probe          = ssif_bmc_probe,
	.remove         = ssif_bmc_remove,
	.id_table       = ssif_bmc_id,
};

module_i2c_driver(ssif_bmc_driver);

MODULE_AUTHOR("Quan Nguyen <quan@os.amperecomputing.com>");
MODULE_AUTHOR("Chuong Tran <chuong@os.amperecomputing.com>");
MODULE_DESCRIPTION("Linux device driver of the BMC IPMI SSIF interface.");
MODULE_LICENSE("GPL v2");
