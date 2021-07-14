/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * The driver for BMC side of SSIF interface
 *
 * Copyright (c) 2021, Ampere Computing LLC
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
#ifndef __SSIF_BMC_H__
#define __SSIF_BMC_H__

#define DEVICE_NAME				"ipmi-ssif-host"

#define GET_8BIT_ADDR(addr_7bit)		(((addr_7bit) << 1) & 0xff)

/* A standard SMBus Transaction is limited to 32 data bytes */
#define MAX_PAYLOAD_PER_TRANSACTION		32

#define MAX_IPMI_DATA_PER_START_TRANSACTION	30
#define MAX_IPMI_DATA_PER_MIDDLE_TRANSACTION	31

#define SSIF_IPMI_SINGLEPART_WRITE		0x2
#define SSIF_IPMI_SINGLEPART_READ		0x3
#define SSIF_IPMI_MULTIPART_WRITE_START		0x6
#define SSIF_IPMI_MULTIPART_WRITE_MIDDLE	0x7
#define SSIF_IPMI_MULTIPART_WRITE_END		0x8
#define SSIF_IPMI_MULTIPART_READ_START		0x3
#define SSIF_IPMI_MULTIPART_READ_MIDDLE		0x9

#define MSG_PAYLOAD_LEN_MAX			252

struct ssif_msg {
	u8 len;
	u8 netfn_lun;
	u8 cmd;
	u8 payload[MSG_PAYLOAD_LEN_MAX];
} __packed;

static inline u32 ssif_msg_len(struct ssif_msg *ssif_msg)
{
	return ssif_msg->len + 1;
}

/*
 * SSIF internal states:
 *   SSIF_READY         0x00 : Ready state
 *   SSIF_START         0x01 : Start smbus transaction
 *   SSIF_SMBUS_CMD     0x02 : Received SMBus command
 *   SSIF_REQ_RECVING   0x03 : Receiving request
 *   SSIF_RES_SENDING   0x04 : Sending response
 *   SSIF_BAD_SMBUS     0x05 : Bad SMbus transaction
 */
enum ssif_state {
	SSIF_READY,
	SSIF_START,
	SSIF_SMBUS_CMD,
	SSIF_REQ_RECVING,
	SSIF_RES_SENDING,
	SSIF_BAD_SMBUS,
	SSIF_STATE_MAX
};

struct ssif_bmc_ctx {
	struct i2c_client	*client;
	struct miscdevice	miscdev;
	size_t			msg_idx;
	bool			pec_support;
	/* ssif bmc spinlock */
	spinlock_t		lock;
	wait_queue_head_t	wait_queue;
	u8			running;
	enum ssif_state		state;
	u8			smbus_cmd;
	/* Flag to abort current process */
	bool			aborting;
	/* Flag to identify a Multi-part Read Transaction */
	bool			is_singlepart_read;
	u8			nbytes_processed;
	u8			remain_len;
	u8			recv_len;
	/* Block Number of a Multi-part Read Transaction */
	u8			block_num;
	bool			request_available;
	bool			response_in_progress;
	/* Response buffer for Multi-part Read Transaction */
	u8			response_buf[MAX_PAYLOAD_PER_TRANSACTION];
	struct ssif_msg		response;
	struct ssif_msg		request;
};

static inline struct ssif_bmc_ctx *to_ssif_bmc(struct file *file)
{
	return container_of(file->private_data, struct ssif_bmc_ctx, miscdev);
}
#endif /* __SSIF_BMC_H__ */
