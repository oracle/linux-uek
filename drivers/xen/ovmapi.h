/******************************************************************************
 *
 * Header file for the driver for receiving and sending messages for Oracle VM.
 *
 * Copyright (c) 2015, 2020, Oracle and/or its affiliates.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation; or, when distributed
 * separately from the Linux kernel or incorporated into other
 * software packages, subject to the following license:
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this source file (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy, modify,
 * merge, publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#ifndef OVMAPI_H
#define OVMAPI_H

#define IOCTL_XENPCI_REGISTER_EVENT_HANDLER       0x803
#define IOCTL_XENPCI_UNREGISTER_EVENT_HANDLER     0x805
#define IOCTL_XENPCI_READ_PARAMETER               0x80c
#define IOCTL_XENPCI_WRITE_PARAMETER              0x811
#define IOCTL_XENPCI_DELETE_PARAM                 0x812
#define IOCTL_XENPCI_SEND_MESSAGE                 0x80d
#define IOCTL_XENPCI_GET_PARAM_COUNT              0x80e
#define IOCTL_XENPCI_GET_PARAM_BY_INDEX           0x80f
#define IOCTL_XENPCI_GET_ALL_PARAM_NAMES          0x820
#define IOCTL_XENPCI_GET_PARAM_VALUE_SIZE_BY_NAME 0x822
#define IOCTL_XENPCI_MODIFY_EVENT_FILTER          0x823
#define IOCTL_XENPCI_POST_EVENT                   0x824
#define IOCTL_XENPCI_GET_EVENT_HEADER             0x825
#define IOCTL_XENPCI_GET_NEXT_EVENT_HEADER        0x826
#define IOCTL_XENPCI_GET_EVENT                    0x827
#define IOCTL_XENPCI_GET_NEXT_EVENT               0x806
#define IOCTL_XENPCI_DISCARD_EVENT                0x828
#define IOCTL_XENPCI_DISCARD_NEXT_EVENT           0x829

#define OVMM_MAX_CHARS_PER_SEQUENCE               2048
#define OVMM_MAX_NAME_LEN                         256
#define OVMM_MAX_VALUE_LEN                        8192

struct ovmapi_param {
	struct list_head list;
	char *name;
	unsigned long name_size;
	char *value;
	unsigned long value_size;
};

struct ovmapi_app_entry {
	struct list_head list;
	bool registered;
	unsigned long event_mask;
	struct list_head events_list;
	wait_queue_head_t event_waitqueue;
	struct fasync_struct *async_queue;
};

struct ovmapi_information {
	unsigned long parameter_count;
	struct list_head parameter_list;
	struct mutex parameter_mutex;
	struct list_head registered_apps_list;
	struct mutex apps_list_mutex;
	unsigned long last_read_message;
	unsigned long last_write_message;
	struct xenbus_watch dom0_message_watch;
	unsigned long event_counter;
};

/* User space command headers. */
#define OVMAPI_EVT_PHASE_PRE 0x0000
#define OVMAPI_EVT_PHASE_IMMED 0x0001
#define OVMAPI_EVT_PHASE_POST 0x0002

#define OVMAPI_EVT_SEVERITY_DEBUG 0x0000
#define OVMAPI_EVT_SEVERITY_INFO 0x0001
#define OVMAPI_EVT_SEVERITY_WARNING 0x0002
#define OVMAPI_EVT_SEVERITY_ERROR 0x0003
#define OVMAPI_EVT_SEVERITY_CRITICAL 0x0004
#define OVMAPI_EVT_SEVERITY_SYSTEM 0x0005

#define OVMAPI_EVT_SNAPSHOT 0x001
#define OVMAPI_EVT_MIGRATE 0x002
#define OVMAPI_EVT_SHUTDOWN 0x004
#define OVMAPI_EVT_RECONFIG 0x008
#define OVMAPI_EVT_IP_ADDRESS 0x010
#define OVMAPI_EVT_USER 0x20
#define OVMAPI_EVT_NEW_PARAM 0x40
#define OVMAPI_EVT_SYSTEM 0x80

#define OVMAPI_EVT_MORE_PROCESSING    0x4000

#define OVMAPI_MAX_PROC_NAME_LEN 256
#define OVMAPI_MAX_SUBSYS_NAME_LEN 256
#define OVMAPI_MAX_USER_DATA_LEN 4096

struct ovmapi_param_message {
	u32 index;
	char name[OVMM_MAX_NAME_LEN];
	u32 value_size; /* value size includes null terminator */
	char *value;
} __packed;

struct ovmapi_param_names {
	u32 total_names;
	char *name_entries; /* each name is OVMM_MAX_NAME_LEN long */
} __packed;

struct ovmapi_event_header {
	unsigned long event_id;
	u16 type;
	u16 severity;
	u16 phase;
	u16 size; /* size of real payload(struct ovmapi_event) */
} __packed;

#define OVMAPI_EVENT_MAXSIZE      (sizeof(struct ovmapi_event_header))
#define OVMAPI_EVENT_DATA_MAXSIZE (4096 - sizeof(struct ovmapi_event_header))

/* keep it under one page for effeciency */
struct ovmapi_event_more_processing {
	struct ovmapi_event_header header;
	unsigned long event_mask;
	char data[OVMAPI_EVENT_DATA_MAXSIZE - sizeof(unsigned long)];
} __packed;

struct ovmapi_event {
	struct ovmapi_event_header header;
	char payload[OVMAPI_EVENT_DATA_MAXSIZE];
} __packed;

struct ovmapi_event_list {
	struct list_head list;
	struct ovmapi_event event_entry;
};

struct ovmapi_event_subscription {
	unsigned long subscribe;
	unsigned long unsubscribe;
} __packed;

#endif /* OVMAPI_H */
