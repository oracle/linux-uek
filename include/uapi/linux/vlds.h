/*
 * Copyright (C) 2015 Oracle Corporation
 */

#ifndef _UAPI_VLDS_H
#define _UAPI_VLDS_H

#include <linux/ioctl.h>
#include <linux/types.h>

#define	VLDS_DEV_DIR	"/dev/vlds"

#define	VLDS_DEV_DOMAIN_FILENAME_TAG	"host:"

/* String arguments to ioctl */
typedef struct vlds_string_arg {
	u64	vlds_strp;
	u64	vlds_strlen;
} vlds_string_t;
#define	VLDS_MAX_NAMELEN	256

/* Version (used by VLDS_IOCTL_SVC_REG) */
typedef struct vlds_ver {
	u16	vlds_major;
	u16	vlds_minor;
} vlds_ver_t;

/* Capability structure (used by VLDS_IOCTL_SVC_REG) */
typedef struct vlds_cap {
	vlds_string_t	vlds_service;
	vlds_ver_t	vlds_vers; /* max supported version */
} vlds_cap_t;

typedef struct vlds_svc_reg_arg {
	u64	vlds_hdlp;	/* DS Service Handle ptr. (returned) */
	u64	vlds_capp;	/* DS Capability Structure ptr. */
	u64	vlds_reg_flags;	/* DS reg flags */
} vlds_svc_reg_arg_t;

/* vlds_reg_flags */
#define	VLDS_REG_CLIENT		0x01	/* Register as client */
#define	VLDS_REG_EVENT		0x02	/* Event driven service - not polled */

typedef struct vlds_unreg_hdl_arg {
	u64	vlds_hdl;	/* DS Service Handle */
} vlds_unreg_hdl_arg_t;

typedef struct vlds_hdl_lookup_arg {
	vlds_string_t	vlds_service;	/* DS Service Name */
	u64	vlds_isclient;	/* DS Client flag */
	u64	vlds_hdlsp;	/* DS Handle array ptr */
	u64	vlds_maxhdls;	/* DS Max no. of hdls to return */
	u64	vlds_nhdlsp;	/* DS No. of hdls returned */
} vlds_hdl_lookup_arg_t;

typedef struct vlds_dmn_lookup_arg {
	u64	vlds_dhdlp;	/* DS Domain hdl ptr. (returned) */
	vlds_string_t	vlds_dname; /* DS Domain name (returned) */
} vlds_dmn_lookup_arg_t;

typedef struct vlds_send_msg_arg {
	u64	vlds_hdl;	/* DS Service Handle */
	u64	vlds_bufp;	/* buffer */
	u64	vlds_buflen;	/* message length/buffer size */
} vlds_send_msg_arg_t;
#define VLDS_MAX_SENDBUF_LEN	65535 /* 64k max buf size */

typedef struct vlds_recv_msg_arg {
	u64	vlds_hdl;	/* DS Service Handle */
	u64	vlds_bufp;	/* buffer */
	u64	vlds_buflen;	/* message length/buffer size */
	u64	vlds_msglenp;	/* ptr to returned message length */
} vlds_recv_msg_arg_t;

typedef struct vlds_hdl_state {
	u64	state;
	vlds_ver_t vlds_vers; /* negotiated version */
} vlds_hdl_state_t;

typedef struct vlds_hdl_get_state_arg {
	u64	vlds_hdl;	/* DS Service Handle */
	u64	vlds_statep;	/* Ptr to vlds_hdl_state */
} vlds_hdl_get_state_arg_t;
#define VLDS_HDL_STATE_NOT_YET_CONNECTED	0x0
#define VLDS_HDL_STATE_CONNECTED		0x1
#define VLDS_HDL_STATE_DISCONNECTED		0x2

typedef struct vlds_set_event_fd_arg {
	int	fd;		/* eventfd() fd used by process */
} vlds_set_event_fd_arg_t;

typedef struct vlds_get_next_event_arg {
	u64	vlds_hdlp;	/* Event Service Handle (returned) */
	u64	vlds_event_typep; /* Reg, Unreg or Data event? (returned) */
	u64	neg_versp;	/* reg event negotiated version (returned) */
	u64	vlds_bufp;	/* data event msg buffer (returned) */
	u64	vlds_buflen;	/* data event msg buffer size */
	u64	vlds_msglenp;	/* data event returned msg length (returned) */
} vlds_get_next_event_arg_t;
/* event types returned in event_typep field */
#define	VLDS_EVENT_TYPE_REG			0x0
#define	VLDS_EVENT_TYPE_UNREG			0x1
#define	VLDS_EVENT_TYPE_DATA			0x2

#define VLDS_IOCTL_BASE		'D'

#define	VLDS_IOCTL_SVC_REG	_IOWR(VLDS_IOCTL_BASE, 1, \
				     struct vlds_svc_reg_arg)
#define	VLDS_IOCTL_UNREG_HDL	_IOW(VLDS_IOCTL_BASE, 2, \
				     struct vlds_unreg_hdl_arg)
#define	VLDS_IOCTL_HDL_LOOKUP	_IOR(VLDS_IOCTL_BASE, 3, \
				     struct vlds_hdl_lookup_arg)
#define	VLDS_IOCTL_DMN_LOOKUP	_IOR(VLDS_IOCTL_BASE, 4, \
				     struct vlds_dmn_lookup_arg)
#define	VLDS_IOCTL_SEND_MSG	_IOW(VLDS_IOCTL_BASE, 5, \
				     struct vlds_send_msg_arg)
#define	VLDS_IOCTL_RECV_MSG	_IOR(VLDS_IOCTL_BASE, 6, \
				     struct vlds_recv_msg_arg)
#define	VLDS_IOCTL_HDL_GET_STATE _IOR(VLDS_IOCTL_BASE, 7, \
				     struct vlds_hdl_get_state_arg)

/* start Linux specific ioctls at 32 */
#define	VLDS_IOCTL_SET_EVENT_FD	_IOW(VLDS_IOCTL_BASE, 32, \
				     struct vlds_set_event_fd_arg)
#define	VLDS_IOCTL_UNSET_EVENT_FD _IO(VLDS_IOCTL_BASE, 33)
#define	VLDS_IOCTL_GET_NEXT_EVENT _IOR(VLDS_IOCTL_BASE, 34, \
				     struct vlds_get_next_event_arg)

#endif /* _UAPI_VLDS_H */


