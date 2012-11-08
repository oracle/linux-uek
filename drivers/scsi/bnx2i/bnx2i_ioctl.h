/* bnx2i_ioctl.h: Broadcom NetXtreme II iSCSI driver.
 *
 * Copyright (c) 2006 - 2012 Broadcom Corporation
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation.
 *
 * Written by: Anil Veerabhadrappa (anilgv@broadcom.com)
 * Maintained by: Eddie Wai (eddie.wai@broadcom.com)
 */
#ifndef _BNX2I_IOCTL_H
#define _BNX2I_IOCTL_H

#define MAX_SIG_SIZE		32
#define MAX_XPORT_NAME		16
#define MAX_DEV_NAME_SIZE	16

#define BNX2I_MGMT_SIGNATURE	"bnx2i-mgmt:1.0"



struct bnx2i_ioctl_header {
	char signature[MAX_SIG_SIZE];
	char xport_name[MAX_XPORT_NAME];
	char dev_name[MAX_DEV_NAME_SIZE];
};


struct bnx2i_get_port_count {
	struct bnx2i_ioctl_header hdr;
	unsigned int port_count;
};

struct bnx2i_set_port_num {
        struct bnx2i_ioctl_header hdr;
        unsigned int num_ports;
        unsigned short tcp_port[1];
};


#define BNX2I_IOCTL_GET_PORT_REQ	\
		_IOWR('I', 101, struct bnx2i_get_port_count)
#define BNX2I_IOCTL_SET_TCP_PORT	\
		_IOWR('I', 102, struct bnx2i_set_port_num)

#endif
