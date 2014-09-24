/*
 * Copyright (C) 2014 Oracle Corporation
 */

#ifndef _UAPI_DS_H
#define _UAPI_DS_H

#include <linux/ioctl.h>
#include <linux/types.h>

#define	DS_MAJOR_VERSION	1U
#define	DS_MINOR_VERSION	0U

#define	DS_SPTOK_TOKEN_LEN	20	/* SP token length */

#define	DS_MAX_SVC_NAME_LEN	256	/* Max length of DS service name */


typedef struct ds_sptok {
	__u32	ds_sptok_ipaddr;	/* IP address on SP */
	__u32	ds_sptok_portid;	/* Port number on SP */
	__u8	ds_sptok_token[DS_SPTOK_TOKEN_LEN];
} ds_sptok_t;

struct ds_data_t {
	__u32		major_version;
	__u32		minor_version;
	char		service_name[DS_MAX_SVC_NAME_LEN];
	ds_sptok_t	sp_tok;
};

#define DS_IOCTL_BASE		'D'

#define DS_SPTOK_GET	_IOR(DS_IOCTL_BASE, 1, struct ds_data_t)

#endif /* _UAPI_DS_H */
