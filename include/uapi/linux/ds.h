/*
 * Copyright (C) 2015 Oracle Corporation
 */

#ifndef _UAPI_DS_H
#define _UAPI_DS_H

#include <linux/ioctl.h>
#include <linux/types.h>

#define	DS_MAJOR_VERSION	1
#define	DS_MINOR_VERSION	0

#define	DS_SPTOK_TOKEN_LEN	20	/* SP token length */

#define	DS_MAX_DOM_NAME_LEN	256	/* Max length of DS domain name */
#define	DS_MAX_SVC_NAME_LEN	256	/* Max length of DS service name */

#define	DS_SP_NAME		"sp"	/* name assigned to the SP DS dev */

/*
 * Since the SP DS device does not have a domain handle assigned
 * in the MD (perhaps it should?!), we declare a well-known domain
 * handle here for the SP DS device.
 * Domain handles are assigned sequencially and so there should never
 * be a conflict with this value (the DS module checks for conflicts to
 * be sure). Assigning a well-known domain handle
 * to the SP DS device allows upper level interfaces to work without
 * modification since the interfaces rely on the domain handle
 * to distinguish specific DS entities.
 */
#define	DS_SP_DMN_HANDLE	0xFFFFFFFFFFFFFFFEUL

typedef struct ds_sptok {
	__u32	ds_sptok_ipaddr;	/* IP address on SP */
	__u32	ds_sptok_portid;	/* Port number on SP */
	__u8	ds_sptok_token[DS_SPTOK_TOKEN_LEN];
} ds_sptok_t;

typedef struct ds_ioctl_sptok_data {
	__u32		major_version;
	__u32		minor_version;
	char		service_name[DS_MAX_SVC_NAME_LEN];
	ds_sptok_t	sp_tok;
} ds_ioctl_sptok_data_t;

typedef struct ds_ioctl_pri_get {
	u64		bufp;		/* buffer to hold pri */
	u64		buflen;		/* buffer length */
	u64		pri_lenp;	/* pri length (returned) */
} ds_ioctl_pri_get_t;

#define DS_IOCTL_BASE		'D'

#define DS_SPTOK_GET	_IOR(DS_IOCTL_BASE, 1, ds_ioctl_sptok_data_t)
#define DS_PRI_GET	_IOR(DS_IOCTL_BASE, 2, ds_ioctl_pri_get_t)
#define DS_PRI_SET	_IOW(DS_IOCTL_BASE, 10, NULL)

#endif /* _UAPI_DS_H */
