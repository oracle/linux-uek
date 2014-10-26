/* bnx2i_compat_uek3.h: Broadcom NetXtreme II iSCSI compatible header for UEK3
 *
 * Copyright (c) 2014 Oracle Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation.
 *
 * Written by: Joe Jin <joe.jin@oracle.com>
 */

#ifndef _BNX2I_COMPAT_UEK3_H_
#define _BNX2I_COMPAT_UEK3_H_

/* include/scsi/scsi_transport_iscsi.h)
 * iscsi_transport->get_ep_param
 */
#define _DEFINE_GET_EP_PARAM_

/* include/scsi/scsi_transport_iscsi.h
 * iscsi_transport->attr_is_visible
 */
#define _DEFINE_ATTR_IS_VISIBLE_

/* include/scsi/scsi_transport_iscsi.h
 * iscsi_transport->attr_is_visible return is umode_t
 */
#define _DEFINE_ATTR_IS_VISIBLE_UMODE_

/* include/scsi/iscsi_proto.h
 * struct iscsi_scsi_req
 */
#define _DEFINE_USE_SCSI_REQ_

#endif /* _BNX2I_COMPAT_UEK3_H_ */
