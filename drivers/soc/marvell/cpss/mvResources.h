/*******************************************************************************
Copyright (C) Marvell International Ltd. and its affiliates

This software file (the "File") is owned and distributed by Marvell
International Ltd. and/or its affiliates ("Marvell") under the following
alternative licensing terms.  Once you have made an election to distribute the
File under one of the following license alternatives, please (i) delete this
introductory statement regarding license alternatives, (ii) delete the two
license alternatives that you have not elected to use and (iii) preserve the
Marvell copyright notice above.


********************************************************************************
Marvell GPL License Option

If you received this File from Marvell, you may opt to use, redistribute and/or
modify this File in accordance with the terms and conditions of the General
Public License Version 2, June 1991 (the "GPL License"), a copy of which is
available along with the File in the license.txt file or by writing to the Free
Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 or
on the worldwide web at http://www.gnu.org/licenses/gpl.txt.

THE FILE IS DISTRIBUTED AS-IS, WITHOUT WARRANTY OF ANY KIND, AND THE IMPLIED
WARRANTIES OF MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE ARE EXPRESSLY
DISCLAIMED.  The GPL License provides additional details about this warranty
disclaimer.
********************************************************************************
* mvResources.h
*
* DESCRIPTION:
*       Resource numbers for mbusDriver
*       Should be never changed, just new resources can be added
*
* DEPENDENCIES:
*
*       $Revision: 1 $
*******************************************************************************/
#ifndef __mvResources_h__
#define __mvResources_h__

#ifdef __KERNEL__
#include <linux/types.h>

struct mv_resource_info {
	phys_addr_t start;
	phys_addr_t size;
};

int mvGetResourceInfo(int resource, struct mv_resource_info *res);
int mvGetSip6ResourceInfo(int resource, int device, struct mv_resource_info *res);
int mvGetDeviceId(void);
#endif

/* resources. The constants will be never changed, only new can be added */
#define MV_RESOURCE_ID_MASK             0x0000ffff
#define MV_RESOURCE_START               0x00010000
#define MV_RESOURCE_SIZE                0x00000000
#define MV_RESOURCE_DEV_ID              0 /* .start == device id */
#define MV_RESOURCE_MBUS_RUNIT          1 /* Control and Management area */
#define MV_RESOURCE_MBUS_SWITCH         2
#define MV_RESOURCE_MBUS_DFX            3
#define MV_RESOURCE_MBUS_SWITCH_IRQ     4 /* .start == irq */
#define MV_RESOURCE_MBUS_DRAGONITE_ITCM 5
#define MV_RESOURCE_MBUS_DRAGONITE_DTCM 6
#define MV_RESOURCE_MBUS_PSS_PORTS      7

#define IOCTL_MV_MBUS_DRV_MAGIC         'M'
#define IOCTL_MV_MBUS_DRV_SET_DEV_ID    _IOW(IOCTL_MV_MBUS_DRV_MAGIC, 1, int)

#define MV_MBUS_DRV_DEV_ID_UNKNOWN      0
#define MV_MBUS_DRV_DEV_ID_AC5          1
#define MV_MBUS_DRV_DEV_ID_AC5X         2

#define CNM_DEV_ID_REG_ADDR         0x7F90004C
#define CNM_DEV_ID_REG_SIZE         4
#define CNM_DEV_ID_VAL_AC5          0x000B4000
#define CNM_DEV_ID_VAL_AC5X         0x00098000
#define CNM_DEV_ID_VAL_MASK         0x000FF000

#endif /* __mvResources_h__ */
