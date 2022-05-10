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
* mbusDriver.c
*
* DESCRIPTION:
*       mvMbusDrv - driver to read hardware info of internally connected PP
*                   See mvResources.h for resource IDs
*                   Usage:
*                       fd = open("/dev/mvMbusDrv", O_RDWR);
*                       // read info:
*                       //     resource_id: MV_RESOURCE_DEV_ID,
*                       //                  MV_RESOURCE_MBUS_RUNIT, etc
*                       //     addr_size_sel: MV_RESOURCE_START,
*                       //                  MV_RESOURCE_SIZE
*                       //
*                       //     Here BOARD_ID and SWITCH_IRQ are returned
*                       //     in start
*                       unsigned long long res;
*                       lseek(fd, resource_id | addr_size_sel, 0);
*                       read(fd, &res, sizeof(res));
*
*                       // Map resource to user-space:
*                       vaddr = mmap(NULL, maxSize, PROT_READ | PROT_WRITE,
*                               MAP_SHARED, fd,
*                               (off_t)(MV_RESOURCE_MBUS_RUNIT << SYSTEM_PAGE_SHIFT));
*
* DEPENDENCIES:
*
*       $Revision: 1 $
*******************************************************************************/
#define MV_DRV_NAME     "mvMbusDrv"
#define MV_DRV_MAJOR    244
#define MV_DRV_MINOR    5
#define MV_DRV_FOPS     mvMbusDrv_fops
#define MV_DRV_POSTINIT mvMbusDrv_postInitDrv

#include "mvDriverTemplate.h"

#include <linux/mm.h>
#include <linux/of.h>

#include "mvResources.h"

int mvMbusDrvDevId = 0;

static int mvMbusDrv_mmap(struct file * file, struct vm_area_struct *vma)
{
	struct mv_resource_info res = {0};
	switch ((int)vma->vm_pgoff) {
	case MV_RESOURCE_MBUS_RUNIT:
	case MV_RESOURCE_MBUS_SWITCH:
	case MV_RESOURCE_MBUS_DFX:
	case MV_RESOURCE_MBUS_DRAGONITE_ITCM:
	case MV_RESOURCE_MBUS_DRAGONITE_DTCM:
	case MV_RESOURCE_MBUS_PSS_PORTS:
        if((mvMbusDrvDevId == MV_MBUS_DRV_DEV_ID_AC5) || 
            (mvMbusDrvDevId == MV_MBUS_DRV_DEV_ID_AC5X)) {
		    if (mvGetSip6ResourceInfo((int)vma->vm_pgoff, mvMbusDrvDevId, &res) < 0)
			    return -ENXIO;
        } else {
		    if (mvGetResourceInfo((int)vma->vm_pgoff, &res) < 0)
			    return -ENXIO;
        }
		break;
	default:
		return -ENXIO;
	}
	/* VM_IO for I/O memory */
	vma->vm_flags |= VM_IO;
	/* disable caching on mapped memory */
	vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
	vma->vm_pgoff = res.start >> PAGE_SHIFT;

	printk("remap_pfn_range(phys=0x%0llx, PAGE_SHIFT=%x, 0x%lx, 0x%lx, 0x%lx, 0x%lx)\n",
		 (unsigned long long)res.start, PAGE_SHIFT,
		 (unsigned long)(vma->vm_start), (unsigned long)(vma->vm_pgoff),
		 (unsigned long)(vma->vm_end - vma->vm_start),
		 *((unsigned long*)(&(vma->vm_page_prot))));

	if (remap_pfn_range(vma, vma->vm_start, vma->vm_pgoff, vma->vm_end - vma->vm_start,
				vma->vm_page_prot))
	{
		printk("remap_pfn_range failed\n");
		return 1;
	}

	return 0;
}

static ssize_t mvMbusDrv_read(struct file *f, char *buf, size_t siz, loff_t *off)
{
	struct mv_resource_info res = {0};
	unsigned long long rv;

#if 0
	printk("mvMbusDrv_read(): siz=%d, off=%d\n",siz, (int)f->f_pos);
#endif
	if (siz < sizeof(rv))
		return -EINVAL;
    if((mvMbusDrvDevId == MV_MBUS_DRV_DEV_ID_AC5) || 
        (mvMbusDrvDevId == MV_MBUS_DRV_DEV_ID_AC5X)) {
		if (mvGetSip6ResourceInfo(((int)f->f_pos) & MV_RESOURCE_ID_MASK, mvMbusDrvDevId, &res) < 0)
			return -ENXIO;
    } else {
		if (mvGetResourceInfo(((int)f->f_pos) & MV_RESOURCE_ID_MASK, &res) < 0)
			return -ENXIO;
    }

	if (((int)f->f_pos) & MV_RESOURCE_START)
		rv = (unsigned long long)res.start;
	else
		rv = (unsigned long long)res.size;

	if (copy_to_user(buf, &rv, sizeof(rv)))
		return -EFAULT;
	return sizeof(rv);
}

static loff_t mvMbusDrv_llseek(struct file *f, loff_t off, int w)
{
	f->f_pos = off;
	return off;
}
static int mvMbusDrv_open(struct inode *inode, struct file *file)
{
	file->private_data = NULL;
	file->f_pos = 0;

	return 0;
}

static int mvMbusDrv_release(struct inode *inode, struct file *file)
{
	return 0;
}

static struct file_operations mvMbusDrv_fops = {
	.mmap           = mvMbusDrv_mmap,
	.read           = mvMbusDrv_read,
	.llseek         = mvMbusDrv_llseek,
	.open           = mvMbusDrv_open,
	.release        = mvMbusDrv_release, /* A.K.A close */
};

static void mvMbusDrv_postInitDrv(void)
{
	printk(KERN_DEBUG "mvMbusDrv major=%d minor=%d\n", major, minor);
	mvMbusDrvDevId = mvGetDeviceId();
}
