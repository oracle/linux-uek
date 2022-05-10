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
* mbusResources.c
*
* DESCRIPTION:
*       Device-tree-database based implementation of
*       mvGetMbusResource()
*       /soc/ranges used to get resource addresses:
*       The record is
*       0:                                   window_id
*       soc/#address_cells:                  base (../#address_cells)
*       soc/#address_cells+#address_cells:   size (soc/#size_cells)
*
* DEPENDENCIES:
*       DTB database is used, so Linux 3.10+ required
*
*       $Revision: 1 $
*******************************************************************************/
#include <linux/version.h>
#include <linux/types.h>
#include <linux/of.h>
#include <linux/of_irq.h>
#include <linux/memory.h>
#include <linux/io.h>
#include <linux/pci.h>
#include <linux/sizes.h>
#include "mvResources.h"

#define CUSTOM(id) (((id) & 0xF0000000) >> 24)
#define TARGET_ATTR(id) (((id) & 0x0FFF0000) >> 16)

static int mvGetMbusResource(int resource, struct mv_resource_info *res)
{
	struct device_node *soc;
	int ranges_len;
	const __be32 *prop, *ranges;
	int i, addr_cells, c_addr_cells, c_size_cells, cell_count;

	soc = of_find_node_by_name(NULL, "soc");
	if (soc == NULL)
		return -1;
	ranges = of_get_property(soc, "ranges", &ranges_len);
	ranges_len /= sizeof(__be32);
	if (ranges == NULL)
		return -1;

	addr_cells = of_n_addr_cells(soc);
	prop = of_get_property(soc, "#address-cells", NULL);
	c_addr_cells = be32_to_cpup(prop);
	prop = of_get_property(soc, "#size-cells", NULL);
	c_size_cells = be32_to_cpup(prop);

	cell_count = addr_cells + c_addr_cells + c_size_cells;
	if (ranges_len % cell_count)
		return -1;

	for (i = 0; i < ranges_len; i += cell_count, ranges += cell_count) {
		u32 windowid;
		u64 base, size;

		windowid = of_read_number(ranges, 1);
		base = of_read_number(ranges + c_addr_cells, addr_cells);
		size = of_read_number(ranges + c_addr_cells + addr_cells, c_size_cells);

		if (CUSTOM(windowid)) {
			if (resource == MV_RESOURCE_MBUS_RUNIT) {

				res->start = base;
				res->size = size;
				return 0;
			}
		} else {
			static const struct {
				int target_attr;
				int resource;
			} target_map[] = {
				{ 0x300, MV_RESOURCE_MBUS_SWITCH },
				{ 0x800, MV_RESOURCE_MBUS_DFX },
				{ 0xb04, MV_RESOURCE_MBUS_PSS_PORTS },
				{ 0xa00, MV_RESOURCE_MBUS_DRAGONITE_ITCM },
				{ 0xa00, MV_RESOURCE_MBUS_DRAGONITE_DTCM },
				{ -1, -1 }
			};
			int c;
			for (c = 0; target_map[c].resource >= 0; c++) {
				if (TARGET_ATTR(windowid) != target_map[c].target_attr)
					continue;
				if (target_map[c].resource != resource)
					continue;
				res->start = base;
				res->size = size;
				if (resource == MV_RESOURCE_MBUS_DRAGONITE_ITCM)
					res->size = 0x10000; /* 64K */
				if (resource == MV_RESOURCE_MBUS_DRAGONITE_DTCM) {
					res->start += 0x04000000;
					res->size = 0x10000; /* 64K */
				}

				return 0;
			}
		}
	}

	return -1;
}

static int mvGetMbusInterrupt(struct mv_resource_info *res)
{
	struct device_node *prestera;
	int interrupt;
	prestera = of_find_node_by_path("/soc/prestera");
	if (prestera == NULL)
		return -1;
	interrupt = irq_of_parse_and_map(prestera, 0);
	if (interrupt == 0)
		return -1;

	res->start = (phys_addr_t)interrupt;
	res->size = (phys_addr_t)0;
	return 0;
}

int mvGetResourceInfo(int resource, struct mv_resource_info *res)
{
	u32 devId;
#ifdef __aarch64__
	struct pci_dev *cpu_dev = NULL;
#else
	void __iomem *ptr;
#endif
	switch (resource) {
	case MV_RESOURCE_DEV_ID:
#ifdef __aarch64__
		cpu_dev = pci_get_device(0x11ab, PCI_ANY_ID, cpu_dev);
		if (cpu_dev == NULL) {
			return 0;
		}
		devId = cpu_dev->device;
#else
		if (mvGetMbusResource(MV_RESOURCE_MBUS_RUNIT, res) < 0)
			return -1;
		ptr = ioremap(res->start, res->size);
		devId = le32_to_cpup(ptr + 0x1823c);
		iounmap(ptr);
#endif
		res->start = (phys_addr_t)devId;
		res->size = 0;
		return 0;

	case MV_RESOURCE_MBUS_RUNIT:
#ifdef __aarch64__
		res->start = 0xf2000000;
		res->size  = 0x00800000;
		return 0;
#endif
	case MV_RESOURCE_MBUS_SWITCH:
	case MV_RESOURCE_MBUS_DFX:
	case MV_RESOURCE_MBUS_PSS_PORTS:
	case MV_RESOURCE_MBUS_DRAGONITE_ITCM:
	case MV_RESOURCE_MBUS_DRAGONITE_DTCM:
		return mvGetMbusResource(resource, res);

	case MV_RESOURCE_MBUS_SWITCH_IRQ:
		return mvGetMbusInterrupt(res);
	}
	return -1;
}

struct mvMbusResource{
    unsigned int resource;
    unsigned int size;
    unsigned int offset;
};

static struct mvMbusResource mvMbusResourceAc5[] = {
    { MV_RESOURCE_MBUS_RUNIT,   SZ_4M + SZ_1M   , 0x80000000},
    { MV_RESOURCE_MBUS_SWITCH,  SZ_2G - SZ_4    , 0x00000000},
    { MV_RESOURCE_MBUS_DFX,     SZ_1M           , 0x84000000},
    { -1, 0, 0 }
};

static struct mvMbusResource mvMbusResourceAc5x[] = {
    { MV_RESOURCE_MBUS_RUNIT,   SZ_16M  , 0x7F000000},
    { MV_RESOURCE_MBUS_SWITCH,  SZ_1G   , 0x80000000},
    { MV_RESOURCE_MBUS_DFX,     SZ_1M   , 0x94400000},
    { -1, 0, 0 }
};

int mvGetSip6ResourceInfo(int resource, int device, struct mv_resource_info *res) {

    int i;
    u32 devId;
    struct pci_dev *cpu_dev = NULL;

    static struct mvMbusResource *mvMbusResource = NULL;

    if(device == MV_MBUS_DRV_DEV_ID_AC5) {
        mvMbusResource = mvMbusResourceAc5;
    } else if(device == MV_MBUS_DRV_DEV_ID_AC5X) {
        mvMbusResource = mvMbusResourceAc5x;
    } else {
        return -1;
    }

    switch (resource) {

        case MV_RESOURCE_DEV_ID:
            cpu_dev = pci_get_device(0x11ab, PCI_ANY_ID, cpu_dev);
            if (cpu_dev == NULL){
            return 0;
            }
            devId = cpu_dev->device;
            res->start = (phys_addr_t)devId;
            res->size = 0;
            return 0;

        case MV_RESOURCE_MBUS_SWITCH:
        case MV_RESOURCE_MBUS_RUNIT:
        case MV_RESOURCE_MBUS_DFX:

            for(i=0; i<(sizeof(mvMbusResourceAc5)/sizeof(struct mvMbusResource)); i++) {
                if(mvMbusResource[i].resource == resource) {
                    res->start = mvMbusResource[i].offset;
                    res->size = mvMbusResource[i].size;
                    return 0;
                }
            }
            break;

        case MV_RESOURCE_MBUS_SWITCH_IRQ:
            return mvGetMbusInterrupt(res);
            break;

        default:
            break;
    }

    return -1;
}

int mvGetDeviceId(void)
{
#ifdef __aarch64__
    struct resource *dev_id_reg_res;
    void *dev_id_reg;
    unsigned int dev_id = 0;

    dev_id_reg_res = request_mem_region(CNM_DEV_ID_REG_ADDR, CNM_DEV_ID_REG_SIZE, "CnM Device ID Register");
    if(dev_id_reg_res) {
        dev_id_reg = ioremap(CNM_DEV_ID_REG_ADDR, CNM_DEV_ID_REG_SIZE);
        if(dev_id_reg) {
            dev_id = ioread32(dev_id_reg);
            iounmap(dev_id_reg);
        }
        release_mem_region(CNM_DEV_ID_REG_ADDR, CNM_DEV_ID_REG_SIZE);
    }

    if((dev_id & CNM_DEV_ID_VAL_MASK) == CNM_DEV_ID_VAL_AC5) {
        pr_info("Detected AC5, DEV ID = %x\n",(dev_id & CNM_DEV_ID_VAL_MASK));
        return MV_MBUS_DRV_DEV_ID_AC5;
    } else if((dev_id & CNM_DEV_ID_VAL_MASK) == CNM_DEV_ID_VAL_AC5X) {
        pr_info("Detected AC5X, DEV ID = %x\n",(dev_id & CNM_DEV_ID_VAL_MASK));
        return MV_MBUS_DRV_DEV_ID_AC5X;
    } else {
        pr_info("Detected Unknown Device, DEV ID = %x\n", (dev_id & CNM_DEV_ID_VAL_MASK));
    }
#endif

    return MV_MBUS_DRV_DEV_ID_UNKNOWN;
}
