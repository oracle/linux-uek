/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Supports OcteonTX2 Generic Hardware Error Source (BED)
 * Boot Error Data
 *
 * Copyright (C) 2021 Marvell.
 */
#include <linux/module.h>
#include <linux/of_address.h>
#include <acpi/ghes.h>
#include <linux/cper.h>
#include "otx2-ghes-bert.h"

#define DRV_NAME	"bed-bert"

#define initerrmsg(fmt, ...) pr_err(DRV_NAME ":" fmt, __VA_ARGS__)
#define initdbgmsg(fmt, ...) pr_info(DRV_NAME ":" fmt, __VA_ARGS__)

#define BERT_TBL_OEM_ID	"OTX2    "
#define BERT_OEM_ID     "MRVL  "

static const struct of_device_id bed_bert_of_match[] = {
	{ .compatible = "marvell,bed-bert", },
	{},
};
MODULE_DEVICE_TABLE(of, bed_bert_of_match);

static const char * const severity_strs[] = {
	"recoverable",
	"fatal",
	"corrected",
	"info",
};

static const char * __init otx2_cper_mem_err_status_str(u64 status)
{
	switch ((status >> 8) & 0xff) {
	case  1:	return "Error detected internal to the component";
	case  4:	return "Storage error in DRAM memory";
	case  5:	return "Storage error in TLB";
	case  6:	return "Storage error in cache";
	case  7:	return "Error in one or more functional units";
	case  8:	return "Component failed self test";
	case  9:	return "Overflow or undervalue of internal queue";
	case 16:	return "Error detected in the bus";
	case 17:	return "Virtual address not found on IO-TLB or IO-PDIR";
	case 18:	return "Improper access error";
	case 19:	return "Access to a memory address which is not mapped to any component";
	case 20:	return "Loss of Lockstep";
	case 21:	return "Response not associated with a request";
	case 22:	return "Bus parity error - must also set the A, C, or D Bits";
	case 23:	return "Detection of a protocol error";
	case 24:	return "Detection of a PATH_ERROR";
	case 25:	return "Bus operation timeout";
	case 26:	return "A read was issued to data that has been poisoned";
	default:	return "Reserved";
	}
}

static const char * const mem_err_type_strs[] = {
	"unknown",
	"no error",
	"single-bit ECC",
	"multi-bit ECC",
	"single-symbol chipkill ECC",
	"multi-symbol chipkill ECC",
	"master abort",
	"target abort",
	"parity error",
	"watchdog timeout",
	"invalid address",
	"mirror Broken",
	"memory sparing",
	"scrub corrected error",
	"scrub uncorrected error",
	"physical memory map-out event",
};

static const char * __init otx2_cper_mem_err_type_str(unsigned int etype)
{
	return etype < ARRAY_SIZE(mem_err_type_strs) ?
		mem_err_type_strs[etype] : "unknown";
}

static void __init otx2_bert_print_all(struct acpi_bert_region *region, unsigned int region_len)
{
	struct acpi_hest_generic_status *estatus = (struct acpi_hest_generic_status *)region;
	struct acpi_hest_generic_data *gdata;
	struct cper_sec_mem_err *mem_err;
	int remain = region_len;
	u32 estatus_len = 0;
	int sec_no = 0;
	guid_t *sec_type;
	__u16 severity;
	char pfx[64];
	char buff[256];
	char *msg;
	int n = 0;

	while (remain >= sizeof(struct acpi_bert_region)) {
		estatus_len = sizeof(struct acpi_bert_region) + estatus->data_length;
		if (remain < estatus_len) {
			pr_err(FW_BUG "Truncated status block (length: %u).\n", estatus_len);
			break;
		}

		if (!estatus->block_status)
			break;

		severity = estatus->error_severity;

		pr_info_once("Error records from previous boot:\n");

		snprintf(pfx, sizeof(pfx), "%s ", HW_ERR);

		pr_info("%s event severity: %s\n", pfx,
			severity < ARRAY_SIZE(severity_strs) ?
					severity_strs[severity] : "unknown");

		apei_estatus_for_each_section(estatus, gdata) {

			severity = gdata->error_severity;
			pr_info("%s Error %d, type: %s\n", pfx, sec_no,
				severity < ARRAY_SIZE(severity_strs) ?
				severity_strs[severity] : "unknown");

			if (gdata->validation_bits & CPER_SEC_VALID_FRU_ID)
				pr_info("%s fru_id: %pUl\n", pfx, gdata->fru_id);

			if (gdata->validation_bits & CPER_SEC_VALID_FRU_TEXT)
				pr_info("%s fru_text: %.20s\n", pfx, gdata->fru_text);

			sec_type = (guid_t *)gdata->section_type;
			if (guid_equal(sec_type, &CPER_SEC_PLATFORM_MEM)) {

				msg = buff;
				mem_err = (struct cper_sec_mem_err *)(gdata + 1);
				pr_info("%s section_type: memory error\n", pfx);
				if (mem_err->validation_bits & CPER_MEM_VALID_ERROR_STATUS)
					pr_info("%s error_status: %s (0x%016llx)\n",
					pfx, otx2_cper_mem_err_status_str(mem_err->error_status),
					mem_err->error_status);
				if (mem_err->validation_bits & CPER_MEM_VALID_PA)
					pr_info("%s physical_address: 0x%016llx\n",
						pfx, mem_err->physical_addr);
				if (mem_err->validation_bits & CPER_MEM_VALID_PA_MASK)
					pr_info("%s physical_address_mask: 0x%016llx\n",
						pfx, mem_err->physical_addr_mask);
				if (mem_err->validation_bits & CPER_MEM_VALID_ERROR_TYPE)
					pr_info("%s error_type: %d, %s\n",
						pfx, mem_err->error_type,
						otx2_cper_mem_err_type_str(mem_err->error_type));
				if (mem_err->validation_bits & CPER_MEM_VALID_NODE)
					n += scnprintf(msg + n, sizeof(msg) - n,
							"node:%d ", mem_err->node);
				if (mem_err->validation_bits & CPER_MEM_VALID_CARD)
					n += scnprintf(msg + n, sizeof(msg) - n,
						"card:%d ", mem_err->card);
				if (mem_err->validation_bits & CPER_MEM_VALID_MODULE)
					n += scnprintf(msg + n, sizeof(msg) - n,
						"module:%d ", mem_err->module);
				if (mem_err->validation_bits & CPER_MEM_VALID_RANK_NUMBER)
					n += scnprintf(msg + n, sizeof(msg) - n,
						"rank:%d ", mem_err->rank);
				if (mem_err->validation_bits & CPER_MEM_VALID_BANK)
					n += scnprintf(msg + n, sizeof(msg) - n,
						"bank:%d ", mem_err->bank);
				if (mem_err->validation_bits & CPER_MEM_VALID_DEVICE)
					n += scnprintf(msg + n, sizeof(msg) - n,
						"device:%d ", mem_err->device);
				if (mem_err->validation_bits & CPER_MEM_VALID_ROW)
					n += scnprintf(msg + n, sizeof(msg) - n,
						"row:%d ", mem_err->row);
				if (mem_err->validation_bits & CPER_MEM_VALID_COLUMN)
					n += scnprintf(msg + n, sizeof(msg) - n,
						"column:%d ", mem_err->column);
				if (mem_err->validation_bits & CPER_MEM_VALID_BIT_POSITION)
					n += scnprintf(msg + n, sizeof(msg) - n,
						"bit_position:%d ", mem_err->bit_pos);
				if (mem_err->validation_bits & CPER_MEM_VALID_REQUESTOR_ID)
					n += scnprintf(msg + n, sizeof(msg) - n,
						"requestor_id:0x%016llx ", mem_err->requestor_id);
				if (mem_err->validation_bits & CPER_MEM_VALID_RESPONDER_ID)
					n += scnprintf(msg + n, sizeof(msg) - n,
						"responder_id:0x%016llx ", mem_err->responder_id);
				if (mem_err->validation_bits & CPER_MEM_VALID_TARGET_ID)
					n += scnprintf(msg + n, sizeof(msg) - n,
						"target_id:0x%016llx ", mem_err->target_id);
				pr_info("%s%s\n", pfx, buff);
			}
		}

		sec_no++;
		estatus->block_status = 0;

		/* sync shared memory */
		wmb();
		estatus = (void *)estatus + estatus_len;
		remain -= estatus_len;
	}
}

static int __init ghes_bed_of_match_resource(struct mrvl_bed_source *bsrc)
{
	struct device_node *of_node;
	struct device_node *child_node;
	const __be32 *res;
	u64 size;
	u64 base;

	of_node = of_find_matching_node_and_match(NULL, bed_bert_of_match, NULL);
	if (!of_node)
		return -ENODEV;

	child_node = of_get_next_available_child(of_node, NULL);
	if (!child_node) {
		initerrmsg("BERT initialization no child node %p\n", child_node);
		return -ENODEV;
	}

	res = of_get_address(child_node, 0, &size, NULL);
	if (!res)
		goto err;

	base = of_translate_address(child_node, res);
	if (base == OF_BAD_ADDR)
		goto err;

	bsrc->estatus_pa = (phys_addr_t)base;
	bsrc->estatus_sz = (phys_addr_t)size;

	initdbgmsg("BERT: 0x%llx/0x%llx\n", bsrc->estatus_pa, bsrc->estatus_sz);

	res = of_get_address(child_node, 2, &size, NULL);
	if (!res)
		goto err;

	base = of_translate_address(child_node, res);
	if (base == OF_BAD_ADDR)
		goto err;

	bsrc->ring_pa = (phys_addr_t)base;
	bsrc->ring_sz = (phys_addr_t)size;

	initdbgmsg("BERT: 0x%llx/0x%llx\n", bsrc->ring_pa, bsrc->ring_sz);

	return 0;

err:
	initerrmsg("%s BERT unable get/translate address block\n", __func__);
	return -ENODEV;
}

static int __init ghes_bed_map_resource(struct mrvl_bed_source *bsrc)
{
	if (!request_mem_region(bsrc->estatus_pa, bsrc->estatus_sz, "BERT"))
		return -ENODEV;

	bsrc->estatus_va = ioremap(bsrc->estatus_pa, bsrc->estatus_sz);
	if (!bsrc->estatus_va)
		return -ENODEV;

	initdbgmsg("BERT block VA=0x%llx\n", (long long)bsrc->estatus_va);

	if (!request_mem_region(bsrc->ring_pa, bsrc->ring_sz, "RING"))
		return -ENODEV;

	bsrc->ring_va = ioremap(bsrc->ring_pa, bsrc->ring_sz);
	if (!bsrc->ring_va)
		return -ENODEV;

	initdbgmsg("RING block VA=0x%llx\n", (long long)bsrc->ring_va);


	return 0;
}

static int __init ghes_bert_init(void)
{
	struct mrvl_bed_source bed_src;
	struct acpi_bert_region *estatus;
	struct otx2_ghes_err_ring *err_ring;
	void __iomem *blk;
	uint8_t *buff;
	int len = 0;
	int ret = -ENODEV;

	ret = ghes_bed_of_match_resource(&bed_src);
	if (ret)
		return ret;

	ret = ghes_bed_map_resource(&bed_src);
	if (ret) {
		initerrmsg("%s Unable map BERT resource\n", __func__);
		return ret;
	}

	err_ring = (struct otx2_ghes_err_ring *)bed_src.ring_va;
	estatus = (struct acpi_bert_region *)bed_src.estatus_va;

	len = sizeof(struct bed_bert_mem_entry) * err_ring->size;
	buff = kzalloc(len, GFP_KERNEL);
	if (!buff) {
		initerrmsg("%s Unable alloc bert\n", __func__);
		return ret;
	}
	memcpy_fromio(buff, estatus, len);

	estatus = (struct acpi_bert_region *)buff;

	otx2_bert_print_all(estatus, len);

	blk = (void __iomem *)(((uint8_t *)bed_src.estatus_va));
	memset_io(blk, 0, len);

	kfree(buff);

	return 0;
}

late_initcall(ghes_bert_init);

MODULE_DESCRIPTION("OcteonTX2 GHES BERT Module");
MODULE_LICENSE("GPL v2");
MODULE_ALIAS("platform:" DRV_NAME);
