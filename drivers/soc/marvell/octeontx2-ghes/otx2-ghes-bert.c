/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Supports OcteonTX2 Generic Hardware Error Source (BED)
 * Boot Error Data (BED) from BERT table DT and ACPI
 *
 * Copyright (C) 2021 Marvell.
 */

#include <linux/io.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_device.h>
#include <linux/platform_device.h>
#include <linux/of_address.h>
#include <linux/arm_sdei.h>
#include <linux/uuid.h>
#include <linux/acpi.h>
#include <acpi/apei.h>
#include <linux/pci.h>
#include <linux/crash_dump.h>
#include "otx2-ghes-bert.h"
#include "otx2-sdei-ghes.h"

#define DRV_NAME	"bed-bert"

#define initerrmsg(fmt, ...) pr_err(DRV_NAME ":" fmt, __VA_ARGS__)
#define initdbgmsg(fmt, ...) pr_info(DRV_NAME ":" fmt, __VA_ARGS__)
#define dbgmsg(dev, ...) dev_info((dev), __VA_ARGS__)


#define BERT_TBL_OEM_ID	"OTX2    "
#define BERT_OEM_ID     "MRVL  "

#ifdef CONFIG_OF
static const struct of_device_id bed_bert_of_match[] = {
	{ .compatible = "marvell,bed-bert", },
	{},
};
MODULE_DEVICE_TABLE(of, bed_bert_of_match);
#endif

#ifdef CONFIG_ACPI
static const struct acpi_device_id bed_bert_acpi_match[] = {
	{ "BERT0001", 0 },
	{ },
};
MODULE_DEVICE_TABLE(acpi, bed_bert_acpi_match);
#endif

static int __init ghes_bed_acpi_match_resource(struct platform_device *pdev,
		struct mrvl_bed_source *bsrc)
{
	struct resource *res;

	// BERT
	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if (!res) {
		initerrmsg("%s ACPI unable get bert block\n", __func__);
		return -ENOENT;
	}
	initdbgmsg("%s Status BERT %s [%llx - %llx, %lx, %lx]\n", __func__,
			res->name, res->start, res->end, res->flags, res->desc);
	bsrc->bert_pa = res->start;
	bsrc->bert_sz = resource_size(res);
	initdbgmsg("BERT RING: 0x%llx/0x%llx\n", bsrc->bert_pa, bsrc->bert_sz);

	// Error Block Ring
	res = platform_get_resource(pdev, IORESOURCE_MEM, 2);
	if (!res) {
		initerrmsg("%s ACPI unable get ring block\n", __func__);
		return -ENOENT;
	}
	initdbgmsg("%s Status Ring %s [%llx - %llx, %lx, %lx]\n", __func__,
			res->name, res->start, res->end, res->flags, res->desc);
	bsrc->block_pa = res->start;
	bsrc->block_sz = resource_size(res);
	initdbgmsg("BERT RING: 0x%llx/0x%llx\n", bsrc->block_pa, bsrc->block_sz);

	return 0;
}

static int __init ghes_bed_of_match_resource(struct mrvl_bed_source *bsrc)
{
	struct device_node *of_node;
	struct device_node *child_node;
	const __be32 *res;
	u64 size;
	u64 base;

	of_node = of_find_matching_node_and_match(NULL, bed_bert_of_match, NULL);
	if (!of_node) {
		initerrmsg("BERT initialization no dev node %p\n", of_node);
		return -ENODEV;
	}

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

	bsrc->bert_pa = (phys_addr_t)base;
	bsrc->bert_sz = (phys_addr_t)size;

	res = of_get_address(child_node, 2, &size, NULL);
	if (!res)
		goto err;

	base = of_translate_address(child_node, res);
	if (base == OF_BAD_ADDR)
		goto err;

	bsrc->block_pa = (phys_addr_t)base;
	bsrc->block_sz = (phys_addr_t)size;

	initdbgmsg("BERT: 0x%llx/0x%llx  0x%llx/0x%llx\n",
			bsrc->bert_pa, bsrc->bert_sz, bsrc->block_pa, bsrc->block_sz);

	return 0;

err:
	initerrmsg("%s BERT unable get/translate address block\n", __func__);
	return -ENODEV;
}

static int __init ghes_bed_map_resource(struct device *dev, struct mrvl_bed_source *bsrc)
{
	if (pfn_valid(PHYS_PFN(bsrc->block_pa))) {
		bsrc->block_va = phys_to_virt(bsrc->block_pa);
	} else {
		if (!devm_request_mem_region(dev, bsrc->block_pa, bsrc->block_sz, "BERT")) {
			initerrmsg("Failure BERT request 0x%llx\n", bsrc->block_pa);
			return -ENODEV;
		}
		bsrc->block_va = devm_ioremap(dev, bsrc->block_pa, bsrc->block_sz);
		if (!bsrc->block_va) {
			initerrmsg("%s Unable to map Boot Error Data\n", __func__);
			return -ENODEV;
		}
	}
	initdbgmsg("%s BERT Ring block VA=0x%llx\n", __func__, (long long)bsrc->block_va);

	if (pfn_valid(PHYS_PFN(bsrc->bert_pa))) {
		bsrc->bert_va = phys_to_virt(bsrc->bert_pa);
	} else {
		if (!devm_request_mem_region(dev, bsrc->bert_pa, bsrc->bert_sz, "BERT")) {
			initerrmsg("Failure BERT request 0x%llx\n", bsrc->bert_pa);
			return -ENODEV;
		}
		bsrc->bert_va = devm_ioremap(dev, bsrc->bert_pa, bsrc->bert_sz);
		if (!bsrc->bert_va) {
			initerrmsg("%s Unable to map Boot Error Data\n", __func__);
			return -ENODEV;
		}
	}
	initdbgmsg("%s BERT Ring block VA=0x%llx\n", __func__, (long long)bsrc->bert_va);


	return 0;
}

static int __init ghes_bed_count_error(struct mrvl_bed_source *bsrc)
{
	struct otx2_ghes_err_ring *ring;
	size_t error_cnt = 0;

	ring = bsrc->block_va;
	ring->reg = OTX2_GHES_ERR_RING_SIG;

	if (!ring->size) {
		initerrmsg("%s BERT support disabled by firmware\n", __func__);
		return 0;
	}

	if (ring->head >= ring->tail)
		error_cnt = ring->head - ring->tail;
	else
		error_cnt = ring->size - (ring->tail - ring->head);

	bsrc->error_cnt = error_cnt;

	initdbgmsg("BED mem @ %llx (%llx PA), %llu B, error entries %ld\n",
		   (long long)bsrc->block_va, bsrc->block_pa,
		   (long long)bsrc->block_sz, error_cnt);

	return error_cnt;
}

static int __init ghes_bed_fetch_errors(struct mrvl_bed_source *bsrc)
{
	struct acpi_table_bert *bert_tbl;
	struct acpi_bert_region *bert_esb;
	struct bed_bert_mem_entry *bert_entries;
	struct otx2_ghes_err_ring *ring;
	struct acpi_hest_generic_data *hest_gen_data;
	struct bed_bert_mem_entry *bert_mem_entry;
	struct acpi_hest_generic_status *estatus;
	struct cper_sec_mem_err_old *mem_err;
	struct otx2_ghes_err_record *err_rec;
	u8 *p;
	u8 sum = 0;
	u32 idx = 0;

	ring = bsrc->block_va;

	bert_tbl = kzalloc(bsrc->bert_sz, GFP_KERNEL);

	if (!bert_tbl) {
		initerrmsg("Unable to allocate BERT data (0x%llx B)\n", bsrc->bert_sz);
		return -ENOMEM;
	}

	bert_esb = (struct acpi_bert_region *)(bert_tbl + 1);

	bert_entries = (struct bed_bert_mem_entry *)bert_esb;

	strcpy(bert_tbl->header.signature, ACPI_SIG_BERT);
	bert_tbl->header.length = sizeof(*bert_tbl);
	bert_tbl->header.revision = 1;
	bert_tbl->header.oem_revision = 1;
	strcpy(bert_tbl->header.oem_id, BERT_OEM_ID);
	strcpy(bert_tbl->header.oem_table_id, BERT_TBL_OEM_ID);
	strcpy(bert_tbl->header.asl_compiler_id, BERT_OEM_ID);
	bert_tbl->header.asl_compiler_revision = 1;

	p = (u8 *)&bert_tbl->header;
	while (p < (u8 *)(&bert_tbl->header + 1))
		sum += *p, p++;
	bert_tbl->header.checksum -= sum;

	bert_tbl->region_length = (bsrc->error_cnt * sizeof(*bert_entries));
	bert_tbl->address = bsrc->bert_pa + ((void *)bert_esb - (void *)bert_tbl);

	initdbgmsg("BERT: 0x%llx -> 0x%llx\n", bsrc->bert_pa, (long long)bsrc->bert_va);

	for (idx = 0; idx < bsrc->error_cnt; idx++) {
		err_rec = &ring->records[ring->tail];

		bert_mem_entry = &bert_entries[idx];

		estatus = &bert_mem_entry->estatus.hest;

		estatus->raw_data_length = 0;
		estatus->raw_data_offset = 0;
		estatus->data_length = sizeof(bert_mem_entry->gen_data);
		estatus->error_severity = err_rec->severity;

		hest_gen_data = &bert_mem_entry->gen_data;

		hest_gen_data->revision = 0x201; /* ACPI 4.x */
		if (err_rec->fru_text[0]) {
			hest_gen_data->validation_bits = ACPI_HEST_GEN_VALID_FRU_STRING;
			strncpy(hest_gen_data->fru_text, err_rec->fru_text,
				sizeof(hest_gen_data->fru_text));
		}

		hest_gen_data->error_severity = estatus->error_severity;
		memcpy((guid_t *)hest_gen_data->section_type,
		       &CPER_SEC_PLATFORM_MEM, sizeof(guid_t));

		hest_gen_data->error_data_length = sizeof(*mem_err);
		estatus->data_length += hest_gen_data->error_data_length;

		mem_err = &bert_mem_entry->mem_err;

		if (pfn_valid(PHYS_PFN(bsrc->block_pa)))
			memcpy(mem_err, &err_rec->u.mcc, sizeof(*mem_err));
		else
			memcpy_fromio(mem_err, &err_rec->u.mcc, sizeof(*mem_err));

		/*
		 * This simply needs the entry count to be non-zero.
		 * Set entry count to one (see ACPI_HEST_ERROR_ENTRY_COUNT).
		 */
		estatus->block_status = (1 << 4); /* i.e. one entry */

		if (++ring->tail >= ring->size)
			ring->tail = 0;
	}

	memcpy(bsrc->bert_va, bert_tbl, bsrc->bert_sz);
	kfree(bert_tbl);

	return 0;
}

/*
 * Boot Error Data probe BERT ring
 */
static int __init ghes_bert_probe(struct platform_device *pdev)
{
	struct mrvl_bed_source bed_src;
	struct device *dev = &pdev->dev;
	int ret = -ENODEV;

#ifdef CONFIG_CRASH_DUMP
	if (is_kdump_kernel())
#else
	#pragma message "CONFIG_CRASH_DUMP setting is required for this module"
	if (true)
#endif
		return ret;

	if (has_acpi_companion(dev)) {
		initdbgmsg("%s ACPI\n", __func__);
		ret = ghes_bed_acpi_match_resource(pdev, &bed_src);
	} else {
		initdbgmsg("%s Device Tree\n", __func__);
		ret = ghes_bed_of_match_resource(&bed_src);
	}
	if (ret)
		goto exit0;

	ret = ghes_bed_map_resource(dev, &bed_src);
	if (ret) {
		initerrmsg("%s Unable map BERT resource\n", __func__);
		goto exit0;
	}

	ret = ghes_bed_count_error(&bed_src);
	if (ret <= 0) {
		initdbgmsg("%s No BERT errors\n", __func__);
		goto exit1;
	}

	ret = ghes_bed_fetch_errors(&bed_src);
	if (ret) {
		initerrmsg("%s Unable setup BERT\n", __func__);
		goto exit1;
	}

	if (!has_acpi_companion(dev)) {
		bert_table_set(bed_src.bert_va);
	}

	if (has_acpi_companion(dev) && !pfn_valid(PHYS_PFN(bed_src.block_pa))) {
		devm_iounmap(dev, bed_src.block_va);
		devm_release_mem_region(dev, bed_src.block_pa, bed_src.block_sz);
	}

exit1:
	initdbgmsg("%s BERT setup done.\n", __func__);
	return ret;

exit0:
	initerrmsg("%s BERT setup failure %d\n", __func__, ret);
	return ret;
}

static void ghes_bert_shutdown(struct platform_device *pdev)
{
}

static int ghes_bert_remove(struct platform_device *pdev)
{
	return 0;
}


static const struct platform_device_id ghes_bert_pdev_match[] = {
	{ .name = DRV_NAME, },
	{},
};
MODULE_DEVICE_TABLE(platform, ghes_bert_pdev_match);

static struct platform_driver ghes_bert_drv_ops = {
	.driver = {
		.name             = DRV_NAME,
		.of_match_table   = bed_bert_of_match,
		.acpi_match_table = ACPI_PTR(bed_bert_acpi_match),
	},
	.probe    = ghes_bert_probe,
	.remove   = ghes_bert_remove,
	.shutdown = ghes_bert_shutdown,
	.id_table = ghes_bert_pdev_match,
};

static int __init ghes_bert_init(void)
{
	platform_driver_probe(&ghes_bert_drv_ops, ghes_bert_probe);
	return 0;
}

static void __exit ghes_bert_exit(void)
{
	platform_driver_unregister(&ghes_bert_drv_ops);
}

module_init(ghes_bert_init);
module_exit(ghes_bert_exit);

MODULE_DESCRIPTION("OcteonTX2 GHES BERT Module");
MODULE_LICENSE("GPL v2");
MODULE_ALIAS("platform:" DRV_NAME);
