// SPDX-License-Identifier: GPL-2.0
/*
 * Secure Launch early setup.
 *
 * Copyright (c) 2022, Oracle and/or its affiliates.
 */

#include <linux/delay.h>
#include <linux/pci.h>
#include <linux/printk.h>
#include <linux/slaunch.h>
#include <asm/cpufeatures.h>
#include <asm/msr.h>
#include <asm/pci_x86.h>
#include <asm/svm.h>

#define	DRTM_MBOX_READY_MASK		0x80000000
#define	DRTM_MBOX_TMR_INDEX_ID_MASK	0x0F000000
#define	DRTM_MBOX_CMD_MASK		0x00FF0000
#define	DRTM_MBOX_STATUS_MASK		0x0000FFFF

#define	DRTM_MBOX_CMD_SHIFT		16

#define	DRTM_NO_ERROR			0x00000000
#define	DRTM_NOT_SUPPORTED		0x00000001
#define	DRTM_LAUNCH_ERROR		0x00000002
#define	DRTM_TMR_SETUP_FAILED_ERROR	0x00000003
#define	DRTM_TMR_DESTROY_FAILED_ERROR	0x00000004
#define	DRTM_GET_TCG_LOGS_FAILED_ERROR	0x00000007
#define	DRTM_OUT_OF_RESOURCES_ERROR	0x00000008
#define	DRTM_GENERIC_ERROR		0x00000009
#define	DRTM_INVALID_SERVICE_ID_ERROR	0x0000000A
#define	DRTM_MEMORY_UNALIGNED_ERROR	0x0000000B
#define	DRTM_MINIMUM_SIZE_ERROR		0x0000000C
#define	DRTM_GET_TMR_DESCRIPTOR_FAILED	0x0000000D
#define	DRTM_EXTEND_OSSL_DIGEST_FAILED	0x0000000E
#define	DRTM_SETUP_NOT_ALLOWED		0x0000000F
#define	DRTM_GET_IVRS_TABLE_FAILED	0x00000010

#define DRTM_CMD_GET_CAPABILITY		0x1
#define	DRTM_CMD_TMR_SETUP		0x2
#define	DRTM_CMD_TMR_RELEASE		0x3
#define	DRTM_CMD_LAUNCH			0x4
#define	DRTM_CMD_GET_TCG_LOGS		0x7
#define	DRTM_CMD_TPM_LOCALITY_ACCESS	0x8
#define	DRTM_CMD_GET_TMR_DESCRIPTORS	0x9
#define	DRTM_CMD_ALLOCATE_SHARED_MEMORY	0xA
#define	DRTM_CMD_EXTEND_OSSL_DIGEST	0xB
#define	DRTM_CMD_GET_IVRS_TABLE_INFO	0xC

#define DRTM_TMR_INDEX_0		0
#define DRTM_TMR_INDEX_1		1
#define DRTM_TMR_INDEX_2		2
#define DRTM_TMR_INDEX_3		3
#define DRTM_TMR_INDEX_4		4
#define DRTM_TMR_INDEX_5		5
#define DRTM_TMR_INDEX_6		6
#define DRTM_TMR_INDEX_7		7

#define	DRTM_CMD_READY			0
#define	DRTM_RESPONSE_READY		1

bool slaunch_psp_early_setup;

static volatile u32  __iomem *c2pmsg_72;
static volatile u32  __iomem *c2pmsg_93;
static volatile u32  __iomem *c2pmsg_94;
static volatile u32  __iomem *c2pmsg_95;

static void slaunch_smn_register_read(u32 address, u32 *value)
{
	u32 val;

	val = address;
	pci_direct_conf1.write(0, 0, 0, 0xB8, 4, val);
	pci_direct_conf1.read(0, 0, 0, 0xBC, 4, &val);

	*value = val;
}

#define IOHC0NBCFG_SMNBASE		0x13B00000
#define PSP_BASE_ADDR_LO_SMN_ADDRESS	(IOHC0NBCFG_SMNBASE + 0x102E0)

static u32 slaunch_get_psp_bar_addr(void)
{
	u32 pspbaselo = 0;

	slaunch_smn_register_read(PSP_BASE_ADDR_LO_SMN_ADDRESS, &pspbaselo);

	/* Mask out the lower bits */
	pspbaselo &= 0xFFF00000;

	return pspbaselo;
}

static void slaunch_clear_c2pmsg_regs(void)
{
	if (c2pmsg_72)
		iounmap(c2pmsg_72);

	if (c2pmsg_93)
		iounmap(c2pmsg_93);

	if (c2pmsg_94)
		iounmap(c2pmsg_94);

	if (c2pmsg_95)
		iounmap(c2pmsg_95);

	c2pmsg_72 = NULL;
	c2pmsg_93 = NULL;
	c2pmsg_94 = NULL;
	c2pmsg_95 = NULL;
}

static bool slaunch_setup_c2pmsg_regs(void)
{
	phys_addr_t bar2 = (phys_addr_t)slaunch_get_psp_bar_addr();

	if (!bar2)
		return false;

	c2pmsg_72 = ioremap(bar2 + 0x10a20, 4);
	c2pmsg_93 = ioremap(bar2 + 0x10a74, 4);
	c2pmsg_94 = ioremap(bar2 + 0x10a78, 4);
	c2pmsg_95 = ioremap(bar2 + 0x10a7c, 4);

	if (!c2pmsg_72 || !c2pmsg_93 || !c2pmsg_94 || !c2pmsg_95) {
		slaunch_clear_c2pmsg_regs();
		return false;
	}

	return true;
}

static const char *slaunch_status_strings[] = {
	"DRTM_NO_ERROR",
	"DRTM_NOT_SUPPORTED",
	"DRTM_LAUNCH_ERROR",
	"DRTM_TMR_SETUP_FAILED_ERROR",
	"DRTM_TMR_DESTROY_FAILED_ERROR",
	"UNDEFINED",
	"UNDEFINED",
	"DRTM_GET_TCG_LOGS_FAILED_ERROR",
	"DRTM_OUT_OF_RESOURCES_ERROR",
	"DRTM_GENERIC_ERROR",
	"DRTM_INVALID_SERVICE_ID_ERROR",
	"DRTM_MEMORY_UNALIGNED_ERROR",
	"DRTM_MINIMUM_SIZE_ERROR",
	"DRTM_GET_TMR_DESCRIPTOR_FAILED",
	"DRTM_EXTEND_OSSL_DIGEST_FAILED",
	"DRTM_SETUP_NOT_ALLOWED",
	"DRTM_GET_IVRS_TABLE_FAILED"
};

static const char *slaunch_status_string(u32 status)
{
	if (status > DRTM_GET_IVRS_TABLE_FAILED) {
		return "UNDEFINED";
	}

	return slaunch_status_strings[status];
}

static bool slaunch_wait_for_psp_ready(u32 *status)
{
    int retry = 5;
    u32 reg_val = 0;

    if (*c2pmsg_72 == 0xFFFFFFFF)
	return false;

    while (--retry) {
        reg_val = *c2pmsg_72;

        if (reg_val & DRTM_MBOX_READY_MASK) {
            break;
        }

        /* TODO: select wait time appropriately */
        mdelay(100);
    };

    if (!retry) {
        return false;
    }

    if (status) {
        *status = reg_val & 0xffff;
    }

    return true;
}

static bool slaunch_tpm_locality_access(void)
{
	u32 status;

	*c2pmsg_72 = DRTM_CMD_TPM_LOCALITY_ACCESS << DRTM_MBOX_CMD_SHIFT;

	if (!slaunch_wait_for_psp_ready(&status)) {
		pr_err("Failed to execute DRTM_CMD_TPM_LOCALITY_ACCESS\n");
		return false;
	}

	if (status != DRTM_NO_ERROR) {
		pr_err("DRTM_CMD_TPM_LOCALITY_ACCESS failed - %s",
		       slaunch_status_string(status));
		return false;
	}

	return true;
}

static bool slaunch_tmr_release(void)
{
	u32 status;

	*c2pmsg_72 = DRTM_CMD_TMR_RELEASE << DRTM_MBOX_CMD_SHIFT;

	if (!slaunch_wait_for_psp_ready(&status)) {
		pr_err("Failed to execute DRTM_CMD_TMR_RELEASE_ACCESS\n");
		return false;
	}

	if (status != DRTM_NO_ERROR) {
		pr_err("DRTM_CMD_TMR_RELEASE failed - %s",
		       slaunch_status_string(status));
		return false;
	}

	return true;
}

void slaunch_psp_setup(void)
{
	if (slaunch_psp_early_setup)
		return;

	if ((slaunch_get_flags() & (SL_FLAG_ACTIVE | SL_FLAG_ARCH_SKINIT)) !=
	    (SL_FLAG_ACTIVE | SL_FLAG_ARCH_SKINIT)) {
		return;
	}

	if (!slaunch_setup_c2pmsg_regs())
		return;

	if (!slaunch_wait_for_psp_ready(NULL)) {
		pr_err("PSP not ready to take commands\n");
		return;
	}

	if (!slaunch_tmr_release())
		return;

	slaunch_psp_early_setup = true;
}

void slaunch_psp_finalize(void)
{
	printk("jaraman_debug: %s: Trying to lock TPM\n", __func__);

	if (!slaunch_tpm_locality_access()) {
		printk("jaraman_debug: %s: failed to lock TPM\n", __func__);
		return;
	}

	slaunch_clear_c2pmsg_regs();

}
EXPORT_SYMBOL(slaunch_psp_setup);
