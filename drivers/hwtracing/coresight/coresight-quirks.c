// SPDX-License-Identifier: GPL-2.0
//
#include <asm/cputype.h>
#include <linux/coresight.h>
#include "coresight-priv.h"
#include "coresight-quirks.h"
#include "coresight-etm4x.h"

/* Raw enable/disable APIs for ETM sync insertion */
void etm4_enable_raw(struct coresight_device *csdev)
{
	struct etmv4_drvdata *drvdata = dev_get_drvdata(csdev->dev.parent);
	struct csdev_access *csa = &csdev->access;

	CS_UNLOCK(drvdata->base);

	/* Writing 0 to TRCOLSAR unlocks the trace registers */
	writel(0x0, drvdata->base + TRCOSLAR);

	/* Enable the trace unit */
	writel(1, drvdata->base + TRCPRGCTLR);

	coresight_timeout(csa, TRCSTATR, TRCSTATR_IDLE_BIT, 0);

	dsb(sy);
	isb();

	CS_LOCK(drvdata->base);
}
EXPORT_SYMBOL(etm4_enable_raw);

void etm4_disable_raw(struct coresight_device *csdev)
{
	struct etmv4_drvdata *drvdata = dev_get_drvdata(csdev->dev.parent);
	struct csdev_access *csa = &csdev->access;

	CS_UNLOCK(drvdata->base);
	/*
	 * Make sure everything completes before disabling, as recommended
	 * by section 7.3.77 ("TRCVICTLR, ViewInst Main Control Register,
	 * SSTATUS") of ARM IHI 0064D
	 */
	dsb(sy);
	isb();

	writel_relaxed(0x0, drvdata->base + TRCPRGCTLR);

	/* Wait for ETM to become stable */
	coresight_timeout(csa, TRCSTATR, TRCSTATR_PMSTABLE_BIT, 1);

	CS_LOCK(drvdata->base);
}
EXPORT_SYMBOL(etm4_disable_raw);

bool coresight_etm_has_hw_sync(void)
{
	/* Check if hardware supports sync insertion */
	if (midr_is_cpu_model_range(read_cpuid_id(),
				    MIDR_MRVL_OCTEONTX2_96XX,
				    MIDR_CPU_VAR_REV(0, 0),
				    MIDR_CPU_VAR_REV(3, 1)) ||
	    midr_is_cpu_model_range(read_cpuid_id(),
				    MIDR_MRVL_OCTEONTX2_95XX,
				    MIDR_CPU_VAR_REV(0, 0),
				    MIDR_CPU_VAR_REV(2, 0)))
		return false;
	else
		return true;
}

/* ETM quirks on OcteonTX */
u32 coresight_get_etm_quirks(unsigned int id)
{
	u32 quirks = 0; /* reset */

	if (id == OCTEONTX_CN9XXX_ETM)
		quirks |= CORESIGHT_QUIRK_ETM_TREAT_ETMv43;

	if (!coresight_etm_has_hw_sync())
		quirks |= CORESIGHT_QUIRK_ETM_SW_SYNC;

	return quirks;
}
EXPORT_SYMBOL(coresight_get_etm_quirks);

/* APIs for choosing the sync insertion mode */
int coresight_get_etm_sync_mode(void)
{
	/* Check if hardware supports sync insertion */
	if (coresight_etm_has_hw_sync())
		return SYNC_MODE_HW;

	/* Find the software based sync insertion mode */
#ifdef CONFIG_TASK_ISOLATION
	return SYNC_MODE_SW_GLOBAL;
#else
	return SYNC_MODE_SW_PER_CORE;
#endif
}
EXPORT_SYMBOL(coresight_get_etm_sync_mode);

/* Support functions for managing active ETM list used by
 * global mode sync insertion.
 *
 * Note: It is assumed that all accessor functions
 * on etm_active_list should be called in a atomic context
 */

static cpumask_t etm_active_list; /* Bitmap of active ETMs cpu wise */

void coresight_etm_active_enable(int cpu)
{
	cpumask_set_cpu(cpu, &etm_active_list);
}
EXPORT_SYMBOL(coresight_etm_active_enable);

void coresight_etm_active_disable(int cpu)
{
	cpumask_clear_cpu(cpu, &etm_active_list);
}
EXPORT_SYMBOL(coresight_etm_active_disable);

cpumask_t coresight_etm_active_list(void)
{
	return etm_active_list;
}
EXPORT_SYMBOL(coresight_etm_active_list);

/* ETR quirks on OcteonTX */
u32 coresight_get_etr_quirks(unsigned int id)
{
	u32 quirks = 0; /* reset */

	if (midr_is_cpu_model_range(read_cpuid_id(),
				    MIDR_MRVL_OCTEONTX2_96XX,
				    MIDR_CPU_VAR_REV(0, 0),
				    MIDR_CPU_VAR_REV(3, 1)) ||
	    midr_is_cpu_model_range(read_cpuid_id(),
				    MIDR_MRVL_OCTEONTX2_95XX,
				    MIDR_CPU_VAR_REV(0, 0),
				    MIDR_CPU_VAR_REV(2, 0)))
		quirks |= CORESIGHT_QUIRK_ETR_RESET_CTL_REG |
			  CORESIGHT_QUIRK_ETR_BUFFSIZE_8BX |
			  CORESIGHT_QUIRK_ETR_NO_STOP_FLUSH;

	/* Common across all Chip variants and revisions */
	if (id == OCTEONTX_CN9XXX_ETR) {
		quirks |= CORESIGHT_QUIRK_ETR_SECURE_BUFF |
			  CORESIGHT_QUIRK_ETR_FORCE_64B_DBA_RW;
		quirks |= coresight_get_etm_quirks(OCTEONTX_CN9XXX_ETM);
	}

	return quirks;
}
EXPORT_SYMBOL(coresight_get_etr_quirks);
