#ifndef	_CORESIGHT_QUIRKS_H
#define	_CORESIGHT_QUIRKS_H

/* Marvell OcteonTx CN9xxx ETM device */
#define OCTEONTX_CN9XXX_ETM			0x000cc210

/* Coresight ETM Hardware quirks */
#define CORESIGHT_QUIRK_ETM_SW_SYNC		0x1 /* No Hardware sync */
#define CORESIGHT_QUIRK_ETM_TREAT_ETMv43	0x2 /* ETMv4.2 as ETMv4.3 */

/* ETM sync insertion modes
 * 1. MODE_HW
 *    Sync insertion is done by hardware without any software intervention
 *
 * 2. MODE_SW_GLOBAL
 *    sync insertion runs from common timer handler on primary core
 *
 * 3. MODE_SW_PER_CORE
 *    sync insertion runs from per core timer handler
 *
 * When hardware doesn't support sync insertion, we fall back to software based
 * ones. Typically, GLOBAL mode would be preferred when the traced cores are
 * running performance critical applications and cannot be interrupted,
 * but at the same time there would be a small loss of trace data during the
 * insertion sequence as well.
 *
 * For the sake of simplicity, in GLOBAL mode, common timer handler is
 * always expected to run on primary core(core 0).
 */
#define SYNC_GLOBAL_CORE			0 /* Core 0 */

enum etm_sync_mode {
	SYNC_MODE_INVALID,
	SYNC_MODE_HW,
	SYNC_MODE_SW_GLOBAL,
	SYNC_MODE_SW_PER_CORE,
};

enum hw_state {
	USR_STOP,
	SW_STOP,
	USR_START,
};

u32 coresight_get_etm_quirks(unsigned int id);
int coresight_get_etm_sync_mode(void);

void etm4_enable_raw(struct coresight_device *csdev);
void etm4_disable_raw(struct coresight_device *csdev);
void coresight_etm_active_enable(int cpu);
void coresight_etm_active_disable(int cpu);
cpumask_t coresight_etm_active_list(void);
#endif
