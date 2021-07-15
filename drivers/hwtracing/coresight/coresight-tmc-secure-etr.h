#ifndef _CORESIGHT_TMC_SECURE_ETR_H
#define _CORESIGHT_TMC_SECURE_ETR_H

#include <linux/arm-smccc.h>

void tmc_etr_timer_start(void *data);
void tmc_etr_timer_init(struct tmc_drvdata *drvdata);
void tmc_etr_timer_cancel(void *data);
void tmc_flushstop_etm_off(void *data);
void tmc_flushstop_etm_on(void *data);
void tmc_etr_add_cpumap(struct tmc_drvdata *drvdata);

struct etr_secure_buf {
	struct device	*dev;
	dma_addr_t	daddr;
	dma_addr_t	secure_hwaddr;
	void		*vaddr;
	size_t		size;
};

/* SMC call ids for managing the secure trace buffer */

/* Args: x1 - size, x2 - cpu, x3 - llc lock flag
 * Returns: x0 - status, x1 - secure buffer address
 */
#define OCTEONTX_TRC_ALLOC_SBUF		0xc2000c05
/* Args: x1 - non secure buffer address, x2 - size */
#define OCTEONTX_TRC_REGISTER_DRVBUF	0xc2000c06
/* Args: x1 - dst(non secure), x2 - src(secure), x3 - size */
#define OCTEONTX_TRC_COPY_TO_DRVBUF	0xc2000c07
/* Args: x1 - secure buffer address, x2 - size */
#define OCTEONTX_TRC_FREE_SBUF		0xc2000c08
/* Args: x1 - non secure buffer address, x2 - size */
#define OCTEONTX_TRC_UNREGISTER_DRVBUF	0xc2000c09
/* Args: Nil
 * Returns: cpu trace buffer size
 */
#define OCTEONTX_TRC_GET_CPU_BUFSIZE    0xc2000c0a

/* SMC Calls for secure buffer management */
static inline int tmc_alloc_secbuf(struct tmc_drvdata *drvdata,
				   size_t len, dma_addr_t *s_paddr)
{
	struct arm_smccc_res res;

	arm_smccc_smc(OCTEONTX_TRC_ALLOC_SBUF, len, drvdata->cpu,
		      0, 0, 0, 0, 0, &res);
	if (res.a0 != SMCCC_RET_SUCCESS)
		return -EFAULT;

	*s_paddr = res.a1;
	return 0;
}

static inline int tmc_free_secbuf(struct tmc_drvdata *drvdata,
				  dma_addr_t s_paddr, size_t len)
{
	struct arm_smccc_res res;

	arm_smccc_smc(OCTEONTX_TRC_FREE_SBUF, s_paddr, len,
		      0, 0, 0, 0, 0, &res);
	return 0;
}

static inline int tmc_register_drvbuf(struct tmc_drvdata *drvdata,
				      dma_addr_t paddr, size_t len)
{
	struct arm_smccc_res res;

	arm_smccc_smc(OCTEONTX_TRC_REGISTER_DRVBUF, paddr, len,
		      0, 0, 0, 0, 0, &res);
	if (res.a0 != SMCCC_RET_SUCCESS)
		return -EFAULT;

	return 0;
}

static inline int tmc_unregister_drvbuf(struct tmc_drvdata *drvdata,
					dma_addr_t paddr, size_t len)
{
	struct arm_smccc_res res;

	arm_smccc_smc(OCTEONTX_TRC_UNREGISTER_DRVBUF, paddr, len,
		      0, 0, 0, 0, 0, &res);
	return 0;

}

static inline int tmc_copy_secure_buffer(struct etr_secure_buf *secure_buf,
					 uint64_t offset, size_t len)
{
	struct arm_smccc_res res;

	arm_smccc_smc(OCTEONTX_TRC_COPY_TO_DRVBUF, secure_buf->daddr + offset,
		      secure_buf->secure_hwaddr + offset, len, 0, 0, 0, 0, &res);
	if (res.a0 != SMCCC_RET_SUCCESS)
		return -EFAULT;

	return 0;
}

static inline int tmc_get_cpu_tracebufsize(struct tmc_drvdata *drvdata, u32 *len)
{
	struct arm_smccc_res res;

	arm_smccc_smc(OCTEONTX_TRC_GET_CPU_BUFSIZE, 0, 0, 0,
		      0, 0, 0, 0, &res);
	if (res.a0 != SMCCC_RET_SUCCESS)
		return -EFAULT;

	*len = (u32)res.a1;
	return 0;
}

#endif
