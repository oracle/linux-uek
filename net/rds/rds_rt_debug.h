#ifndef _RDS_RT_DEBUG_H
#define _RDS_RT_DEBUG_H

extern u32 kernel_rds_rt_debug_bitmap;

enum {
	/* bit 0 ~ 19 are feature related bits */
	RDS_RTD_ERR			= 1 << 0,	/* 0x1    */
	RDS_RTD_ERR_EXT			= 1 << 1,	/* 0x2    */

	RDS_RTD_CM			= 1 << 3,	/* 0x8    */
	RDS_RTD_CM_EXT			= 1 << 4,	/* 0x10   */
	RDS_RTD_CM_EXT_P		= 1 << 5,	/* 0x20   */

	RDS_RTD_ACT_BND			= 1 << 7,	/* 0x80   */
	RDS_RTD_ACT_BND_EXT		= 1 << 8,	/* 0x100  */

	RDS_RTD_RCV			= 1 << 11,	/* 0x800  */
	RDS_RTD_RCV_EXT			= 1 << 12,	/* 0x1000 */

	RDS_RTD_SND			= 1 << 14,	/* 0x4000 */
	RDS_RTD_SND_EXT			= 1 << 15,	/* 0x8000 */
	RDS_RTD_FLOW_CNTRL		= 1 << 16,	/* 0x10000 */

	/* bit 20 ~ 31 are module specific bits */
	RDS_RTD_CORE			= 1 << 20,	/* 0x100000   */
	RDS_RTD_RDMA_IB			= 1 << 23,	/* 0x800000   */

	/* the following are placeholders for now */
	RDS_RTD_RDMA_IW			= 1 << 26,	/* 0x4000000  */
	RDS_RTD_TCP			= 1 << 28,	/* 0x10000000 */
};

#define rds_rtd_printk(format, arg...)		\
	trace_printk("%d: " format, __LINE__, ## arg)

#define rds_rtd(enabling_bit, format, arg...)				       \
	do {  if (likely(!(enabling_bit & kernel_rds_rt_debug_bitmap))) break; \
		 rds_rtd_printk(format, ## arg);		       \
	} while (0)

#endif /* _RDS_RT_DEBUG_H */

