/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2020 Apertus Solutions, LLC
 *
 * Author(s):
 *      Daniel P. Smith <dpsmith@apertussolutions.com>
 *
 */

#ifndef _TPM_COMMON_H
#define _TPM_COMMON_H

#define TPM_MMIO_BASE		0xFED40000
#define TPM_MAX_LOCALITY	4

#define SHA1_SIZE	20
#define SHA256_SIZE	32
#define SHA384_SIZE	48
#define SHA512_SIZE	64
#define SM3256_SIZE	32

struct tpm_header {
	u16 tag;
	u32 size;
	u32 code;
} __packed;

#define TPM_INTERFACE_ID_0	0x30
#define TPM_TIS_INTF_ACTIVE	0x00
#define TPM_CRB_INTF_ACTIVE	0x01

struct tpm_interface_id {
	union {
		u32 val;
		struct {
			u32 interface_type:4;
			u32 interface_version:4;
			u32 cap_locality:1;
			u32 reserved1:4;
			u32 cap_tis:1;
			u32 cap_crb:1;
			u32 cap_if_res:2;
			u32 interface_selector:2;
			u32 intf_sel_lock:1;
			u32 reserved2:4;
			u32 reserved3:8;
		};
	};
} __packed;

#define TPM_INTF_CAPABILITY_0	0x14
#define TPM12_TIS_INTF_12	0x00
#define TPM12_TIS_INTF_13	0x02
#define TPM20_TIS_INTF_13	0x03

struct tpm_intf_capability {
	union {
		u32 val;
		struct {
			u32 data_avail_int_support:1;
			u32 sts_valid_int_support:1;
			u32 locality_change_int_support:1;
			u32 interrupt_level_high:1;
			u32 interrupt_level_low:1;
			u32 interrupt_edge_rising:1;
			u32 interrupt_edge_falling:1;
			u32 command_ready_int_support:1;
			u32 burst_count_static:1;
			u32 data_transfer_size_support:2;
			u32 reserved1:17;
			u32 interface_version:3;
			u32 reserved2:1;
		};
	};
} __packed;

void tpm_udelay(int loops);
void tpm_mdelay(int ms);

/*
 * Timeouts defined in Table 16 from the TPM2 PTP and
 * Table 15 from the PC Client TIS
 */

/* TPM Timeout A: 750ms */
static inline void timeout_a(void)
{
	tpm_mdelay(750);
}

/* TPM Timeout B: 2000ms */
static inline void timeout_b(void)
{
	tpm_mdelay(2000);
}

/* Timeouts C & D are different between 1.2 & 2.0 */
/* TPM1.2 Timeout C: 750ms */
static inline void tpm1_timeout_c(void)
{
	tpm_mdelay(750);
}

/* TPM1.2 Timeout D: 750ms */
static inline void tpm1_timeout_d(void)
{
	tpm_mdelay(750);
}

/* TPM2 Timeout C: 200ms */
static inline void tpm2_timeout_c(void)
{
	tpm_mdelay(200);
}

/* TPM2 Timeout D: 30ms */
static inline void tpm2_timeout_d(void)
{
	tpm_mdelay(30);
}

u8 tpm_read8(u32 field);
void tpm_write8(unsigned char val, u32 field);
u32 tpm_read32(u32 field);
void tpm_write32(unsigned int val, u32 field);

#endif
