// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2020 Apertus Solutions, LLC
 *
 * Author(s):
 *      Daniel P. Smith <dpsmith@apertussolutions.com>
 */

#include <linux/types.h>
#include <asm/io.h>
#include "tpm_common.h"

static noinline void tpm_io_delay(void)
{
	/* This is the default delay type in native_io_delay */
	asm volatile ("outb %al, $0x80");
}

void tpm_udelay(int loops)
{
	while (loops--)
		tpm_io_delay();	/* Approximately 1 us */
}

void tpm_mdelay(int ms)
{
	int i;

	for (i = 0; i < ms; i++)
		tpm_udelay(1000);
}

u8 tpm_read8(u32 field)
{
	return readb((void *)(u64)(TPM_MMIO_BASE | field));
}

void tpm_write8(unsigned char val, u32 field)
{
	writeb(val, (void *)(u64)(TPM_MMIO_BASE | field));
}

u32 tpm_read32(u32 field)
{
	return readl((void *)(u64)(TPM_MMIO_BASE | field));
}

void tpm_write32(u32 val, u32 field)
{
	writel(val, (void *)(u64)(TPM_MMIO_BASE | field));
}
