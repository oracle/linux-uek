/*
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (C) 2004-2007 Cavium Networks
 */
#include <linux/module.h>
#include <linux/init.h>
#include <linux/interrupt.h>

#include <asm/octeon/octeon.h>


#ifdef CONFIG_CAVIUM_GDB

static irqreturn_t interrupt_debug_char(int cpl, void *dev_id)
{
	unsigned long lsrval;
	unsigned long tmp;

	lsrval = cvmx_read_csr(CVMX_MIO_UARTX_LSR(OCTEON_DEBUG_UART));
	if (lsrval & 1) {
#ifdef CONFIG_KGDB
		/*
		 * The Cavium EJTAG bootmonitor stub is not compatible
		 * with KGDB.  We should never get here.
		 */
#error Illegal to use both CONFIG_KGDB and CONFIG_CAVIUM_GDB
#endif
		/*
		 * Pulse MCD0 signal on Ctrl-C to stop all the
		 * cores. Also set the MCD0 to be not masked by this
		 * core so we know the signal is received by
		 * someone.
		 */
		octeon_write_lcd("brk");
		asm volatile ("dmfc0 %0, $22\n\t"
			      "ori   %0, %0, 0x10\n\t"
			      "dmtc0 %0, $22" : "=r" (tmp));
		octeon_write_lcd("");
		return IRQ_HANDLED;
	}
	return IRQ_NONE;
}

/* Enable uart1 interrupts for debugger Control-C processing */

static int octeon_setup_debug_uart(void)
{
	unsigned int hwirq;
	int irq;

	if (octeon_has_feature(OCTEON_FEATURE_CIU3))
		hwirq = 0x8000 + (0x40 * OCTEON_DEBUG_UART);
	else if (OCTEON_IS_MODEL(OCTEON_CN68XX))
		hwirq = (3 << 6) + 36 + OCTEON_DEBUG_UART;
	else
		hwirq = 34 + OCTEON_DEBUG_UART;

	/* explicit irq, don't rely on device-tree */
	irq = irq_create_mapping(NULL, hwirq);
	if (!irq)
		return -EINVAL;

	irq_set_irq_type(irq, IRQ_TYPE_LEVEL_HIGH);

	if (request_irq(irq, interrupt_debug_char,
			0, "cvmx-debug", interrupt_debug_char)) {
		panic("request_irq(%d) failed.", irq);
	}
	cvmx_write_csr(CVMX_MIO_UARTX_IER(OCTEON_DEBUG_UART),
		       cvmx_read_csr(CVMX_MIO_UARTX_IER(OCTEON_DEBUG_UART)) | 1);
	return 0;
}
/* Install this as early as possible to be able to debug the boot
   sequence.  */
core_initcall(octeon_setup_debug_uart);
#endif	/* CONFIG_CAVIUM_GDB */
