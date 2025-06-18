/*
 * Driver for Pepperl+Fuchs RocketPort EXPRESS/INFINITY cards
 *
 * Copyright (c) 2012 Kevin Cernekee <cernekee@gmail.com>
 *
 * Updates and modifications: Copyright (c) Pepperl+Fuchs.
 *
 * Inspired by, and loosely based on:
 *
 *   ar933x_uart.c
 *     Copyright (c) 2011 Gabor Juhos <juhosg@openwrt.org>
 *
 *   rocketport_infinity_express-linux-1.20.tar.gz
 *     Copyright (c) 2004-2011 Pepperl+Fuchs.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation.
 */

#include <linux/version.h>

#if KERNEL_VERSION(2, 6, 25) > LINUX_VERSION_CODE
#error " ================================================"
#error " == kernel too old -- 2.6.25 or newer required =="
#error " ================================================"
#pragma GCC diagnostic error "-Wfatal-errors"
#error
#endif

#include <linux/bitops.h>
#include <linux/compiler.h>
#include <linux/completion.h>
#include <linux/console.h>
#include <linux/delay.h>
#include <linux/firmware.h>
#include <linux/init.h>
#include <linux/io.h>
#include <linux/ioport.h>
#include <linux/irq.h>
#include <linux/kernel.h>
#include <linux/log2.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/serial.h>
#include <linux/serial_core.h>
#include <linux/slab.h>
#include <linux/sysrq.h>
#include <linux/tty.h>
#include <linux/tty_flip.h>
#include <linux/types.h>

#define USE_INTERNAL_FIRMWARE 1
#define DEBUG_PORT_MODES 0

#define xstr(s) str(s)
#define str(s) #s

// definition to expand macro then apply to pragma message
#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)

#define TraceLine(fmt, ...) \
    printk(KERN_INFO "rp2: Trace %s():%d " fmt "\n", \
	__func__, __LINE__, ##__VA_ARGS__)

#if defined(RHEL_RELEASE_CODE)
//#pragma message "RHEL_RELEASE_CODE: " TOSTRING(RHEL_RELEASE_CODE)
//"  RHEL_RELEASE: " TOSTRING(RHEL_RELEASE)
#if RHEL_RELEASE_CODE >= 2308
#define CONST_KTERMIOS
#endif
#else
#if KERNEL_VERSION(6, 1, 0) <= LINUX_VERSION_CODE
#define CONST_KTERMIOS
#endif
#endif

//======================================================================
// start of backwards compatibility stuff

#if !defined(BIT)
#define BIT(n) (1<<(n))
#endif

#if !defined PORT_RP2
#define PORT_RP2 102
#endif

// How many ports to support? (max is 256)
#define RP2_NR_UARTS 256

#if !defined(for_each_set_bit)
#define for_each_set_bit(bit, addr, size)         \
    for ((bit) = find_first_bit((addr), (size));  \
	 (bit) < (size);                          \
	 (bit) = find_next_bit((addr), (size), (bit) + 1))
#endif

#if !defined(DEFINE_PCI_DEVICE_TABLE)
#define DEFINE_PCI_DEVICE_TABLE(_table)      \
    const struct pci_device_id _table[] __devinitconst
#endif

#if KERNEL_VERSION(2, 6, 33) > LINUX_VERSION_CODE
#define request_firmware_nowait(module, uevent, name, device, gfp, context, cont) \
    request_firmware_nowait(module, uevent, name, device, context, cont)
#define release_firmware(fw) \
    // continuation functions don't release firmware prior to 2.6.33
#endif

// macros to handle things that have moved around in the serial_core/tty API

#if KERNEL_VERSION(2, 6, 27) > LINUX_VERSION_CODE
#define rp2_tty(up)             up->port.info->tty
#elif KERNEL_VERSION(2, 6, 32) > LINUX_VERSION_CODE
#define rp2_tty(up)             up->port.info->port.tty
#else
#define rp2_tty(up)             up->port.state->port.tty
#endif

#if KERNEL_VERSION(2, 6, 32) > LINUX_VERSION_CODE
#define rp2_state(up)           up->port.info
#define rp2_delta_msr_wait(up)  up->port.info->delta_msr_wait
#else
#define rp2_state(up)           up->port.state
#define rp2_delta_msr_wait(up)  up->port.state->port.delta_msr_wait
#endif

#if KERNEL_VERSION(3, 9, 0) > LINUX_VERSION_CODE
#define rp2_tty_flip_buffer_push(up)                             \
    tty_flip_buffer_push(rp2_tty(up))

#define rp2_tty_buffer_request_room(tty, size)                    \
    tty_buffer_request_room(tty, size)

#define rp2_tty_insert_flip_string(tty, cbuf, size)               \
    tty_insert_flip_string(tty, cbuf, size)

#define rp2_tty_insert_flip_string_flags(tty, cbuf, fbuf, size)   \
    tty_insert_flip_string_flags(tty, cbuf, fbuf, size)

#else
#define rp2_tty_flip_buffer_push(up)                             \
    tty_flip_buffer_push(&up->port.state->port)

#define rp2_tty_buffer_request_room(tty, size)                    \
    tty_buffer_request_room(tty->port, size)

#define rp2_tty_insert_flip_string(tty, cbuf, size)               \
    tty_insert_flip_string(tty->port, cbuf, size)

#define rp2_tty_insert_flip_string_flags(tty, cbuf, fbuf, size)   \
    tty_insert_flip_string_flags(tty->port, cbuf, fbuf, size)

#endif

// Compatibility macros for timer API change
#if KERNEL_VERSION(4, 14, 0) > LINUX_VERSION_CODE
#if !defined(from_timer)
#define from_timer(var, callback_timer, timer_fieldname)                \
    container_of((struct timer_list *)(callback_timer), typeof(*var),  \
		 timer_fieldname)
#endif

#define timer_setup(timer, callback, flags)                             \
    setup_timer((timer), (callback), (unsigned long)(timer))

#define callback_param_type   unsigned long

#else
#define callback_param_type   struct timer_list *
#endif

// end of backwards compatibility stuff
//======================================================================

//======================================================================
// To avoid problems with old distros/kernels, use internal firmware blob
#if USE_INTERNAL_FIRMWARE
static u8 rp2_firmware_blob[] = {
	0xf6, 0x8c, 0x9e, 0xc5, 0x13, 0xc5, 0x11, 0x99,
	0x98, 0x20, 0x0a, 0x21, 0x0a, 0x8d, 0xfa, 0x86,
	0x01, 0x40, 0x11, 0x19, 0x0a, 0x00, 0x40, 0x13,
	0x19, 0x0a, 0xfa, 0x83, 0x01, 0x0a, 0x00, 0x0a,
	0x41, 0xff, 0x89, 0xc2, 0x66, 0x86, 0x81, 0x91,
	0x40, 0x65, 0x8e, 0x89, 0xc2, 0x66, 0x86, 0x81,
	0x88, 0x40, 0x65, 0x85, 0x84, 0x00, 0x82, 0x0a,
	0x08, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x08, 0x0a,
};

static struct firmware rp2_firmware = {
	.size = sizeof(rp2_firmware_blob),
	.data = rp2_firmware_blob,
};
#endif
//
//======================================================================

#define DRV_VERS                        "3.04"
#define DRV_NAME                        "rp2"

#define RP2_FW_NAME                     "rp2.fw"
#define RP2_UCODE_BYTES                 0x3f

#define PORTS_PER_ASIC                  16
#define ALL_PORTS_MASK                  (BIT(PORTS_PER_ASIC) - 1)

#define UART_CLOCK                      44236800

#define FIFO_SIZE                       512

/* PLX registers */
#define RP2_FPGA_CTL0                   0x110
#define RP2_FPGA_CTL1                   0x11c
#define RP2_IRQ_MASK                    0x1ec
#define RP2_IRQ_MASK_EN_m               BIT(0)
#define RP2_IRQ_STATUS                  0x1f0

/* Unity registers */
#define RP2_ASIC_SPACING                0x1000
#define RP2_ASIC_OFFSET(i)              ((i) << ilog2(RP2_ASIC_SPACING))

#define RP2_PORT_BASE                   0x000
#define RP2_PORT_SPACING                0x040

#define RP2_UCODE_BASE                  0x400
#define RP2_UCODE_SPACING               0x80

#define RP2_CLK_PRESCALER               0xc00
#define RP2_CH_IRQ_STAT                 0xc04
#define RP2_CH_IRQ_MASK                 0xc08
#define RP2_ASIC_IRQ                    0xd00
#define RP2_ASIC_IRQ_EN_m               BIT(20)
#define RP2_GLOBAL_CMD                  0xd0c
#define RP2_ASIC_CFG                    0xd04

/* port registers */
#define RP2_DATA_DWORD                  0x000
#define RP2_DATA_HWORD                  0x004
#define RP2_DATA_BYTE                   0x008
#define RP2_DATA_BYTE_ERR_PARITY_m      BIT(8)
#define RP2_DATA_BYTE_ERR_OVERRUN_m     BIT(9)
#define RP2_DATA_BYTE_ERR_FRAMING_m     BIT(10)
#define RP2_DATA_BYTE_BREAK_m           BIT(11)

/* This lets uart_insert_char() drop bytes received on a !CREAD port */
#define RP2_DUMMY_READ                  BIT(16)

#define RP2_DATA_BYTE_EXCEPTION_MASK    (RP2_DATA_BYTE_ERR_PARITY_m | \
					 RP2_DATA_BYTE_ERR_OVERRUN_m | \
					 RP2_DATA_BYTE_ERR_FRAMING_m | \
					 RP2_DATA_BYTE_BREAK_m)

#define RP2_RX_FIFO_COUNT               0x00c
#define RP2_TX_FIFO_COUNT               0x00e

#define RP2_CHAN_STAT                   0x010
#define RP2_CHAN_STAT_RXDATA_m          BIT(0)
#define RP2_CHAN_STAT_DCD_m             BIT(3)
#define RP2_CHAN_STAT_DSR_m             BIT(4)
#define RP2_CHAN_STAT_CTS_m             BIT(5)
#define RP2_CHAN_STAT_RI_m              BIT(6)
#define RP2_CHAN_STAT_RTS_m             BIT(7)
#define RP2_CHAN_STAT_PARITY_m          BIT(8)
#define RP2_CHAN_STAT_FRAME_m           BIT(9)
#define RP2_CHAN_STAT_BREAK_m           BIT(10)
#define RP2_CHAN_STAT_TIMEOUT_m         BIT(11)
#define RP2_CHAN_STAT_OVERRUN_m         BIT(13)
#define RP2_CHAN_STAT_DSR_CHANGED_m     BIT(16)
#define RP2_CHAN_STAT_CTS_CHANGED_m     BIT(17)
#define RP2_CHAN_STAT_CD_CHANGED_m      BIT(18)
#define RP2_CHAN_STAT_RI_CHANGED_m      BIT(22)
#define RP2_CHAN_STAT_TXEMPTY_m         BIT(25)
#define RP2_CHAN_STAT_RXERR_m           (RP2_CHAN_STAT_PARITY_m | \
					 RP2_CHAN_STAT_FRAME_m |  \
					 RP2_CHAN_STAT_BREAK_m |  \
					 RP2_CHAN_STAT_OVERRUN_m)

#define RP2_CHAN_STAT_MS_CHANGED_MASK   (RP2_CHAN_STAT_DSR_CHANGED_m | \
					 RP2_CHAN_STAT_CTS_CHANGED_m | \
					 RP2_CHAN_STAT_CD_CHANGED_m | \
					 RP2_CHAN_STAT_RI_CHANGED_m)

#define RP2_TXRX_CTL                    0x014
#define RP2_TXRX_CTL_MSRIRQ_m           BIT(0)
#define RP2_TXRX_CTL_RXIRQ_m            BIT(2)
#define RP2_TXRX_CTL_RX_TRIG_s          3
#define RP2_TXRX_CTL_RX_TRIG_m          (0x3 << RP2_TXRX_CTL_RX_TRIG_s)
#define RP2_TXRX_CTL_RX_TRIG_none       (0x0 << RP2_TXRX_CTL_RX_TRIG_s)
#define RP2_TXRX_CTL_RX_TRIG_1          (0x1 << RP2_TXRX_CTL_RX_TRIG_s)
#define RP2_TXRX_CTL_RX_TRIG_256        (0x2 << RP2_TXRX_CTL_RX_TRIG_s)
#define RP2_TXRX_CTL_RX_TRIG_448        (0x3 << RP2_TXRX_CTL_RX_TRIG_s)
#define RP2_TXRX_CTL_RX_EN_m            BIT(5)
#define RP2_TXRX_CTL_RTSFLOW_m          BIT(6)
#define RP2_TXRX_CTL_DTRFLOW_m          BIT(7)
#define RP2_TXRX_CTL_RX_TMOUTIRQ_m      BIT(9)
#define RP2_TXRX_CTL_TX_TRIG_s          16
#define RP2_TXRX_CTL_TX_TRIG_m          (0x3 << RP2_TXRX_CTL_TX_TRIG_s)
#define RP2_TXRX_CTL_TX_TRIG_none       (0x0 << RP2_TXRX_CTL_TX_TRIG_s)
#define RP2_TXRX_CTL_TX_TRIG_64         (0x1 << RP2_TXRX_CTL_TX_TRIG_s)
#define RP2_TXRX_CTL_TX_TRIG_128        (0x2 << RP2_TXRX_CTL_TX_TRIG_s)
#define RP2_TXRX_CTL_TX_TRIG_256        (0x3 << RP2_TXRX_CTL_TX_TRIG_s)
#define RP2_TXRX_CTL_DSRFLOW_m          BIT(18)
#define RP2_TXRX_CTL_TXIRQ_m            BIT(19)
#define RP2_TXRX_CTL_TX_FIFO_INT_EN_m   BIT(20)
#define RP2_TXRX_CTL_RTS_POLARITY_m     BIT(21)
#define RP2_TXRX_CTL_RTS_TOGGLE_m       BIT(22)
#define RP2_TXRX_CTL_CTSFLOW_m          BIT(23)
#define RP2_TXRX_CTL_TX_EN_m            BIT(24)
#define RP2_TXRX_CTL_RTS_m              BIT(25)
#define RP2_TXRX_CTL_DTR_m              BIT(26)
#define RP2_TXRX_CTL_LOOP_m             BIT(27)
#define RP2_TXRX_CTL_BREAK_m            BIT(28)
#define RP2_TXRX_CTL_CMSPAR_m           BIT(29)
#define RP2_TXRX_CTL_nPARODD_m          BIT(30)
#define RP2_TXRX_CTL_PARENB_m           BIT(31)

#define RP2_UART_CTL                    0x018
#define RP2_UART_CTL_MODE_m             0x7
#define RP2_UART_CTL_MODE_rs232         0x1
#define RP2_UART_CTL_MODE_rs422         0x2
#define RP2_UART_CTL_MODE_rs485m        0x2
#define RP2_UART_CTL_MODE_rs485s        0x3
#define RP2_UART_CTL_MODE_rs485         0x4
#define RP2_UART_CTL_FLUSH_RX_m         BIT(3)
#define RP2_UART_CTL_FLUSH_TX_m         BIT(4)
#define RP2_UART_CTL_RESET_CH_m         BIT(5)
#define RP2_UART_CTL_XMIT_EN_m          BIT(6)
#define RP2_UART_CTL_DATABITS_s         8
#define RP2_UART_CTL_DATABITS_m         (0x3 << RP2_UART_CTL_DATABITS_s)
#define RP2_UART_CTL_DATABITS_8         (0x3 << RP2_UART_CTL_DATABITS_s)
#define RP2_UART_CTL_DATABITS_7         (0x2 << RP2_UART_CTL_DATABITS_s)
#define RP2_UART_CTL_DATABITS_6         (0x1 << RP2_UART_CTL_DATABITS_s)
#define RP2_UART_CTL_DATABITS_5         (0x0 << RP2_UART_CTL_DATABITS_s)
#define RP2_UART_CTL_STOPBITS_m         BIT(10)

#define RP2_BAUD                        0x01c

#define RP2_UNCOND_TX                   0x030

/* ucode registers */
#define RP2_TX_SWFLOW                   0x02
#define RP2_TX_SWFLOW_ena               0x81
#define RP2_TX_SWFLOW_dis               0x9e

#define RP2_RX_SWFLOW                   0x0d
#define RP2_RX_SWFLOW_ena               0x81
#define RP2_RX_SWFLOW_dis               0x8d

#define RP2_TX_XOFF_CHAR                0x17
#define RP2_RX_XOFF_CHAR                0x04
#define RP2_TX_XON_CHAR                 0x12
#define RP2_RX_XON_CHAR                 0x06

#define RP2_XANY                        0x07
#define RP2_XANY_ena                    0x21
#define RP2_XANY_dis                    0x99

#define RP2_RX_FIFO                     0x38
#define RP2_RX_FIFO_ena                 0x08
#define RP2_RX_FIFO_dis                 0x81

static int polling_mode = 100;	// 0 is interrupt-mode, >0 is polling freq (Hz)
static int polling_jiffies;	// jiffies per polling cycle

#define EnablePortMonitor

#if defined(RP2_MONITOR_ENABLE)
#include "rp2monitor.c"
#else
#define portMonitorInit()	// noop
#define portMonitorCleanup()	// noop
#define portMonitorNew(port)  NULL
#define portMonitorFree(monp)	// noop
#define portMonitorQueueBytes(monp, txrx, data, len, flush)	// noop
typedef void portMonitor;
#endif

static struct uart_driver rp2_uart_driver = {
	.owner = THIS_MODULE,
	.driver_name = DRV_NAME,
	.dev_name = "ttyRP",
	.nr = RP2_NR_UARTS,
};

struct rp2_card;

struct rp2_uart_port {
	struct uart_port port;
	int idx;
	int active;
	int throttled;
	const struct port_mode *mode;
	struct rp2_card *card;
	void __iomem *asic_base;
	void __iomem *base;
	void __iomem *ucode;

	// in order to avoid stack frame size warnings for rx handler we put
	// rx buffer here instead of using automatic variables in the
	// handler
	union {
		uint8_t u8[512];	// when there are errors we read a byte at a time
		uint32_t u32[128];	// when there are no errors we read 4 bytes at a time
	} rxbuf;
	uint8_t fbuf[512];
	int txcount;
	uint8_t txbuf[FIFO_SIZE + 128];

	int rx_data_last_poll;	// flag used to detect gaps in rx data
	portMonitor *monp;
};

struct rp2_card {
	struct pci_dev *pdev;
	struct rp2_uart_port *ports;
	int gen2;
	int n_ports;
	int initialized_ports;
	int minor_start;
	int smpte;
	void __iomem *base;	// base address for Unity UARTs
	void __iomem *plx;	// base address for PLX bridge
	spinlock_t card_lock;
	bool shutting_down;
	const char *description;
	struct completion fw_loaded;
	struct timer_list poll_timer;
};

static const char *board_description(unsigned int device_id);

// map three-character mode abbreviation strings from port_modes module
// parameter string into mode control bits and descriptive strings

#define MaxPorts 256

static char *port_modes[MaxPorts];
static int port_modes_count;
static char *low_latency[MaxPorts];
static int low_latency_count;

static struct port_mode *port_mode[MaxPorts];
static char latency_flag[MaxPorts];

static struct port_mode {
	const char *abbrev;	// abbreviation specified in port_modes module param
	unsigned int modebits;	// mode control bits for TX control register
	unsigned int rtstoggle;	// RTS toggle enable bit
	unsigned int rtspolarity;	// RTS polarity bit
	const char *modestr;	// description shown in /proc/tty/drivers/rp2 and syslog
} port_mode_tbl[] = {
	{ "rs232", RP2_UART_CTL_MODE_rs232, 0, 0, "rs232" },	// default
	{ "rs232h", RP2_UART_CTL_MODE_rs232, RP2_TXRX_CTL_RTS_TOGGLE_m, 0,
	 "rs232 half-duplex" },
	{ "rs422", RP2_UART_CTL_MODE_rs422, 0, 0, "rs422" },
	{ "rs485", RP2_UART_CTL_MODE_rs485, RP2_TXRX_CTL_RTS_TOGGLE_m,
	 RP2_TXRX_CTL_RTS_POLARITY_m, "rs485 2-wire" },
	{ "rs485-2", RP2_UART_CTL_MODE_rs485, RP2_TXRX_CTL_RTS_TOGGLE_m,
	 RP2_TXRX_CTL_RTS_POLARITY_m, "rs485 2-wire" },
	{ "rs485-4s", RP2_UART_CTL_MODE_rs485s, RP2_TXRX_CTL_RTS_TOGGLE_m,
	 RP2_TXRX_CTL_RTS_POLARITY_m, "rs485 4-wire slave" },
	{ "rs485-4m", RP2_UART_CTL_MODE_rs485m, 0, 0, "rs485 4-wire master" },
	{ NULL, 0, 0, 0, NULL }
};

#define DEFAULT_MODE (&port_mode_tbl[0])
#define SMPTE_MODE (&port_mode_tbl[2])

static const struct port_mode *get_port_mode(int line)
{
	if (!port_mode[line])
		return DEFAULT_MODE;
	return port_mode[line];
}

#define RP_ID(prod) PCI_VDEVICE(RP, (prod))
#define RP_CAP(ports, smpte, gen2) (((ports) << 8) | ((smpte) << 7) | (gen2))

static inline void rp2_decode_cap(const struct pci_device_id *id,
				  int *ports, int *smpte, int *gen2)
{
	*ports = id->driver_data >> 8;
	*smpte = id->driver_data & (1 << 7);
	*gen2 = id->driver_data & 1;
}

static DEFINE_SPINLOCK(rp2_minor_lock);
static int rp2_minor_next;

static int rp2_alloc_ports(int n_ports)
{
	int ret = -ENOSPC;

	spin_lock(&rp2_minor_lock);
	if (rp2_minor_next + n_ports <= RP2_NR_UARTS) {
		/* sorry, no support for hot unplugging individual cards */
		ret = rp2_minor_next;
		rp2_minor_next += n_ports;
	}
	spin_unlock(&rp2_minor_lock);

	return ret;
}

static inline struct rp2_uart_port *port_to_up(struct uart_port *port)
{
	return container_of(port, struct rp2_uart_port, port);
}

static void rp2_rmw(struct rp2_uart_port *up, int reg,
		    u32 clr_bits, u32 set_bits)
{
	u32 tmp = readl(up->base + reg);
	tmp &= ~clr_bits;
	tmp |= set_bits;
	writel(tmp, up->base + reg);
}

static void rp2_rmw_clr(struct rp2_uart_port *up, int reg, u32 val)
{
	rp2_rmw(up, reg, val, 0);
}

static void rp2_rmw_set(struct rp2_uart_port *up, int reg, u32 val)
{
	rp2_rmw(up, reg, 0, val);
}

static void rp2_mask_ch_irq(struct rp2_uart_port *up, int ch_num,
			    int is_enabled)
{
	unsigned long flags, irq_mask;

	spin_lock_irqsave(&up->card->card_lock, flags);

	irq_mask = readl(up->asic_base + RP2_CH_IRQ_MASK);
	if (is_enabled)
		irq_mask &= ~BIT(ch_num);
	else
		irq_mask |= BIT(ch_num);
	writel(irq_mask, up->asic_base + RP2_CH_IRQ_MASK);

	spin_unlock_irqrestore(&up->card->card_lock, flags);
}

static unsigned int rp2_uart_tx_empty(struct uart_port *port)
{
	struct rp2_uart_port *up = port_to_up(port);
	unsigned long tx_fifo_bytes, flags;

	/*
	 * This should probably check the transmitter, not the FIFO.
	 * But the TXEMPTY bit doesn't seem to work unless the TX IRQ is
	 * enabled.
	 */
	spin_lock_irqsave(&up->port.lock, flags);
	tx_fifo_bytes = readw(up->base + RP2_TX_FIFO_COUNT);
	spin_unlock_irqrestore(&up->port.lock, flags);

	return tx_fifo_bytes ? 0 : TIOCSER_TEMT;
}

static unsigned int rp2_uart_get_mctrl(struct uart_port *port)
{
	struct rp2_uart_port *up = port_to_up(port);
	u32 status;

	status = readl(up->base + RP2_CHAN_STAT);
	return ((status & RP2_CHAN_STAT_DCD_m) ? TIOCM_CAR : 0) |
	    ((status & RP2_CHAN_STAT_DSR_m) ? TIOCM_DSR : 0) |
	    ((status & RP2_CHAN_STAT_CTS_m) ? TIOCM_CTS : 0) |
	    ((status & RP2_CHAN_STAT_RI_m) ? TIOCM_RI : 0);
}

static void rp2_uart_set_mctrl(struct uart_port *port, unsigned int mctrl)
{
	rp2_rmw(port_to_up(port), RP2_TXRX_CTL,
		RP2_TXRX_CTL_DTR_m | RP2_TXRX_CTL_RTS_m | RP2_TXRX_CTL_LOOP_m,
		((mctrl & TIOCM_DTR) ? RP2_TXRX_CTL_DTR_m : 0) |
		((mctrl & TIOCM_RTS) ? RP2_TXRX_CTL_RTS_m : 0) |
		((mctrl & TIOCM_LOOP) ? RP2_TXRX_CTL_LOOP_m : 0));
}

static void rp2_uart_start_tx(struct uart_port *port)
{
	rp2_rmw_set(port_to_up(port), RP2_TXRX_CTL, RP2_TXRX_CTL_TXIRQ_m);
}

static void rp2_uart_stop_tx(struct uart_port *port)
{
	rp2_rmw_clr(port_to_up(port), RP2_TXRX_CTL, RP2_TXRX_CTL_TXIRQ_m);
}

static void rp2_uart_stop_rx(struct uart_port *port)
{
	rp2_rmw_clr(port_to_up(port), RP2_TXRX_CTL, RP2_TXRX_CTL_RXIRQ_m);
}

static void rp2_uart_break_ctl(struct uart_port *port, int break_state)
{
	unsigned long flags;

	spin_lock_irqsave(&port->lock, flags);
	rp2_rmw(port_to_up(port), RP2_TXRX_CTL, RP2_TXRX_CTL_BREAK_m,
		break_state ? RP2_TXRX_CTL_BREAK_m : 0);
	spin_unlock_irqrestore(&port->lock, flags);
}

static void enable_rx_fifo_trigger(struct rp2_uart_port *up, int low_latency)
{
	//printk(KERN_INFO "low_latency %d %d\n", up->idx, low_latency);
	rp2_rmw(up, RP2_TXRX_CTL, RP2_TXRX_CTL_RX_TRIG_m,
		low_latency ? RP2_TXRX_CTL_RX_TRIG_1 :
		RP2_TXRX_CTL_RX_TRIG_256);
}

#if KERNEL_VERSION(3, 8, 0) <= LINUX_VERSION_CODE

static void disable_rx_fifo_trigger(struct rp2_uart_port *up)
{
	rp2_rmw(up, RP2_TXRX_CTL, RP2_TXRX_CTL_RX_TRIG_m, 0);
}

static void rp2_uart_throttle(struct uart_port *port)
{
	struct rp2_uart_port *up = port_to_up(port);
	// stop reading rx data
	up->throttled = 1;
	disable_rx_fifo_trigger(up);
}

static void rp2_uart_unthrottle(struct uart_port *port)
{
	struct rp2_uart_port *up = port_to_up(port);
	// struct tty_struct *tty = rp2_tty(up);
	// resume reading rx data
	up->throttled = 0;
	enable_rx_fifo_trigger(up, latency_flag[port->line]);
}

#endif

static void rp2_uart_enable_ms(struct uart_port *port)
{
	rp2_rmw_set(port_to_up(port), RP2_TXRX_CTL, RP2_TXRX_CTL_MSRIRQ_m);
}

static void __rp2_uart_set_termios(struct rp2_uart_port *up,
				   unsigned long cfl,
				   unsigned long ifl,
				   cc_t *c_cc, unsigned int baud_div)
{
	/* baud rate divisor (calculated elsewhere).  0 = divide-by-1 */
	writew(baud_div - 1, up->base + RP2_BAUD);

	/* data bits and stop bits */
	rp2_rmw(up, RP2_UART_CTL,
		RP2_UART_CTL_STOPBITS_m | RP2_UART_CTL_DATABITS_m,
		((cfl & CSTOPB) ? RP2_UART_CTL_STOPBITS_m : 0) |
		(((cfl & CSIZE) == CS8) ? RP2_UART_CTL_DATABITS_8 : 0) |
		(((cfl & CSIZE) == CS7) ? RP2_UART_CTL_DATABITS_7 : 0) |
		(((cfl & CSIZE) == CS6) ? RP2_UART_CTL_DATABITS_6 : 0) |
		(((cfl & CSIZE) == CS5) ? RP2_UART_CTL_DATABITS_5 : 0));

	/* parity and hardware flow control */
	rp2_rmw(up, RP2_TXRX_CTL,
		RP2_TXRX_CTL_PARENB_m | RP2_TXRX_CTL_nPARODD_m |
		RP2_TXRX_CTL_CMSPAR_m | RP2_TXRX_CTL_DTRFLOW_m |
		RP2_TXRX_CTL_DSRFLOW_m | RP2_TXRX_CTL_RTSFLOW_m |
		RP2_TXRX_CTL_CTSFLOW_m,
		((cfl & PARENB) ? RP2_TXRX_CTL_PARENB_m : 0) |
		((cfl & PARODD) ? 0 : RP2_TXRX_CTL_nPARODD_m) |
		((cfl & CMSPAR) ? RP2_TXRX_CTL_CMSPAR_m : 0) |
		((cfl & CRTSCTS) ? (RP2_TXRX_CTL_RTSFLOW_m |
				    RP2_TXRX_CTL_CTSFLOW_m) : 0));
#if defined(UPF_SOFT_FLOW)
	// Hardware xon/xoff support currently can only be used with
	// newer kernels that have the UPF_SOFT_FLOW uart flag defined
	if (c_cc) {
		writeb(c_cc[VSTOP], up->ucode + RP2_TX_XOFF_CHAR);
		writeb(c_cc[VSTOP], up->ucode + RP2_RX_XOFF_CHAR);
		writeb(c_cc[VSTART], up->ucode + RP2_TX_XON_CHAR);
		writeb(c_cc[VSTART], up->ucode + RP2_RX_XON_CHAR);
	}
	writeb((ifl & IXANY) ? RP2_XANY_ena : RP2_XANY_dis,
	       up->ucode + RP2_XANY);
	writeb((ifl & IXON) ? RP2_TX_SWFLOW_ena : RP2_TX_SWFLOW_dis,
	       up->ucode + RP2_TX_SWFLOW);
	writeb((ifl & IXOFF) ? RP2_RX_SWFLOW_ena : RP2_RX_SWFLOW_dis,
	       up->ucode + RP2_RX_SWFLOW);
#endif
}

static void rp2_uart_set_termios(struct uart_port *port, struct ktermios *new,
#if defined(CONST_KTERMIOS)
				 const struct ktermios *old)
#else
				 struct ktermios *old)
#endif
{
	struct rp2_uart_port *up = port_to_up(port);
	unsigned long flags;
	unsigned int baud, baud_div;

	baud = uart_get_baud_rate(port, new, old, 0, port->uartclk / 16);
	baud_div = uart_get_divisor(port, baud);

	if (tty_termios_baud_rate(new))
		tty_termios_encode_baud_rate(new, baud, baud);

	spin_lock_irqsave(&port->lock, flags);

	/* ignore all characters if CREAD is not set */
	port->ignore_status_mask = (new->c_cflag & CREAD) ? 0 : RP2_DUMMY_READ;

	__rp2_uart_set_termios(up, new->c_cflag, new->c_iflag, new->c_cc,
			       baud_div);
	uart_update_timeout(port, new->c_cflag, baud);

	spin_unlock_irqrestore(&port->lock, flags);
}

static void rp2_rx_chars(struct rp2_uart_port *up)
{
	int rxfifo, chanstat, bytes;
	struct tty_struct *tty;

	chanstat = readw(up->base + RP2_CHAN_STAT);

	if ((chanstat & RP2_CHAN_STAT_RXDATA_m) == 0) {
		// no rx data
		if (polling_mode && up->rx_data_last_poll) {
			portMonitorQueueBytes(up->monp, 0, NULL, 0, 1);	// flush any queued monitor data
			up->rx_data_last_poll = 0;
		}
		return;
	}

	up->rx_data_last_poll = 1;

	if (up->throttled)
		return;

	tty = rp2_tty(up);

	rxfifo = readw(up->base + RP2_RX_FIFO_COUNT);
	bytes = rp2_tty_buffer_request_room(tty, rxfifo);

	if (bytes == 0)
		return;

	if (chanstat & RP2_CHAN_STAT_RXERR_m) {
		// errors present in RX fifo, so read bytes one at a time along
		// with status
		int i;

		for (i = 0; i < bytes; ++i) {
			u32 byte =
			    readw(up->base + RP2_DATA_BYTE) | RP2_DUMMY_READ;

			up->rxbuf.u8[i] = byte & 0xff;

			if (likely(!(byte & RP2_DATA_BYTE_EXCEPTION_MASK)))
				up->fbuf[i] = TTY_NORMAL;
			else {
				if (byte & RP2_DATA_BYTE_BREAK_m)
					up->fbuf[i] = TTY_BREAK;
				else if (byte & RP2_DATA_BYTE_ERR_FRAMING_m)
					up->fbuf[i] = TTY_FRAME;
				else if (byte & RP2_DATA_BYTE_ERR_PARITY_m)
					up->fbuf[i] = TTY_PARITY;
				else if (byte & RP2_DATA_BYTE_ERR_OVERRUN_m)
					up->fbuf[i] = TTY_OVERRUN;
				else
					up->fbuf[i] = TTY_NORMAL;
			}
		}
		rp2_tty_insert_flip_string_flags(tty, up->rxbuf.u8, up->fbuf,
						 bytes);
	} else {
		// no errors in rx FIFO, so read a block of data with no flags
		uint8_t *bp;
		uint32_t *lp = up->rxbuf.u32;
		int i = bytes;

		while (i > 4) {
			*lp++ = readl(up->base + RP2_DATA_DWORD);
			i -= 4;
		}

		bp = (uint8_t *) lp;

		while (i) {
			*bp++ = readw(up->base + RP2_DATA_BYTE);
			--i;
		}
		rp2_tty_insert_flip_string(tty, up->rxbuf.u8, bytes);
	}

	// if we're in interrupt mode, we don't let monitor buffer the rx
	// bytes
	portMonitorQueueBytes(up->monp, 0, up->rxbuf.u8, bytes,
			      polling_mode == 0);

	up->port.icount.rx += bytes;

#if KERNEL_VERSION(3, 12, 0) <= LINUX_VERSION_CODE
	spin_unlock(&up->port.lock);
	rp2_tty_flip_buffer_push(up);
	spin_lock(&up->port.lock);
#else
	rp2_tty_flip_buffer_push(up);
#endif

}

#if KERNEL_VERSION(6, 10, 0) <= LINUX_VERSION_CODE
// Use the macro contents of rp2_tx_chars from the kernel tree version of the driver.
#define MACRO_TX_CHARS
//#pragma message "MACRO_TX_CHARS"
#endif

#ifdef MACRO_TX_CHARS
static void rp2_write(struct rp2_uart_port *up, char ch)
{
	writeb(ch, up->base + RP2_DATA_BYTE);
	up->txbuf[up->txcount++] = ch;
}
#endif

static void rp2_tx_chars(struct rp2_uart_port *up)
{

#ifdef MACRO_TX_CHARS
	//As seen in 6.10 kernel rp2.
	u8 ch;

	up->txcount = 0;
	uart_port_tx_limited(&up->port, ch,
			     FIFO_SIZE - readw(up->base + RP2_TX_FIFO_COUNT),
			     true, rp2_write(up, ch), ({
						       }));
#else
	u16 max_tx;
	struct circ_buf *xmit;

	up->txcount = 0;
	max_tx = FIFO_SIZE - readw(up->base + RP2_TX_FIFO_COUNT);
	xmit = &rp2_state(up)->xmit;

	if (uart_tx_stopped(&up->port)) {
		rp2_uart_stop_tx(&up->port);
		return;
	}

	for (; max_tx != 0; max_tx--) {
		uint8_t b;
		if (up->port.x_char) {
			// We do not think this is used on our UARTs.
			writeb(up->port.x_char, up->base + RP2_DATA_BYTE);
			up->port.x_char = 0;
			up->port.icount.tx++;
			continue;
		}
		if (uart_circ_empty(xmit)) {
			rp2_uart_stop_tx(&up->port);
			break;
		}
		b = xmit->buf[xmit->tail];
		writeb(b, up->base + RP2_DATA_BYTE);
		up->txbuf[up->txcount++] = b;
		xmit->tail = (xmit->tail + 1) & (UART_XMIT_SIZE - 1);
		up->port.icount.tx++;
	}

	if (uart_circ_chars_pending(xmit) < WAKEUP_CHARS)
		uart_write_wakeup(&up->port);
#endif // MACRO_TX_CHARS

	if (up->txcount) {
		//printk(KERN_DEBUG "rp2: txcount %d\n", up->txcount);
		portMonitorQueueBytes(up->monp, 1, up->txbuf, up->txcount, 1);
	}
}

static void rp2_ch_interrupt(struct rp2_uart_port *up)
{
	u32 status;

	spin_lock(&up->port.lock);
	if (!up->active) {
		spin_unlock(&up->port.lock);
		return;
	}

	// The IRQ status bits are clear-on-write.  Other status bits in
	// this register aren't, so it's harmless to write to them.
	status = readl(up->base + RP2_CHAN_STAT);
	writel(status, up->base + RP2_CHAN_STAT);

	// The polling mode rx code needs to be called even when there's no
	// rx data in order to deal with buffering logic in the port monitor
	// function
	rp2_rx_chars(up);

	// There's no status bit that tells us there's room in the tx fifo
	// for more data, so only way to tell is to read the tx fifo count
	// count, so go ahead and call the function that handles tx data
	rp2_tx_chars(up);

	if (status & RP2_CHAN_STAT_MS_CHANGED_MASK) {
		if (status & RP2_CHAN_STAT_RI_CHANGED_m)
			up->port.icount.rng++;
		if (status & RP2_CHAN_STAT_DSR_CHANGED_m)
			up->port.icount.dsr++;
		if (status & RP2_CHAN_STAT_CD_CHANGED_m)
			uart_handle_dcd_change(&up->port,
					       status & RP2_CHAN_STAT_DCD_m);
		if (status & RP2_CHAN_STAT_CTS_CHANGED_m)
			uart_handle_cts_change(&up->port,
					       status & RP2_CHAN_STAT_CTS_m);
		wake_up_interruptible(&rp2_delta_msr_wait(up));
	}

	spin_unlock(&up->port.lock);
}

static int rp2_asic_interrupt(struct rp2_card *card, unsigned int asic_id)
{
	void __iomem *base = card->base + RP2_ASIC_OFFSET(asic_id);
	int ch, handled = 0;
	unsigned long status = readl(base + RP2_CH_IRQ_STAT) &
	    ~readl(base + RP2_CH_IRQ_MASK);

	for_each_set_bit(ch, &status, PORTS_PER_ASIC) {
		rp2_ch_interrupt(&card->ports[ch + asic_id * PORTS_PER_ASIC]);
		handled++;
	}
	return handled;
}

static irqreturn_t rp2_uart_interrupt(int irq, void *dev_id)
{
	struct rp2_card *card = dev_id;
	int handled;

	handled = rp2_asic_interrupt(card, 0);
	if (card->n_ports >= PORTS_PER_ASIC)
		handled += rp2_asic_interrupt(card, 1);

	return handled ? IRQ_HANDLED : IRQ_NONE;
}

static inline void rp2_flush_fifos(struct rp2_uart_port *up)
{
	rp2_rmw_set(up, RP2_UART_CTL,
		    RP2_UART_CTL_FLUSH_RX_m | RP2_UART_CTL_FLUSH_TX_m);
	readl(up->base + RP2_UART_CTL);
	udelay(10);
	rp2_rmw_clr(up, RP2_UART_CTL,
		    RP2_UART_CTL_FLUSH_RX_m | RP2_UART_CTL_FLUSH_TX_m);
}

static inline void rp2_flush_tx_fifo(struct rp2_uart_port *up)
{
	rp2_rmw_set(up, RP2_UART_CTL, RP2_UART_CTL_FLUSH_TX_m);
	readl(up->base + RP2_UART_CTL);
	udelay(10);
	rp2_rmw_clr(up, RP2_UART_CTL, RP2_UART_CTL_FLUSH_TX_m);
}

static void rp2_uart_send_xchar(struct uart_port *port, char xchar)
{
	struct rp2_uart_port *up = port_to_up(port);
	writeb(xchar, up->base + RP2_UNCOND_TX);
}

static int rp2_uart_startup(struct uart_port *port)
{
	unsigned long flags;
	struct rp2_uart_port *up;
	struct tty_struct *tty;

	spin_lock_irqsave(&port->lock, flags);

	up = port_to_up(port);
	tty = rp2_tty(up);
	rp2_flush_fifos(up);
	rp2_rmw(up, RP2_TXRX_CTL, 0,
		RP2_TXRX_CTL_MSRIRQ_m | RP2_TXRX_CTL_RXIRQ_m |
		RP2_TXRX_CTL_RX_TMOUTIRQ_m);
	rp2_rmw(up, RP2_TXRX_CTL, RP2_TXRX_CTL_TX_TRIG_m,
		RP2_TXRX_CTL_TX_TRIG_128);
	enable_rx_fifo_trigger(up, latency_flag[port->line]);
	rp2_rmw(up, RP2_CHAN_STAT, 0, 0);
	rp2_mask_ch_irq(up, up->idx, 1);
	up->active = 1;
	up->throttled = 0;

#if defined(UPF_SOFT_FLOW)
	port->flags |= UPF_SOFT_FLOW | UPF_HARD_FLOW;
#endif

	spin_unlock_irqrestore(&port->lock, flags);
	return 0;
}

#if KERNEL_VERSION(2, 6, 27) <= LINUX_VERSION_CODE
static void rp2_uart_flush_buffer(struct uart_port *port)
{
	rp2_flush_tx_fifo(port_to_up(port));
}
#endif

static void rp2_uart_shutdown(struct uart_port *port)
{
	struct rp2_uart_port *up = port_to_up(port);
	unsigned long flags;

	rp2_uart_break_ctl(port, 0);
	spin_lock_irqsave(&port->lock, flags);
	up->active = 0;
	rp2_mask_ch_irq(up, up->idx, 0);
	rp2_rmw(up, RP2_CHAN_STAT, 0, 0);
	spin_unlock_irqrestore(&port->lock, flags);
}

static const char *rp2_uart_type(struct uart_port *port)
{
	if (port->type == PORT_RP2) {
		static char buffer[1024];
		char *latency = "";
		struct rp2_uart_port *up = port_to_up(port);

		if ((latency_flag[port->line]) && (polling_mode == 0))
			latency = " low_latency";

		snprintf(buffer, sizeof(buffer), "%s (%s%s)",
			 up->card->description, up->mode->modestr, latency);
		return buffer;
	}
	return NULL;
}

static void rp2_uart_release_port(struct uart_port *port)
{
	/* Nothing to release ... */
}

static int rp2_uart_request_port(struct uart_port *port)
{
	/* UARTs always present */
	return 0;
}

static void rp2_uart_config_port(struct uart_port *port, int flags)
{
	if (flags & UART_CONFIG_TYPE)
		port->type = PORT_RP2;
}

static int rp2_uart_verify_port(struct uart_port *port,
				struct serial_struct *ser)
{
	if (ser->type != PORT_UNKNOWN && ser->type != PORT_RP2)
		return -EINVAL;

	return 0;
}

static const struct uart_ops rp2_uart_ops = {
	.tx_empty = rp2_uart_tx_empty,
	.set_mctrl = rp2_uart_set_mctrl,
	.get_mctrl = rp2_uart_get_mctrl,
	.stop_tx = rp2_uart_stop_tx,
	.start_tx = rp2_uart_start_tx,
	.stop_rx = rp2_uart_stop_rx,
	.send_xchar = rp2_uart_send_xchar,
	.enable_ms = rp2_uart_enable_ms,
	.break_ctl = rp2_uart_break_ctl,
	.startup = rp2_uart_startup,
	.shutdown = rp2_uart_shutdown,
#if KERNEL_VERSION(3, 8, 0) <= LINUX_VERSION_CODE
	.throttle = rp2_uart_throttle,
	.unthrottle = rp2_uart_unthrottle,
#endif
#if KERNEL_VERSION(2, 6, 27) <= LINUX_VERSION_CODE
	.flush_buffer = rp2_uart_flush_buffer,
#endif
	.set_termios = rp2_uart_set_termios,
	.type = rp2_uart_type,
	.release_port = rp2_uart_release_port,
	.request_port = rp2_uart_request_port,
	.config_port = rp2_uart_config_port,
	.verify_port = rp2_uart_verify_port,
};

static void rp2_reset_asic(struct rp2_card *card, unsigned int asic_id)
{
	void __iomem *base = card->base + RP2_ASIC_OFFSET(asic_id);
	u32 clk_cfg;

	writew(1, base + RP2_GLOBAL_CMD);
	readw(base + RP2_GLOBAL_CMD);
	msleep(100);

	// gen2 boards have hard-wired prescaler and don't have config
	// register for TDM clock
	if (!card->gen2) {
		writel(0, base + RP2_CLK_PRESCALER);

		/* TDM clock configuration */
		clk_cfg = readw(base + RP2_ASIC_CFG);
		clk_cfg = (clk_cfg & ~BIT(8)) | BIT(9);
		writew(clk_cfg, base + RP2_ASIC_CFG);
	}

	/* IRQ routing */
	writel(ALL_PORTS_MASK, base + RP2_CH_IRQ_MASK);
	if (!polling_mode)
		writel(RP2_ASIC_IRQ_EN_m, base + RP2_ASIC_IRQ);
}

static void rp2_init_card(struct rp2_card *card)
{
	if (!card->gen2) {
		writel(4, card->plx + RP2_FPGA_CTL0);
		writel(0, card->plx + RP2_FPGA_CTL1);
	}

	rp2_reset_asic(card, 0);
	if (card->n_ports >= PORTS_PER_ASIC)
		rp2_reset_asic(card, 1);

	if (!polling_mode && !card->gen2)
		writel(RP2_IRQ_MASK_EN_m, card->plx + RP2_IRQ_MASK);
}

static void rp2_init_port(struct rp2_uart_port *up, const struct firmware *fw)
{
	int i;

	// resetting Unity channel w/ full rx FIFO kills receive processor
	writel((RP2_UART_CTL_FLUSH_RX_m | RP2_UART_CTL_FLUSH_TX_m),
	       up->base + RP2_UART_CTL);
	readl(up->base + RP2_UART_CTL);

	writel(RP2_UART_CTL_RESET_CH_m, up->base + RP2_UART_CTL);
	readl(up->base + RP2_UART_CTL);
	udelay(1);

	writel(0, up->base + RP2_TXRX_CTL);
	writel(0, up->base + RP2_UART_CTL);
	readl(up->base + RP2_UART_CTL);
	udelay(1);

	rp2_flush_fifos(up);

	for (i = 0; i < min_t(int, fw->size, RP2_UCODE_BYTES); i++)
		writeb(fw->data[i], up->ucode + i);

	__rp2_uart_set_termios(up, CS8 | CREAD | CLOCAL, 0, NULL,
			       up->port.uartclk / (9600 * 16));
	rp2_uart_set_mctrl(&up->port, 0);

	writeb(RP2_RX_FIFO_ena, up->ucode + RP2_RX_FIFO);
	rp2_rmw(up, RP2_UART_CTL, RP2_UART_CTL_MODE_m,
		RP2_UART_CTL_XMIT_EN_m | up->mode->modebits);
	rp2_rmw(up, RP2_TXRX_CTL, RP2_TXRX_CTL_RTS_TOGGLE_m,
		up->mode->rtstoggle);
	rp2_rmw(up, RP2_TXRX_CTL, RP2_TXRX_CTL_RTS_POLARITY_m,
		up->mode->rtspolarity);
	rp2_rmw_set(up, RP2_TXRX_CTL,
		    RP2_TXRX_CTL_TX_EN_m | RP2_TXRX_CTL_RX_EN_m);
}

static void rp2_remove_ports(struct rp2_card *card)
{
	int i;

	for (i = 0; i < card->initialized_ports; i++) {
		portMonitorFree(card->ports[i].monp);
		uart_remove_one_port(&rp2_uart_driver, &card->ports[i].port);
	}
	card->initialized_ports = 0;
}

// called by per-card timer at a frequency set by polling_mode module
// parameter
static void rp2_card_poll(callback_param_type param)
{
	int i;
	struct rp2_card *card =
	    from_timer(card, (struct timer_list *)param, poll_timer);
	if (card->shutting_down)
		return;
	for (i = 0; i < card->n_ports; i++)
		rp2_ch_interrupt(&card->ports[i]);
	mod_timer(&card->poll_timer, jiffies + polling_jiffies);
}

static void rp2_fw_cb(const struct firmware *fw, void *context)
{
	struct rp2_card *card = context;
	resource_size_t phys_base;
	int i, rc = -ENOENT;

	if (!fw) {
		dev_err(&card->pdev->dev, "cannot find '%s' firmware image\n",
			RP2_FW_NAME);
		goto no_fw;
	}

	phys_base = pci_resource_start(card->pdev, card->gen2 ? 0 : 1);

	for (i = 0; i < card->n_ports; i++) {
		struct rp2_uart_port *rp = &card->ports[i];
		struct uart_port *p;
		int j = (unsigned)i % PORTS_PER_ASIC;
		int line = card->minor_start + i;

		rp->asic_base = card->base;
		rp->base = card->base + RP2_PORT_BASE + j * RP2_PORT_SPACING;
		rp->ucode = card->base + RP2_UCODE_BASE + j * RP2_UCODE_SPACING;
		rp->card = card;
		rp->idx = j;
		rp->mode = card->smpte ? SMPTE_MODE : get_port_mode(line);
		p = &rp->port;
		p->line = line;
		p->dev = &card->pdev->dev;
		p->type = PORT_RP2;
		p->iotype = UPIO_MEM32;
		p->uartclk = UART_CLOCK;
		p->regshift = 2;
		p->fifosize = FIFO_SIZE;
		p->ops = &rp2_uart_ops;
		p->irq = card->pdev->irq;
		p->membase = rp->base;
		p->mapbase = phys_base + RP2_PORT_BASE + j * RP2_PORT_SPACING;

		if (i >= PORTS_PER_ASIC) {
			rp->asic_base += RP2_ASIC_SPACING;
			rp->base += RP2_ASIC_SPACING;
			rp->ucode += RP2_ASIC_SPACING;
			p->mapbase += RP2_ASIC_SPACING;
		}

		rp2_init_port(rp, fw);
		rp->monp = portMonitorNew(line);
		rc = uart_add_one_port(&rp2_uart_driver, p);
		if (rc) {
			dev_err(&card->pdev->dev,
				"error registering port %d: %d\n", i, rc);
			rp2_remove_ports(card);
			break;
		}
		card->initialized_ports++;
	}

#if !USE_INTERNAL_FIRMWARE
	release_firmware(fw);
#endif

no_fw:
	/*
	 * rp2_fw_cb() is called from a workqueue long after rp2_probe()
	 * has already returned success.  So if something failed here,
	 * we'll just leave the now-dormant device in place until somebody
	 * unbinds it.
	 */
	if (rc)
		dev_warn(&card->pdev->dev, "driver initialization failed\n");

	complete(&card->fw_loaded);

	if (polling_mode) {
		dev_info(&card->pdev->dev, "polling at %dHz\n",
			 HZ / polling_jiffies);
		timer_setup(&card->poll_timer, rp2_card_poll, 0);
		mod_timer(&card->poll_timer, jiffies + 1);
	}
}

static int rp2_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
	struct rp2_card *card;
	struct rp2_uart_port *ports;
	void __iomem *const *bars;
	int rc;

	card = devm_kzalloc(&pdev->dev, sizeof(*card), GFP_KERNEL);
	if (!card)
		return -ENOMEM;
	pci_set_drvdata(pdev, card);
	spin_lock_init(&card->card_lock);
	init_completion(&card->fw_loaded);

	rp2_decode_cap(id, &card->n_ports, &card->smpte, &card->gen2);
	card->description = board_description(id->device);

	dev_info(&pdev->dev, "found %s with %d ports\n", card->description,
		 card->n_ports);

	rc = pcim_enable_device(pdev);
	if (rc)
		return rc;

	rc = pcim_iomap_regions_request_all(pdev, (card->gen2 ? 0x01 : 0x03),
					    DRV_NAME);
	if (rc)
		return rc;

	bars = pcim_iomap_table(pdev);

	if (card->gen2) {
		card->plx = NULL;
		card->base = bars[0];
	} else {
		card->plx = bars[0];
		card->base = bars[1];
	}

	card->pdev = pdev;

	card->minor_start = rp2_alloc_ports(card->n_ports);
	if (card->minor_start < 0) {
		dev_err(&pdev->dev,
			"too many ports (RP2_NR_UARTS in rp2.c is "
			xstr(RP2_NR_UARTS) ")\n");
		return -EINVAL;
	}

	rp2_init_card(card);

	ports =
	    devm_kzalloc(&pdev->dev, sizeof(*ports) * card->n_ports,
			 GFP_KERNEL);
	if (!ports)
		return -ENOMEM;
	card->ports = ports;

	if (!polling_mode) {
		rc = devm_request_irq(&pdev->dev, pdev->irq, rp2_uart_interrupt,
				      IRQF_SHARED, DRV_NAME, card);
		if (rc)
			return rc;
	}

#if USE_INTERNAL_FIRMWARE
	rp2_fw_cb(&rp2_firmware, card);
#else
	// Only catastrophic errors (e.g. ENOMEM) are reported here.  If the
	// FW image is missing, we'll find out in rp2_fw_cb() and print an
	// error message.
	rc = request_firmware_nowait(THIS_MODULE, 1, RP2_FW_NAME, &pdev->dev,
				     GFP_KERNEL, card, rp2_fw_cb);
	if (rc)
		return rc;
#endif

	dev_dbg(&pdev->dev, "waiting for firmware blob...\n");

	return 0;
}

static void rp2_remove(struct pci_dev *pdev)
{
	struct rp2_card *card = pci_get_drvdata(pdev);

	wait_for_completion(&card->fw_loaded);

	if (polling_mode) {
		int i = 10;

		card->shutting_down = true;
		while (--i) {
			if (del_timer_sync(&card->poll_timer) == 0)
				break;
			msleep(100);
		}
		if (i == 0)
			dev_info(&pdev->dev, "error removing poll timer\n");
	}
	rp2_remove_ports(card);
}

//======================================================================
// When adding a new board, it must be added to _both_ tables below:
// the description table used to generate messages and the PCI device
// table used to register the driver with the kernel.

static const struct rp2descr {
	unsigned int device_id;
	const char *board_descr;
} board_descr_tbl[] = {
	{ 0x40, "RocketPort Infinity, Octa RJ45, Selectable" },
	{ 0x41, "RocketPort Infinity 32, External Interface" },
	{ 0x42, "RocketPort Infinity 8, External Interface" },
	{ 0x43, "RocketPort Infinity 16, External Interface" },
	{ 0x44, "RocketPort Infinity 4, Quad DB, Selectable" },
	{ 0x45, "RocketPort Infinity 8, Octa DB, Selectable" },
	{ 0x46, "RocketPort Infinity 4, External Interface" },
	{ 0x47, "RocketPort Infinity, 4, RJ45" },
	{ 0x48, "RocketPort Infinity, 8, RJ11" },
	{ 0x4a, "RocketPort Infinity Plus, Quad" },
	{ 0x4b, "RocketPort Infinity Plus, Octa" },
	{ 0x4c, "RocketModem Infinity III, 8" },
	{ 0x4d, "RocketModem Infinity III, 4" },
	{ 0x4e, "RocketPort Infinity Plus 2, 232" },
	{ 0x4f, "RocketPort Infinity 2, SMPTE" },
	{ 0x50, "RocketPort Infinity Plus 4, RJ45" },
	{ 0x51, "RocketPort Infinity Plus 8, RJ11" },
	{ 0x52, "RocketPort Infinity Octa SMPTE" },

	{ 0x60, "RocketPort Express, Octa RJ45, Selectable" },
	{ 0x61, "RocketPort Express 32, External Interface" },
	{ 0x62, "RocketPort Express 8, External Interface" },
	{ 0x63, "RocketPort Express 16, External Interface" },
	{ 0x64, "RocketPort Express 4, Quad DB, Selectable" },
	{ 0x65, "RocketPort Express 8, Octa DB, Selectable" },
	{ 0x66, "RocketPort Express 4, External Interface" },
	{ 0x67, "RocketPort Express, 4, RJ45" },
	{ 0x68, "RocketPort Express, 8, RJ11" },
	{ 0x6f, "RocketPort Express, 2, SMPTE" },
	{ 0x72, "RocketPort Express Octa SMPTE" },

	{ 0x80, "ICRPC-8RJ45-FC (RocketPort EXPRESS Octa RJ45)" },
	{ 0x81, "ICRPC-32P (RocketPort EXPRESS 32-Port)" },
	{ 0x82, "ICRPC-8P (RocketPort EXPRESS 8 Port)" },
	{ 0x83, "ICRPC-16P (RocketPort EXPRESS 16 Port)" },
	{ 0x84, "ICRPC-4DBx-FC (RocketPort EXPRESS Quad DB)" },
	{ 0x85, "ICRPC-8DBx-FC (RocketPort EXPRESS Octa DB)" },
	{ 0x86, "ICRPC-4P (RocketPort EXPRESS 4 Port)" },
	{ 0x87, "ICRPC-4RJ45-EC (RocketPort EXPRESS 4J)" },
	{ 0x88, "ICRPC-8RJ11-EC (RocketPort EXPRESS 8 Port RJ11)" },
	{ }
};

static const char *board_description(unsigned int device_id)
{
	const struct rp2descr *p;

	for (p = board_descr_tbl; p->device_id; ++p)
		if (device_id == p->device_id)
			return p->board_descr;
	return "<unknown>";
}

#if KERNEL_VERSION(4, 8, 0) > LINUX_VERSION_CODE
static DEFINE_PCI_DEVICE_TABLE(rp2_pci_tbl) =
#else
static const struct pci_device_id rp2_pci_tbl[] =
#endif
{
	/* RocketPort INFINITY cards */

	{ RP_ID(0x0040), RP_CAP(8, 0, 0) },	/* INF Octa, RJ45, selectable */
	{ RP_ID(0x0041), RP_CAP(32, 0, 0) },	/* INF 32, ext interface */
	{ RP_ID(0x0042), RP_CAP(8, 0, 0) },	/* INF Octa, ext interface */
	{ RP_ID(0x0043), RP_CAP(16, 0, 0) },	/* INF 16, ext interface */
	{ RP_ID(0x0044), RP_CAP(4, 0, 0) },	/* INF Quad, DB, selectable */
	{ RP_ID(0x0045), RP_CAP(8, 0, 0) },	/* INF Octa, DB, selectable */
	{ RP_ID(0x0046), RP_CAP(4, 0, 0) },	/* INF Quad, ext interface */
	{ RP_ID(0x0047), RP_CAP(4, 0, 0) },	/* INF 4, RJ45 */
	{ RP_ID(0x0048), RP_CAP(8, 0, 0) },	/* INF 8, RJ11 */
	{ RP_ID(0x004a), RP_CAP(4, 0, 0) },	/* INF Plus, Quad */
	{ RP_ID(0x004b), RP_CAP(8, 0, 0) },	/* INF Plus, Octa */
	{ RP_ID(0x004c), RP_CAP(8, 0, 0) },	/* INF III, Octa */
	{ RP_ID(0x004d), RP_CAP(4, 0, 0) },	/* INF III, Quad */
	{ RP_ID(0x004e), RP_CAP(2, 0, 0) },	/* INF Plus, 2, RS232 */
	{ RP_ID(0x004f), RP_CAP(2, 1, 0) },	/* INF Plus, 2, SMPTE */
	{ RP_ID(0x0050), RP_CAP(4, 0, 0) },	/* INF Plus, Quad, RJ45 */
	{ RP_ID(0x0051), RP_CAP(8, 0, 0) },	/* INF Plus, Octa, RJ45 */
	{ RP_ID(0x0052), RP_CAP(8, 1, 0) },	/* INF Octa, SMPTE */

	/* RocketPort EXPRESS cards */

	{ RP_ID(0x0060), RP_CAP(8, 0, 0) },	/* EXP Octa, RJ45, selectable */
	{ RP_ID(0x0061), RP_CAP(32, 0, 0) },	/* EXP 32, ext interface */
	{ RP_ID(0x0062), RP_CAP(8, 0, 0) },	/* EXP Octa, ext interface */
	{ RP_ID(0x0063), RP_CAP(16, 0, 0) },	/* EXP 16, ext interface */
	{ RP_ID(0x0064), RP_CAP(4, 0, 0) },	/* EXP Quad, DB, selectable */
	{ RP_ID(0x0065), RP_CAP(8, 0, 0) },	/* EXP Octa, DB, selectable */
	{ RP_ID(0x0066), RP_CAP(4, 0, 0) },	/* EXP Quad, ext interface */
	{ RP_ID(0x0067), RP_CAP(4, 0, 0) },	/* EXP Quad, RJ45 */
	{ RP_ID(0x0068), RP_CAP(8, 0, 0) },	/* EXP Octa, RJ11 */
	{ RP_ID(0x006f), RP_CAP(2, 0, 0) },	/* EXP SMPTE */
	{ RP_ID(0x0072), RP_CAP(8, 1, 0) },	/* EXP Octa, SMPTE */

	/* Gen2 RocketPort EXPRESS cards */

	{ RP_ID(0x0080), RP_CAP(8, 0, 1) },	/* EXP Octa, RJ45, selectable */
	{ RP_ID(0x0081), RP_CAP(32, 0, 1) },	/* EXP 32, ext interface */
	{ RP_ID(0x0082), RP_CAP(8, 0, 1) },	/* EXP Octa, ext interface */
	{ RP_ID(0x0083), RP_CAP(16, 0, 1) },	/* EXP 16, ext interface */
	{ RP_ID(0x0084), RP_CAP(4, 0, 1) },	/* EXP Quad, DB, selectable */
	{ RP_ID(0x0085), RP_CAP(8, 0, 1) },	/* EXP Octa, DB, selectable */
	{ RP_ID(0x0086), RP_CAP(4, 0, 1) },	/* EXP Quad, ext interface */
	{ RP_ID(0x0087), RP_CAP(4, 0, 1) },	/* EXP Quad, RJ45 */
	{ RP_ID(0x0088), RP_CAP(8, 0, 1) },	/* EXP Octa, RJ11 */
	{ }
};

MODULE_DEVICE_TABLE(pci, rp2_pci_tbl);

static struct pci_driver rp2_pci_driver = {
	.name = DRV_NAME,
	.id_table = rp2_pci_tbl,
	.probe = rp2_probe,
	.remove = rp2_remove,
};

static void __init parse_port_modes(char *modes[], int count, char *latency[],
				    int latency_count)
{
	/* Initialize to defaults */
	int i;

	for (i = 0; i < MaxPorts; i++) {
		port_mode[i] = DEFAULT_MODE;
		latency_flag[i] = 0;
	}

	/* Set latency_flag flags. */
	for (i = 0; i < latency_count; ++i) {
		char *latent = latency[i];
		unsigned int start_port, end_port;
		int j;

		if (DEBUG_PORT_MODES > 2)
			printk(KERN_DEBUG "rp2: latency[%d] '%s'\n", i, latent);

		if (!latent) {
			printk(KERN_ERR "rp2: NULL latency string!\n");
			continue;
		}

		if (sscanf(latent, "%u-%u", &start_port, &end_port) == 2) {
		} else if (sscanf(latent, "%u", &start_port) == 1) {
			end_port = start_port;
		} else {
			printk(KERN_WARNING
			       "rp2: unrecognized latency setting: '%s'\n",
			       latent);
			continue;
		}

		if (DEBUG_PORT_MODES > 1)
			printk(KERN_DEBUG
			       "rp2: low_latency start_port=%u  end_port=%u\n",
			       start_port, end_port);

		if (start_port >= MaxPorts) {
			printk(KERN_WARNING
			       "rp2: illegal low_latency port number %u in setting '%s'\n",
			       start_port, latent);
			continue;
		}
		if (end_port >= MaxPorts) {
			printk(KERN_WARNING
			       "rp2: illegal low_latency port number %u in setting '%s'\n",
			       end_port, latent);
			continue;
		}

		for (j = start_port; j <= end_port; ++j)
			latency_flag[j] = 1;
	}

	for (i = 0; i < count; ++i) {
		char *mode = modes[i];
		unsigned int start_port, end_port;
		char modestr[16];
		struct port_mode *p;
		int j;

		if (DEBUG_PORT_MODES > 2)
			printk(KERN_DEBUG "rp2: port_modes[%d] '%s'\n", i,
			       mode);

		if (!mode) {
			printk(KERN_ERR "rp2: NULL mode string!\n");
			continue;
		}

		if (sscanf(mode, "%u-%u:%14s", &start_port, &end_port,
			   modestr) == 3) {
		} else if (sscanf(mode, "%u:%14s", &start_port, modestr) == 2) {
			end_port = start_port;
		} else {
			printk(KERN_WARNING
			       "rp2: unrecognized mode setting: '%s'\n", mode);
			continue;
		}

		if (DEBUG_PORT_MODES > 1)
			printk(KERN_DEBUG
			       "rp2: start_port=%u  end_port=%u  modestr='%s'\n",
			       start_port, end_port, modestr);

		if (start_port >= MaxPorts) {
			printk(KERN_WARNING
			       "rp2: illegal port number %u in setting '%s'\n",
			       start_port, mode);
			continue;
		}
		if (end_port >= MaxPorts) {
			printk(KERN_WARNING
			       "rp2: illegal port number %u in setting '%s'\n",
			       end_port, mode);
			continue;
		}

		for (p = port_mode_tbl; p->abbrev; ++p)
			if (!strcmp(modestr, p->abbrev))
				break;

		if (!p->abbrev) {
			printk(KERN_WARNING
			       "rp2: unrecognized port mode '%s' for port %u\n",
			       modestr, start_port);
			continue;
		}

		for (j = start_port; j <= end_port; ++j) {
			port_mode[j] = p;
			if (DEBUG_PORT_MODES)
				printk(KERN_DEBUG
				       "rp2: port %u mode: %s low_latency %d\n",
				       j, p->modestr, latency_flag[j]);
		}
	}

}

static int __init rp2_uart_init(void)
{
	int rc;

	printk(KERN_INFO
	       "rp2: Pepperl+Fuchs RocketPort Infinity/Express driver version "
	       DRV_VERS " (%s mode)\n", polling_mode ? "Polled" : "Interrupt");

	portMonitorInit();

	if (polling_mode) {
		if (polling_mode < 10) {
			printk(KERN_WARNING
			       "rp2: Polling frequency (%dHz) is too low -- using %dHz\n",
			       polling_mode, 10);
			polling_mode = 10;
		}
		polling_jiffies = HZ / polling_mode;
		if (polling_jiffies == 0) {
			printk(KERN_WARNING
			       "rp2: Polling frequency (%dHz) is too high -- using %dHz\n",
			       polling_mode, HZ);
			polling_jiffies = 1;
		}
	}

	parse_port_modes(port_modes, port_modes_count, low_latency,
			 low_latency_count);

	rc = uart_register_driver(&rp2_uart_driver);
	if (rc)
		return rc;

	rc = pci_register_driver(&rp2_pci_driver);
	if (rc) {
		uart_unregister_driver(&rp2_uart_driver);
		printk(KERN_ERR "rp2: error registering PCI driver\n");
		return rc;
	}

	return 0;
}

static void __exit rp2_uart_exit(void)
{
	printk(KERN_INFO "rp2: unregistering driver\n");
	pci_unregister_driver(&rp2_pci_driver);
	uart_unregister_driver(&rp2_uart_driver);
	portMonitorCleanup();
}

// See modinfo rp2.
module_param_array(port_modes, charp, &port_modes_count, 0444);
MODULE_PARM_DESC(port_modes,
		 "Port interface settings. Example: port_modes=0:rs232,1:rs485,2-7:rs232,8-15:rs422 ");
module_param_array(low_latency, charp, &low_latency_count, 0444);
MODULE_PARM_DESC(low_latency,
		 "Ports to set low_latency. Example: low_latency=1,8-15 ");
module_param(polling_mode, int, 0444);
MODULE_PARM_DESC(polling_mode,
		 "Polling frequency in Hz (0 == interrupt-driven)");
module_init(rp2_uart_init);
module_exit(rp2_uart_exit);

MODULE_DESCRIPTION("Pepperl+Fuchs RocketPort EXPRESS/INFINITY driver");
MODULE_AUTHOR("Kevin Cernekee <cernekee@gmail.com>");
MODULE_AUTHOR("Pepperl+Fuchs. <support@comtrol.com>");
MODULE_LICENSE("GPL v2");
#if !USE_INTERNAL_FIRMWARE
MODULE_FIRMWARE(RP2_FW_NAME);
#endif
