/* Copyright (c) 2020 Arista Networks, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <linux/module.h>
#include <linux/tty.h>
#include <linux/tty_flip.h>
#include <linux/version.h>

#include "scd.h"
#include "scd-hwmon.h"
#include "scd-uart.h"

/*
 * helpers
 */

#define scd_invalid_reg(_reg) ((_reg).reg ==  0xffffffff)
#define scd_invalid_default_ctl_reg(_reg) ((_reg).reg == 0x00000000)

static inline struct scd_uart_port *to_scd_uart_port(struct uart_port *port)
{
   return container_of(port, struct scd_uart_port, port);
}

static inline struct scd_context *to_scd_ctx(struct scd_uart_port *port)
{
   return container_of(port->uart, struct scd_context, uart);
}

static inline u32 scd_read_uart_port(struct scd_uart_port *port, u32 offset)
{
   return scd_read_register(to_scd_ctx(port)->pdev, offset);
}

static inline void scd_write_uart_port(struct scd_uart_port *port, u32 offset,
                                       u32 val)
{
   scd_write_register(to_scd_ctx(port)->pdev, offset, val);
}

static inline union uart_rx_ctl scd_read_rx_ctl(struct scd_uart_port *port)
{
   return (union uart_rx_ctl) {
      .reg = scd_read_uart_port(port, SCD_UART_RX_CTL_ADDR(port))
   };
}

static inline void scd_write_rx_ctl(struct scd_uart_port *port,
                                    union uart_rx_ctl ctl)
{
   scd_write_uart_port(port, SCD_UART_RX_CTL_ADDR(port), ctl.reg);
}

static inline union uart_rx_sm_ctl scd_read_rx_sm_ctl(struct scd_uart_port *port)
{
   return (union uart_rx_sm_ctl) {
      .reg = scd_read_uart_port(port, SCD_UART_RX_SM_CTL_ADDR(port))
   };
}

static inline union uart_rx_sm_res scd_read_rx_sm_res(struct scd_uart_port *port)
{
   return (union uart_rx_sm_res) {
      .reg = scd_read_uart_port(port, SCD_UART_RX_SM_RES_ADDR(port))
   };
}

static inline union uart_tx_ctl scd_read_tx_ctl(struct scd_uart_port *port)
{
   return (union uart_tx_ctl) {
      .reg = scd_read_uart_port(port, SCD_UART_TX_CTL_ADDR(port))
   };
}

static inline void scd_write_tx_ctl(struct scd_uart_port *port,
                                    union uart_tx_ctl ctl)
{
   scd_write_uart_port(port, SCD_UART_TX_CTL_ADDR(port), ctl.reg);
}

static inline union uart_tx_sm_req scd_read_tx_sm_req(struct scd_uart_port *port)
{
   return (union uart_tx_sm_req) {
      .reg = scd_read_uart_port(port, SCD_UART_TX_SM_REQ_ADDR(port))
   };
}

static inline void scd_write_tx_sm_req(struct scd_uart_port *port,
                                       union uart_tx_sm_req req)
{
   scd_write_uart_port(port, SCD_UART_TX_SM_REQ_ADDR(port), req.reg);
}

static inline union uart_tx_sm_res scd_read_tx_sm_res(struct scd_uart_port *port)
{
   return (union uart_tx_sm_res) {
      .reg = scd_read_uart_port(port, SCD_UART_TX_SM_RES_ADDR(port))
   };
}

#define uart_prefix(_func, _uart, _fmt, _args...)            \
   _func(&to_scd_ctx(to_scd_uart_port(_uart))->pdev->dev,    \
         "UART #%u: " _fmt, to_scd_uart_port(_uart)->id, ##_args)
#define uart_dbg(_uart, _fmt, _args...)                       \
   uart_prefix(dev_dbg, _uart, _fmt, ##_args)
#define uart_notice(_uart, _fmt, _args...)                    \
   uart_prefix(dev_notice, _uart, _fmt, ##_args)
#define uart_warn(_uart, _fmt, _args...)                      \
   uart_prefix(dev_warn, _uart, _fmt " (%s:%d)", ##_args, __func__, __LINE__)
#define uart_err(_uart, _fmt, _args...)                      \
   uart_prefix(dev_err, _uart, _fmt " (%s:%d)", ##_args, __func__, __LINE__)

/*
 * uart ops
 */

static unsigned int scd_uart_tx_empty(struct uart_port *port)
{
   struct scd_uart_port *sp = to_scd_uart_port(port);
   union uart_tx_sm_res res = scd_read_tx_sm_res(sp);

   return (res.nrs >= SCD_UART_FIFO_DEPTH) ? 0 : TIOCSER_TEMT;
}

static void scd_uart_set_mctrl(struct uart_port *port, unsigned int mctrl)
{
}

static unsigned int scd_uart_get_mctrl(struct uart_port *port)
{
   return 0;
}

static void scd_uart_stop_tx(struct uart_port *port)
{
   struct scd_uart_port *sp = to_scd_uart_port(port);
   uart_dbg(port, "stop tx\n");
   sp->tx_started = false;
}


#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 9, 0)
static void scd_uart_transmit_chars(struct uart_port *port)
{
   struct circ_buf *xmit = &port->state->xmit;
   struct scd_uart_port *sp = to_scd_uart_port(port);
   union uart_tx_sm_res res = scd_read_tx_sm_res(sp);
   union uart_tx_sm_req req = { .reg = 0 };

   uart_dbg(port, "transmit chars pending=%ld\n", uart_circ_chars_pending(xmit));

   scd_write_tx_sm_req(sp, req);

   req.push = 1;
   req.st = 1;

   while (res.nrs < SCD_UART_FIFO_DEPTH) {
      if (port->x_char) {
         req.d = port->x_char;
         scd_write_tx_sm_req(sp, req);
         port->icount.tx++;
         port->x_char = 0;
      }

      if (uart_circ_empty(xmit) || uart_tx_stopped(port))
         break;

      req.d = xmit->buf[xmit->tail];
      scd_write_tx_sm_req(sp, req);
      xmit->tail = (xmit->tail + 1) % UART_XMIT_SIZE;
      port->icount.tx++;

      res.nrs++;
   }

   if (uart_circ_chars_pending(xmit) < WAKEUP_CHARS)
      uart_write_wakeup(port);

   if (uart_circ_empty(xmit))
      scd_uart_stop_tx(port);
}
#else
static void scd_uart_transmit_chars(struct uart_port *port)
{
   struct tty_port *tp = &port->state->port;
   struct scd_uart_port *sp = to_scd_uart_port(port);
   union uart_tx_sm_res res = scd_read_tx_sm_res(sp);
   union uart_tx_sm_req req = { .reg = 0 };
   char data;

   uart_dbg(port, "transmit chars pending=%u\n", kfifo_len(&tp->xmit_fifo));

   req.push = 1;
   req.st = 1;

   while (res.nrs < SCD_UART_FIFO_DEPTH) {
      if (port->x_char) {
         req.d = port->x_char;
         scd_write_tx_sm_req(sp, req);
         port->icount.tx++;
         port->x_char = 0;
      }

      if (uart_tx_stopped(port) || !kfifo_get(&tp->xmit_fifo, &data))
         break;

      req.d = data;
      scd_write_tx_sm_req(sp, req);
      port->icount.tx++;

      res.nrs++;
   }

   if (kfifo_len(&tp->xmit_fifo) < WAKEUP_CHARS)
      uart_write_wakeup(port);

   if (kfifo_is_empty(&tp->xmit_fifo))
      scd_uart_stop_tx(port);
}
#endif

static void scd_uart_flush_rx_queue(struct uart_port *port)
{
   struct scd_uart_port *sp = to_scd_uart_port(port);
   union uart_rx_sm_res res = scd_read_rx_sm_res(sp);

   uart_dbg(port, "flushing %u chars from rx queue\n", res.nrs);

   while (res.nrs != 0) {
      scd_read_rx_sm_res(sp);
      res.nrs--;
   }
}

static void scd_uart_receive_chars(struct uart_port *port)
{
   struct tty_port *tp = &port->state->port;
   struct scd_uart_port *sp = to_scd_uart_port(port);
   union uart_rx_sm_res res = scd_read_rx_sm_res(sp);

   uart_dbg(port, "receive chars %u\n", res.nrs);
   sp->no_rx_since = res.nrs ? 1 : min(sp->no_rx_since + 1, SCD_UART_FIFO_DEPTH / 2);

   while (!res.fe && !scd_invalid_reg(res)) {
      port->icount.rx++;
      tty_insert_flip_char(tp, res.d, TTY_NORMAL);
      res = scd_read_rx_sm_res(sp);
   }

   tty_flip_buffer_push(tp);
}

static void scd_uart_start_tx(struct uart_port *port)
{
   struct scd_uart_port *sp = to_scd_uart_port(port);

   uart_dbg(port, "start tx\n");
   sp->tx_started = true;

   scd_uart_transmit_chars(port);
}

static void scd_uart_stop_rx(struct uart_port *port)
{
   uart_dbg(port, "stop rx\n");
}

static void scd_uart_break_ctl(struct uart_port *port, int ctl)
{
}

#define UART_AVG_BITS_PER_BYTE 10
static ktime_t scd_uart_poll_interval(struct scd_uart_port *port)
{
   unsigned bits_delay = UART_AVG_BITS_PER_BYTE * port->no_rx_since;
   port->poll_interval = ktime_set(0, NSEC_PER_SEC / (port->baud / bits_delay));
   return port->poll_interval;
}

static enum hrtimer_restart scd_uart_port_timer_callback(struct hrtimer *timer)
{
   struct scd_uart_port *sp = container_of(timer, struct scd_uart_port, timer);
   uart_dbg(&sp->port, "timer callback interval=%lld\n", sp->poll_interval);
   if (sp->tx_started) {
      spin_lock(&sp->port.lock);
      scd_uart_transmit_chars(&sp->port);
      spin_unlock(&sp->port.lock);
   }
   scd_uart_receive_chars(&sp->port);
   hrtimer_forward(timer, timer->base->get_time(), scd_uart_poll_interval(sp));
   return HRTIMER_RESTART;
}

static int scd_uart_startup(struct uart_port *port)
{
   struct scd_uart_port *sp = to_scd_uart_port(port);

   uart_dbg(port, "startup\n");

   if (scd_invalid_default_ctl_reg(scd_read_rx_ctl(sp))) {
      uart_warn(port, "uart unsupported on this platform\n");
      return -ENOPROTOOPT;
   }

   scd_uart_flush_rx_queue(&sp->port);

   hrtimer_init(&sp->timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
   sp->timer.function = scd_uart_port_timer_callback;
   hrtimer_start(&sp->timer, sp->poll_interval, HRTIMER_MODE_REL);

   return 0;
}

static void scd_uart_shutdown(struct uart_port *port)
{
   struct scd_uart_port *sp = to_scd_uart_port(port);

   uart_dbg(port, "shutdown\n");

   hrtimer_cancel(&sp->timer);
}

static u8 scd_uart_brs_for_baud(speed_t baud) {
   static const speed_t rates[] = { 4800, 9600, 19200, 38400, 57600, 115200,
                                    230400, 460800, 921600, 1843200 };
   int i;

   for (i = 0; i < ARRAY_SIZE(rates); i++)
      if (baud == rates[i])
         return i;

   return 0xff;
}

static void scd_uart_set_termios(struct uart_port *port,
                                 struct ktermios *new,
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 0, 0)
                                 struct ktermios *old
#else
                                 const struct ktermios *old
#endif
                                 )
{
   struct scd_uart_port *sp = to_scd_uart_port(port);
   union uart_rx_ctl rx_ctl = scd_read_rx_ctl(sp);
   union uart_tx_ctl tx_ctl = scd_read_tx_ctl(sp);
   speed_t baud;
   u8 parity;
   u8 stb;
   u8 brs;

   uart_dbg(port, "set_termios\n");

   baud = tty_termios_baud_rate(new);
   brs = scd_uart_brs_for_baud(baud);
   if (brs == 0xff) {
      baud = sp->baud;
      brs = scd_uart_brs_for_baud(baud);
   }
   sp->baud = baud;

   tty_termios_encode_baud_rate(new, baud, baud);

   scd_uart_poll_interval(sp);

   rx_ctl.brs = brs;
   tx_ctl.brs = brs;

   stb = (new->c_cflag & CSTOPB) ? 2 : 1;
   rx_ctl.stb = stb;
   tx_ctl.stb = stb;

   parity = (new->c_cflag & PARENB) ? 1 : 0;
   rx_ctl.parity = parity;
   tx_ctl.parity = parity;

   // mask missing features
   new->c_cflag &= ~(CMSPAR | PARODD);

   scd_write_rx_ctl(sp, rx_ctl);
   scd_write_tx_ctl(sp, tx_ctl);

   uart_update_timeout(port, new->c_cflag, baud);
}

static const char *scd_uart_type(struct uart_port *port)
{
   return "scd";
}

static void scd_uart_config_port(struct uart_port *port, int flags)
{
   uart_dbg(port, "config port flags=%d\n", flags);
}

static struct uart_ops scd_uart_ops = {
   .tx_empty = scd_uart_tx_empty,
   .set_mctrl = scd_uart_set_mctrl,
   .get_mctrl = scd_uart_get_mctrl,
   .stop_tx = scd_uart_stop_tx,
   .start_tx = scd_uart_start_tx,
   .stop_rx = scd_uart_stop_rx,
   .break_ctl = scd_uart_break_ctl,
   .startup = scd_uart_startup,
   .shutdown = scd_uart_shutdown,
   .set_termios = scd_uart_set_termios,
   .type = scd_uart_type,
   .config_port = scd_uart_config_port,
};

static void scd_uart_remove_port(struct scd_uart_port *port)
{
   uart_dbg(&port->port, "removing\n");
   uart_remove_one_port(&port->uart->driver, &port->port);
   list_del(&port->list);
   kfree(port);
}

void scd_uart_remove_all(struct scd_context *ctx)
{
   struct scd_uart *uart = &ctx->uart;
   struct scd_uart_port *port;
   struct scd_uart_port *tmp_port;

   if (!uart->initialized)
      return;

   list_for_each_entry_safe(port, tmp_port, &uart->port_list, list) {
      scd_uart_remove_port(port);
   }

   uart_unregister_driver(&uart->driver);
   uart->initialized = false;
}

static int scd_uart_maybe_initialize(struct scd_context *ctx)
{
   struct scd_uart *uart = &ctx->uart;
   int res;

   if (uart->initialized)
      return 0;

   dev_dbg(get_scd_dev(ctx), "initializing uart context\n");

   uart->driver.owner = THIS_MODULE;
   uart->driver.driver_name = "scd-uart";
   uart->driver.dev_name = "ttySCD";
   uart->driver.nr = SCD_UART_MAX_PORT_NR;

   res = uart_register_driver(&uart->driver);
   if (res) {
      dev_err(get_scd_dev(ctx), "failed to register UART driver %d\n", res);
      return res;
   }

   INIT_LIST_HEAD(&uart->port_list);
   uart->initialized = true;

   return 0;
}

int scd_uart_add(struct scd_context *ctx, u32 addr, u32 id)
{
   struct scd_uart *uart = &ctx->uart;
   struct scd_uart_port *port;
   int err;

   err = scd_uart_maybe_initialize(ctx);
   if (err)
      return err;

   dev_dbg(get_scd_dev(ctx), "adding uart port %u at addr %#x\n", id, addr);

   port = kzalloc(sizeof(*port), GFP_KERNEL);
   if (!port)
      return -ENOMEM;

   port->uart = uart;
   port->addr_rx = addr + SCD_UART_RX_ADDR_OFFSET;
   port->addr_tx = addr + SCD_UART_TX_ADDR_OFFSET;
   port->id = id;
   port->baud = 9600;
   port->no_rx_since = 1;
   port->tx_started = false;
   scd_uart_poll_interval(port);

   spin_lock_init(&port->port.lock);
   port->port.dev = get_scd_dev(ctx);
   port->port.irq = ctx->pdev->irq;
   port->port.line = id;
   port->port.type = PORT_SCD;
   port->port.ops = &scd_uart_ops;
   port->port.fifosize = SCD_UART_FIFO_DEPTH;
   port->port.iotype = UPIO_MEM;
   port->port.flags = UPF_BOOT_AUTOCONF;

   err = uart_add_one_port(&uart->driver, &port->port);
   if (err) {
      dev_err(get_scd_dev(ctx), "failed to register UART port %u: %d\n", id, err);
      goto fail_add;
   }

   list_add_tail(&port->list, &uart->port_list);

   return 0;

fail_add:
   kfree(port);

   return err;
}
