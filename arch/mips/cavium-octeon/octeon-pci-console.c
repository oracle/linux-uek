/*
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (C) 2006-2012 Cavium, Inc.
 *
 * octeon_pci_console uses a protocol for sending and receiving byte
 * streams through in-memory ring buffers.  The typical use case is to
 * have a pseudo-tty like driver/program running on a host machine that
 * services the buffers via a PCI link.  This driver implements the
 * client side of the protocol when the OCTEON SOC is in PCI target
 * mode.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/console.h>
#include <linux/tty.h>
#include <linux/tty_driver.h>
#include <linux/tty_flip.h>
#include <linux/module.h>

#include <asm/byteorder.h>
#include <asm/io.h>

#include <asm/octeon/octeon.h>

#define OCTEON_PCI_CONSOLE_MAJOR_VERSION    1
#define OCTEON_PCI_CONSOLE_MINOR_VERSION    0

#define OCTEON_PCI_CONSOLE_BLOCK_NAME   "__pci_console"

struct octeon_pci_console_rings {
#ifdef __BIG_ENDIAN
	u64 input_base_addr;
	volatile u32 input_read_index;
	volatile u32 input_write_index;
	u64 output_base_addr;
	volatile u32 output_read_index;
	volatile u32 output_write_index;
	u32 unused;
	u32 buf_size;
#else /* __LITTLE_ENDIAN */
	u64 input_base_addr;

	volatile u32 input_write_index;
	volatile u32 input_read_index;

	u64 output_base_addr;

	volatile u32 output_write_index;
	volatile u32 output_read_index;

	u32 buf_size;
	u32 unused;
#endif
};

struct octeon_pci_console_desc {
#ifdef __BIG_ENDIAN
	u32 major_version;
	u32 minor_version;
	u32 lock;
	u32 flags;
	u32 num_consoles;
	u32 pad;
#else /* __LITTLE_ENDIAN */
	u32 minor_version;
	u32 major_version;

	u32 flags;
	u32 lock;

	u32 pad;
	u32 num_consoles;
#endif
	/* Array of addresses of struct octeon_pci_console_rings structures */
	uint64_t console_addr_array[0];
	/* Implicit storage for console_addr_array */
};

struct octeon_pci_console {
	struct console con;
	struct tty_driver *ttydrv;
	spinlock_t lock;
	struct octeon_pci_console_rings *rings;
	/* Pointers to the ring memory referred to in rings. */
	u8 *input_ring;
	u8 *output_ring;
	struct timer_list poll_timer;
	int open_count;
	int index;
	struct tty_port tty_port;
};

static struct octeon_pci_console octeon_pci_console;

#ifdef __BIG_ENDIAN
#define copy_to_ring memcpy
#else /* __LITTLE_ENDIAN */
/* console buffers are scrambled for __LITTLE_ENDIAN */
static void copy_to_ring(u8 *dst, const u8 *src, unsigned int n)
{
	while (n) {
		u8 *pd = (u8 *)((unsigned long)dst ^ 7);
		*pd = *src;
		n--;
		dst++;
		src++;
	}
}
#endif

/*
 * Write all the data, possibly spinning waiting for the reader to
 * free buffer space.
 */
static void octeon_pci_console_lowlevel_write(struct octeon_pci_console *opc,
					      const char *str, unsigned int len)
{
	u32 s = opc->rings->buf_size;

	spin_lock(&opc->lock);
	while (len > 0) {
		u32 r =  opc->rings->output_read_index;
		u32 w =  opc->rings->output_write_index;
		u32 a = ((s - 1) - (w - r)) % s;
		unsigned int n;

		if (!a)
			continue;
		if (r <= w)
			n = min(a, min(len, s - w));
		else
			n = min(a, min(len, r - w));

		copy_to_ring(opc->output_ring + w, str, n);
		len -= n;
		str += n;
		w = (w + n) % s;
		wmb();
		opc->rings->output_write_index = w;
		wmb();
	}
	spin_unlock(&opc->lock);
}

static void octeon_pci_console_write(struct console *con, const char *str,
				     unsigned int len)
{
	octeon_pci_console_lowlevel_write(con->data, str, len);
}

static struct tty_driver *octeon_pci_console_device(struct console *con,
						    int *index)
{
	struct octeon_pci_console  *opc = con->data;

	*index = 0;
	return opc->ttydrv;
}

static int octeon_pci_console_setup0(struct octeon_pci_console *opc)
{
	struct octeon_pci_console_desc *opcd;

	if (!opc->rings) {
		const struct cvmx_bootmem_named_block_desc *block_desc =
			cvmx_bootmem_find_named_block(OCTEON_PCI_CONSOLE_BLOCK_NAME);
		if (block_desc == NULL || block_desc->base_addr == 0)
			goto fail;

		opcd = phys_to_virt(block_desc->base_addr);
		/*
		 * We only work with version 1.0 of the protocol (the
		 * only one that exists).
		 */
		if (opcd->major_version != 1 || opcd->minor_version != 0)
			goto fail;

		if (opcd->console_addr_array[opc->index])
			opc->rings = phys_to_virt(opcd->console_addr_array[opc->index]);
		else
			goto fail;
		spin_lock_init(&octeon_pci_console.lock);
		opc->input_ring = phys_to_virt(opc->rings->input_base_addr);
		opc->output_ring = phys_to_virt(opc->rings->output_base_addr);
	}
	return 0;
fail:
	return -1;
}

static int octeon_pci_console_setup(struct console *con, char *arg)
{
	struct octeon_pci_console *opc = con->data;

	octeon_write_lcd("pci cons");
	if (octeon_pci_console_setup0(opc)) {
		octeon_write_lcd("pci fail");
		return -1;
	}
	return 0;
}

void octeon_pci_console_init(const char *arg)
{
	struct octeon_pci_console *c = &octeon_pci_console;

	memset(c, 0, sizeof(*c));
	strcpy(c->con.name, "pci");
	c->con.write = octeon_pci_console_write;
	c->con.device = octeon_pci_console_device;
	c->con.setup = octeon_pci_console_setup;
	c->con.data = &octeon_pci_console;
	if (arg && (arg[3] >= '0') && (arg[3] <= '9'))
		sscanf(arg + 3, "%d", &c->index);
	else
		c->index = 0;
	register_console(&c->con);
}

/*
 * called by a timer to poll the PCI device for input data
 */
static void octeon_pci_console_read_poll(unsigned long arg)
{
	struct tty_struct *tty = (struct tty_struct *) arg;
	struct octeon_pci_console  *opc = tty->driver->driver_state;
	int nr;
	u32 s = opc->rings->buf_size;
	u32 r =  opc->rings->input_read_index;
	u32 w =  opc->rings->input_write_index;
	u32 a = (w - r) % s;
#ifdef __LITTLE_ENDIAN
	int i;
	u8 buffer[32];
#endif

	while (a > 0) {
		u8 *buf;
		unsigned int n;

		if (r > w)
			n = min(a, s - r);
		else
			n = min(a, w - r);
#ifdef __LITTLE_ENDIAN
		n = min_t(unsigned int, n, sizeof(buffer));
		for (i = 0; i < n; i++) {
			u8 *ps = (u8 *)((unsigned long)(opc->input_ring + r + i) ^ 7);
			buffer[i] = *ps;
		}
		buf = buffer;
#else /*  __BIG_ENDIAN */
		buf = opc->input_ring + r;
#endif
		nr = tty_insert_flip_string(tty->port, buf, n);
		if (!nr)
			break;
		r = (r + nr) % s;
		a -= nr;
		tty_flip_buffer_push(tty->port);
	}
	opc->rings->input_read_index = r;
	wmb();

	mod_timer(&opc->poll_timer, jiffies + 1);
}

static int octeon_pci_console_tty_open(struct tty_struct *tty,
				       struct file *filp)
{
	struct octeon_pci_console  *opc = tty->driver->driver_state;

	opc->open_count++;
	if (opc->open_count == 1) {
		init_timer(&opc->poll_timer);
		opc->poll_timer.data = (unsigned long) tty;
		opc->poll_timer.function = octeon_pci_console_read_poll;
		mod_timer(&opc->poll_timer, jiffies + 1);
	}
	return 0;
}

static void octeon_pci_console_tty_close(struct tty_struct *tty,
					 struct file *filp)
{
	struct octeon_pci_console  *opc = tty->driver->driver_state;

	opc->open_count--;
	if (opc->open_count == 0)
		del_timer(&opc->poll_timer);
}

static int octeon_pci_console_tty_write(struct tty_struct *tty,
					const unsigned char *buf,
					int count)
{
	struct octeon_pci_console  *opc = tty->driver->driver_state;

	octeon_pci_console_lowlevel_write(opc, buf, count);
	return count;
}

static void octeon_pci_console_tty_send_xchar(struct tty_struct *tty, char ch)
{
	struct octeon_pci_console  *opc = tty->driver->driver_state;

	octeon_pci_console_lowlevel_write(opc, &ch, 1);
}

/*
 * Room available for output.  Assume maximum buffer size is
 * available, we will spin if it is not.
 */
static int octeon_pci_console_tty_write_room(struct tty_struct *tty)
{
	struct octeon_pci_console  *opc = tty->driver->driver_state;

	return opc->rings->buf_size - 1;
}

static int octeon_pci_console_tty_chars_in_buffer(struct tty_struct *tty)
{
	return 0;
}

static const struct tty_operations octeon_pci_tty_ops = {
	.open = octeon_pci_console_tty_open,
	.close = octeon_pci_console_tty_close,
	.write = octeon_pci_console_tty_write,
	.write_room = octeon_pci_console_tty_write_room,
	.send_xchar = octeon_pci_console_tty_send_xchar,
	.chars_in_buffer = octeon_pci_console_tty_chars_in_buffer,
};

static int __init octeon_pci_console_module_init(void)
{
	int r;
	struct tty_driver *d = tty_alloc_driver(1, 0);

	if (IS_ERR(d))
		return PTR_ERR(d);

	octeon_pci_console.ttydrv = d;

	if (octeon_pci_console_setup0(&octeon_pci_console)) {
		pr_notice("Console not created.\n");
		r = -ENODEV;
		goto err;
	} else {
		pr_info("Initialized.\n");
	}

	d->owner = THIS_MODULE;
	d->driver_name = "octeon_pci_console";
	d->name = "ttyPCI";
	d->type = TTY_DRIVER_TYPE_SERIAL;
	d->subtype = SERIAL_TYPE_NORMAL;
	d->flags = TTY_DRIVER_REAL_RAW;
	d->major = 4;
	d->minor_start = 96;
	d->init_termios = tty_std_termios;
	d->init_termios.c_cflag = B9600 | CS8 | CREAD | HUPCL | CLOCAL;
	d->driver_state = &octeon_pci_console;
	tty_set_operations(d, &octeon_pci_tty_ops);
	tty_port_init(&octeon_pci_console.tty_port);
	tty_port_link_device(&octeon_pci_console.tty_port, d, 0);
	r = tty_register_driver(d);
	if (r)
		goto err;

	return 0;
err:
	put_tty_driver(d);
	return r;
}
module_init(octeon_pci_console_module_init);
