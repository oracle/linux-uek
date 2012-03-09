/*
 * This file is part of Xen USB backend driver.
 *
 * Copyright (C) 2009, FUJITSU LABORATORIES LTD.
 * Author: Noboru Iwamatsu <n_iwamatsu@jp.fujitsu.com>
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
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 *
 * or, by your choice,
 *
 * When distributed separately from the Linux kernel or incorporated into
 * other software packages, subject to the following license:
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#ifndef __XEN_USBBACK__COMMON_H__
#define __XEN_USBBACK__COMMON_H__

#include <linux/module.h>
#include <linux/interrupt.h>
#include <linux/slab.h>
#include <linux/usb.h>
#include <linux/vmalloc.h>
#include <linux/kthread.h>
#include <linux/wait.h>
#include <linux/list.h>
#include <linux/kref.h>
#include <asm/hypervisor.h>
#include <xen/xen.h>
#include <xen/events.h>
#include <xen/interface/xen.h>
#include <xen/xenbus.h>
#include <xen/page.h>
#include <xen/grant_table.h>
#include <xen/interface/io/usbif.h>

#define DRV_PFX "xen-usbback:"

struct xen_usbdev;

#ifndef BUS_ID_SIZE
#define XEN_USB_BUS_ID_SIZE 20
#else
#define XEN_USB_BUS_ID_SIZE BUS_ID_SIZE
#endif

#define XEN_USB_DEV_ADDR_SIZE 128

struct xen_usbif {
	domid_t				domid;
	unsigned int			handle;
	int				num_ports;
	enum usb_spec_version		usb_ver;

	struct list_head		usbif_list;

	struct xenbus_device		*xbdev;

	unsigned int			irq;

	void				*urb_sring;
	void				*conn_sring;
	struct usbif_urb_back_ring	urb_ring;
	struct usbif_conn_back_ring	conn_ring;

	spinlock_t			urb_ring_lock;
	spinlock_t			conn_ring_lock;
	atomic_t			refcnt;

	struct xenbus_watch		backend_watch;

	/* device address lookup table */
	struct xen_usbdev		*addr_table[XEN_USB_DEV_ADDR_SIZE];
	spinlock_t			addr_lock;

	/* connected device list */
	struct list_head		dev_list;
	spinlock_t			dev_lock;

	/* request schedule */
	struct task_struct		*xenusbd;
	unsigned int			waiting_reqs;
	wait_queue_head_t		waiting_to_free;
	wait_queue_head_t		wq;
};

struct xen_usbport {
	struct list_head	port_list;

	char			phys_bus[XEN_USB_BUS_ID_SIZE];
	domid_t			domid;
	unsigned int		handle;
	int			portnum;
	unsigned		is_connected:1;
};

struct xen_usbdev {
	struct kref		kref;
	struct list_head	dev_list;

	struct xen_usbport	*port;
	struct usb_device	*udev;
	struct xen_usbif	*usbif;
	int			addr;

	struct list_head	submitting_list;
	spinlock_t		submitting_lock;
};

#define usbif_get(_b) (atomic_inc(&(_b)->refcnt))
#define usbif_put(_b) \
	do { \
		if (atomic_dec_and_test(&(_b)->refcnt)) \
			wake_up(&(_b)->waiting_to_free); \
	} while (0)

int xen_usbif_xenbus_init(void);
void xen_usbif_xenbus_exit(void);
struct xen_usbif *xen_usbif_find(domid_t domid, unsigned int handle);

int xen_usbdev_init(void);
void xen_usbdev_exit(void);

void xen_usbif_attach_device(struct xen_usbif *usbif, struct xen_usbdev *dev);
void xen_usbif_detach_device(struct xen_usbif *usbif, struct xen_usbdev *dev);
void xen_usbif_detach_device_without_lock(struct xen_usbif *usbif,
						struct xen_usbdev *dev);
void xen_usbif_hotplug_notify(struct xen_usbif *usbif, int portnum, int speed);
struct xen_usbdev *xen_usbif_find_attached_device(struct xen_usbif *usbif,
								int port);
irqreturn_t xen_usbif_be_int(int irq, void *dev_id);
int xen_usbif_schedule(void *arg);
void xen_usbif_unlink_urbs(struct xen_usbdev *dev);

struct xen_usbport *xen_usbport_find_by_busid(const char *busid);
struct xen_usbport *xen_usbport_find(const domid_t domid,
				const unsigned int handle, const int portnum);
int xen_usbport_add(const char *busid, const domid_t domid,
				const unsigned int handle, const int portnum);
int xen_usbport_remove(const domid_t domid, const unsigned int handle,
							const int portnum);
#endif /* __XEN_USBBACK__COMMON_H__ */
