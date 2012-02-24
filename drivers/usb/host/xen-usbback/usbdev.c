/*
 * USB stub device driver - grabbing and managing USB devices.
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

#include "common.h"

static LIST_HEAD(port_list);
static DEFINE_SPINLOCK(port_list_lock);

struct xen_usbport *xen_usbport_find_by_busid(const char *busid)
{
	struct xen_usbport *port;
	int found = 0;
	unsigned long flags;

	spin_lock_irqsave(&port_list_lock, flags);
	list_for_each_entry(port, &port_list, port_list) {
		if (!(strncmp(port->phys_bus, busid, XEN_USB_BUS_ID_SIZE))) {
			found = 1;
			break;
		}
	}
	spin_unlock_irqrestore(&port_list_lock, flags);

	if (found)
		return port;

	return NULL;
}

struct xen_usbport *xen_usbport_find(const domid_t domid,
				const unsigned int handle, const int portnum)
{
	struct xen_usbport *port;
	int found = 0;
	unsigned long flags;

	spin_lock_irqsave(&port_list_lock, flags);
	list_for_each_entry(port, &port_list, port_list) {
		if ((port->domid == domid) &&
					(port->handle == handle) &&
					(port->portnum == portnum)) {
			found = 1;
			break;
		}
	}
	spin_unlock_irqrestore(&port_list_lock, flags);

	if (found)
		return port;

	return NULL;
}

int xen_usbport_add(const char *busid, const domid_t domid,
		const unsigned int handle, const int portnum)
{
	struct xen_usbport *port;
	unsigned long flags;

	port = kzalloc(sizeof(*port), GFP_KERNEL);
	if (!port)
		return -ENOMEM;

	port->domid = domid;
	port->handle = handle;
	port->portnum = portnum;

	strncpy(port->phys_bus, busid, XEN_USB_BUS_ID_SIZE);

	spin_lock_irqsave(&port_list_lock, flags);
	list_add(&port->port_list, &port_list);
	spin_unlock_irqrestore(&port_list_lock, flags);

	return 0;
}

int xen_usbport_remove(const domid_t domid, const unsigned int handle,
			const int portnum)
{
	struct xen_usbport *port, *tmp;
	int err = -ENOENT;
	unsigned long flags;

	spin_lock_irqsave(&port_list_lock, flags);
	list_for_each_entry_safe(port, tmp, &port_list, port_list) {
		if (port->domid == domid &&
					port->handle == handle &&
					port->portnum == portnum) {
			list_del(&port->port_list);
			kfree(port);

			err = 0;
		}
	}
	spin_unlock_irqrestore(&port_list_lock, flags);

	return err;
}

static struct xen_usbdev *xen_usbdev_alloc(struct usb_device *udev,
						struct xen_usbport *port)
{
	struct xen_usbdev *dev;

	dev = kzalloc(sizeof(*dev), GFP_KERNEL);
	if (!dev) {
		pr_alert(DRV_PFX "no memory for alloc xen_usbdev\n");
		return NULL;
	}
	kref_init(&dev->kref);
	dev->udev = usb_get_dev(udev);
	dev->port = port;
	spin_lock_init(&dev->submitting_lock);
	INIT_LIST_HEAD(&dev->submitting_list);

	return dev;
}

static void usbdev_release(struct kref *kref)
{
	struct xen_usbdev *dev;

	dev = container_of(kref, struct xen_usbdev, kref);

	usb_put_dev(dev->udev);
	dev->udev = NULL;
	dev->port = NULL;
	kfree(dev);
}

static inline void usbdev_get(struct xen_usbdev *dev)
{
	kref_get(&dev->kref);
}

static inline void usbdev_put(struct xen_usbdev *dev)
{
	kref_put(&dev->kref, usbdev_release);
}

static int usbdev_probe(struct usb_interface *intf,
			 const struct usb_device_id *id)
{
	struct usb_device *udev = interface_to_usbdev(intf);
	const char *busid = dev_name(intf->dev.parent);
	struct xen_usbport *port = NULL;
	struct xen_usbdev *dev = NULL;
	struct xen_usbif *usbif = NULL;
	int retval = -ENODEV;

	/* hub currently not supported, so skip. */
	if (udev->descriptor.bDeviceClass == USB_CLASS_HUB)
		goto out;

	port = xen_usbport_find_by_busid(busid);
	if (!port)
		goto out;

	usbif = xen_usbif_find(port->domid, port->handle);
	if (!usbif)
		goto out;

	switch (udev->speed) {
	case USB_SPEED_LOW:
	case USB_SPEED_FULL:
		break;
	case USB_SPEED_HIGH:
		if (usbif->usb_ver >= USB_VER_USB20)
			break;
		/* fall through */
	default:
		goto out;
	}

	dev = xen_usbif_find_attached_device(usbif, port->portnum);
	if (!dev) {
		/* new connection */
		dev = xen_usbdev_alloc(udev, port);
		if (!dev)
			return -ENOMEM;
		xen_usbif_attach_device(usbif, dev);
		xen_usbif_hotplug_notify(usbif, port->portnum, udev->speed);
	} else {
		/* maybe already called and connected by other intf */
		if (strncmp(dev->port->phys_bus, busid, XEN_USB_BUS_ID_SIZE))
			goto out; /* invalid call */
	}

	usbdev_get(dev);
	usb_set_intfdata(intf, dev);
	retval = 0;

out:
	return retval;
}

static void usbdev_disconnect(struct usb_interface *intf)
{
	struct xen_usbdev *dev
		= (struct xen_usbdev *) usb_get_intfdata(intf);

	usb_set_intfdata(intf, NULL);

	if (!dev)
		return;

	if (dev->usbif) {
		xen_usbif_hotplug_notify(dev->usbif, dev->port->portnum, 0);
		xen_usbif_detach_device(dev->usbif, dev);
	}
	xen_usbif_unlink_urbs(dev);
	usbdev_put(dev);
}

static ssize_t usbdev_show_ports(struct device_driver *driver, char *buf)
{
	struct xen_usbport *port;
	size_t count = 0;
	unsigned long flags;

	spin_lock_irqsave(&port_list_lock, flags);
	list_for_each_entry(port, &port_list, port_list) {
		if (count >= PAGE_SIZE)
			break;
		count += scnprintf((char *)buf + count, PAGE_SIZE - count,
				"%s:%d:%d:%d\n",
				&port->phys_bus[0],
				port->domid,
				port->handle,
				port->portnum);
	}
	spin_unlock_irqrestore(&port_list_lock, flags);

	return count;
}

DRIVER_ATTR(port_ids, S_IRUSR, usbdev_show_ports, NULL);

/* table of devices that matches any usbdevice */
static const struct usb_device_id usbdev_table[] = {
	{ .driver_info = 1 }, /* wildcard, see usb_match_id() */
	{ } /* Terminating entry */
};
MODULE_DEVICE_TABLE(usb, usbdev_table);

static struct usb_driver xen_usbdev_driver = {
	.name = "usbback",
	.probe = usbdev_probe,
	.disconnect = usbdev_disconnect,
	.id_table = usbdev_table,
	.no_dynamic_id = 1,
};

int __init xen_usbdev_init(void)
{
	int err;

	err = usb_register(&xen_usbdev_driver);
	if (err < 0) {
		pr_alert(DRV_PFX "usb_register failed (error %d)\n",
									err);
		goto out;
	}

	err = driver_create_file(&xen_usbdev_driver.drvwrap.driver,
							&driver_attr_port_ids);
	if (err)
		usb_deregister(&xen_usbdev_driver);

out:
	return err;
}

void xen_usbdev_exit(void)
{
	driver_remove_file(&xen_usbdev_driver.drvwrap.driver,
							&driver_attr_port_ids);
	usb_deregister(&xen_usbdev_driver);
}
