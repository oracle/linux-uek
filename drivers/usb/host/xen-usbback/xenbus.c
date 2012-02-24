/*
 * Xenbus interface for USB backend driver.
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

#include <linux/delay.h>
#include "common.h"

static LIST_HEAD(usbif_list);
static DEFINE_SPINLOCK(usbif_list_lock);

struct xen_usbif *xen_usbif_find(domid_t domid, unsigned int handle)
{
	struct xen_usbif *usbif;
	int found = 0;
	unsigned long flags;

	spin_lock_irqsave(&usbif_list_lock, flags);
	list_for_each_entry(usbif, &usbif_list, usbif_list) {
		if (usbif->domid == domid && usbif->handle == handle) {
			found = 1;
			break;
		}
	}
	spin_unlock_irqrestore(&usbif_list_lock, flags);

	if (found)
		return usbif;

	return NULL;
}

struct xen_usbif *xen_usbif_alloc(domid_t domid, unsigned int handle)
{
	struct xen_usbif *usbif;
	unsigned long flags;
	int i;

	usbif = kzalloc(sizeof(struct xen_usbif), GFP_KERNEL);
	if (!usbif)
		return NULL;

	usbif->domid = domid;
	usbif->handle = handle;
	INIT_LIST_HEAD(&usbif->usbif_list);
	spin_lock_init(&usbif->urb_ring_lock);
	spin_lock_init(&usbif->conn_ring_lock);
	atomic_set(&usbif->refcnt, 0);
	init_waitqueue_head(&usbif->wq);
	init_waitqueue_head(&usbif->waiting_to_free);
	spin_lock_init(&usbif->dev_lock);
	INIT_LIST_HEAD(&usbif->dev_list);
	spin_lock_init(&usbif->addr_lock);
	for (i = 0; i < XEN_USB_DEV_ADDR_SIZE; i++)
		usbif->addr_table[i] = NULL;

	spin_lock_irqsave(&usbif_list_lock, flags);
	list_add(&usbif->usbif_list, &usbif_list);
	spin_unlock_irqrestore(&usbif_list_lock, flags);

	return usbif;
}

static int xen_usbif_map(struct xen_usbif *usbif, unsigned long urb_ring_ref,
			unsigned long conn_ring_ref, unsigned int evtchn)
{
	int err = -ENOMEM;

	if (usbif->irq)
		return 0;

	err = xenbus_map_ring_valloc(usbif->xbdev, urb_ring_ref,
	    &usbif->urb_sring);
	if (err < 0)
		return err;

	err = xenbus_map_ring_valloc(usbif->xbdev, conn_ring_ref,
	    &usbif->conn_sring);
	if (err < 0)
		goto fail_alloc;

	err = bind_interdomain_evtchn_to_irqhandler(usbif->domid, evtchn,
				xen_usbif_be_int, 0, "usbif-backend", usbif);
	if (err < 0)
		goto fail_evtchn;
	usbif->irq = err;

	BACK_RING_INIT(&usbif->urb_ring,
	    (struct usbif_urb_sring *)usbif->urb_sring, PAGE_SIZE);
	BACK_RING_INIT(&usbif->conn_ring,
	    (struct usbif_conn_sring *)usbif->conn_sring, PAGE_SIZE);

	return 0;

fail_evtchn:
	xenbus_unmap_ring_vfree(usbif->xbdev, usbif->conn_sring);
fail_alloc:
	xenbus_unmap_ring_vfree(usbif->xbdev, usbif->urb_sring);

	return err;
}

static void xen_usbif_disconnect(struct xen_usbif *usbif)
{
	struct xen_usbdev *dev, *tmp;
	unsigned long flags;

	if (usbif->xenusbd) {
		kthread_stop(usbif->xenusbd);
		usbif->xenusbd = NULL;
	}

	spin_lock_irqsave(&usbif->dev_lock, flags);
	list_for_each_entry_safe(dev, tmp, &usbif->dev_list, dev_list) {
		xen_usbif_unlink_urbs(dev);
		xen_usbif_detach_device_without_lock(usbif, dev);
	}
	spin_unlock_irqrestore(&usbif->dev_lock, flags);

	wait_event(usbif->waiting_to_free, atomic_read(&usbif->refcnt) == 0);

	if (usbif->irq) {
		unbind_from_irqhandler(usbif->irq, usbif);
		usbif->irq = 0;
	}

	if (usbif->urb_ring.sring) {
		xenbus_unmap_ring_vfree(usbif->xbdev, usbif->urb_sring);
		usbif->urb_ring.sring = NULL;
		xenbus_unmap_ring_vfree(usbif->xbdev, usbif->conn_sring);
		usbif->conn_ring.sring = NULL;
	}
}

static void xen_usbif_free(struct xen_usbif *usbif)
{
	unsigned long flags;

	spin_lock_irqsave(&usbif_list_lock, flags);
	list_del(&usbif->usbif_list);
	spin_unlock_irqrestore(&usbif_list_lock, flags);
	kfree(usbif);
}

static void usbbk_changed(struct xenbus_watch *watch, const char **vec,
				unsigned int len)
{
	struct xenbus_transaction xbt;
	int err;
	int i;
	char node[8];
	char *busid;
	struct xen_usbport *port = NULL;

	struct xen_usbif *usbif = container_of(watch, struct xen_usbif,
						backend_watch);
	struct xenbus_device *dev = usbif->xbdev;

again:
	err = xenbus_transaction_start(&xbt);
	if (err) {
		xenbus_dev_fatal(dev, err, "starting transaction");
		return;
	}

	for (i = 1; i <= usbif->num_ports; i++) {
		sprintf(node, "port/%d", i);
		busid = xenbus_read(xbt, dev->nodename, node, NULL);
		if (IS_ERR(busid)) {
			err = PTR_ERR(busid);
			xenbus_dev_fatal(dev, err, "reading port/%d", i);
			goto abort;
		}

		/*
		 * remove port, if the port is not connected,
		 */
		if (strlen(busid) == 0) {
			port = xen_usbport_find(usbif->domid, usbif->handle, i);
			if (port) {
				if (port->is_connected)
					xenbus_dev_fatal(dev, err,
						"can't remove port/%d, "
						"unbind first", i);
				else
					xen_usbport_remove(usbif->domid,
							usbif->handle, i);
			}
			continue; /* never configured, ignore */
		}

		/*
		 * add port,
		 * if the port is not configured and not used from other usbif.
		 */
		port = xen_usbport_find(usbif->domid, usbif->handle, i);
		if (port) {
			if ((strncmp(port->phys_bus, busid,
							XEN_USB_BUS_ID_SIZE)))
				xenbus_dev_fatal(dev, err, "can't add port/%d, "
						"remove first", i);
			else
				continue; /* already configured, ignore */
		} else {
			if (xen_usbport_find_by_busid(busid))
				xenbus_dev_fatal(dev, err, "can't add port/%d, "
						"busid already used", i);
			else
				xen_usbport_add(busid, usbif->domid,
						usbif->handle, i);
		}
	}

	err = xenbus_transaction_end(xbt, 0);
	if (err == -EAGAIN)
		goto again;
	if (err)
		xenbus_dev_fatal(dev, err, "completing transaction");

	return;

abort:
	xenbus_transaction_end(xbt, 1);

	return;
}

static int usbbk_remove(struct xenbus_device *dev)
{
	struct xen_usbif *usbif = dev_get_drvdata(&dev->dev);
	int i;

	if (usbif->backend_watch.node) {
		unregister_xenbus_watch(&usbif->backend_watch);
		kfree(usbif->backend_watch.node);
		usbif->backend_watch.node = NULL;
	}

	if (usbif) {
		/* remove all ports */
		for (i = 1; i <= usbif->num_ports; i++)
			xen_usbport_remove(usbif->domid, usbif->handle, i);
		xen_usbif_disconnect(usbif);
		xen_usbif_free(usbif);
	}
	dev_set_drvdata(&dev->dev, NULL);

	return 0;
}

static int usbbk_probe(struct xenbus_device *dev,
				const struct xenbus_device_id *id)
{
	struct xen_usbif *usbif;
	unsigned long handle;
	int num_ports;
	int usb_ver;
	int err;

	if (usb_disabled())
		return -ENODEV;

	if (kstrtoul(strrchr(dev->otherend, '/') + 1, 0, &handle))
		return -ENOENT;

	usbif = xen_usbif_alloc(dev->otherend_id, handle);
	if (!usbif) {
		xenbus_dev_fatal(dev, -ENOMEM, "allocating backend interface");
		return -ENOMEM;
	}
	usbif->xbdev = dev;
	dev_set_drvdata(&dev->dev, usbif);

	err = xenbus_scanf(XBT_NIL, dev->nodename, "num-ports",
							"%d", &num_ports);
	if (err != 1) {
		xenbus_dev_fatal(dev, err, "reading num-ports");
		goto fail;
	}
	if (num_ports < 1 || num_ports > USB_MAXCHILDREN) {
		xenbus_dev_fatal(dev, err, "invalid num-ports");
		goto fail;
	}
	usbif->num_ports = num_ports;

	err = xenbus_scanf(XBT_NIL, dev->nodename, "usb-ver", "%d", &usb_ver);
	if (err != 1) {
		xenbus_dev_fatal(dev, err, "reading usb-ver");
		goto fail;
	}
	switch (usb_ver) {
	case USB_VER_USB11:
	case USB_VER_USB20:
		usbif->usb_ver = usb_ver;
		break;
	default:
		xenbus_dev_fatal(dev, err, "invalid usb-ver");
		goto fail;
	}

	err = xenbus_switch_state(dev, XenbusStateInitWait);
	if (err)
		goto fail;

	return 0;

fail:
	usbbk_remove(dev);
	return err;
}

static int connect_rings(struct xen_usbif *usbif)
{
	struct xenbus_device *dev = usbif->xbdev;
	unsigned long urb_ring_ref;
	unsigned long conn_ring_ref;
	unsigned int evtchn;
	int err;

	err = xenbus_gather(XBT_NIL, dev->otherend,
			    "urb-ring-ref", "%lu", &urb_ring_ref,
			    "conn-ring-ref", "%lu", &conn_ring_ref,
			    "event-channel", "%u", &evtchn, NULL);
	if (err) {
		xenbus_dev_fatal(dev, err,
				 "reading %s/ring-ref and event-channel",
				 dev->otherend);
		return err;
	}

	pr_info(DRV_PFX "urb-ring-ref %ld, conn-ring-ref %ld, "
	    "event-channel %d\n", urb_ring_ref, conn_ring_ref, evtchn);

	err = xen_usbif_map(usbif, urb_ring_ref, conn_ring_ref, evtchn);
	if (err) {
		xenbus_dev_fatal(dev, err, "mapping urb-ring-ref %lu "
					"conn-ring-ref %lu port %u",
					urb_ring_ref, conn_ring_ref, evtchn);
		return err;
	}

	return 0;
}

static int start_xenusbd(struct xen_usbif *usbif)
{
	int err = 0;
	char name[TASK_COMM_LEN];

	snprintf(name, TASK_COMM_LEN, "usbback.%d.%d", usbif->domid,
			usbif->handle);
	usbif->xenusbd = kthread_run(xen_usbif_schedule, usbif, name);
	if (IS_ERR(usbif->xenusbd)) {
		err = PTR_ERR(usbif->xenusbd);
		usbif->xenusbd = NULL;
		xenbus_dev_error(usbif->xbdev, err, "start xenusbd");
	}

	return err;
}

static void frontend_changed(struct xenbus_device *dev,
			     enum xenbus_state frontend_state)
{
	struct xen_usbif *usbif = dev_get_drvdata(&dev->dev);
	int err;

	switch (frontend_state) {
	case XenbusStateReconfiguring:
	case XenbusStateReconfigured:
		break;

	case XenbusStateInitialising:
		if (dev->state == XenbusStateClosed) {
			pr_info(DRV_PFX "%s: %s: prepare for reconnect\n",
			       __func__, dev->nodename);
			xenbus_switch_state(dev, XenbusStateInitWait);
		}
		break;

	case XenbusStateInitialised:
	case XenbusStateConnected:
		if (dev->state == XenbusStateConnected)
			break;

		xen_usbif_disconnect(usbif);

		err = connect_rings(usbif);
		if (err)
			break;
		err = start_xenusbd(usbif);
		if (err)
			break;
		err = xenbus_watch_pathfmt(dev, &usbif->backend_watch,
		    usbbk_changed,  "%s/%s", dev->nodename, "port");
		if (err)
			break;
		xenbus_switch_state(dev, XenbusStateConnected);
		break;

	case XenbusStateClosing:
		xenbus_switch_state(dev, XenbusStateClosing);
		break;

	case XenbusStateClosed:
		xen_usbif_disconnect(usbif);
		xenbus_switch_state(dev, XenbusStateClosed);
		if (xenbus_dev_is_online(dev))
			break;
		/* fall through if not online */
	case XenbusStateUnknown:
		device_unregister(&dev->dev);
		break;

	default:
		xenbus_dev_fatal(dev, -EINVAL, "saw state %d at frontend",
				 frontend_state);
		break;
	}
}


/* ** Driver Registration ** */

static const struct xenbus_device_id usbback_ids[] = {
	{ "vusb" },
	{ "" },
};

static DEFINE_XENBUS_DRIVER(usbback, ,
	.probe = usbbk_probe,
	.remove = usbbk_remove,
	.otherend_changed = frontend_changed,
);

int __init xen_usbif_xenbus_init(void)
{
	return xenbus_register_backend(&usbback_driver);
}

void __exit xen_usbif_xenbus_exit(void)
{
	xenbus_unregister_driver(&usbback_driver);
}
