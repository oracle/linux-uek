/*
 * xen-usbfront.c
 *
 * This file is part of Xen USB Virtual Host Controller driver.
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

#include <linux/module.h>
#include <linux/usb.h>
#include <linux/usb/hcd.h>
#include <linux/list.h>
#include <linux/kthread.h>
#include <linux/wait.h>
#include <linux/io.h>
#include <xen/xenbus.h>
#include <xen/events.h>
#include <xen/page.h>
#include <xen/grant_table.h>
#include <xen/interface/xen.h>
#include <xen/interface/io/usbif.h>

static inline struct usbfront_info *hcd_to_info(struct usb_hcd *hcd)
{
	return (struct usbfront_info *) (hcd->hcd_priv);
}

static inline struct usb_hcd *info_to_hcd(struct usbfront_info *info)
{
	return container_of((void *) info, struct usb_hcd, hcd_priv);
}

/* Private per-URB data */
struct urb_priv {
	struct list_head list;
	struct urb *urb;
	int req_id;		/* RING_REQUEST id for submitting */
	int unlink_req_id;	/* RING_REQUEST id for unlinking */
	int status;
	unsigned unlinked:1;	/* dequeued marker */
};

/* virtual roothub port status */
struct rhport_status {
	u32 status;
	unsigned resuming:1;		/* in resuming */
	unsigned c_connection:1;	/* connection changed */
	unsigned long timeout;
};

/* status of attached device */
struct vdevice_status {
	int devnum;
	enum usb_device_state status;
	enum usb_device_speed speed;
};

/* RING request shadow */
struct usb_shadow {
	struct usbif_urb_request req;
	struct urb *urb;
};

/* statistics for tuning, monitoring, ... */
struct xenhcd_stats {
	unsigned long ring_full;	/* RING_FULL conditions */
	unsigned long complete;		/* normal giveback urbs */
	unsigned long unlink;		/* unlinked urbs */
};

struct usbfront_info {
	/* Virtual Host Controller has 4 urb queues */
	struct list_head pending_submit_list;
	struct list_head pending_unlink_list;
	struct list_head in_progress_list;
	struct list_head giveback_waiting_list;

	spinlock_t lock;

	/* timer that kick pending and giveback waiting urbs */
	struct timer_list watchdog;
	unsigned long actions;

	/* virtual root hub */
	int rh_numports;
	struct rhport_status ports[USB_MAXCHILDREN];
	struct vdevice_status devices[USB_MAXCHILDREN];

	/* Xen related staff */
	struct xenbus_device *xbdev;
	int urb_ring_ref;
	int conn_ring_ref;
	struct usbif_urb_front_ring urb_ring;
	struct usbif_conn_front_ring conn_ring;

	unsigned int evtchn, irq; /* event channel */
	struct usb_shadow shadow[USB_URB_RING_SIZE];
	unsigned long shadow_free;

	/* RING_RESPONSE thread */
	struct task_struct *kthread;
	wait_queue_head_t wq;
	unsigned int waiting_resp;

	/* xmit statistics */
#ifdef XENHCD_STATS
	struct xenhcd_stats stats;
#define COUNT(x) do { (x)++; } while (0)
#else
#define COUNT(x) do {} while (0)
#endif
};

#define XENHCD_RING_JIFFIES (HZ/200)
#define XENHCD_SCAN_JIFFIES 1

enum xenhcd_timer_action {
	TIMER_RING_WATCHDOG,
	TIMER_SCAN_PENDING_URBS,
};

static inline void
timer_action_done(struct usbfront_info *info, enum xenhcd_timer_action action)
{
	clear_bit(action, &info->actions);
}

static inline void
timer_action(struct usbfront_info *info, enum xenhcd_timer_action action)
{
	if (timer_pending(&info->watchdog) &&
	    test_bit(TIMER_SCAN_PENDING_URBS, &info->actions))
		return;

	if (!test_and_set_bit(action, &info->actions)) {
		unsigned long t;

		switch (action) {
		case TIMER_RING_WATCHDOG:
			t = XENHCD_RING_JIFFIES;
			break;
		default:
			t = XENHCD_SCAN_JIFFIES;
			break;
		}
		mod_timer(&info->watchdog, t + jiffies);
	}
}

struct kmem_cache *xenhcd_urbp_cachep;
struct hc_driver xen_usb20_hc_driver;
struct hc_driver xen_usb11_hc_driver;

static ssize_t show_statistics(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	struct usb_hcd *hcd;
	struct usbfront_info *info;
	unsigned long flags;
	unsigned temp, size;
	char *next;

	hcd = dev_get_drvdata(dev);
	info = hcd_to_info(hcd);
	next = buf;
	size = PAGE_SIZE;

	spin_lock_irqsave(&info->lock, flags);

	temp = scnprintf(next, size,
			"bus %s, device %s\n"
			"%s\n"
			"xenhcd, hcd state %d\n",
			hcd->self.controller->bus->name,
			dev_name(hcd->self.controller),
			hcd->product_desc,
			hcd->state);
	size -= temp;
	next += temp;

#ifdef XENHCD_STATS
	temp = scnprintf(next, size,
			"complete %ld unlink %ld ring_full %ld\n",
			info->stats.complete, info->stats.unlink,
			info->stats.ring_full);
	size -= temp;
	next += temp;
#endif

	spin_unlock_irqrestore(&info->lock, flags);

	return PAGE_SIZE - size;
}

static DEVICE_ATTR(statistics, S_IRUGO, show_statistics, NULL);

static inline void create_debug_file(struct usbfront_info *info)
{
	struct device *dev = info_to_hcd(info)->self.controller;
	if (device_create_file(dev, &dev_attr_statistics))
		printk(KERN_WARNING "statistics file not created for %s\n",
					info_to_hcd(info)->self.bus_name);
}

static inline void remove_debug_file(struct usbfront_info *info)
{
	struct device *dev = info_to_hcd(info)->self.controller;
	device_remove_file(dev, &dev_attr_statistics);
}

/*
 * set virtual port connection status
 */
void set_connect_state(struct usbfront_info *info, int portnum)
{
	int port;

	port = portnum - 1;
	if (info->ports[port].status & USB_PORT_STAT_POWER) {
		switch (info->devices[port].speed) {
		case USB_SPEED_UNKNOWN:
			info->ports[port].status &=
					~(USB_PORT_STAT_CONNECTION |
						USB_PORT_STAT_ENABLE |
						USB_PORT_STAT_LOW_SPEED |
						USB_PORT_STAT_HIGH_SPEED |
						USB_PORT_STAT_SUSPEND);
			break;
		case USB_SPEED_LOW:
			info->ports[port].status |= USB_PORT_STAT_CONNECTION;
			info->ports[port].status |= USB_PORT_STAT_LOW_SPEED;
			break;
		case USB_SPEED_FULL:
			info->ports[port].status |= USB_PORT_STAT_CONNECTION;
			break;
		case USB_SPEED_HIGH:
			info->ports[port].status |= USB_PORT_STAT_CONNECTION;
			info->ports[port].status |= USB_PORT_STAT_HIGH_SPEED;
			break;
		default: /* error */
			return;
		}
		info->ports[port].status |= (USB_PORT_STAT_C_CONNECTION << 16);
	}
}

/*
 * set virtual device connection status
 */
void rhport_connect(struct usbfront_info *info, int portnum,
			enum usb_device_speed speed)
{
	int port;

	if (portnum < 1 || portnum > info->rh_numports)
		return; /* invalid port number */

	port = portnum - 1;
	if (info->devices[port].speed != speed) {
		switch (speed) {
		case USB_SPEED_UNKNOWN: /* disconnect */
			info->devices[port].status = USB_STATE_NOTATTACHED;
			break;
		case USB_SPEED_LOW:
		case USB_SPEED_FULL:
		case USB_SPEED_HIGH:
			info->devices[port].status = USB_STATE_ATTACHED;
			break;
		default: /* error */
			return;
		}
		info->devices[port].speed = speed;
		info->ports[port].c_connection = 1;

		set_connect_state(info, portnum);
	}
}

/*
 * SetPortFeature(PORT_SUSPENDED)
 */
void rhport_suspend(struct usbfront_info *info, int portnum)
{
	int port;

	port = portnum - 1;
	info->ports[port].status |= USB_PORT_STAT_SUSPEND;
	info->devices[port].status = USB_STATE_SUSPENDED;
}

/*
 * ClearPortFeature(PORT_SUSPENDED)
 */
void rhport_resume(struct usbfront_info *info, int portnum)
{
	int port;

	port = portnum - 1;
	if (info->ports[port].status & USB_PORT_STAT_SUSPEND) {
		info->ports[port].resuming = 1;
		info->ports[port].timeout = jiffies + msecs_to_jiffies(20);
	}
}

/*
 * SetPortFeature(PORT_POWER)
 */
void rhport_power_on(struct usbfront_info *info, int portnum)
{
	int port;

	port = portnum - 1;
	if ((info->ports[port].status & USB_PORT_STAT_POWER) == 0) {
		info->ports[port].status |= USB_PORT_STAT_POWER;
		if (info->devices[port].status != USB_STATE_NOTATTACHED)
			info->devices[port].status = USB_STATE_POWERED;
		if (info->ports[port].c_connection)
			set_connect_state(info, portnum);
	}
}

/*
 * ClearPortFeature(PORT_POWER)
 * SetConfiguration(non-zero)
 * Power_Source_Off
 * Over-current
 */
void rhport_power_off(struct usbfront_info *info, int portnum)
{
	int port;

	port = portnum - 1;
	if (info->ports[port].status & USB_PORT_STAT_POWER) {
		info->ports[port].status = 0;
		if (info->devices[port].status != USB_STATE_NOTATTACHED)
			info->devices[port].status = USB_STATE_ATTACHED;
	}
}

/*
 * ClearPortFeature(PORT_ENABLE)
 */
void rhport_disable(struct usbfront_info *info, int portnum)
{
	int port;

	port = portnum - 1;
	info->ports[port].status &= ~USB_PORT_STAT_ENABLE;
	info->ports[port].status &= ~USB_PORT_STAT_SUSPEND;
	info->ports[port].resuming = 0;
	if (info->devices[port].status != USB_STATE_NOTATTACHED)
		info->devices[port].status = USB_STATE_POWERED;
}

/*
 * SetPortFeature(PORT_RESET)
 */
void rhport_reset(struct usbfront_info *info, int portnum)
{
	int port;

	port = portnum - 1;
	info->ports[port].status &= ~(USB_PORT_STAT_ENABLE
					| USB_PORT_STAT_LOW_SPEED
					| USB_PORT_STAT_HIGH_SPEED);
	info->ports[port].status |= USB_PORT_STAT_RESET;

	if (info->devices[port].status != USB_STATE_NOTATTACHED)
		info->devices[port].status = USB_STATE_ATTACHED;

	/* 10msec reset signaling */
	info->ports[port].timeout = jiffies + msecs_to_jiffies(10);
}

#ifdef XENHCD_PM
#ifdef CONFIG_PM
static int xenhcd_bus_suspend(struct usb_hcd *hcd)
{
	struct usbfront_info *info = hcd_to_info(hcd);
	int ret = 0;
	int i, ports;

	ports = info->rh_numports;

	spin_lock_irq(&info->lock);
	if (!test_bit(HCD_FLAG_HW_ACCESSIBLE, &hcd->flags))
		ret = -ESHUTDOWN;
	else {
		/* suspend any active ports*/
		for (i = 1; i <= ports; i++)
			rhport_suspend(info, i);
	}
	spin_unlock_irq(&info->lock);

	del_timer_sync(&info->watchdog);

	return ret;
}

static int xenhcd_bus_resume(struct usb_hcd *hcd)
{
	struct usbfront_info *info = hcd_to_info(hcd);
	int ret = 0;
	int i, ports;

	ports = info->rh_numports;

	spin_lock_irq(&info->lock);
	if (!test_bit(HCD_FLAG_HW_ACCESSIBLE, &hcd->flags))
		ret = -ESHUTDOWN;
	else {
		/* resume any suspended ports*/
		for (i = 1; i <= ports; i++)
			rhport_resume(info, i);
	}
	spin_unlock_irq(&info->lock);

	return ret;
}
#endif
#endif

static void xenhcd_hub_descriptor(struct usbfront_info *info,
					struct usb_hub_descriptor *desc)
{
	u16 temp;
	int ports = info->rh_numports;

	desc->bDescriptorType = 0x29;
	desc->bPwrOn2PwrGood = 10; /* EHCI says 20ms max */
	desc->bHubContrCurrent = 0;
	desc->bNbrPorts = ports;

	/* size of DeviceRemovable and PortPwrCtrlMask fields*/
	temp = 1 + (ports / 8);
	desc->bDescLength = 7 + 2 * temp;

	/* bitmaps for DeviceRemovable and PortPwrCtrlMask */
	memset(&desc->u.hs.DeviceRemovable[0], 0, temp);
	memset(&desc->u.hs.DeviceRemovable[temp], 0xff, temp);

	/* per-port over current reporting and no power switching */
	temp = 0x000a;
	desc->wHubCharacteristics = cpu_to_le16(temp);
}

/* port status change mask for hub_status_data */
#define PORT_C_MASK \
	((USB_PORT_STAT_C_CONNECTION \
	| USB_PORT_STAT_C_ENABLE \
	| USB_PORT_STAT_C_SUSPEND \
	| USB_PORT_STAT_C_OVERCURRENT \
	| USB_PORT_STAT_C_RESET) << 16)

/*
 * See USB 2.0 Spec, 11.12.4 Hub and Port Status Change Bitmap.
 * If port status changed, writes the bitmap to buf and return
 * that length(number of bytes).
 * If Nothing changed, return 0.
 */
static int xenhcd_hub_status_data(struct usb_hcd *hcd, char *buf)
{
	struct usbfront_info *info = hcd_to_info(hcd);

	int ports;
	int i;
	int length;

	unsigned long flags;
	int ret = 0;

	int changed = 0;

	if (!HC_IS_RUNNING(hcd->state))
		return 0;

	/* initialize the status to no-changes */
	ports = info->rh_numports;
	length = 1 + (ports / 8);
	for (i = 0; i < length; i++) {
		buf[i] = 0;
		ret++;
	}

	spin_lock_irqsave(&info->lock, flags);

	for (i = 0; i < ports; i++) {
		/* check status for each port */
		if (info->ports[i].status & PORT_C_MASK) {
			if (i < 7)
				buf[0] |= 1 << (i + 1);
			else if (i < 15)
				buf[1] |= 1 << (i - 7);
			else if (i < 23)
				buf[2] |= 1 << (i - 15);
			else
				buf[3] |= 1 << (i - 23);
			changed = 1;
		}
	}

	if (!changed)
		ret = 0;

	spin_unlock_irqrestore(&info->lock, flags);

	return ret;
}

static int xenhcd_hub_control(struct usb_hcd *hcd, u16 typeReq, u16 wValue,
				u16 wIndex, char *buf, u16 wLength)
{
	struct usbfront_info *info = hcd_to_info(hcd);
	int ports = info->rh_numports;
	unsigned long flags;
	int ret = 0;
	int i;
	int changed = 0;

	spin_lock_irqsave(&info->lock, flags);
	switch (typeReq) {
	case ClearHubFeature:
		/* ignore this request */
		break;
	case ClearPortFeature:
		if (!wIndex || wIndex > ports)
			goto error;

		switch (wValue) {
		case USB_PORT_FEAT_SUSPEND:
			rhport_resume(info, wIndex);
			break;
		case USB_PORT_FEAT_POWER:
			rhport_power_off(info, wIndex);
			break;
		case USB_PORT_FEAT_ENABLE:
			rhport_disable(info, wIndex);
			break;
		case USB_PORT_FEAT_C_CONNECTION:
			info->ports[wIndex-1].c_connection = 0;
			/* falling through */
		default:
			info->ports[wIndex-1].status &= ~(1 << wValue);
			break;
		}
		break;
	case GetHubDescriptor:
		xenhcd_hub_descriptor(info, (struct usb_hub_descriptor *) buf);
		break;
	case GetHubStatus:
		/* always local power supply good and no over-current exists. */
		*(__le32 *)buf = cpu_to_le32(0);
		break;
	case GetPortStatus:
		if (!wIndex || wIndex > ports)
			goto error;

		wIndex--;

		/* resume completion */
		if (info->ports[wIndex].resuming &&
		    time_after_eq(jiffies, info->ports[wIndex].timeout)) {
			info->ports[wIndex].status |=
						(USB_PORT_STAT_C_SUSPEND << 16);
			info->ports[wIndex].status &= ~USB_PORT_STAT_SUSPEND;
		}

		/* reset completion */
		if ((info->ports[wIndex].status & USB_PORT_STAT_RESET) != 0 &&
		    time_after_eq(jiffies, info->ports[wIndex].timeout)) {
			info->ports[wIndex].status |=
						(USB_PORT_STAT_C_RESET << 16);
			info->ports[wIndex].status &= ~USB_PORT_STAT_RESET;

			if (info->devices[wIndex].status !=
							USB_STATE_NOTATTACHED) {
				info->ports[wIndex].status |=
							USB_PORT_STAT_ENABLE;
				info->devices[wIndex].status =
							USB_STATE_DEFAULT;
			}

			switch (info->devices[wIndex].speed) {
			case USB_SPEED_LOW:
				info->ports[wIndex].status |=
						USB_PORT_STAT_LOW_SPEED;
				break;
			case USB_SPEED_HIGH:
				info->ports[wIndex].status |=
						USB_PORT_STAT_HIGH_SPEED;
				break;
			default:
				break;
			}
		}

		((u16 *) buf)[0] = cpu_to_le16(info->ports[wIndex].status);
		((u16 *) buf)[1] = cpu_to_le16(info->ports[wIndex].status
									>> 16);
		break;
	case SetHubFeature:
		/* not supported */
		goto error;
	case SetPortFeature:
		if (!wIndex || wIndex > ports)
			goto error;

		switch (wValue) {
		case USB_PORT_FEAT_POWER:
			rhport_power_on(info, wIndex);
			break;
		case USB_PORT_FEAT_RESET:
			rhport_reset(info, wIndex);
			break;
		case USB_PORT_FEAT_SUSPEND:
			rhport_suspend(info, wIndex);
			break;
		default:
			if ((info->ports[wIndex-1].status &
						USB_PORT_STAT_POWER) != 0)
				info->ports[wIndex-1].status |= (1 << wValue);
		}
		break;

	default:
error:
		ret = -EPIPE;
	}
	spin_unlock_irqrestore(&info->lock, flags);

	/* check status for each port */
	for (i = 0; i < ports; i++) {
		if (info->ports[i].status & PORT_C_MASK)
			changed = 1;
	}
	if (changed)
		usb_hcd_poll_rh_status(hcd);

	return ret;
}

struct kmem_cache *xenhcd_urbp_cachep;

static struct urb_priv *alloc_urb_priv(struct urb *urb)
{
	struct urb_priv *urbp;

	urbp = kmem_cache_zalloc(xenhcd_urbp_cachep, GFP_ATOMIC);
	if (!urbp)
		return NULL;

	urbp->urb = urb;
	urb->hcpriv = urbp;
	urbp->req_id = ~0;
	urbp->unlink_req_id = ~0;
	INIT_LIST_HEAD(&urbp->list);

	return urbp;
}

static void free_urb_priv(struct urb_priv *urbp)
{
	urbp->urb->hcpriv = NULL;
	kmem_cache_free(xenhcd_urbp_cachep, urbp);
}

static inline int get_id_from_freelist(struct usbfront_info *info)
{
	unsigned long free;
	free = info->shadow_free;
	BUG_ON(free >= USB_URB_RING_SIZE);
	info->shadow_free = info->shadow[free].req.id;
	info->shadow[free].req.id = (unsigned int)0x0fff; /* debug */
	return free;
}

static inline void add_id_to_freelist(struct usbfront_info *info,
							unsigned long id)
{
	info->shadow[id].req.id  = info->shadow_free;
	info->shadow[id].urb = NULL;
	info->shadow_free = id;
}

static inline int count_pages(void *addr, int length)
{
	unsigned long start = (unsigned long) addr >> PAGE_SHIFT;
	unsigned long end = (unsigned long)
				(addr + length + PAGE_SIZE - 1) >> PAGE_SHIFT;
	return end - start;
}

static inline void xenhcd_gnttab_map(struct usbfront_info *info, void *addr,
					int length, grant_ref_t *gref_head,
					struct usbif_request_segment *seg,
					int nr_pages, int flags)
{
	grant_ref_t ref;
	unsigned long mfn;
	unsigned int offset;
	unsigned int len;
	unsigned int bytes;
	int i;

	len = length;

	for (i = 0; i < nr_pages; i++) {
		BUG_ON(!len);

		mfn = virt_to_mfn(addr);
		offset = offset_in_page(addr);

		bytes = PAGE_SIZE - offset;
		if (bytes > len)
			bytes = len;

		ref = gnttab_claim_grant_reference(gref_head);
		BUG_ON(ref == -ENOSPC);
		gnttab_grant_foreign_access_ref(ref, info->xbdev->otherend_id,
						mfn, flags);
		seg[i].gref = ref;
		seg[i].offset = (uint16_t)offset;
		seg[i].length = (uint16_t)bytes;

		addr += bytes;
		len -= bytes;
	}
}

static int map_urb_for_request(struct usbfront_info *info, struct urb *urb,
				struct usbif_urb_request *req)
{
	grant_ref_t gref_head;
	int nr_buff_pages = 0;
	int nr_isodesc_pages = 0;
	int ret = 0;

	if (urb->transfer_buffer_length) {
		nr_buff_pages = count_pages(urb->transfer_buffer,
						urb->transfer_buffer_length);

		if (usb_pipeisoc(urb->pipe))
			nr_isodesc_pages = count_pages(&urb->iso_frame_desc[0],
				sizeof(struct usb_iso_packet_descriptor) *
							urb->number_of_packets);

		if (nr_buff_pages + nr_isodesc_pages >
						USBIF_MAX_SEGMENTS_PER_REQUEST)
			return -E2BIG;

		ret = gnttab_alloc_grant_references(
				USBIF_MAX_SEGMENTS_PER_REQUEST, &gref_head);
		if (ret) {
			printk(KERN_ERR "usbfront: "
				"gnttab_alloc_grant_references() error\n");
			return -ENOMEM;
		}

		xenhcd_gnttab_map(info, urb->transfer_buffer,
				urb->transfer_buffer_length, &gref_head,
				&req->seg[0], nr_buff_pages,
				usb_pipein(urb->pipe) ? 0 : GTF_readonly);

		if (!usb_pipeisoc(urb->pipe))
			gnttab_free_grant_references(gref_head);
	}

	req->pipe = usbif_setportnum_pipe(urb->pipe, urb->dev->portnum);
	req->transfer_flags = urb->transfer_flags;
	req->buffer_length = urb->transfer_buffer_length;
	req->nr_buffer_segs = nr_buff_pages;

	switch (usb_pipetype(urb->pipe)) {
	case PIPE_ISOCHRONOUS:
		req->u.isoc.interval = urb->interval;
		req->u.isoc.start_frame = urb->start_frame;
		req->u.isoc.number_of_packets = urb->number_of_packets;
		req->u.isoc.nr_frame_desc_segs = nr_isodesc_pages;
		/* urb->number_of_packets must be > 0 */
		if (unlikely(urb->number_of_packets <= 0))
			BUG();
		xenhcd_gnttab_map(info, &urb->iso_frame_desc[0],
				sizeof(struct usb_iso_packet_descriptor) *
					urb->number_of_packets, &gref_head,
				&req->seg[nr_buff_pages], nr_isodesc_pages, 0);
		gnttab_free_grant_references(gref_head);
		break;
	case PIPE_INTERRUPT:
		req->u.intr.interval = urb->interval;
		break;
	case PIPE_CONTROL:
		if (urb->setup_packet)
			memcpy(req->u.ctrl, urb->setup_packet, 8);
		break;
	case PIPE_BULK:
		break;
	default:
		ret = -EINVAL;
	}

	return ret;
}

static void xenhcd_gnttab_done(struct usb_shadow *shadow)
{
	int nr_segs = 0;
	int i;

	nr_segs = shadow->req.nr_buffer_segs;

	if (usb_pipeisoc(shadow->req.pipe))
		nr_segs +=  shadow->req.u.isoc.nr_frame_desc_segs;

	for (i = 0; i < nr_segs; i++)
		gnttab_end_foreign_access(shadow->req.seg[i].gref, 0, 0UL);

	shadow->req.nr_buffer_segs = 0;
	shadow->req.u.isoc.nr_frame_desc_segs = 0;
}

static void xenhcd_giveback_urb(struct usbfront_info *info, struct urb *urb,
								int status)
__releases(info->lock)
__acquires(info->lock)
{
	struct urb_priv *urbp = (struct urb_priv *) urb->hcpriv;

	list_del_init(&urbp->list);
	free_urb_priv(urbp);
	switch (urb->status) {
	case -ECONNRESET:
	case -ENOENT:
		COUNT(info->stats.unlink);
		break;
	case -EINPROGRESS:
		urb->status = status;
		/* falling through */
	default:
		COUNT(info->stats.complete);
	}
	spin_unlock(&info->lock);
	usb_hcd_giveback_urb(info_to_hcd(info), urb,
				urbp->status <= 0 ? urbp->status : urb->status);
	spin_lock(&info->lock);
}

static inline int xenhcd_do_request(struct usbfront_info *info,
					struct urb_priv *urbp)
{
	struct usbif_urb_request *req;
	struct urb *urb = urbp->urb;
	uint16_t id;
	int notify;
	int ret = 0;

	req = RING_GET_REQUEST(&info->urb_ring, info->urb_ring.req_prod_pvt);
	id = get_id_from_freelist(info);
	req->id = id;

	if (unlikely(urbp->unlinked)) {
		req->u.unlink.unlink_id = urbp->req_id;
		req->pipe = usbif_setunlink_pipe(usbif_setportnum_pipe(
						urb->pipe, urb->dev->portnum));
		urbp->unlink_req_id = id;
	} else {
		ret = map_urb_for_request(info, urb, req);
		if (ret < 0) {
			add_id_to_freelist(info, id);
			return ret;
		}
		urbp->req_id = id;
	}

	info->urb_ring.req_prod_pvt++;
	info->shadow[id].urb = urb;
	info->shadow[id].req = *req;

	RING_PUSH_REQUESTS_AND_CHECK_NOTIFY(&info->urb_ring, notify);
	if (notify)
		notify_remote_via_irq(info->irq);

	return ret;
}

static void xenhcd_kick_pending_urbs(struct usbfront_info *info)
{
	struct urb_priv *urbp;
	int ret;

	while (!list_empty(&info->pending_submit_list)) {
		if (RING_FULL(&info->urb_ring)) {
			COUNT(info->stats.ring_full);
			timer_action(info, TIMER_RING_WATCHDOG);
			goto done;
		}

		urbp = list_entry(info->pending_submit_list.next,
							struct urb_priv, list);
		ret = xenhcd_do_request(info, urbp);
		if (ret == 0)
			list_move_tail(&urbp->list, &info->in_progress_list);
		else
			xenhcd_giveback_urb(info, urbp->urb, -ESHUTDOWN);
	}
	timer_action_done(info, TIMER_SCAN_PENDING_URBS);

done:
	return;
}

/*
 * caller must lock info->lock
 */
static void xenhcd_cancel_all_enqueued_urbs(struct usbfront_info *info)
{
	struct urb_priv *urbp, *tmp;

	list_for_each_entry_safe(urbp, tmp, &info->in_progress_list, list) {
		if (!urbp->unlinked) {
			xenhcd_gnttab_done(&info->shadow[urbp->req_id]);
			barrier();
			if (urbp->urb->status == -EINPROGRESS)/* not dequeued */
				xenhcd_giveback_urb(info, urbp->urb,
								-ESHUTDOWN);
			else /* dequeued */
				xenhcd_giveback_urb(info, urbp->urb,
							urbp->urb->status);
		}
		info->shadow[urbp->req_id].urb = NULL;
	}

	list_for_each_entry_safe(urbp, tmp, &info->pending_submit_list, list) {
		xenhcd_giveback_urb(info, urbp->urb, -ESHUTDOWN);
	}

	return;
}

/*
 * caller must lock info->lock
 */
static void xenhcd_giveback_unlinked_urbs(struct usbfront_info *info)
{
	struct urb_priv *urbp, *tmp;

	list_for_each_entry_safe(urbp, tmp,
					&info->giveback_waiting_list, list) {
		xenhcd_giveback_urb(info, urbp->urb, urbp->urb->status);
	}
}

static int xenhcd_submit_urb(struct usbfront_info *info, struct urb_priv *urbp)
{
	int ret = 0;

	if (RING_FULL(&info->urb_ring)) {
		list_add_tail(&urbp->list, &info->pending_submit_list);
		COUNT(info->stats.ring_full);
		timer_action(info, TIMER_RING_WATCHDOG);
		goto done;
	}

	if (!list_empty(&info->pending_submit_list)) {
		list_add_tail(&urbp->list, &info->pending_submit_list);
		timer_action(info, TIMER_SCAN_PENDING_URBS);
		goto done;
	}

	ret = xenhcd_do_request(info, urbp);
	if (ret == 0)
		list_add_tail(&urbp->list, &info->in_progress_list);

done:
	return ret;
}

static int xenhcd_unlink_urb(struct usbfront_info *info, struct urb_priv *urbp)
{
	int ret = 0;

	/* already unlinked? */
	if (urbp->unlinked)
		return -EBUSY;

	urbp->unlinked = 1;

	/* the urb is still in pending_submit queue */
	if (urbp->req_id == ~0) {
		list_move_tail(&urbp->list, &info->giveback_waiting_list);
		timer_action(info, TIMER_SCAN_PENDING_URBS);
		goto done;
	}

	/* send unlink request to backend */
	if (RING_FULL(&info->urb_ring)) {
		list_move_tail(&urbp->list, &info->pending_unlink_list);
		COUNT(info->stats.ring_full);
		timer_action(info, TIMER_RING_WATCHDOG);
		goto done;
	}

	if (!list_empty(&info->pending_unlink_list)) {
		list_move_tail(&urbp->list, &info->pending_unlink_list);
		timer_action(info, TIMER_SCAN_PENDING_URBS);
		goto done;
	}

	ret = xenhcd_do_request(info, urbp);
	if (ret == 0)
		list_move_tail(&urbp->list, &info->in_progress_list);

done:
	return ret;
}

static int xenhcd_urb_request_done(struct usbfront_info *info)
{
	struct usbif_urb_response *res;
	struct urb *urb;

	RING_IDX i, rp;
	uint16_t id;
	int more_to_do = 0;
	unsigned long flags;

	spin_lock_irqsave(&info->lock, flags);

	rp = info->urb_ring.sring->rsp_prod;
	rmb(); /* ensure we see queued responses up to "rp" */

	for (i = info->urb_ring.rsp_cons; i != rp; i++) {
		res = RING_GET_RESPONSE(&info->urb_ring, i);
		id = res->id;

		if (likely(usbif_pipesubmit(info->shadow[id].req.pipe))) {
			xenhcd_gnttab_done(&info->shadow[id]);
			urb = info->shadow[id].urb;
			barrier();
			if (likely(urb)) {
				urb->actual_length = res->actual_length;
				urb->error_count = res->error_count;
				urb->start_frame = res->start_frame;
				barrier();
				xenhcd_giveback_urb(info, urb, res->status);
			}
		}

		add_id_to_freelist(info, id);
	}
	info->urb_ring.rsp_cons = i;

	if (i != info->urb_ring.req_prod_pvt)
		RING_FINAL_CHECK_FOR_RESPONSES(&info->urb_ring, more_to_do);
	else
		info->urb_ring.sring->rsp_event = i + 1;

	spin_unlock_irqrestore(&info->lock, flags);

	cond_resched();

	return more_to_do;
}

static int xenhcd_conn_notify(struct usbfront_info *info)
{
	struct usbif_conn_response *res;
	struct usbif_conn_request *req;
	RING_IDX rc, rp;
	uint16_t id;
	uint8_t portnum, speed;
	int more_to_do = 0;
	int notify;
	int port_changed = 0;
	unsigned long flags;

	spin_lock_irqsave(&info->lock, flags);

	rc = info->conn_ring.rsp_cons;
	rp = info->conn_ring.sring->rsp_prod;
	rmb(); /* ensure we see queued responses up to "rp" */

	while (rc != rp) {
		res = RING_GET_RESPONSE(&info->conn_ring, rc);
		id = res->id;
		portnum = res->portnum;
		speed = res->speed;
		info->conn_ring.rsp_cons = ++rc;

		rhport_connect(info, portnum, speed);
		if (info->ports[portnum-1].c_connection)
			port_changed = 1;

		barrier();

		req = RING_GET_REQUEST(&info->conn_ring,
					info->conn_ring.req_prod_pvt);
		req->id = id;
		info->conn_ring.req_prod_pvt++;
	}

	if (rc != info->conn_ring.req_prod_pvt)
		RING_FINAL_CHECK_FOR_RESPONSES(&info->conn_ring, more_to_do);
	else
		info->conn_ring.sring->rsp_event = rc + 1;

	RING_PUSH_REQUESTS_AND_CHECK_NOTIFY(&info->conn_ring, notify);
	if (notify)
		notify_remote_via_irq(info->irq);

	spin_unlock_irqrestore(&info->lock, flags);

	if (port_changed)
		usb_hcd_poll_rh_status(info_to_hcd(info));

	cond_resched();

	return more_to_do;
}

int xenhcd_schedule(void *arg)
{
	struct usbfront_info *info = (struct usbfront_info *) arg;

	while (!kthread_should_stop()) {
		wait_event_interruptible(info->wq,
				info->waiting_resp || kthread_should_stop());
		info->waiting_resp = 0;
		smp_mb();

		if (xenhcd_urb_request_done(info))
			info->waiting_resp = 1;

		if (xenhcd_conn_notify(info))
			info->waiting_resp = 1;
	}

	return 0;
}

static void xenhcd_notify_work(struct usbfront_info *info)
{
	info->waiting_resp = 1;
	wake_up(&info->wq);
}

irqreturn_t xenhcd_int(int irq, void *dev_id)
{
	xenhcd_notify_work((struct usbfront_info *) dev_id);
	return IRQ_HANDLED;
}

static void xenhcd_watchdog(unsigned long param)
{
	struct usbfront_info *info = (struct usbfront_info *) param;
	unsigned long flags;

	spin_lock_irqsave(&info->lock, flags);
	if (likely(HC_IS_RUNNING(info_to_hcd(info)->state))) {
		timer_action_done(info, TIMER_RING_WATCHDOG);
		xenhcd_giveback_unlinked_urbs(info);
		xenhcd_kick_pending_urbs(info);
	}
	spin_unlock_irqrestore(&info->lock, flags);
}

/*
 * one-time HC init
 */
static int xenhcd_setup(struct usb_hcd *hcd)
{
	struct usbfront_info *info = hcd_to_info(hcd);

	spin_lock_init(&info->lock);
	INIT_LIST_HEAD(&info->pending_submit_list);
	INIT_LIST_HEAD(&info->pending_unlink_list);
	INIT_LIST_HEAD(&info->in_progress_list);
	INIT_LIST_HEAD(&info->giveback_waiting_list);
	init_timer(&info->watchdog);
	info->watchdog.function = xenhcd_watchdog;
	info->watchdog.data = (unsigned long) info;
	return 0;
}

/*
 * start HC running
 */
static int xenhcd_run(struct usb_hcd *hcd)
{
	hcd->uses_new_polling = 1;
	hcd->state = HC_STATE_RUNNING;
	create_debug_file(hcd_to_info(hcd));
	return 0;
}

/*
 * stop running HC
 */
static void xenhcd_stop(struct usb_hcd *hcd)
{
	struct usbfront_info *info = hcd_to_info(hcd);

	del_timer_sync(&info->watchdog);
	remove_debug_file(info);
	spin_lock_irq(&info->lock);
	/* cancel all urbs */
	hcd->state = HC_STATE_HALT;
	xenhcd_cancel_all_enqueued_urbs(info);
	xenhcd_giveback_unlinked_urbs(info);
	spin_unlock_irq(&info->lock);
}

/*
 * called as .urb_enqueue()
 * non-error returns are promise to giveback the urb later
 */
static int xenhcd_urb_enqueue(struct usb_hcd *hcd, struct urb *urb,
				gfp_t mem_flags)
{
	struct usbfront_info *info = hcd_to_info(hcd);
	struct urb_priv *urbp;
	unsigned long flags;
	int ret = 0;

	spin_lock_irqsave(&info->lock, flags);

	urbp = alloc_urb_priv(urb);
	if (!urbp) {
		ret = -ENOMEM;
		goto done;
	}
	urbp->status = 1;

	ret = xenhcd_submit_urb(info, urbp);
	if (ret != 0)
		free_urb_priv(urbp);

done:
	spin_unlock_irqrestore(&info->lock, flags);
	return ret;
}

/*
 * called as .urb_dequeue()
 */
static int xenhcd_urb_dequeue(struct usb_hcd *hcd, struct urb *urb, int status)
{
	struct usbfront_info *info = hcd_to_info(hcd);
	struct urb_priv *urbp;
	unsigned long flags;
	int ret = 0;

	spin_lock_irqsave(&info->lock, flags);

	urbp = urb->hcpriv;
	if (!urbp)
		goto done;

	urbp->status = status;
	ret = xenhcd_unlink_urb(info, urbp);

done:
	spin_unlock_irqrestore(&info->lock, flags);
	return ret;
}

/*
 * called from usb_get_current_frame_number(),
 * but, almost all drivers not use such function.
 */
static int xenhcd_get_frame(struct usb_hcd *hcd)
{
	/* it means error, but probably no problem :-) */
	return 0;
}

static const char hcd_name[] = "xen_hcd";

struct hc_driver xen_usb20_hc_driver = {
	.description = hcd_name,
	.product_desc = "Xen USB2.0 Virtual Host Controller",
	.hcd_priv_size = sizeof(struct usbfront_info),
	.flags = HCD_USB2,

	/* basic HC lifecycle operations */
	.reset = xenhcd_setup,
	.start = xenhcd_run,
	.stop = xenhcd_stop,

	/* managing urb I/O */
	.urb_enqueue = xenhcd_urb_enqueue,
	.urb_dequeue = xenhcd_urb_dequeue,
	.get_frame_number = xenhcd_get_frame,

	/* root hub operations */
	.hub_status_data = xenhcd_hub_status_data,
	.hub_control = xenhcd_hub_control,
#ifdef XENHCD_PM
#ifdef CONFIG_PM
	.bus_suspend = xenhcd_bus_suspend,
	.bus_resume = xenhcd_bus_resume,
#endif
#endif
};

struct hc_driver xen_usb11_hc_driver = {
	.description = hcd_name,
	.product_desc = "Xen USB1.1 Virtual Host Controller",
	.hcd_priv_size = sizeof(struct usbfront_info),
	.flags = HCD_USB11,

	/* basic HC lifecycle operations */
	.reset = xenhcd_setup,
	.start = xenhcd_run,
	.stop = xenhcd_stop,

	/* managing urb I/O */
	.urb_enqueue = xenhcd_urb_enqueue,
	.urb_dequeue = xenhcd_urb_dequeue,
	.get_frame_number = xenhcd_get_frame,

	/* root hub operations */
	.hub_status_data = xenhcd_hub_status_data,
	.hub_control = xenhcd_hub_control,
#ifdef XENHCD_PM
#ifdef CONFIG_PM
	.bus_suspend = xenhcd_bus_suspend,
	.bus_resume = xenhcd_bus_resume,
#endif
#endif
};

#define GRANT_INVALID_REF 0

static void destroy_rings(struct usbfront_info *info)
{
	if (info->irq)
		unbind_from_irqhandler(info->irq, info);
	info->evtchn = info->irq = 0;

	if (info->urb_ring_ref != GRANT_INVALID_REF) {
		gnttab_end_foreign_access(info->urb_ring_ref, 0,
					(unsigned long)info->urb_ring.sring);
		info->urb_ring_ref = GRANT_INVALID_REF;
	}
	info->urb_ring.sring = NULL;

	if (info->conn_ring_ref != GRANT_INVALID_REF) {
		gnttab_end_foreign_access(info->conn_ring_ref, 0,
					(unsigned long)info->conn_ring.sring);
		info->conn_ring_ref = GRANT_INVALID_REF;
	}
	info->conn_ring.sring = NULL;
}

static int setup_rings(struct xenbus_device *dev, struct usbfront_info *info)
{
	struct usbif_urb_sring *urb_sring;
	struct usbif_conn_sring *conn_sring;
	int err;

	info->urb_ring_ref = GRANT_INVALID_REF;
	info->conn_ring_ref = GRANT_INVALID_REF;

	urb_sring = (struct usbif_urb_sring *)
					get_zeroed_page(GFP_NOIO|__GFP_HIGH);
	if (!urb_sring) {
		xenbus_dev_fatal(dev, -ENOMEM, "allocating urb ring");
		return -ENOMEM;
	}
	SHARED_RING_INIT(urb_sring);
	FRONT_RING_INIT(&info->urb_ring, urb_sring, PAGE_SIZE);

	err = xenbus_grant_ring(dev, virt_to_mfn(info->urb_ring.sring));
	if (err < 0) {
		free_page((unsigned long)urb_sring);
		info->urb_ring.sring = NULL;
		goto fail;
	}
	info->urb_ring_ref = err;

	conn_sring = (struct usbif_conn_sring *)
					get_zeroed_page(GFP_NOIO|__GFP_HIGH);
	if (!conn_sring) {
		xenbus_dev_fatal(dev, -ENOMEM, "allocating conn ring");
		return -ENOMEM;
	}
	SHARED_RING_INIT(conn_sring);
	FRONT_RING_INIT(&info->conn_ring, conn_sring, PAGE_SIZE);

	err = xenbus_grant_ring(dev, virt_to_mfn(info->conn_ring.sring));
	if (err < 0) {
		free_page((unsigned long)conn_sring);
		info->conn_ring.sring = NULL;
		goto fail;
	}
	info->conn_ring_ref = err;

	err = xenbus_alloc_evtchn(dev, &info->evtchn);
	if (err)
		goto fail;

	err = bind_evtchn_to_irqhandler(info->evtchn, xenhcd_int, 0,
					"usbif", info);
	if (err <= 0) {
		xenbus_dev_fatal(dev, err, "bind_listening_port_to_irqhandler");
		goto fail;
	}
	info->irq = err;

	return 0;
fail:
	destroy_rings(info);
	return err;
}

static int talk_to_usbback(struct xenbus_device *dev,
				struct usbfront_info *info)
{
	const char *message;
	struct xenbus_transaction xbt;
	int err;

	err = setup_rings(dev, info);
	if (err)
		goto out;

again:
	err = xenbus_transaction_start(&xbt);
	if (err) {
		xenbus_dev_fatal(dev, err, "starting transaction");
		goto destroy_ring;
	}

	err = xenbus_printf(xbt, dev->nodename, "urb-ring-ref",
				"%u", info->urb_ring_ref);
	if (err) {
		message = "writing urb-ring-ref";
		goto abort_transaction;
	}

	err = xenbus_printf(xbt, dev->nodename, "conn-ring-ref",
				"%u", info->conn_ring_ref);
	if (err) {
		message = "writing conn-ring-ref";
		goto abort_transaction;
	}

	err = xenbus_printf(xbt, dev->nodename, "event-channel",
				"%u", info->evtchn);
	if (err) {
		message = "writing event-channel";
		goto abort_transaction;
	}

	err = xenbus_transaction_end(xbt, 0);
	if (err) {
		if (err == -EAGAIN)
			goto again;
		xenbus_dev_fatal(dev, err, "completing transaction");
		goto destroy_ring;
	}

	return 0;

abort_transaction:
	xenbus_transaction_end(xbt, 1);
	xenbus_dev_fatal(dev, err, "%s", message);

destroy_ring:
	destroy_rings(info);

out:
	return err;
}

static int connect(struct xenbus_device *dev)
{
	struct usbfront_info *info = dev_get_drvdata(&dev->dev);

	struct usbif_conn_request *req;
	int i, idx, err;
	int notify;
	char name[TASK_COMM_LEN];
	struct usb_hcd *hcd;

	hcd = info_to_hcd(info);
	snprintf(name, TASK_COMM_LEN, "xenhcd.%d", hcd->self.busnum);

	err = talk_to_usbback(dev, info);
	if (err)
		return err;

	info->kthread = kthread_run(xenhcd_schedule, info, name);
	if (IS_ERR(info->kthread)) {
		err = PTR_ERR(info->kthread);
		info->kthread = NULL;
		xenbus_dev_fatal(dev, err, "Error creating thread");
		return err;
	}
	/* prepare ring for hotplug notification */
	for (idx = 0, i = 0; i < USB_CONN_RING_SIZE; i++) {
		req = RING_GET_REQUEST(&info->conn_ring, idx);
		req->id = idx;
		idx++;
	}
	info->conn_ring.req_prod_pvt = idx;

	RING_PUSH_REQUESTS_AND_CHECK_NOTIFY(&info->conn_ring, notify);
	if (notify)
		notify_remote_via_irq(info->irq);

	return 0;
}

static struct usb_hcd *create_hcd(struct xenbus_device *dev)
{
	int i;
	int err = 0;
	int num_ports;
	int usb_ver;
	struct usb_hcd *hcd = NULL;
	struct usbfront_info *info = NULL;

	err = xenbus_scanf(XBT_NIL, dev->otherend, "num-ports",
				"%d", &num_ports);
	if (err != 1) {
		xenbus_dev_fatal(dev, err, "reading num-ports");
		return ERR_PTR(-EINVAL);
	}
	if (num_ports < 1 || num_ports > USB_MAXCHILDREN) {
		xenbus_dev_fatal(dev, err, "invalid num-ports");
		return ERR_PTR(-EINVAL);
	}

	err = xenbus_scanf(XBT_NIL, dev->otherend, "usb-ver", "%d", &usb_ver);
	if (err != 1) {
		xenbus_dev_fatal(dev, err, "reading usb-ver");
		return ERR_PTR(-EINVAL);
	}
	switch (usb_ver) {
	case USB_VER_USB11:
		hcd = usb_create_hcd(&xen_usb11_hc_driver,
					&dev->dev, dev_name(&dev->dev));
		break;
	case USB_VER_USB20:
		hcd = usb_create_hcd(&xen_usb20_hc_driver,
					&dev->dev, dev_name(&dev->dev));
		break;
	default:
		xenbus_dev_fatal(dev, err, "invalid usb-ver");
		return ERR_PTR(-EINVAL);
	}
	if (!hcd) {
		xenbus_dev_fatal(dev, err,
					"fail to allocate USB host controller");
		return ERR_PTR(-ENOMEM);
	}

	info = hcd_to_info(hcd);
	info->xbdev = dev;
	info->rh_numports = num_ports;

	for (i = 0; i < USB_URB_RING_SIZE; i++) {
		info->shadow[i].req.id = i + 1;
		info->shadow[i].urb = NULL;
	}
	info->shadow[USB_URB_RING_SIZE-1].req.id = 0x0fff;

	return hcd;
}

static int usbfront_probe(struct xenbus_device *dev,
				const struct xenbus_device_id *id)
{
	int err;
	struct usb_hcd *hcd;
	struct usbfront_info *info;

	if (usb_disabled())
		return -ENODEV;

	hcd = create_hcd(dev);
	if (IS_ERR(hcd)) {
		err = PTR_ERR(hcd);
		xenbus_dev_fatal(dev, err,
					"failed to create usb host controller");
		goto fail;
	}

	info = hcd_to_info(hcd);
	dev_set_drvdata(&dev->dev, info);

	err = usb_add_hcd(hcd, 0, 0);
	if (err != 0) {
		xenbus_dev_fatal(dev, err, "fail to add USB host controller");
		goto fail;
	}

	init_waitqueue_head(&info->wq);

	return 0;

fail:
	usb_put_hcd(hcd);
	dev_set_drvdata(&dev->dev, NULL);
	return err;
}

static void usbfront_disconnect(struct xenbus_device *dev)
{
	struct usbfront_info *info = dev_get_drvdata(&dev->dev);
	struct usb_hcd *hcd = info_to_hcd(info);

	usb_remove_hcd(hcd);
	if (info->kthread) {
		kthread_stop(info->kthread);
		info->kthread = NULL;
	}
	xenbus_frontend_closed(dev);
}

static void usbback_changed(struct xenbus_device *dev,
				enum xenbus_state backend_state)
{
	switch (backend_state) {
	case XenbusStateInitialising:
	case XenbusStateInitialised:
	case XenbusStateConnected:
	case XenbusStateReconfiguring:
	case XenbusStateReconfigured:
	case XenbusStateUnknown:
	case XenbusStateClosed:
		break;

	case XenbusStateInitWait:
		if (dev->state != XenbusStateInitialising)
			break;
		if (!connect(dev))
			xenbus_switch_state(dev, XenbusStateConnected);
		break;

	case XenbusStateClosing:
		usbfront_disconnect(dev);
		break;

	default:
		xenbus_dev_fatal(dev, -EINVAL, "saw state %d at frontend",
					backend_state);
		break;
	}
}

static int usbfront_remove(struct xenbus_device *dev)
{
	struct usbfront_info *info = dev_get_drvdata(&dev->dev);
	struct usb_hcd *hcd = info_to_hcd(info);

	destroy_rings(info);
	usb_put_hcd(hcd);

	return 0;
}

static const struct xenbus_device_id usbfront_ids[] = {
	{ "vusb" },
	{ "" },
};
MODULE_ALIAS("xen:vusb");

static DEFINE_XENBUS_DRIVER(usbfront, ,
	.probe = usbfront_probe,
	.remove = usbfront_remove,
	.otherend_changed = usbback_changed,
);

static int __init usbfront_init(void)
{
	if (!xen_domain())
		return -ENODEV;

	xenhcd_urbp_cachep = kmem_cache_create("xenhcd_urb_priv",
					sizeof(struct urb_priv), 0, 0, NULL);
	if (!xenhcd_urbp_cachep) {
		printk(KERN_ERR "usbfront failed to create kmem cache\n");
		return -ENOMEM;
	}

	return xenbus_register_frontend(&usbfront_driver);
}

static void __exit usbfront_exit(void)
{
	kmem_cache_destroy(xenhcd_urbp_cachep);
	xenbus_unregister_driver(&usbfront_driver);
}

module_init(usbfront_init);
module_exit(usbfront_exit);

MODULE_AUTHOR("");
MODULE_DESCRIPTION("Xen USB Virtual Host Controller driver (usbfront)");
MODULE_LICENSE("Dual BSD/GPL");
