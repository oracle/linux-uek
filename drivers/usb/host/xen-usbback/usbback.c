/*
 * Xen USB backend driver
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

#include <linux/mm.h>
#include "common.h"

static int xen_usbif_reqs = USBIF_BACK_MAX_PENDING_REQS;
module_param_named(reqs, xen_usbif_reqs, int, 0);
MODULE_PARM_DESC(reqs, "Number of usbback requests to allocate");

struct pending_req_segment {
	uint16_t offset;
	uint16_t length;
};

struct pending_req {
	struct xen_usbif	*usbif;

	uint16_t		id; /* request id */

	struct xen_usbdev	*dev;
	struct list_head	urb_list;

	/* urb */
	struct urb		*urb;
	void			*buffer;
	dma_addr_t		transfer_dma;
	struct usb_ctrlrequest	*setup;
	dma_addr_t		setup_dma;

	/* request segments */
	uint16_t		nr_buffer_segs;
				/* number of urb->transfer_buffer segments */
	uint16_t		nr_extra_segs;
				/* number of iso_frame_desc segments (ISO) */
	struct pending_req_segment *seg;

	struct list_head	free_list;
};

#define USBBACK_INVALID_HANDLE (~0)

struct xen_usbbk {
	struct pending_req	*pending_reqs;
	struct list_head	pending_free;
	spinlock_t		pending_free_lock;
	wait_queue_head_t	pending_free_wq;
	struct list_head	urb_free;
	spinlock_t		urb_free_lock;
	struct page		**pending_pages;
	grant_handle_t		*pending_grant_handles;
};

static struct xen_usbbk *usbbk;

static inline int vaddr_pagenr(struct pending_req *req, int seg)
{
	return (req - usbbk->pending_reqs) *
		USBIF_MAX_SEGMENTS_PER_REQUEST + seg;
}

#define pending_page(req, seg) pending_pages[vaddr_pagenr(req, seg)]

static inline unsigned long vaddr(struct pending_req *req, int seg)
{
	unsigned long pfn = page_to_pfn(usbbk->pending_page(req, seg));
	return (unsigned long)pfn_to_kaddr(pfn);
}

#define pending_handle(_req, _seg) \
	(usbbk->pending_grant_handles[vaddr_pagenr(_req, _seg)])

static struct pending_req *alloc_req(void)
{
	struct pending_req *req = NULL;
	unsigned long flags;

	spin_lock_irqsave(&usbbk->pending_free_lock, flags);
	if (!list_empty(&usbbk->pending_free)) {
		req = list_entry(usbbk->pending_free.next, struct pending_req,
								free_list);
		list_del(&req->free_list);
	}
	spin_unlock_irqrestore(&usbbk->pending_free_lock, flags);
	return req;
}

static void free_req(struct pending_req *req)
{
	unsigned long flags;
	int was_empty;

	spin_lock_irqsave(&usbbk->pending_free_lock, flags);
	was_empty = list_empty(&usbbk->pending_free);
	list_add(&req->free_list, &usbbk->pending_free);
	spin_unlock_irqrestore(&usbbk->pending_free_lock, flags);
	if (was_empty)
		wake_up(&usbbk->pending_free_wq);
}

static inline void add_req_to_submitting_list(struct xen_usbdev *dev,
						struct pending_req *pending_req)
{
	unsigned long flags;

	spin_lock_irqsave(&dev->submitting_lock, flags);
	list_add_tail(&pending_req->urb_list, &dev->submitting_list);
	spin_unlock_irqrestore(&dev->submitting_lock, flags);
}

static inline void remove_req_from_submitting_list(struct xen_usbdev *dev,
						struct pending_req *pending_req)
{
	unsigned long flags;

	spin_lock_irqsave(&dev->submitting_lock, flags);
	list_del_init(&pending_req->urb_list);
	spin_unlock_irqrestore(&dev->submitting_lock, flags);
}

void xen_usbif_unlink_urbs(struct xen_usbdev *dev)
{
	struct pending_req *req, *tmp;
	unsigned long flags;

	spin_lock_irqsave(&dev->submitting_lock, flags);
	list_for_each_entry_safe(req, tmp, &dev->submitting_list, urb_list) {
		usb_unlink_urb(req->urb);
	}
	spin_unlock_irqrestore(&dev->submitting_lock, flags);
}

static void copy_buff_to_pages(void *buff, struct pending_req *pending_req,
				int start, int nr_pages)
{
	unsigned long copied = 0;
	int i;

	for (i = start; i < start + nr_pages; i++) {
		memcpy((void *) vaddr(pending_req, i) +
						pending_req->seg[i].offset,
			buff + copied, pending_req->seg[i].length);
		copied += pending_req->seg[i].length;
	}
}

static void copy_pages_to_buff(void *buff, struct pending_req *pending_req,
							int start, int nr_pages)
{
	unsigned long copied = 0;
	int i;

	for (i = start; i < start + nr_pages; i++) {
		void *src = (void *) vaddr(pending_req, i) +
						pending_req->seg[i].offset;
		memcpy(buff + copied, src, pending_req->seg[i].length);
		copied += pending_req->seg[i].length;
	}
}

static int usbbk_alloc_urb(struct usbif_urb_request *req,
				struct pending_req *pending_req)
{
	int ret;

	if (usb_pipeisoc(req->pipe))
		pending_req->urb = usb_alloc_urb(req->u.isoc.number_of_packets,
						 GFP_KERNEL);
	else
		pending_req->urb = usb_alloc_urb(0, GFP_KERNEL);
	if (!pending_req->urb) {
		pr_alert(DRV_PFX "can't alloc urb\n");
		ret = -ENOMEM;
		goto fail;
	}

	if (req->buffer_length) {
		pending_req->buffer =
			usb_alloc_coherent(pending_req->dev->udev,
						req->buffer_length, GFP_KERNEL,
						&pending_req->transfer_dma);
		if (!pending_req->buffer) {
			pr_alert(DRV_PFX "can't alloc urb buffer\n");
			ret = -ENOMEM;
			goto fail_free_urb;
		}
	}

	if (usb_pipecontrol(req->pipe)) {
		pending_req->setup = usb_alloc_coherent(pending_req->dev->udev,
					sizeof(struct usb_ctrlrequest),
					GFP_KERNEL, &pending_req->setup_dma);
		if (!pending_req->setup) {
			pr_alert(DRV_PFX "can't alloc usb_ctrlrequest\n");
			ret = -ENOMEM;
			goto fail_free_buffer;
		}
	}

	return 0;

fail_free_buffer:
	if (req->buffer_length)
		usb_free_coherent(pending_req->dev->udev, req->buffer_length,
				pending_req->buffer, pending_req->transfer_dma);
fail_free_urb:
	usb_free_urb(pending_req->urb);
fail:
	return ret;
}

static void usbbk_release_urb(struct urb *urb)
{
	unsigned long flags;

	spin_lock_irqsave(&usbbk->urb_free_lock, flags);
	list_add(&urb->urb_list, &usbbk->urb_free);
	spin_unlock_irqrestore(&usbbk->urb_free_lock, flags);
}

static void usbbk_free_urb(struct urb *urb)
{
	if (usb_pipecontrol(urb->pipe))
		usb_free_coherent(urb->dev, sizeof(struct usb_ctrlrequest),
				urb->setup_packet, urb->setup_dma);
	if (urb->transfer_buffer_length)
		usb_free_coherent(urb->dev, urb->transfer_buffer_length,
				urb->transfer_buffer, urb->transfer_dma);
	barrier();
	usb_free_urb(urb);
}

static void usbbk_free_urbs(void)
{
	unsigned long flags;
	struct list_head tmp_list;

	if (list_empty(&usbbk->urb_free))
		return;

	INIT_LIST_HEAD(&tmp_list);

	spin_lock_irqsave(&usbbk->urb_free_lock, flags);
	list_splice_init(&usbbk->urb_free, &tmp_list);
	spin_unlock_irqrestore(&usbbk->urb_free_lock, flags);

	while (!list_empty(&tmp_list)) {
		struct urb *next_urb =
			list_first_entry(&tmp_list, struct urb, urb_list);
		list_del(&next_urb->urb_list);
		usbbk_free_urb(next_urb);
	}
}

static void usbif_notify_work(struct xen_usbif *usbif)
{
	usbif->waiting_reqs = 1;
	wake_up(&usbif->wq);
}

irqreturn_t xen_usbif_be_int(int irq, void *dev_id)
{
	usbif_notify_work(dev_id);
	return IRQ_HANDLED;
}

static void xen_usbbk_unmap(struct pending_req *req)
{
	struct gnttab_unmap_grant_ref unmap[USBIF_MAX_SEGMENTS_PER_REQUEST];
	unsigned int i, nr_segs, invcount = 0;
	grant_handle_t handle;
	int ret;

	nr_segs = req->nr_buffer_segs + req->nr_extra_segs;

	if (nr_segs == 0)
		return;

	for (i = 0; i < nr_segs; i++) {
		handle = pending_handle(req, i);
		if (handle == USBBACK_INVALID_HANDLE)
			continue;
		gnttab_set_unmap_op(&unmap[invcount], vaddr(req, i),
					GNTMAP_host_map, handle);
		pending_handle(req, i) = USBBACK_INVALID_HANDLE;
		invcount++;
	}

	ret = HYPERVISOR_grant_table_op(
		GNTTABOP_unmap_grant_ref, unmap, invcount);
	BUG_ON(ret);
	/*
	 * Note, we use invcount, not nr_segs, so we can't index
	 * using vaddr(req, i).
	 */
	for (i = 0; i < invcount; i++) {
		ret = m2p_remove_override(
			virt_to_page(unmap[i].host_addr), false);
		if (ret) {
			pr_alert(DRV_PFX "Failed to remove M2P override for "
				"%lx\n", (unsigned long)unmap[i].host_addr);
			continue;
		}
	}

	kfree(req->seg);
}

static int xen_usbbk_map(struct xen_usbif *usbif,
				struct usbif_urb_request *req,
				struct pending_req *pending_req)
{
	int i, ret;
	unsigned int nr_segs;
	uint32_t flags;
	struct gnttab_map_grant_ref map[USBIF_MAX_SEGMENTS_PER_REQUEST];

	nr_segs = pending_req->nr_buffer_segs + pending_req->nr_extra_segs;

	if (nr_segs == 0)
		return 0;

	if (nr_segs > USBIF_MAX_SEGMENTS_PER_REQUEST) {
		pr_alert(DRV_PFX "Bad number of segments in request\n");
		ret = -EINVAL;
		goto fail;
	}

	pending_req->seg = kmalloc(sizeof(struct pending_req_segment) *
							nr_segs, GFP_KERNEL);
	if (!pending_req->seg) {
		ret = -ENOMEM;
		goto fail;
	}

	flags = GNTMAP_host_map;
	if (usb_pipeout(req->pipe))
		flags |= GNTMAP_readonly;
	for (i = 0; i < pending_req->nr_buffer_segs; i++) {
		gnttab_set_map_op(&map[i], vaddr(pending_req, i), flags,
					req->seg[i].gref, usbif->domid);
	}

	flags = GNTMAP_host_map;
	for (i = pending_req->nr_buffer_segs; i < nr_segs; i++) {
		gnttab_set_map_op(&map[i], vaddr(pending_req, i), flags,
					req->seg[i].gref, usbif->domid);
	}

	ret = HYPERVISOR_grant_table_op(GNTTABOP_map_grant_ref, map, nr_segs);
	BUG_ON(ret);

	for (i = 0; i < nr_segs; i++) {
		if (unlikely(map[i].status != 0)) {
			pr_alert(DRV_PFX "invalid buffer "
					"-- could not remap it (error %d)\n",
				map[i].status);
			map[i].handle = USBBACK_INVALID_HANDLE;
			ret |= 1;
		}

		pending_handle(pending_req, i) = map[i].handle;

		if (ret)
			continue;

		ret = m2p_add_override(PFN_DOWN(map[i].dev_bus_addr),
			usbbk->pending_page(pending_req, i), NULL);
		if (ret) {
			pr_alert(DRV_PFX "Failed to install M2P override for "
			    "%lx (ret: %d)\n",
			    (unsigned long)map[i].dev_bus_addr, ret);
			/* We could switch over to GNTTABOP_copy */
			continue;
		}

		pending_req->seg[i].offset = req->seg[i].offset;
		pending_req->seg[i].length = req->seg[i].length;

		barrier();

		if (pending_req->seg[i].offset >= PAGE_SIZE ||
			pending_req->seg[i].length > PAGE_SIZE ||
			pending_req->seg[i].offset +
				pending_req->seg[i].length > PAGE_SIZE)
			ret |= 1;
	}

	if (ret)
		goto fail_flush;

	return 0;

fail_flush:
	xen_usbbk_unmap(pending_req);
	ret = -ENOMEM;

fail:
	return ret;
}

static void usbbk_do_response(struct pending_req *pending_req, int32_t status,
				int32_t actual_length, int32_t error_count,
				uint16_t start_frame)
{
	struct xen_usbif *usbif = pending_req->usbif;
	struct usbif_urb_response *res;
	unsigned long flags;
	int notify;

	spin_lock_irqsave(&usbif->urb_ring_lock, flags);
	res = RING_GET_RESPONSE(&usbif->urb_ring, usbif->urb_ring.rsp_prod_pvt);
	res->id = pending_req->id;
	res->status = status;
	res->actual_length = actual_length;
	res->error_count = error_count;
	res->start_frame = start_frame;
	usbif->urb_ring.rsp_prod_pvt++;
	barrier();
	RING_PUSH_RESPONSES_AND_CHECK_NOTIFY(&usbif->urb_ring, notify);
	spin_unlock_irqrestore(&usbif->urb_ring_lock, flags);

	if (notify)
		notify_remote_via_irq(usbif->irq);
}

static void usbbk_urb_complete(struct urb *urb)
{
	struct pending_req *pending_req = (struct pending_req *)urb->context;

	if (usb_pipein(urb->pipe) && urb->status == 0 && urb->actual_length > 0)
		copy_buff_to_pages(pending_req->buffer, pending_req, 0,
					pending_req->nr_buffer_segs);

	if (usb_pipeisoc(urb->pipe))
		copy_buff_to_pages(&urb->iso_frame_desc[0], pending_req,
					pending_req->nr_buffer_segs,
					pending_req->nr_extra_segs);

	barrier();

	xen_usbbk_unmap(pending_req);

	usbbk_do_response(pending_req, urb->status, urb->actual_length,
				urb->error_count, urb->start_frame);

	remove_req_from_submitting_list(pending_req->dev, pending_req);

	barrier();
	usbbk_release_urb(urb);
	usbif_put(pending_req->usbif);
	free_req(pending_req);
}

static void usbbk_init_urb(struct usbif_urb_request *req,
				struct pending_req *pending_req)
{
	unsigned int pipe;
	struct usb_device *udev = pending_req->dev->udev;
	struct urb *urb = pending_req->urb;

	switch (usb_pipetype(req->pipe)) {
	case PIPE_ISOCHRONOUS:
		if (usb_pipein(req->pipe))
			pipe = usb_rcvisocpipe(udev,
						usb_pipeendpoint(req->pipe));
		else
			pipe = usb_sndisocpipe(udev,
						usb_pipeendpoint(req->pipe));

		urb->dev = udev;
		urb->pipe = pipe;
		urb->transfer_flags = req->transfer_flags;
		urb->transfer_flags |= URB_ISO_ASAP;
		urb->transfer_buffer = pending_req->buffer;
		urb->transfer_buffer_length = req->buffer_length;
		urb->complete = usbbk_urb_complete;
		urb->context = pending_req;
		urb->interval = req->u.isoc.interval;
		urb->start_frame = req->u.isoc.start_frame;
		urb->number_of_packets = req->u.isoc.number_of_packets;

		break;
	case PIPE_INTERRUPT:
		if (usb_pipein(req->pipe))
			pipe = usb_rcvintpipe(udev,
						usb_pipeendpoint(req->pipe));
		else
			pipe = usb_sndintpipe(udev,
						usb_pipeendpoint(req->pipe));

		usb_fill_int_urb(urb, udev, pipe,
				pending_req->buffer, req->buffer_length,
				usbbk_urb_complete,
				pending_req, req->u.intr.interval);
		/*
		 * high speed interrupt endpoints use a logarithmic encoding of
		 * the endpoint interval, and usb_fill_int_urb() initializes a
		 * interrupt urb with the encoded interval value.
		 *
		 * req->u.intr.interval is the interval value that already
		 * encoded in the frontend part, and the above
		 * usb_fill_int_urb() initializes the urb->interval with double
		 * encoded value.
		 *
		 * so, simply overwrite the urb->interval with original value.
		 */
		urb->interval = req->u.intr.interval;
		urb->transfer_flags = req->transfer_flags;

		break;
	case PIPE_CONTROL:
		if (usb_pipein(req->pipe))
			pipe = usb_rcvctrlpipe(udev, 0);
		else
			pipe = usb_sndctrlpipe(udev, 0);

		usb_fill_control_urb(urb, udev, pipe,
				(unsigned char *) pending_req->setup,
				pending_req->buffer, req->buffer_length,
				usbbk_urb_complete, pending_req);
		memcpy(pending_req->setup, req->u.ctrl, 8);
		urb->setup_dma = pending_req->setup_dma;
		urb->transfer_flags = req->transfer_flags;

		break;
	case PIPE_BULK:
		if (usb_pipein(req->pipe))
			pipe = usb_rcvbulkpipe(udev,
						usb_pipeendpoint(req->pipe));
		else
			pipe = usb_sndbulkpipe(udev,
						usb_pipeendpoint(req->pipe));

		usb_fill_bulk_urb(urb, udev, pipe, pending_req->buffer,
				req->buffer_length, usbbk_urb_complete,
				pending_req);
		urb->transfer_flags = req->transfer_flags;

		break;
	default:
		break;
	}

	if (req->buffer_length) {
		urb->transfer_dma = pending_req->transfer_dma;
		urb->transfer_flags |= URB_NO_TRANSFER_DMA_MAP;
	}
}

struct set_interface_request {
	struct pending_req *pending_req;
	int interface;
	int alternate;
	struct work_struct work;
};

static void usbbk_set_interface_work(struct work_struct *arg)
{
	struct set_interface_request *req
		= container_of(arg, struct set_interface_request, work);
	struct pending_req *pending_req = req->pending_req;
	struct usb_device *udev = req->pending_req->dev->udev;

	int ret;

	usb_lock_device(udev);
	ret = usb_set_interface(udev, req->interface, req->alternate);
	usb_unlock_device(udev);
	usb_put_dev(udev);

	usbbk_do_response(pending_req, ret, 0, 0, 0);
	usbif_put(pending_req->usbif);
	free_req(pending_req);
	kfree(req);
}

static int usbbk_set_interface(struct pending_req *pending_req, int interface,
				int alternate)
{
	struct set_interface_request *req;
	struct usb_device *udev = pending_req->dev->udev;

	req = kmalloc(sizeof(*req), GFP_KERNEL);
	if (!req)
		return -ENOMEM;
	req->pending_req = pending_req;
	req->interface = interface;
	req->alternate = alternate;
	INIT_WORK(&req->work, usbbk_set_interface_work);
	usb_get_dev(udev);
	schedule_work(&req->work);
	return 0;
}

struct clear_halt_request {
	struct pending_req *pending_req;
	int pipe;
	struct work_struct work;
};

static void usbbk_clear_halt_work(struct work_struct *arg)
{
	struct clear_halt_request *req = container_of(arg,
					struct clear_halt_request, work);
	struct pending_req *pending_req = req->pending_req;
	struct usb_device *udev = req->pending_req->dev->udev;
	int ret;

	usb_lock_device(udev);
	ret = usb_clear_halt(req->pending_req->dev->udev, req->pipe);
	usb_unlock_device(udev);
	usb_put_dev(udev);

	usbbk_do_response(pending_req, ret, 0, 0, 0);
	usbif_put(pending_req->usbif);
	free_req(pending_req);
	kfree(req);
}

static int usbbk_clear_halt(struct pending_req *pending_req, int pipe)
{
	struct clear_halt_request *req;
	struct usb_device *udev = pending_req->dev->udev;

	req = kmalloc(sizeof(*req), GFP_KERNEL);
	if (!req)
		return -ENOMEM;
	req->pending_req = pending_req;
	req->pipe = pipe;
	INIT_WORK(&req->work, usbbk_clear_halt_work);

	usb_get_dev(udev);
	schedule_work(&req->work);
	return 0;
}

#if 0
struct port_reset_request {
	struct pending_req *pending_req;
	struct work_struct work;
};

static void usbbk_port_reset_work(struct work_struct *arg)
{
	struct port_reset_request *req = container_of(arg,
					struct port_reset_request, work);
	struct pending_req *pending_req = req->pending_req;
	struct usb_device *udev = pending_req->dev->udev;
	int ret, ret_lock;

	ret = ret_lock = usb_lock_device_for_reset(udev, NULL);
	if (ret_lock >= 0) {
		ret = usb_reset_device(udev);
		if (ret_lock)
			usb_unlock_device(udev);
	}
	usb_put_dev(udev);

	usbbk_do_response(pending_req, ret, 0, 0, 0);
	usbif_put(pending_req->usbif);
	free_req(pending_req);
	kfree(req);
}

static int usbbk_port_reset(struct pending_req *pending_req)
{
	struct port_reset_request *req;
	struct usb_device *udev = pending_req->dev->udev;

	req = kmalloc(sizeof(*req), GFP_KERNEL);
	if (!req)
		return -ENOMEM;

	req->pending_req = pending_req;
	INIT_WORK(&req->work, usbbk_port_reset_work);

	usb_get_dev(udev);
	schedule_work(&req->work);
	return 0;
}
#endif

static void usbbk_set_address(struct xen_usbif *usbif, struct xen_usbdev *dev,
				int cur_addr, int new_addr)
{
	unsigned long flags;

	spin_lock_irqsave(&usbif->addr_lock, flags);
	if (cur_addr)
		usbif->addr_table[cur_addr] = NULL;
	if (new_addr)
		usbif->addr_table[new_addr] = dev;
	dev->addr = new_addr;
	spin_unlock_irqrestore(&usbif->addr_lock, flags);
}

static void process_unlink_req(struct xen_usbif *usbif,
				struct usbif_urb_request *req,
				struct pending_req *pending_req)
{
	struct pending_req *unlink_req = NULL;
	int devnum;
	int ret = 0;
	unsigned long flags;

	devnum = usb_pipedevice(req->pipe);
	if (unlikely(devnum == 0)) {
		pending_req->dev = xen_usbif_find_attached_device(usbif,
						usbif_pipeportnum(req->pipe));
		if (unlikely(!pending_req->dev)) {
			ret = -ENODEV;
			goto fail_response;
		}
	} else {
		if (unlikely(!usbif->addr_table[devnum])) {
			ret = -ENODEV;
			goto fail_response;
		}
		pending_req->dev = usbif->addr_table[devnum];
	}

	spin_lock_irqsave(&pending_req->dev->submitting_lock, flags);
	list_for_each_entry(unlink_req, &pending_req->dev->submitting_list,
								urb_list) {
		if (unlink_req->id == req->u.unlink.unlink_id) {
			ret = usb_unlink_urb(unlink_req->urb);
			break;
		}
	}
	spin_unlock_irqrestore(&pending_req->dev->submitting_lock, flags);

fail_response:
	usbbk_do_response(pending_req, ret, 0, 0, 0);
	usbif_put(usbif);
	free_req(pending_req);
	return;
}

static int check_and_submit_special_ctrlreq(struct xen_usbif *usbif,
						struct usbif_urb_request *req,
						struct pending_req *pending_req)
{
	int devnum;
	struct xen_usbdev *dev = NULL;
	struct usb_ctrlrequest *ctrl = (struct usb_ctrlrequest *) req->u.ctrl;
	int ret;
	int done = 0;

	devnum = usb_pipedevice(req->pipe);

	/*
	 * When the device is first connected or reseted, USB device has no
	 * address. In this initial state, following requests are send to
	 * device address (#0),
	 *
	 *  1. GET_DESCRIPTOR (with Descriptor Type is "DEVICE") is send, and
	 *     OS knows what device is connected to.
	 *
	 *  2. SET_ADDRESS is send, and then, device has its address.
	 *
	 * In the next step, SET_CONFIGURATION is send to addressed device, and
	 * then, the device is finally ready to use.
	 */
	if (unlikely(devnum == 0)) {
		dev = xen_usbif_find_attached_device(usbif,
						usbif_pipeportnum(req->pipe));
		if (unlikely(!dev)) {
			ret = -ENODEV;
			goto fail_response;
		}

		switch (ctrl->bRequest) {
		case USB_REQ_GET_DESCRIPTOR:
			/*
			 * GET_DESCRIPTOR request to device #0.
			 * through to normal urb transfer.
			 */
			pending_req->dev = dev;
			return 0;
			break;
		case USB_REQ_SET_ADDRESS:
			/*
			 * SET_ADDRESS request to device #0.
			 * add attached device to addr_table.
			 */
			{
				__u16 addr = le16_to_cpu(ctrl->wValue);
				usbbk_set_address(usbif, dev, 0, addr);
			}
			ret = 0;
			goto fail_response;
			break;
		default:
			ret = -EINVAL;
			goto fail_response;
		}
	} else {
		if (unlikely(!usbif->addr_table[devnum])) {
			ret = -ENODEV;
			goto fail_response;
		}
		pending_req->dev = usbif->addr_table[devnum];
	}

	/*
	 * Check special request
	 */
	switch (ctrl->bRequest) {
	case USB_REQ_SET_ADDRESS:
		/*
		 * SET_ADDRESS request to addressed device.
		 * change addr or remove from addr_table.
		 */
		{
			__u16 addr = le16_to_cpu(ctrl->wValue);
			usbbk_set_address(usbif, dev, devnum, addr);
		}
		ret = 0;
		goto fail_response;
		break;
#if 0
	case USB_REQ_SET_CONFIGURATION:
		/*
		 * linux 2.6.27 or later version only!
		 */
		if (ctrl->RequestType == USB_RECIP_DEVICE) {
			__u16 config = le16_to_cpu(ctrl->wValue);
			usb_driver_set_configuration(pending_req->dev->udev,
							config);
			done = 1;
		}
		break;
#endif
	case USB_REQ_SET_INTERFACE:
		if (ctrl->bRequestType == USB_RECIP_INTERFACE) {
			__u16 alt = le16_to_cpu(ctrl->wValue);
			__u16 intf = le16_to_cpu(ctrl->wIndex);
			usbbk_set_interface(pending_req, intf, alt);
			done = 1;
		}
		break;
	case USB_REQ_CLEAR_FEATURE:
		if (ctrl->bRequestType == USB_RECIP_ENDPOINT
			&& ctrl->wValue == USB_ENDPOINT_HALT) {
			int pipe;
			int ep = le16_to_cpu(ctrl->wIndex) & 0x0f;
			int dir = le16_to_cpu(ctrl->wIndex) & USB_DIR_IN;
			if (dir)
				pipe = usb_rcvctrlpipe(pending_req->dev->udev,
							ep);
			else
				pipe = usb_sndctrlpipe(pending_req->dev->udev,
							ep);
			usbbk_clear_halt(pending_req, pipe);
			done = 1;
		}
		break;
#if 0 /* not tested yet */
	case USB_REQ_SET_FEATURE:
		if (ctrl->bRequestType == USB_RT_PORT) {
			__u16 feat = le16_to_cpu(ctrl->wValue);
			if (feat == USB_PORT_FEAT_RESET) {
				usbbk_port_reset(pending_req);
				done = 1;
			}
		}
		break;
#endif
	default:
		break;
	}

	return done;

fail_response:
	usbbk_do_response(pending_req, ret, 0, 0, 0);
	usbif_put(usbif);
	free_req(pending_req);
	return 1;
}

static void dispatch_request_to_pending_reqs(struct xen_usbif *usbif,
						struct usbif_urb_request *req,
						struct pending_req *pending_req)
{
	int ret;

	pending_req->id = req->id;
	pending_req->usbif = usbif;

	barrier();

	usbif_get(usbif);

	/* unlink request */
	if (unlikely(usbif_pipeunlink(req->pipe))) {
		process_unlink_req(usbif, req, pending_req);
		return;
	}

	if (usb_pipecontrol(req->pipe)) {
		if (check_and_submit_special_ctrlreq(usbif, req, pending_req))
			return;
	} else {
		int devnum = usb_pipedevice(req->pipe);
		if (unlikely(!usbif->addr_table[devnum])) {
			ret = -ENODEV;
			goto fail_response;
		}
		pending_req->dev = usbif->addr_table[devnum];
	}

	barrier();

	ret = usbbk_alloc_urb(req, pending_req);
	if (ret) {
		ret = -ESHUTDOWN;
		goto fail_response;
	}

	add_req_to_submitting_list(pending_req->dev, pending_req);

	barrier();

	usbbk_init_urb(req, pending_req);

	barrier();

	pending_req->nr_buffer_segs = req->nr_buffer_segs;
	if (usb_pipeisoc(req->pipe))
		pending_req->nr_extra_segs = req->u.isoc.nr_frame_desc_segs;
	else
		pending_req->nr_extra_segs = 0;

	barrier();

	ret = xen_usbbk_map(usbif, req, pending_req);
	if (ret) {
		pr_alert(DRV_PFX "invalid buffer\n");
		ret = -ESHUTDOWN;
		goto fail_free_urb;
	}

	barrier();

	if (usb_pipeout(req->pipe) && req->buffer_length)
		copy_pages_to_buff(pending_req->buffer, pending_req, 0,
					pending_req->nr_buffer_segs);
	if (usb_pipeisoc(req->pipe)) {
		copy_pages_to_buff(&pending_req->urb->iso_frame_desc[0],
				pending_req, pending_req->nr_buffer_segs,
				pending_req->nr_extra_segs);
	}

	barrier();

	ret = usb_submit_urb(pending_req->urb, GFP_KERNEL);
	if (ret) {
		pr_alert(DRV_PFX "failed submitting urb, error %d\n", ret);
		ret = -ESHUTDOWN;
		goto fail_flush_area;
	}
	return;

fail_flush_area:
	xen_usbbk_unmap(pending_req);
fail_free_urb:
	remove_req_from_submitting_list(pending_req->dev, pending_req);
	barrier();
	usbbk_release_urb(pending_req->urb);
fail_response:
	usbbk_do_response(pending_req, ret, 0, 0, 0);
	usbif_put(usbif);
	free_req(pending_req);
}

static int usbbk_start_submit_urb(struct xen_usbif *usbif)
{
	struct usbif_urb_back_ring *urb_ring = &usbif->urb_ring;
	struct usbif_urb_request *req;
	struct pending_req *pending_req;
	RING_IDX rc, rp;
	int more_to_do = 0;

	rc = urb_ring->req_cons;
	rp = urb_ring->sring->req_prod;
	rmb();

	while (rc != rp) {
		if (RING_REQUEST_CONS_OVERFLOW(urb_ring, rc)) {
			pr_warn(DRV_PFX "RING_REQUEST_CONS_OVERFLOW\n");
			break;
		}

		pending_req = alloc_req();
		if (NULL == pending_req) {
			more_to_do = 1;
			break;
		}

		req = RING_GET_REQUEST(urb_ring, rc);
		urb_ring->req_cons = ++rc;

		dispatch_request_to_pending_reqs(usbif, req, pending_req);
	}

	RING_FINAL_CHECK_FOR_REQUESTS(&usbif->urb_ring, more_to_do);

	cond_resched();

	return more_to_do;
}

void xen_usbif_hotplug_notify(struct xen_usbif *usbif, int portnum, int speed)
{
	struct usbif_conn_back_ring *ring = &usbif->conn_ring;
	struct usbif_conn_request *req;
	struct usbif_conn_response *res;
	unsigned long flags;
	u16 id;
	int notify;

	spin_lock_irqsave(&usbif->conn_ring_lock, flags);

	req = RING_GET_REQUEST(ring, ring->req_cons);
	id = req->id;
	ring->req_cons++;
	ring->sring->req_event = ring->req_cons + 1;

	res = RING_GET_RESPONSE(ring, ring->rsp_prod_pvt);
	res->id = id;
	res->portnum = portnum;
	res->speed = speed;
	ring->rsp_prod_pvt++;
	RING_PUSH_RESPONSES_AND_CHECK_NOTIFY(ring, notify);

	spin_unlock_irqrestore(&usbif->conn_ring_lock, flags);

	if (notify)
		notify_remote_via_irq(usbif->irq);
}

int xen_usbif_schedule(void *arg)
{
	struct xen_usbif *usbif = (struct xen_usbif *) arg;

	usbif_get(usbif);

	while (!kthread_should_stop()) {
		wait_event_interruptible(usbif->wq,
				usbif->waiting_reqs || kthread_should_stop());
		wait_event_interruptible(usbbk->pending_free_wq,
		    !list_empty(&usbbk->pending_free) || kthread_should_stop());
		usbif->waiting_reqs = 0;
		smp_mb();

		if (usbbk_start_submit_urb(usbif))
			usbif->waiting_reqs = 1;

		usbbk_free_urbs();
	}

	usbbk_free_urbs();
	usbif->xenusbd = NULL;
	usbif_put(usbif);

	return 0;
}

/*
 * attach xen_usbdev device to usbif.
 */
void xen_usbif_attach_device(struct xen_usbif *usbif, struct xen_usbdev *dev)
{
	unsigned long flags;

	spin_lock_irqsave(&usbif->dev_lock, flags);
	list_add(&dev->dev_list, &usbif->dev_list);
	spin_unlock_irqrestore(&usbif->dev_lock, flags);
	dev->usbif = usbif;
}

/*
 * detach usbdev device from usbif.
 */
void xen_usbif_detach_device(struct xen_usbif *usbif, struct xen_usbdev *dev)
{
	unsigned long flags;

	if (dev->addr)
		usbbk_set_address(usbif, dev, dev->addr, 0);
	spin_lock_irqsave(&usbif->dev_lock, flags);
	list_del(&dev->dev_list);
	spin_unlock_irqrestore(&usbif->dev_lock, flags);
	dev->usbif = NULL;
}

void xen_usbif_detach_device_without_lock(struct xen_usbif *usbif,
							struct xen_usbdev *dev)
{
	if (dev->addr)
		usbbk_set_address(usbif, dev, dev->addr, 0);
	list_del(&dev->dev_list);
	dev->usbif = NULL;
}

static int __init xen_usbif_init(void)
{
	int i, mmap_pages;
	int rc = 0;

	if (!xen_pv_domain())
		return -ENODEV;

	usbbk = kzalloc(sizeof(struct xen_usbbk), GFP_KERNEL);
	if (!usbbk) {
		pr_alert(DRV_PFX "%s: out of memory!\n", __func__);
		return -ENOMEM;
	}

	mmap_pages = xen_usbif_reqs * USBIF_MAX_SEGMENTS_PER_REQUEST;
	usbbk->pending_reqs =
		kzalloc(sizeof(usbbk->pending_reqs[0]) * xen_usbif_reqs,
								GFP_KERNEL);
	usbbk->pending_grant_handles =
		kmalloc(sizeof(usbbk->pending_grant_handles[0]) * mmap_pages,
								GFP_KERNEL);
	usbbk->pending_pages =
		kzalloc(sizeof(usbbk->pending_pages[0]) * mmap_pages,
								GFP_KERNEL);

	if (!usbbk->pending_reqs || !usbbk->pending_grant_handles ||
	    !usbbk->pending_pages) {
		rc = -ENOMEM;
		pr_alert(DRV_PFX "%s: out of memory\n", __func__);
		goto failed_init;
	}

	for (i = 0; i < mmap_pages; i++) {
		usbbk->pending_grant_handles[i] = USBBACK_INVALID_HANDLE;
		usbbk->pending_pages[i] = alloc_page(GFP_KERNEL);
		if (usbbk->pending_pages[i] == NULL) {
			rc = -ENOMEM;
			pr_alert(DRV_PFX "%s: out of memory\n", __func__);
			goto failed_init;
		}
	}

	INIT_LIST_HEAD(&usbbk->pending_free);
	spin_lock_init(&usbbk->pending_free_lock);
	init_waitqueue_head(&usbbk->pending_free_wq);

	INIT_LIST_HEAD(&usbbk->urb_free);
	spin_lock_init(&usbbk->urb_free_lock);

	for (i = 0; i < xen_usbif_reqs; i++)
		list_add_tail(&usbbk->pending_reqs[i].free_list,
				&usbbk->pending_free);

	rc = xen_usbdev_init();
	if (rc)
		goto failed_init;

	rc = xen_usbif_xenbus_init();
	if (rc)
		goto usb_exit;

	return 0;

 usb_exit:
	xen_usbdev_exit();
 failed_init:
	kfree(usbbk->pending_reqs);
	kfree(usbbk->pending_grant_handles);
	if (usbbk->pending_pages) {
		for (i = 0; i < mmap_pages; i++) {
			if (usbbk->pending_pages[i])
				__free_page(usbbk->pending_pages[i]);
		}
		kfree(usbbk->pending_pages);
	}
	kfree(usbbk);
	usbbk = NULL;
	return rc;
}

struct xen_usbdev *xen_usbif_find_attached_device(struct xen_usbif *usbif,
								int portnum)
{
	struct xen_usbdev *dev;
	int found = 0;
	unsigned long flags;

	spin_lock_irqsave(&usbif->dev_lock, flags);
	list_for_each_entry(dev, &usbif->dev_list, dev_list) {
		if (dev->port->portnum == portnum) {
			found = 1;
			break;
		}
	}
	spin_unlock_irqrestore(&usbif->dev_lock, flags);

	if (found)
		return dev;

	return NULL;
}

static void __exit xen_usbif_exit(void)
{
	int i;
	int mmap_pages = xen_usbif_reqs * USBIF_MAX_SEGMENTS_PER_REQUEST;

	xen_usbif_xenbus_exit();
	xen_usbdev_exit();
	kfree(usbbk->pending_reqs);
	kfree(usbbk->pending_grant_handles);
	for (i = 0; i < mmap_pages; i++) {
		if (usbbk->pending_pages[i])
			__free_page(usbbk->pending_pages[i]);
	}
	kfree(usbbk->pending_pages);
	usbbk = NULL;
}

module_init(xen_usbif_init);
module_exit(xen_usbif_exit);

MODULE_AUTHOR("");
MODULE_DESCRIPTION("Xen USB backend driver (xen_usbback)");
MODULE_LICENSE("Dual BSD/GPL");
