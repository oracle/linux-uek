/*
 * vds_main.c: LDOM Virtual Disk Server.
 *
 * Copyright (C) 2014 Oracle. All rights reserved.
 */

#include "vds.h"
#include "vds_io.h"

#define DRV_MOD_NAME		"vds"
#define DRV_MOD_VERSION		"1.0"

static char version[] = DRV_MOD_NAME ".c:v" DRV_MOD_VERSION "\n";
MODULE_DESCRIPTION("LDOM virtual disk server driver");
MODULE_LICENSE("GPL");
MODULE_VERSION(DRV_MOD_VERSION);

#define	VDS_OPS			(1 << VD_OP_BREAD |		\
				 1 << VD_OP_BWRITE |		\
				 1 << VD_OP_GET_VTOC |		\
				 1 << VD_OP_SET_VTOC |		\
				 1 << VD_OP_GET_DISKGEOM |	\
				 1 << VD_OP_SET_DISKGEOM |	\
				 1 << VD_OP_GET_EFI |		\
				 1 << VD_OP_SET_EFI |		\
				 1 << VD_OP_FLUSH)
/*
 * XXX The recommended value is 0 but that creates threads
 * which scale with ncpu and because of some apparent
 * flow control issues cause scsi timeouts so limit to
 * 1 thread for now.
 */
int vds_wq = 1;
int vds_dbg;
int vds_dbg_ldc;
int vds_dbg_vio;

module_param(vds_dbg, uint, 0664);
module_param(vds_dbg_ldc, uint, 0664);
module_param(vds_dbg_vio, uint, 0664);
module_param(vds_wq, uint, 0664);

/* Ordered from largest major to lowest */
static struct vio_version vds_versions[] = {
	{ .major = 1, .minor = 1 },
	{ .major = 1, .minor = 0 },
};

static void vds_handshake_complete(struct vio_driver_state *vio)
{
	struct vio_dring_state *dr;

	dr = &vio->drings[VIO_DRIVER_RX_RING];
	dr->snd_nxt = dr->rcv_nxt = 1;
}

static int vds_handle_unknown(struct vds_port *port)
{
	struct vio_msg_tag *pkt = port->msgbuf;

	vdsmsg(err, "Received unknown msg [%02x:%02x:%04x:%08x]\n",
	       pkt->type, pkt->stype, pkt->stype_env, pkt->sid);
	vdsmsg(err, "Resetting connection.\n");

	ldc_disconnect(port->vio.lp);

	return -ECONNRESET;
}

/* vio_driver_init() expects this. */
static int vds_send_attr(struct vio_driver_state *vio)
{
	return 0;
}

static int vds_handle_attr(struct vio_driver_state *vio, void *arg)
{
	struct vds_port *port = to_vds_port(vio);
	struct vio_disk_attr_info *pkt = arg;

	/* checkpatch.pl doesn't like split format strings */
	vdsdbg(HS, "GOT ATTR stype[0x%x] stype_env[0x%x] ",
	       pkt->tag.stype, pkt->tag.stype_env);

	vdsdbg(HS, "xfer_mode[0x%x] blksz[%u] max_xfer[%llu]\n",
	       pkt->xfer_mode, pkt->vdisk_block_size, pkt->max_xfer_size);

	if (pkt->tag.type != VIO_TYPE_CTRL ||
	    pkt->tag.stype != VIO_SUBTYPE_INFO ||
	    pkt->tag.stype_env != VIO_ATTR_INFO ||
	    pkt->max_xfer_size == 0) {
		vdsmsg(err, "%s: Attribute NACK\n", vio->name);
		return -ECONNRESET;
	}

	if (pkt->xfer_mode == VIO_DESC_MODE) {
		struct vio_disk_attr_info tmp;

		/*
		 * vio_disk_dring_inband contains no cookies; need room
		 * for up to n cookies, where "n" is the number of full
		 * pages plus possibly one partial page required to cover
		 * "max_xfer_size".  Add room for one more cookie if
		 * "max_xfer_size" isn't an integral multiple of the page size.
		 * Must first get the maximum transfer size in bytes.
		 */
		size_t max_xfer_bytes = pkt->vdisk_block_size ?
		    pkt->vdisk_block_size * pkt->max_xfer_size :
		    pkt->max_xfer_size;

		size_t max_inband_msglen =
		    sizeof(struct vio_disk_desc_inband) +
		    (((roundup(max_xfer_bytes, PAGE_SIZE) / PAGE_SIZE) + 1) *
		    sizeof(struct ldc_trans_cookie));

		vdsdbg(HS, "DESC ATTR max_ibm=%ld\n", max_inband_msglen);

		/*
		 * Set the maximum expected message length to
		 * accommodate in-band-descriptor messages with all
		 * their cookies.
		 */
		vio->desc_buf_len = max_inband_msglen;

		/*
		 * Reallocate before responding to the message since
		 * the next request in the handshake will use this size
		 * and a small msgbuf would make the ldc read fail.
		 */
		tmp = *pkt;
		kfree(port->msgbuf);
		port->msglen = max_inband_msglen;
		port->msgbuf = kzalloc(port->msglen, GFP_ATOMIC);
		if (!port->msgbuf) {
			vdsmsg(err, "%s: kzalloc failed\n", vio->name);
			return -ECONNRESET;
		}
		memcpy(port->msgbuf, &tmp, sizeof(tmp));
		pkt = port->msgbuf;

	}

	port->xfer_mode = pkt->xfer_mode;

	pkt->vdisk_block_size = port->vdisk_bsize;

	/* XXX OBP doesn't seem to honor max_xfer_size */
	pkt->max_xfer_size = port->max_xfer_size;
	pkt->vdisk_size = port->vdisk_size;
	pkt->vdisk_type = VD_DISK_TYPE_DISK;
	pkt->vdisk_mtype = port->media_type;
	pkt->operations = VDS_OPS;
	pkt->tag.stype = VIO_SUBTYPE_ACK;
	pkt->tag.sid = vio_send_sid(vio);

	vdsdbg(HS, "SEND ATTR dksz[%llu] blksz[%u] max_xfer[%llu] ops[%llx]\n",
	       pkt->vdisk_size, pkt->vdisk_block_size,
	       pkt->max_xfer_size, pkt->operations);

	return vio_ldc_send(&port->vio, pkt, sizeof(*pkt));
}

static struct vio_driver_ops vds_vio_ops = {
	.send_attr		= vds_send_attr,
	.handle_attr		= vds_handle_attr,
	.handshake_complete	= vds_handshake_complete,
};

static void vds_reset(struct vio_driver_state *vio);
static void vds_evt_reset(struct vio_driver_state *vio);

static int vds_dring_done(struct vds_io *io)
{
	struct vio_driver_state *vio = io->vio;
	struct vds_port *port = to_vds_port(vio);
	struct vio_dring_data *pkt = io->msgbuf;
	struct vio_dring_state *dr = &vio->drings[VIO_DRIVER_RX_RING];
	struct vio_disk_desc *desc;
	int rv;
	int idx;

	desc = io->desc_buf;
	desc->status = io->error;
	desc->hdr.state = VIO_DESC_DONE;

	vdsdbg(DATA, "DRING DONE [%08llx:%08x:%08x:%02x:%08llx:%08llx]\n",
	       pkt->dring_ident,
	       pkt->start_idx,
	       pkt->end_idx,
	       pkt->state,
	       pkt->seq,
	       port->seq);

	vdsdbg(DATA,
	       "DRING DONE"
	       " [%02x:%02x:%08llx:%02x:%02x:%04d:%08llx:%08llx:%08x]\n",
	       desc->hdr.state,
	       desc->hdr.ack,
	       desc->req_id,
	       desc->operation,
	       desc->slice,
	       desc->status,
	       desc->offset,
	       desc->size,
	       desc->ncookies);

	idx = pkt->start_idx;
	rv = ldc_put_dring_entry(vio->lp, io->desc_buf, dr->entry_size,
				  (idx * dr->entry_size), dr->cookies,
				  dr->ncookies);
	if (rv != dr->entry_size)
		goto reset;

	/*
	 * If we successfully responded to the request (ack or nack),
	 * then return the actual IO operation return value, otherwise
	 * reset the connection.
	 */
	pkt->tag.stype = io->ack;
	rv = vio_ldc_send(vio, pkt, sizeof(*pkt));
	if (rv > 0) {
		rv = io->error;
		vds_io_free(io);
		vdsdbg(DATA, "DRING RET %d\n", rv);
		return rv;
	}

reset:
	vdsmsg(err, "Reset VDS LDC rv[%d]\n", rv);
	vds_reset(vio);
	vds_io_free(io);

	vdsdbg(DATA, "DRING RESET\n");
	return -ECONNRESET;
}

static int vds_desc_done(struct vds_io *io)
{
	struct vio_driver_state *vio = io->vio;
	struct vds_port *port = to_vds_port(vio);
	struct vio_disk_desc_inband *pkt = io->msgbuf;
	struct vio_desc_data *hdr = &pkt->hdr;
	int rv;

	pkt->payload.status = io->error;
	hdr->tag.stype = io->ack;

	vdsdbg(DATA, "DESC DONE [%02x:%02x:%04x:%08x:%08llx:%08llx:%08llx]\n",
	       hdr->tag.type,
	       hdr->tag.stype,
	       hdr->tag.stype_env,
	       hdr->tag.sid,
	       hdr->desc_handle,
	       hdr->seq,
	       port->seq);

	vdsdbg(DATA, "DESC DONE [%08llx:%02x:%02x:%04d:%08llx:%08llx:%08x]\n",
	       pkt->payload.req_id,
	       pkt->payload.operation,
	       pkt->payload.slice,
	       pkt->payload.status,
	       pkt->payload.offset,
	       pkt->payload.size,
	       pkt->payload.ncookies);

	rv = vio_ldc_send(vio, pkt, io->msglen);
	if (rv <= 0) {
		vdsmsg(err, "Reset VDS LDC rv[%d]\n", rv);
		vds_reset(vio);
		rv = -ECONNRESET;
	} else {
		rv = io->error;
	}

	vds_io_free(io);
	return rv;
}

static void vds_get_desc(struct vds_io *io)
{
	struct vio_driver_state *vio = io->vio;
	struct vds_port *port = to_vds_port(vio);
	struct vio_disk_dring_payload *desc = NULL;

	switch (port->xfer_mode) {
	case VIO_DRING_MODE: {
		struct vio_disk_desc *d = io->desc_buf;
		desc = (struct vio_disk_dring_payload *)&d->req_id;

		vdsdbg(DATA, "DRING desc[%08llx:%08x:%08llx:%08llx]\n",
		       desc->size, desc->ncookies,
		       desc->cookies[0].cookie_addr,
		       desc->cookies[0].cookie_size);
		break;
	}
	case VIO_DESC_MODE: {
		int i;
		struct vio_disk_desc_inband *d = io->desc_buf;

		desc = &d->payload;
		for (i = 0; i < desc->ncookies; i++)
			vdsdbg(DATA, "DESC desc[%08llx:%04x:%08llx:%08llx]\n",
			       desc->size, desc->ncookies,
			       desc->cookies[i].cookie_addr,
			       desc->cookies[i].cookie_size);
		break;
	}
	default:
		break;
	}

	io->desc = desc;
	return;
}

/*
 * Bottom half handshake routine.
 */
static void vds_bh_hs(struct work_struct *work)
{
	struct vds_io *io = container_of(work, struct vds_io, vds_work);
	struct vio_driver_state *vio = io->vio;
	struct vds_port *port = to_vds_port(vio);
	int err = 0;

	vdsdbg(HS, "%s\n", port->path);

	BUG_ON(in_interrupt());

	if (io->flags & VDS_IO_INIT)
		err = vds_be_init(port);

	if (!err)
		err = vio_control_pkt_engine(vio, port->msgbuf);

	if (err)
		vdsmsg(err, "%s: handshake failed (%d)\n", port->path, err);

	vds_io_free(io);
}

/*
 * Bottom half IO routine.
 */
static void vds_bh_io(struct work_struct *work)
{
	struct vds_io *io = container_of(work, struct vds_io, vds_work);
	struct vio_driver_state *vio = io->vio;
	struct vds_port *port = to_vds_port(vio);
	int err;

	BUG_ON(in_interrupt());

	vds_get_desc(io);
	BUG_ON(!io->desc);

	io->ack = VIO_SUBTYPE_ACK;
	io->error = 0;

	switch (io->desc->operation) {
	case VD_OP_BREAD:
		err = vd_op_rw(io);
		break;
	case VD_OP_BWRITE:
		io->rw = WRITE;
		err = vd_op_rw(io);
		break;
	case VD_OP_GET_VTOC:
		err = vd_op_get_vtoc(io);
		break;
	case VD_OP_SET_VTOC:
		err = vd_op_set_vtoc(io);
		break;
	case VD_OP_GET_DISKGEOM:
		err = vd_op_get_geom(io);
		break;
	case VD_OP_SET_DISKGEOM:
		err = vd_op_set_geom(io);
		break;
	case VD_OP_GET_EFI:
		err = vd_op_get_efi(io);
		break;
	case VD_OP_SET_EFI:
		err = vd_op_set_efi(io);
		break;
	case VD_OP_FLUSH:
		err = vd_op_flush(vio);
		break;
	default:
		err = -ENOTSUPP;
		break;
	}

	if (io->ack == VIO_SUBTYPE_ACK && err != 0 && io->error == 0)
		io->error = err > 0 ? err : -err;

	if (port->xfer_mode == VIO_DRING_MODE)
		(void) vds_dring_done(io);
	else if (port->xfer_mode == VIO_DESC_MODE)
		(void) vds_desc_done(io);
	else
		BUG();
}

static void vds_reset(struct vio_driver_state *vio)
{
	struct vds_port *port = to_vds_port(vio);
	unsigned long flags;
	int err;

	vdsdbg(HS, "%s\n", port->path);

	BUG_ON(in_interrupt());

	vds_vio_lock(vio, flags);
	vds_be_fini(port);

	vio_link_state_change(vio, LDC_EVENT_RESET);
	vio->desc_buf_len = 0;

	port->flags = 0;
	kfree(port->msgbuf);
	port->msglen = LDC_PACKET_SIZE;
	port->msgbuf = kzalloc(port->msglen, GFP_ATOMIC);
	if (!port->msgbuf) {
		vdsmsg(err, "%s: kzalloc failed\n", vio->name);
		goto done;
	}

	err = ldc_connect(vio->lp);
	if (err)
		vdsmsg(warn, "%s: Port %lu connect failed, err=%d\n",
			 vio->name, vio->vdev->channel_id, err);

done:
	vds_vio_unlock(vio, flags);
}

static void vds_bh_reset(struct work_struct *work)
{
	struct vds_io *io = container_of(work, struct vds_io, vds_work);
	struct vio_driver_state *vio = io->vio;

	vds_io_free(io);
	vds_reset(vio);
	ldc_enable_hv_intr(vio->lp);
}

static int vds_dring_io(struct vio_driver_state *vio)
{
	struct vds_port *port = to_vds_port(vio);
	struct vio_dring_data *pkt = port->msgbuf;
	struct vio_dring_state *dr = &vio->drings[VIO_DRIVER_RX_RING];
	struct vio_disk_desc *desc;
	struct vds_io *io;
	int reset = 0;
	int rv;
	int idx;

	vdsdbg(DATA, "DRING [%08llx:%08x:%08x:%02x:%08llx:%08llx]\n",
	       pkt->dring_ident,
	       pkt->start_idx,
	       pkt->end_idx,
	       pkt->state,
	       pkt->seq,
	       port->seq);

	io = vds_io_alloc(vio, vds_bh_io);
	if (!io)
		return -ENOMEM;

	memcpy(io->msgbuf, port->msgbuf, port->msglen);

	if ((port->flags & VDS_PORT_SEQ) && (pkt->seq != port->seq + 1)) {
		vdsmsg(err,
		       "Message out of sequence seq[0x%llx] vds_seq[0x%llx]\n",
		       pkt->seq, port->seq);
		goto err;
	}
	port->seq = pkt->seq;
	port->flags |= VDS_PORT_SEQ;
	reset = 1;

	if (port->xfer_mode != VIO_DRING_MODE) {
		vdsmsg(err, "Invalid xfer mode pkt[0x%x] port[0x%x]\n",
		       pkt->tag.stype_env, port->xfer_mode);
		goto err;
	}

	idx = pkt->start_idx;
	if (idx != pkt->end_idx) {
		vdsmsg(err,
		       "Invalid idx start[%d] end[%d]\n", idx, pkt->end_idx);
		goto err;
	}

	rv = ldc_get_dring_entry(vio->lp, io->desc_buf, dr->entry_size,
				  (idx * dr->entry_size), dr->cookies,
				  dr->ncookies);
	if (rv != dr->entry_size)
		goto err;

	desc = (struct vio_disk_desc *)io->desc_buf;

	vdsdbg(DATA,
	       "DRING [%02x:%02x:%08llx:%02x:%02x:%04d:%08llx:%08llx:%08x]\n",
	       desc->hdr.state,
	       desc->hdr.ack,
	       desc->req_id,
	       desc->operation,
	       desc->slice,
	       desc->status,
	       desc->offset,
	       desc->size,
	       desc->ncookies);

	/*
	 * Queue the request.
	 */
	if (desc->hdr.state == VIO_DESC_READY) {
		vds_io_enq(io);
		return 0;
	}

err:
	if (reset) {
		vdsmsg(err, "Reset VDS LDC\n");
		vds_io_free(io);
		vds_evt_reset(vio);
		rv = -ECONNRESET;
	} else {
		vdsmsg(err, "NACK request io=%p\n", io);
		io->ack = VIO_SUBTYPE_NACK;
		io->error = 0;
		rv = vds_dring_done(io);
	}
	return rv;
}

static int vds_desc_io(struct vio_driver_state *vio, int msglen)
{
	struct vds_port *port = to_vds_port(vio);
	struct vio_disk_desc_inband *pkt = port->msgbuf;
	struct vio_desc_data *hdr = &pkt->hdr;
	struct vds_io *io;
	int rv;

	vdsdbg(DATA, "DESC [%02x:%02x:%04x:%08x:%08llx:%08llx:%08llx]\n",
	       hdr->tag.type,
	       hdr->tag.stype,
	       hdr->tag.stype_env,
	       hdr->tag.sid,
	       hdr->desc_handle,
	       hdr->seq,
	       port->seq);

	vdsdbg(DATA, "DESC [%08llx:%02x:%02x:%04d:%08llx:%08llx:%08x]\n",
	       pkt->payload.req_id,
	       pkt->payload.operation,
	       pkt->payload.slice,
	       pkt->payload.status,
	       pkt->payload.offset,
	       pkt->payload.size,
	       pkt->payload.ncookies);

	io = vds_io_alloc(vio, vds_bh_io);
	if (!io)
		return -ENOMEM;

	memcpy(io->msgbuf, port->msgbuf, msglen);

	if ((port->flags & VDS_PORT_SEQ) && (hdr->seq != port->seq + 1)) {
		vdsmsg(err,
		       "Message out of sequence seq[0x%llx] vds_seq[0x%llx]\n",
		       hdr->seq, port->seq);
#if 0
		/* XXX OBP seems to send out of sequence messages */
		goto nack;
#endif
	}
	port->seq = hdr->seq;
	port->flags |= VDS_PORT_SEQ;

	if (port->xfer_mode != VIO_DESC_MODE) {
		vdsmsg(err, "Invalid xfer mode pkt[0x%x] port[0x%x]\n",
		       hdr->tag.stype_env, port->xfer_mode);
		goto nack;
	}

	/*
	 * Queue the request.
	 */
	memcpy(io->desc_buf, port->msgbuf, msglen);
	io->msglen = msglen;
	vds_io_enq(io);

	return 0;

nack:
	io->ack = VIO_SUBTYPE_NACK;
	io->error = 0;
	rv = vds_desc_done(io);
	return rv;
}

static void vds_evt_reset(struct vio_driver_state *vio)
{
	struct vds_io *io;

	vdsdbg(HS, "\n");

	BUG_ON(!in_interrupt());

	io = vds_io_alloc(vio, vds_bh_reset);
	if (!io)
		return;

	ldc_disable_hv_intr(vio->lp);
	io->flags |= VDS_IO_FINI;

	vds_io_enq(io);
}

static void vds_evt_up(struct vio_driver_state *vio)
{
	BUG_ON(!in_interrupt());

	vio_link_state_change(vio, LDC_EVENT_UP);
	/* this is needed in dring mode */
	vio->dr_state &= ~VIO_DR_STATE_RXREQ;
}

static int
vds_evt_ctl(struct vio_driver_state *vio)
{
	struct vds_io *io;

	BUG_ON(!in_interrupt());

	io = vds_io_alloc(vio, vds_bh_hs);
	if (!io)
		return -ENOMEM;

	if (vio->hs_state == VIO_HS_INVALID)
		io->flags |= VDS_IO_INIT;

	vds_io_enq(io);

	return 0;
}

static void vds_evt_data(struct vio_driver_state *vio)
{
	int rv;
	int msglen;
	struct vio_msg_tag *tag;
	struct vds_port *port = to_vds_port(vio);

	BUG_ON(!in_interrupt());

	while (1) {
		rv = ldc_read(vio->lp, port->msgbuf, port->msglen);
		vdsdbg(DATA, "ldc_read(%d)=%d\n", port->msglen, rv);
		if (rv < 0) {
			if (rv == -ECONNRESET)
				vds_evt_reset(vio);
			break;
		}
		if (rv == 0)
			break;
		tag = port->msgbuf;
		vdsdbg(DATA, "TAG [%02x:%02x:%04x:%08x]\n",
		       tag->type,
		       tag->stype,
		       tag->stype_env,
		       tag->sid);
		msglen = rv;
		rv = vio_validate_sid(vio, tag);
		if (rv < 0)
			break;
		switch (tag->type) {
		case VIO_TYPE_CTRL:
			/*
			 * This is needed in dring mode.
			 */
			if (tag->stype == VIO_SUBTYPE_INFO &&
			    tag->stype_env == VIO_DRING_REG)
				vio->dr_state |= VIO_DR_STATE_RXREQ;
			rv = vds_evt_ctl(vio);
			break;
		case VIO_TYPE_DATA:
			switch (tag->stype) {
			case VIO_SUBTYPE_INFO:
				switch (tag->stype_env) {
				case VIO_DRING_DATA:
					rv = vds_dring_io(vio);
					break;
				case VIO_DESC_DATA:
					rv = vds_desc_io(vio, msglen);
					break;
				default:
					rv = -EINVAL;
					break;
				}
				break;
			default:
				rv = vds_handle_unknown(port);
				break;
			}
			break;
		default:
			rv = vds_handle_unknown(port);
			break;
		}
		if (rv < 0)
			break;
	}
}

static void vds_event(void *arg, int event)
{
	unsigned long flags;
	struct vds_port *port = arg;
	struct vio_driver_state *vio = &port->vio;

	vdsdbg(DATA, "event=%d cpu=%d\n", event, smp_processor_id());

	vds_vio_lock(vio, flags);

	switch (event) {
	case LDC_EVENT_RESET:
		vds_evt_reset(vio);
		break;
	case LDC_EVENT_UP:
		vds_evt_up(vio);
		break;
	case LDC_EVENT_DATA_READY:
		vds_evt_data(vio);
		break;
	default:
		vdsmsg(warn, "Unexpected LDC event %d\n", event);
		break;
	}

	vds_vio_unlock(vio, flags);
}

static struct ldc_channel_config vds_ldc_cfg = {
	.event		= vds_event,
	.mtu		= 64,
	.mode		= LDC_MODE_UNRELIABLE,
};

static ssize_t vds_sysfs_path_show(struct device *device,
	struct device_attribute *attr, char *buf)
{
	int rv;
	unsigned long flags;
	struct vds_port *port = dev_get_drvdata(device);
	struct vio_driver_state *vio = &port->vio;

	vds_vio_lock(vio, flags);
	rv = scnprintf(buf, PAGE_SIZE, "%s\n", port->path);
	vds_vio_unlock(vio, flags);

	return rv;
}

static DEVICE_ATTR(path, S_IRUSR, vds_sysfs_path_show, NULL);

static struct attribute *vds_sysfs_entries[] = {
	&dev_attr_path.attr,
	NULL
};

static struct attribute_group vds_attribute_group = {
	.name = NULL,	/* put in device directory */
	.attrs = vds_sysfs_entries,
};

static void print_version(void)
{
	printk_once(KERN_INFO "%s", version);
}

static int vds_port_probe(struct vio_dev *vdev, const struct vio_device_id *id)
{
	struct mdesc_handle *hp;
	struct vds_port *port;
	struct vio_driver_state *vio;
	const char *path;
	u64 node;
	int err;

	print_version();

	port = kzalloc(sizeof(*port), GFP_KERNEL);
	if (!port) {
		vdsmsg(err, "Cannot allocate vds_port.\n");
		return -ENOMEM;
	}

	port->msglen = LDC_PACKET_SIZE;
	port->msgbuf = kzalloc(port->msglen, GFP_KERNEL);
	if (!port->msgbuf) {
		err = -ENOMEM;
		goto free_port;
	}

	vio = &port->vio;

	err = vio_driver_init(vio, vdev, VDEV_DISK_SERVER,
			      vds_versions, ARRAY_SIZE(vds_versions),
			      &vds_vio_ops, (char *)dev_name(&vdev->dev));
	if (err)
		goto free_msgbuf;

	vio->debug = vds_dbg_vio;
	vds_ldc_cfg.debug = vds_dbg_ldc;

	err = vio_ldc_alloc(vio, &vds_ldc_cfg, port);
	if (err)
		goto free_msgbuf;

	hp = mdesc_grab();

	node = vio_vdev_node(hp, vdev);
	if (node == MDESC_NODE_NULL) {
		err = -ENXIO;
		mdesc_release(hp);
		goto free_ldc;
	}

	path = mdesc_get_property(hp, node, "vds-block-device", NULL);
	if (!path) {
		err = -ENXIO;
		mdesc_release(hp);
		goto free_ldc;
	}
	port->path = kstrdup(path, GFP_KERNEL);
	mdesc_release(hp);
	vdsdbg(INIT, "path=%s\n", path);
	port->vtoc = kzalloc(roundup(sizeof(*port->vtoc), 8), GFP_KERNEL);
	port->geom = kzalloc(roundup(sizeof(*port->geom), 8), GFP_KERNEL);
	port->part = kzalloc(sizeof(*port->part) * VDS_MAXPART, GFP_KERNEL);

	/*
	 * The io and reset work queues are separate because the
	 * io work queue is flushed during reset which would hang
	 * if reset itself was scheduled on the io queue.
	 */
	port->ioq = alloc_workqueue("vds_io", WQ_UNBOUND, vds_wq);
	port->rtq = alloc_ordered_workqueue("vds_reset", 0);
	if (!port->ioq || !port->rtq) {
		err = -ENXIO;
		goto free_path;
	}

	mutex_init(&port->label_lock);

	dev_set_drvdata(&vdev->dev, port);

	err = sysfs_create_group(&vdev->dev.kobj, &vds_attribute_group);
	if (err)
		goto free_path;

	vio_port_up(vio);

	return 0;

free_path:
	kfree(port->path);
	kfree(port->vtoc);
	kfree(port->geom);
	kfree(port->part);

free_ldc:
	vio_ldc_free(vio);

free_msgbuf:
	kfree(port->msgbuf);

free_port:
	kfree(port);

	return err;
}

static int vds_port_remove(struct vio_dev *vdev)
{
	struct vds_port *port = dev_get_drvdata(&vdev->dev);
	struct vio_driver_state *vio = &port->vio;

	if (!port)
		return 0;

	del_timer_sync(&vio->timer);
	ldc_disconnect(vio->lp);	/* XXX vds_port_down() */
	vio_ldc_free(vio);
	sysfs_remove_group(&vdev->dev.kobj, &vds_attribute_group);
	dev_set_drvdata(&vdev->dev, NULL);

	mutex_destroy(&port->label_lock);
	kfree(port->path);
	kfree(port->msgbuf);
	kfree(port->vtoc);
	kfree(port->geom);
	kfree(port->part);
	kfree(port);

	return 0;
}

static const struct vio_device_id vds_port_match[] = {
	{
		.type = "vds-port",
	},
	{},
};

static struct vio_driver vds_port_driver = {
	.id_table	= vds_port_match,
	.probe		= vds_port_probe,
	.remove		= vds_port_remove,
	.name		= "vds_port",
};

static int __init vds_init(void)
{
	int rv;

	rv = vds_io_init();
	if (!rv) {
		rv = vio_register_driver(&vds_port_driver);
		if (rv < 0)
			vds_io_fini();
	}

	return rv;
}

static void __exit vds_exit(void)
{
	vio_unregister_driver(&vds_port_driver);
	vds_io_fini();
}

module_init(vds_init);
module_exit(vds_exit);
