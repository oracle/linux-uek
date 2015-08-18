/*
 * vds_lb.c: LDOM Virtual Disk Server.
 *
 * Copyright (C) 2014 Oracle. All rights reserved.
 */

#include "vds.h"
#include "vds_io.h"
#include <linux/iso_fs.h>

#define	ISO_VOLDESC_SEC	16	/* 1st sector of volume descriptors */

inline void vds_label_clear_part(struct vds_port *port)
{
	memset(port->part, 0, sizeof(*port->part) * VDS_MAXPART);
}

void vds_label_reset(struct vds_port *port)
{
	struct vio_driver_state *vio = &port->vio;

	vdsdbg(IOC, "media=%u label=%u\n", port->media_type, port->label_type);
	vds_label_clear_part(port);
	port->npart = 0;
	port->label_type = VDS_LABEL_NONE;
}

int vds_label_chk_iso(struct vds_port *port, bool *iso)
{
	int rv;
	sector_t sec;
	struct iso_volume_descriptor *vdp;
	char iso_buf[ISOFS_BLOCK_SIZE];
	struct vio_driver_state *vio = &port->vio;

	/*
	 * Read the sector that should contain the 2nd ISO volume
	 * descriptor. The second field in this descriptor is called the
	 * Standard Identifier and is set to CD001 for a CD-ROM compliant
	 * to the ISO 9660 standard.
	 */
	sec = (ISO_VOLDESC_SEC * ISOFS_BLOCK_SIZE) / port->vdisk_bsize;
	rv = vds_read(port, (void *)iso_buf, sec, ISOFS_BLOCK_SIZE);
	if (rv)
		goto done;

	vdp = (struct iso_volume_descriptor *)iso_buf;

	if (strncmp(vdp->id, ISO_STANDARD_ID, sizeof(vdp->id)) == 0)
		*iso = 1;
	else
		*iso = 0;

done:
	vdsdbg(IOC, "media=%d rv=%d\n", port->media_type, rv);
	return rv;
}

/*
 * Cache the label info since partition offsets are needed for
 * IO requests against a particular slice vs. VD_SLICE_NONE.
 *
 * A call to vds_label_init() unconditionally reads the label
 * (VTOC/EFI) from the disk and caches the result if the read
 * succeeds.
 *
 * Don't check for errors here since VD_SLICE_NONE requests
 * don't need partition offsets; instead any IO request requiring
 * partition info will later fail.
 */
void vds_label_init(struct vds_port *port)
{
	struct vio_driver_state *vio = &port->vio;
	int rv;

	/*
	 * Set the ops according to the label type (VTOC/EFI)
	 * and init as appropriate.  Make sure ops is set
	 * atomically and cannot change while the label info is
	 * fetched.  This is conceivably possible if multiple
	 * requests are processed in concurrent work threads.
	 */
	vds_label_lock(port, vio);

	if (port->npart)
		vdsdbg(INIT, "existing partitions (%d).\n", port->npart);

	vds_label_reset(port);

	rv = vds_vtoc_get(port);
	if (rv == -EINVAL)
		rv = vds_efi_validate(port);

	if (rv)
		vdsdbg(INIT, "unknown disk label\n");

	vds_label_unlock(port, vio);
}

void vds_label_fini(struct vds_port *port)
{
	struct vio_driver_state *vio = &port->vio;

	vds_label_lock(port, vio);
	vds_label_reset(port);
	vds_label_unlock(port, vio);
}

int vds_label_get_vtoc(struct vds_port *port)
{
	int rv;
	struct vio_driver_state *vio = &port->vio;

	vds_label_lock(port, vio);

	vds_label_reset(port);

	rv = vds_vtoc_get(port);
	if (rv == -EINVAL) {
		(void) vds_efi_validate(port);
		if (port->label_type == VDS_LABEL_EFI)
			rv = -VDS_ENOTSUP;
	}

	vds_label_unlock(port, vio);

	return rv;
}

int vds_label_get_start(struct vds_port *port, int slice, sector_t *start)
{
	struct vio_driver_state *vio = &port->vio;
	int rv = -EIO;

	vds_label_lock(port, vio);
	if (slice < port->npart) {
		*start = port->part[slice].start;
		rv = 0;
	}
	vds_label_unlock(port, vio);

	vdsdbg(IO, "(%d)=(%d, %lu)\n", slice, rv, *start);

	return rv;
}
