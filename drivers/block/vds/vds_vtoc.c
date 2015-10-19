/*
 * vds_vtoc.c: LDOM Virtual Disk Server.
 *
 * Copyright (C) 2014 Oracle. All rights reserved.
 */

#include "vds.h"
#include "vds_io.h"
#include "vds_vtoc.h"

/*
 * By Solaris convention, slice/partition 2 represents the entire disk;
 * unfortunately, this convention does not appear to be codified.
 */
#define	VDS_ENTIRE_DISK_SLICE	2

/* Number of backup labels */
#define	VDS_DSKIMG_NUM_BACKUP	5

static unsigned short vds_lbl2cksum(struct dk_label *label)
{
	int count;
	unsigned short sum, *sp;

	count =	(sizeof(struct dk_label)) / (sizeof(short)) - 1;
	sp = (unsigned short *)label;
	sum = 0;
	while (count--)
		sum ^= *sp++;

	return sum;
}

static void
vds_vtoc_update_part(struct vds_port *port, struct dk_label *label)
{
	int i;

	vds_label_clear_part(port);

	for (i = 0; i < port->npart; i++) {
		port->part[i].start = label->dkl_map[i].dkl_cylno *
				      label->dkl_nhead * label->dkl_nsect;
		port->part[i].size = label->dkl_map[i].dkl_nblk;
	}
}

/*
 * Function:
 *	vd_get_readable_size
 *
 * Description:
 *	Convert a given size in bytes to a human readable format in
 *	kilobytes, megabytes, gigabytes or terabytes.
 *
 * Parameters:
 *	full_size	- the size to convert in bytes.
 *	size		- the converted size.
 *	unit		- the unit of the converted size: 'K' (kilobyte),
 *			  'M' (Megabyte), 'G' (Gigabyte), 'T' (Terabyte).
 *
 * Return Code:
 *	none
 */
static void vd_get_readable_size(size_t full_size, size_t *size, char *unit)
{
	if (full_size < (1ULL << 20)) {
		*size = full_size >> 10;
		*unit = 'K'; /* Kilobyte */
	} else if (full_size < (1ULL << 30)) {
		*size = full_size >> 20;
		*unit = 'M'; /* Megabyte */
	} else if (full_size < (1ULL << 40)) {
		*size = full_size >> 30;
		*unit = 'G'; /* Gigabyte */
	} else {
		*size = full_size >> 40;
		*unit = 'T'; /* Terabyte */
	}
}

/*
 * Set the default label for a given disk size. This is used when the disk
 * does not have a valid VTOC so that the user can get a valid default
 * configuration. The default label has all slice sizes set to 0 (except
 * slice 2 which is the entire disk) to force the user to write a valid
 * label onto the disk image.
 */
static void vds_vtoc_set_default(struct vds_port *port, struct dk_label *label)
{
	char unit;
	size_t size;
	size_t bsize = port->vdisk_bsize;
	size_t disk_size = port->vdisk_size * bsize;
	struct vio_driver_state *vio = &port->vio;

	memset(label, 0, sizeof(struct dk_label));

	/*
	 * Ideally we would like the cylinder size (nsect * nhead) to be the
	 * same whatever the disk size is. That way the VTOC label could be
	 * easily updated in case the disk size is increased (keeping the
	 * same cylinder size allows to preserve the existing partitioning
	 * when updating the VTOC label). But it is not possible to have
	 * a fixed cylinder size and to cover all disk size.
	 *
	 * So we define different cylinder sizes depending on the disk size.
	 * The cylinder size is chosen so that we don't have too few cylinders
	 * for a small disk image, or so many on a big disk image that you
	 * waste space for backup superblocks or cylinder group structures.
	 * Also we must have a resonable number of cylinders and sectors so
	 * that newfs can run using default values.
	 *
	 *	+-----------+--------+---------+--------+
	 *	| disk_size |  < 2MB | 2MB-4GB | >= 8GB |
	 *	+-----------+--------+---------+--------+
	 *	| nhead	    |	 1   |	   1   |    96  |
	 *	| nsect	    |  200   |   600   |   768  |
	 *	+-----------+--------+---------+--------+
	 *
	 * Other parameters are computed from these values:
	 *
	 *	pcyl = disk_size / (nhead * nsect * 512)
	 *	acyl = (pcyl > 2)? 2 : 0
	 *	ncyl = pcyl - acyl
	 *
	 * The maximum number of cylinder is 65535 so this allows to define a
	 * geometry for a disk size up to 65535 * 96 * 768 * 512 = 2.24 TB
	 * which is more than enough to cover the maximum size allowed by the
	 * extended VTOC format (2TB).
	 */

	if (disk_size >= 8 * ONE_GIGABYTE) {

		label->dkl_nhead = 96;
		label->dkl_nsect = 768;

	} else if (disk_size >= 2 * ONE_MEGABYTE) {

		label->dkl_nhead = 1;
		label->dkl_nsect = 600;

	} else {

		label->dkl_nhead = 1;
		label->dkl_nsect = 200;
	}

	label->dkl_pcyl = disk_size /
	    (label->dkl_nsect * label->dkl_nhead * bsize);

	if (label->dkl_pcyl == 0)
		label->dkl_pcyl = 1;

	label->dkl_acyl = 0;

	if (label->dkl_pcyl > 2)
		label->dkl_acyl = 2;

	label->dkl_ncyl = label->dkl_pcyl - label->dkl_acyl;
	label->dkl_write_reinstruct = 0;
	label->dkl_read_reinstruct = 0;
	label->dkl_rpm = 7200;
	label->dkl_apc = 0;
	label->dkl_intrlv = 0;

	vdsdbg(IOC, "requested disk size: %ld bytes\n", disk_size);
	vdsdbg(IOC, "setup: ncyl=%d nhead=%d nsec=%d\n", label->dkl_pcyl,
	       label->dkl_nhead, label->dkl_nsect);
	vdsdbg(IOC, "provided disk size: %lld bytes\n", (uint64_t)
	       (label->dkl_pcyl * label->dkl_nhead *
	       label->dkl_nsect * bsize));

	vd_get_readable_size(disk_size, &size, &unit);

	/*
	 * We must have a correct label name otherwise format(1m) will
	 * not recognized the disk as labeled.
	 */
	(void) snprintf(label->dkl_asciilabel, LEN_DKL_ASCII,
	    "SUN-DiskImage-%ld%cB cyl %d alt %d hd %d sec %d",
	    size, unit,
	    label->dkl_ncyl, label->dkl_acyl, label->dkl_nhead,
	    label->dkl_nsect);

	/* default VTOC */
	label->dkl_vtoc.v_version = V_EXTVERSION;
	label->dkl_vtoc.v_nparts = V_NUMPAR;
	label->dkl_vtoc.v_sanity = VTOC_SANE;
	label->dkl_vtoc.v_part[VDS_ENTIRE_DISK_SLICE].p_tag = V_BACKUP;
	label->dkl_map[VDS_ENTIRE_DISK_SLICE].dkl_cylno = 0;
	label->dkl_map[VDS_ENTIRE_DISK_SLICE].dkl_nblk = label->dkl_ncyl *
	    label->dkl_nhead * label->dkl_nsect;
	label->dkl_magic = DKL_MAGIC;
	label->dkl_cksum = vds_lbl2cksum(label);
}

/*
 * Get the disk label.  If the type is unknown, initialize a default label.
 */
static int vds_vtoc_get_label(struct vds_port *port, struct dk_label **lp)
{
	int rv = -EIO;
	struct dk_label *label = (struct dk_label *)port->label;
	struct vio_driver_state *vio = &port->vio;

	rv = vds_read(port, label, 0, DK_LABEL_SIZE);
	if (rv)
		return rv;

	if (label->dkl_magic != DKL_MAGIC) {
		vdsdbg(IOC, "bad VTOC label magic %04x\n", label->dkl_magic);
		if (port->label_type == VDS_LABEL_NONE) {
			vds_vtoc_set_default(port, label);
			rv = -EINVAL;
		}
	} else if (label->dkl_cksum != vds_lbl2cksum(label)) {
		vdsmsg(err, "bad VTOC label checksum\n");
	} else {
		vdsdbg(IOC, "VTOC magic=%04x\n", label->dkl_magic);
		vdsdbg(IOC, "ncyl=%d nhead=%d nsec=%d\n", label->dkl_pcyl,
		       label->dkl_nhead, label->dkl_nsect);
		rv = 0;
	}

	if (rv != 0 && rv != -EINVAL)
		label = NULL;

	*lp = label;

	return rv;
}

static void
vds_vtoc_l2g(struct dk_label *label, struct vio_disk_geom *geom)
{
	geom->num_cyl = label->dkl_ncyl;
	geom->alt_cyl = label->dkl_acyl;
	geom->num_hd = label->dkl_nhead;
	geom->num_sec = label->dkl_nsect;
	geom->ifact = label->dkl_intrlv;
	geom->apc = label->dkl_apc;
	geom->rpm = label->dkl_rpm;
	geom->phy_cyl = label->dkl_pcyl;
	geom->rd_skip = label->dkl_read_reinstruct;
	geom->wr_skip = label->dkl_write_reinstruct;
}

static void
vds_vtoc_g2l(struct vio_disk_geom *geom, struct dk_label *label)
{
	label->dkl_ncyl = geom->num_cyl;
	label->dkl_acyl = geom->alt_cyl;
	label->dkl_nhead = geom->num_hd;
	label->dkl_nsect = geom->num_sec;
	label->dkl_intrlv = geom->ifact;
	label->dkl_apc = geom->apc;
	label->dkl_rpm = geom->rpm;
	label->dkl_pcyl = geom->phy_cyl;
	label->dkl_read_reinstruct = geom->rd_skip;
	label->dkl_write_reinstruct = geom->wr_skip;
	label->dkl_cksum = vds_lbl2cksum(label);
}

/*
 * Get the disk VTOC.  If there is no valid label,
 * set a default VTOC.
 */
/*ARGSUSED*/
int vds_vtoc_get(struct vds_port *port)
{
	int i, rv;
	struct dk_label *label;
	struct vio_disk_vtoc *vtoc = port->vtoc;

	rv = vds_vtoc_get_label(port, &label);
	if (!label)
		return rv;

	memcpy(vtoc->volume_name, label->dkl_vtoc.v_volume,
	       VIO_DISK_VNAME_LEN);
	memcpy(vtoc->ascii_label, label->dkl_asciilabel, LEN_DKL_ASCII);
	vtoc->sector_size = 512;
	vtoc->num_partitions = label->dkl_vtoc.v_nparts;

	for (i = 0; i < vtoc->num_partitions; i++) {
		vtoc->partitions[i].id = label->dkl_vtoc.v_part[i].p_tag;
		vtoc->partitions[i].perm_flags =
		    label->dkl_vtoc.v_part[i].p_flag;
		vtoc->partitions[i].start_block =
		    label->dkl_map[i].dkl_cylno *
		    label->dkl_nhead * label->dkl_nsect;
		vtoc->partitions[i].num_blocks = label->dkl_map[i].dkl_nblk;
	}

	vds_vtoc_l2g(label, port->geom);

	/*
	 * Always update the cached copy, in case this is
	 * a shared disk and the label has been updated.
	 */
	if (!rv) {
		port->label_type = VDS_LABEL_VTOC;
		port->npart = label->dkl_vtoc.v_nparts;
		vds_vtoc_update_part(port, label);
	}

	return rv;
}

static int
vds_vtoc_set_backup(struct vds_port *port, struct dk_label *label, bool clear)
{
	int rv;
	sector_t blk, sec, cyl, head, cnt, nsect;
	struct vio_driver_state *vio = &port->vio;

	/*
	 * Backup labels are on the last alternate cylinder's
	 * first five odd sectors.
	 */
	if (label->dkl_acyl == 0) {
		vdsdbg(IOC, "no alt cylinder, cannot store backup labels");
		return 0;
	}

	cyl = label->dkl_ncyl  + label->dkl_acyl - 1;
	head = label->dkl_nhead - 1;
	nsect = label->dkl_nsect;

	blk = (cyl * ((label->dkl_nhead * nsect) - label->dkl_apc)) +
	    (head * nsect);

	if (clear == true)
		memset(label, 0, sizeof(*label));

	/*
	 * Write the backup labels. Make sure we don't try to write past
	 * the last cylinder.
	 */
	sec = 1;

	for (cnt = 0; cnt < VDS_DSKIMG_NUM_BACKUP; cnt++) {

		if (sec >= nsect) {
			vdsdbg(IOC, "not enough sectors for backup labels");
			return 0;
		}

		rv = vds_write(port, label, blk + sec, DK_LABEL_SIZE);
		if (rv) {
			vdsdbg(IOC, "error writing label at block %lu\n rv=%d",
			       blk + sec, rv);
			return rv;
		}

		vdsdbg(IOC, "wrote backup label at block %lu\n", blk + sec);
		vdsdbg(IOC, "ncyl=%d nhead=%d nsec=%d\n",
		       label->dkl_pcyl, label->dkl_nhead, label->dkl_nsect);

		sec += 2;
	}

	return 0;
}

int vds_vtoc_set(struct vds_port *port, struct vio_disk_vtoc *vtoc)
{
	int i, rv;
	struct dk_label *label;

	rv = vds_vtoc_get_label(port, &label);
	if (!label)
		return rv;

	vds_vtoc_g2l(port->geom, label);

	memcpy(label->dkl_vtoc.v_volume, vtoc->volume_name,
	       VIO_DISK_VNAME_LEN);
	memcpy(label->dkl_asciilabel, vtoc->ascii_label, LEN_DKL_ASCII);
	label->dkl_vtoc.v_nparts = vtoc->num_partitions;

	for (i = 0; i < vtoc->num_partitions; i++) {
		label->dkl_vtoc.v_part[i].p_tag = vtoc->partitions[i].id;
		label->dkl_vtoc.v_part[i].p_flag =
		    vtoc->partitions[i].perm_flags;
		label->dkl_map[i].dkl_cylno = vtoc->partitions[i].start_block /
		    (label->dkl_nhead * label->dkl_nsect);
		label->dkl_map[i].dkl_nblk = vtoc->partitions[i].num_blocks;
	}

	label->dkl_cksum = vds_lbl2cksum(label);

	rv = vds_write(port, label, 0, DK_LABEL_SIZE);

	if (!rv) {
		port->label_type = VDS_LABEL_VTOC;
		port->npart = label->dkl_vtoc.v_nparts;
		vds_vtoc_update_part(port, label);
	}

	/*
	 * There is no need to return an error for backups
	 * since the primary succeeded.
	 */
	(void) vds_vtoc_set_backup(port, label, false);

	return rv;
}

int vds_vtoc_clear(struct vds_port *port)
{
	int rv;
	struct dk_label *label;

	rv = vds_vtoc_get_label(port, &label);
	if (!label)
		return rv;

	rv = vds_clear(port, 0, DK_LABEL_SIZE);
	if (!rv) {
		vds_label_reset(port);
		(void) vds_vtoc_set_backup(port, label, true);
	}

	return rv;
}
