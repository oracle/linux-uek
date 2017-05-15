/*
 * vds_devid.c: LDOM Virtual Disk Server.
 *
 * Copyright (C) 2017 Oracle. All rights reserved.
 */

#include "vds.h"
#include "vds_io.h"
#include "vds_devid.h"

static short    devid_gen_number;

static u32 vds_devid_cksum(struct dk_devid *dkdevid)
{
	u32 chksum, *ip;
	int i;

	chksum = 0;
	ip = (void *)dkdevid;
	for (i = 0; i < ((DEVID_BLKSIZE - sizeof(int)) / sizeof(int)); i++)
		chksum ^= ip[i];

	return (chksum);
}

int vds_devid_valid(struct dk_devid *dkdevid)
{
	struct devid_info *id;
	u16 type;
	u32 chksum;

	/* validate the revision */
	if ((dkdevid->dkd_rev_hi != DEVID_REV_MSB) ||
	    (dkdevid->dkd_rev_lo != DEVID_REV_LSB))
		return DEVID_RET_INVALID;

	/* compute checksum */
	chksum = vds_devid_cksum(dkdevid);

	/* compare the checksums */
	if (DEVID_GETCHKSUM(dkdevid) != chksum)
		return DEVID_RET_INVALID;

	id = (struct devid_info *)dkdevid->dkd_devid;

        if (id->did_magic_hi != DEVID_MAGIC_MSB)
                return (DEVID_RET_INVALID);

        if (id->did_magic_lo != DEVID_MAGIC_LSB)
                return (DEVID_RET_INVALID);

        if (id->did_rev_hi != DEVID_REV_MSB)
                return (DEVID_RET_INVALID);

        if (id->did_rev_lo != DEVID_REV_LSB)
                return (DEVID_RET_INVALID);

        type = DEVID_GETTYPE(id);
        if ((type == DEVID_NONE) || (type > DEVID_MAXTYPE))
                return (DEVID_RET_INVALID);

        return (DEVID_RET_VALID);
}

/*
 * Return the sizeof a device id. If called with NULL devid it returns
 * the amount of space needed to determine the size.
 */
size_t vds_devid_sizeof(struct devid_info *id)
{
	if (id == NULL)
		return (sizeof (*id) - sizeof (id->did_id));

	return (sizeof (*id) + DEVID_GETLEN(id) - sizeof (id->did_id));
}

static int vds_devid_init(u16 devid_type, u16 nbytes, void *id,
	struct devid_info *i_devid, u32 hostid)
{
	int		sz = sizeof (*i_devid) + nbytes - sizeof (char);
	int		driver_len;
	const char	*driver_name;

	switch (devid_type) {
	case DEVID_ENCAP:
		if (nbytes == 0)
			return (-1);
		if (id == NULL)
			return (-1);
		break;
	case DEVID_FAB:
		if (nbytes != 0)
			return (-1);
		if (id != NULL)
			return (-1);
		nbytes = sizeof (int) +
		    DEVID_TIMEVAL_SIZE + sizeof(short);
		sz += nbytes;
		break;
	default:
		return (-1);
	}

	i_devid->did_magic_hi = DEVID_MAGIC_MSB;
	i_devid->did_magic_lo = DEVID_MAGIC_LSB;
	i_devid->did_rev_hi = DEVID_REV_MSB;
	i_devid->did_rev_lo = DEVID_REV_LSB;
	DEVID_FORMTYPE(i_devid, devid_type);
	DEVID_FORMLEN(i_devid, nbytes);

	/* Fill in driver name hint */
	driver_name = "vds";
	driver_len = strlen(driver_name);
	if (driver_len > DEVID_HINT_SIZE) {
		/* Pick up last four characters of driver name */
		driver_name += driver_len - DEVID_HINT_SIZE;
		driver_len = DEVID_HINT_SIZE;
	}

	memcpy(i_devid->did_driver, driver_name, driver_len);

	/* Fill in id field */
	if (devid_type == DEVID_FAB) {
		char		*cp;
		struct		timeval now;
		short		gen;
		u32		hi, lo;

		gen = devid_gen_number++;

		cp = i_devid->did_id;

		*cp++ = hibyte(hiword(hostid));
		*cp++ = lobyte(hiword(hostid));
		*cp++ = hibyte(loword(hostid));
		*cp++ = lobyte(loword(hostid));

		do_gettimeofday(&now);

		hi = now.tv_sec;
		*cp++ = hibyte(hiword(hi));
		*cp++ = lobyte(hiword(hi));
		*cp++ = hibyte(loword(hi));
		*cp++ = lobyte(loword(hi));
		lo = now.tv_usec;
		*cp++ = hibyte(hiword(lo));
		*cp++ = lobyte(hiword(lo));
		*cp++ = hibyte(loword(lo));
		*cp++ = lobyte(loword(lo));

		/* fill in the generation number */
		*cp++ = hibyte(gen);
		*cp++ = lobyte(gen);
		vds_devid_dump((u8 *)i_devid, 26, (void *)i_devid,
		    "vds_devid_init:");
	} else
		memcpy(i_devid->did_id, id, nbytes);

	return (0);
}

void vds_devid_dump(unsigned char *buf, int count, void *address, char *info)
{
	int i, j;
	char bp[256];

	if ((vds_dbg & VDS_DEBUG_DEVID) == 0)
		return;

	if (info != NULL)
		pr_warn("%s\n", info);

	memset(bp, 0, 256);

	for (i = j = 0; i < count; i++, j++) {
		if (j == 16) {
			j = 0;
			pr_warn("%s\n", bp);
			memset(bp, 0, 256);
		}
		if (j == 0)
			sprintf(&bp[strlen(bp)], "%p: ", address+i);
		sprintf(&bp[strlen(bp)], "%02x ", buf[i]);
	}
	if (j != 0)
		pr_warn("%s\n", bp);
}

static int vds_dskimg_get_devid_block(struct vds_port *port, size_t *blkp)
{
	struct vio_driver_state *vio = &port->vio;
	unsigned long long spc, head, cyl;

	vdsdbg(DEVID, "port->label_type=%x\n", port->label_type);

	if (port->label_type == VDS_LABEL_EFI) {
		vdsdbg(DEVID, "efi_rsvd_partnum=%x\n", port->efi_rsvd_partnum);
		/*
		 * For an EFI disk, the devid is at the beginning of
		 * the reserved slice
		 */
		if (port->efi_rsvd_partnum == -1) {
			vdsdbg(DEVID, "EFI disk has no reserved slice\n");
			return (-ENOSPC);
		}
		*blkp = port->part[port->efi_rsvd_partnum].start;
	} else if (port->label_type == VDS_LABEL_VTOC) {
		if (port->geom->alt_cyl < 2) {
			vdsdbg(DEVID,
			    "not enough alt cylinders for devid (acyl=%u)\n",
			    port->geom->alt_cyl);
			return (-ENOSPC);
		}

		/* the devid is in on the track next to the last cylinder */
		cyl = port->geom->num_cyl + port->geom->alt_cyl - 2;
		spc = port->geom->num_hd * port->geom->num_sec;
		head = port->geom->num_hd - 1;

		*blkp = (cyl * (spc - port->geom->apc)) +
		    (head * port->geom->num_sec) + 1;
	} else {
		/* unknown disk label */
		return (-ENOENT);
	}

	vdsdbg(DEVID, "devid block: %ld\n", *blkp);

	return 0;
}

static int vds_dskimg_read_devid(struct vds_port *port,
	struct devid_info *devid)
{
	struct vio_driver_state *vio = &port->vio;
	struct dk_devid *dkdevid;
	size_t blk;
	int sz;
	int rv = 0;

	rv = vds_dskimg_get_devid_block(port, &blk);
	if (rv)
		return rv;

	dkdevid = kzalloc(DEVID_BLKSIZE, GFP_ATOMIC);

	/* get the devid */
	rv = vds_read(port, (void *)dkdevid, blk, DEVID_BLKSIZE);
	if (rv) {
		rv = -EIO;
		goto done;
	}

	vds_devid_dump((u8 *)dkdevid, DEVID_BLKSIZE, (void *)dkdevid,
	    "dkdevid:");

	/* validate the device id */
	if (vds_devid_valid(dkdevid) != 0) {
		vdsdbg(DEVID, "invalid devid found at block %lu\n", blk);
		rv = -EINVAL;
		goto done;
	}

	vdsdbg(DEVID, "devid read at block %lu\n", blk);

	sz = vds_devid_sizeof((struct devid_info *)dkdevid->dkd_devid);
	if ((sz > 0) && (sz <= DEVID_BLKSIZE)) {
		memcpy(devid, dkdevid->dkd_devid, sz);
		vds_devid_dump((u8 *)devid, sz, (void *)devid, "devid:");
	}
	rv = 0;
done:
	kfree(dkdevid);
	return rv;

}

int vds_dskimg_write_devid(struct vds_port *port)
{
	struct vio_driver_state *vio = &port->vio;
	struct dk_devid *dkdevid;
	struct devid_info *devid = port->devid;
	u32 chksum;
	size_t blk;
	int rv;

	vdsdbg(DEVID, "%s: label_type=%x, devid=%p\n", port->path,
	    port->label_type, devid);

	if (devid == NULL) {
		/* nothing to write */
		return 0;
	}

	rv = vds_dskimg_get_devid_block(port, &blk);
	if (rv)
		return -EIO;

	dkdevid = kzalloc(DEVID_BLKSIZE, GFP_ATOMIC);

	/* set revision */
	dkdevid->dkd_rev_hi = DEVID_REV_MSB;
	dkdevid->dkd_rev_lo = DEVID_REV_LSB;

	/* copy devid */
	memcpy(&dkdevid->dkd_devid, devid, vds_devid_sizeof(devid));

	/* compute checksum */
	chksum = vds_devid_cksum(dkdevid);

	/* set checksum */
	DEVID_SETCHKSUM(chksum, dkdevid);

	vdsdbg(DEVID, "dkdevid: blk=%ld\n", blk);
	vds_devid_dump((u8 *)dkdevid, DEVID_BLKSIZE, (void *)dkdevid, NULL);

	/* store the devid */
	rv = vds_write(port, (void *)dkdevid, blk, DEVID_BLKSIZE);
	if (rv < 0) {
		vdsdbg(DEVID, "Error writing devid block at %lu\n", blk);
		rv = -EIO;
	} else {
		vdsdbg(DEVID, "devid written at block %lu\n", blk);
		rv = 0;
	}

	kfree(dkdevid);
	return rv;
}

int vds_dskimg_init_devid(struct vds_port *port)
{
	struct vio_driver_state *vio = &port->vio;
	int status;

	/* Setup devid for the disk image */

	vdsdbg(DEVID, "%s: label_type=%x\n", port->path, port->label_type);

	if (!S_ISREG(port->mode))	/* Handle disk image only */
		return 0;

	port->devid = kzalloc(DEVID_BLKSIZE, GFP_KERNEL);

	status = vds_dskimg_read_devid(port, port->devid);

	vdsdbg(DEVID, "read & validate disk image devid, status=%d\n",
	    status);
	if (status == 0) {
		/* a valid devid was found */
		return 0;
	}

	if (status == -EIO) {
		/*
		 * There was an error while trying to read the devid.
		 * So this disk image may have a devid but we are
		 * unable to read it.
		 */
		vdsdbg(DEVID, "cannot read devid\n");
		kfree(port->devid);
		port->devid = NULL;
		return status;
	}

	/* No valid device id was found so create one. */

	vdsdbg(DEVID, "creating devid\n");

	memset(port->devid, 0, DEVID_BLKSIZE);

	if (vds_devid_init(DEVID_FAB, 0, NULL,
	    (struct devid_info *)port->devid, vds_hostid) != 0) {
		vdsdbg(DEVID, "fail to create devid\n");
		kfree(port->devid);
		port->devid = NULL;
		return -EINVAL;
	}

	return 0;
}
