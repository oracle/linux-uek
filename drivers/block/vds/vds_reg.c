/*
 * vds_reg.c: LDOM Virtual Disk Server.
 *
 * Copyright (C) 2014 Oracle. All rights reserved.
 */

#include "vds.h"
#include "vds_io.h"

static int vds_reg_init(struct vds_port *port)
{
	struct file *file;

	file = filp_open(port->path, O_RDWR | O_EXCL | O_LARGEFILE, 0);
	if (IS_ERR(file))
		return (int)PTR_ERR(file);

	port->vdisk_bsize = 512;
	port->vdisk_size = i_size_read(file_inode(file)) /
				       port->vdisk_bsize;
	port->max_xfer_size = 1024;

	port->be_data = file;

	return 0;
}

static void vds_reg_fini(struct vds_port *port)
{
	struct file *file = port->be_data;

	if (file)
		filp_close(file, NULL);
}

static int vds_reg_rw(struct vds_io *io)
{
	loff_t off;
	ssize_t iosz;
	void *addr;
	struct vio_driver_state *vio = io->vio;
	struct vds_port *port = to_vds_port(vio);
	struct file *file = port->be_data;

	vdsdbg(FIO, "(0x%p, %lld, %ld, %d)\n", io->pages, io->size,
	       io->offset, io->rw);

	if (file == NULL) {
		vdsmsg(err, "NULL file pointer for IO\n");
		return -EIO;
	}

	addr = page_address(io->pages);
	off = to_bytes(io->offset);

	if (io->rw & WRITE)
		iosz = file->f_op->write(file, addr, io->size, &off);
	else
		iosz = file->f_op->read(file, addr, io->size, &off);

	if (iosz != io->size) {
		vdsmsg(err, "file IO failed: iosz=%ld\n", iosz);
		return -EIO;
	}

	return 0;
}

static int vds_reg_flush(struct vds_port *port)
{
	struct file *file = port->be_data;

	return vfs_fsync(file, 0);
}

struct vds_be_ops vds_reg_ops = {
	vds_reg_init,
	vds_reg_fini,
	vds_reg_rw,
	vds_reg_flush,
};

struct vds_be_ops *vds_reg_get_ops()
{
	return &vds_reg_ops;
}
