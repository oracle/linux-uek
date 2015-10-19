/*
 * vds_io.h: LDOM Virtual Disk Server.
 *
 * Copyright (C) 2014 Oracle. All rights reserved.
 */

struct vds_port;

/*
 * IO interface.
 *
 * I/O struct allocated dynamically per client request.
 * A request is scheduled in interrupt context and executed later
 * in a worker kernel thread in process context.  The default events
 * worker threads are used (1 per cpu).
 * A client request may cause a number bio operations which
 * are tracked by count below.
 */
struct vds_io {
	int flags;
	int ack;
	int error;
	u32 msglen;
	atomic_t count;
	void *msgbuf;
	void *desc_buf;
	struct vio_disk_dring_payload *desc;
	struct vio_driver_state *vio;
	int rw;
	u64 size;
	unsigned ord;
	void *addr;
	sector_t offset;
	unsigned npages;
	struct page *pages;
	struct completion event;
	struct work_struct vds_work;
	char buf[0];
};

#define	VDS_IO_CACHE		0x1
#define	VDS_IO_INIT		0x2
#define	VDS_IO_FINI		0x4

int vds_io_init(void);
void vds_io_fini(void);
struct vds_io *vds_io_alloc(struct vio_driver_state *vio,
			    void (*func)(struct work_struct *));
void vds_io_free(struct vds_io *io);
void vds_io_enq(struct vds_io *io);

void *vds_get(struct vds_port *port, sector_t offset, u64 size);
int vds_clear(struct vds_port *port, sector_t offset, u64 size);
int vds_read(struct vds_port *port, void *addr, sector_t offset, u64 size);
int vds_write(struct vds_port *port, void *addr, sector_t offset, u64 size);

/*
 * VIO interface.
 */
int vd_op_get_vtoc(struct vds_io *io);
int vd_op_set_vtoc(struct vds_io *io);
int vd_op_get_geom(struct vds_io *io);
int vd_op_set_geom(struct vds_io *io);
int vd_op_get_efi(struct vds_io *io);
int vd_op_set_efi(struct vds_io *io);
int vd_op_flush(struct vio_driver_state *vio);
int vd_op_rw(struct vds_io *io);
