/*
 * vds.h: LDOM Virtual Disk Server.
 *
 * Copyright (C) 2014 Oracle. All rights reserved.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/blkdev.h>
#include <linux/hdreg.h>
#include <linux/spinlock.h>
#include <linux/completion.h>
#include <linux/delay.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/namei.h>
#include <linux/device-mapper.h>
#include <linux/sysfs.h>

#include <asm/vio.h>
#include <asm/ldc.h>

struct vds_part {
	sector_t		start;
	sector_t		size;
};

#define	VDS_MAXPART	128	/* max # of logical partitions */
#define	DK_LABEL_SIZE	512	/* size of disk label */

struct vds_port {
	struct vio_driver_state	vio;
	u8			flags;
	u8			xfer_mode;
	u8			media_type;
	u8			label_type;
	u8			npart;
	u64			max_xfer_size;
	u64			vdisk_size;
	u32			vdisk_bsize;
	u32			msglen;
	u64			seq;
	const char		*path;
	void			*msgbuf;
	struct vds_be_ops	*be_ops;	/* backend ops */
	void			*be_data;
	struct mutex		label_lock;
	char			label[DK_LABEL_SIZE];	/* for vtoc/gpt */
	struct vds_part		*part;
	struct vio_disk_geom	*geom;
	struct vio_disk_vtoc	*vtoc;
	struct workqueue_struct	*ioq;
	struct workqueue_struct	*rtq;
};

#define	VDS_PORT_SEQ		0x1

static inline struct vds_port *to_vds_port(struct vio_driver_state *vio)
{
	return container_of(vio, struct vds_port, vio);
}

struct vds_io;

/*
 * Backend interface.
 */
struct vds_be_ops {
	int (*init)(struct vds_port *port);
	void (*fini)(struct vds_port *port);
	int (*rw)(struct vds_io *io);
	int (*flush)(struct vds_port *port);
};

struct vds_be_ops *vds_blk_get_ops(void);
struct vds_be_ops *vds_reg_get_ops(void);

int vds_be_init(struct vds_port *port);
void vds_be_fini(struct vds_port *port);

/*
 * Label interface.
 */
void vds_label_init(struct vds_port *port);
void vds_label_fini(struct vds_port *port);
void vds_label_reset(struct vds_port *port);
void vds_label_clear_part(struct vds_port *port);
int vds_label_get_vtoc(struct vds_port *port);
int vds_label_get_start(struct vds_port *port, int slice, sector_t *start);
int vds_label_chk_iso(struct vds_port *port, bool *iso);

int vds_efi_get(struct vds_port *port, sector_t lba, size_t len, void *data);
int vds_efi_set(struct vds_port *port, sector_t lba, size_t len, void *data);
int vds_efi_clear(struct vds_port *port);
int vds_efi_validate(struct vds_port *port);

int vds_vtoc_get(struct vds_port *port);
int vds_vtoc_set(struct vds_port *port, struct vio_disk_vtoc *vtoc);
int vds_vtoc_clear(struct vds_port *port);

#define	vds_label_lock(p, v)					\
	do {							\
		vdsdbg(LOCK, "label lock\n");	\
		mutex_lock(&(p)->label_lock);			\
	} while (0)

#define	vds_label_unlock(p, v)					\
	do {							\
		vdsdbg(LOCK, "label unlock\n");	\
		mutex_unlock(&(p)->label_lock);			\
	} while (0)

#define	VDS_LABEL_NONE		0
#define	VDS_LABEL_VTOC		1
#define	VDS_LABEL_EFI		2

#define	VDS_EFI_GPT		1

/*
 * Solaris ENOTSUP error.  Solaris vdisk expects to receive this error
 * when getting the vtoc or geometry of a disk with and EFI label.
 */
#define	VDS_ENOTSUP		48

#define	ONE_MEGABYTE	(1ULL << 20)
#define	ONE_GIGABYTE	(1ULL << 30)

#define	vds_vio_lock(v, f)				\
	do {						\
		vdsdbg(LOCK, "%s: lock\n", __func__);	\
		spin_lock_irqsave(&(v)->lock, (f));	\
	} while (0)

#define	vds_vio_unlock(v, f)				\
	do {						\
		vdsdbg(LOCK, "%s: unlock\n", __func__);	\
		spin_unlock_irqrestore(&(v)->lock, (f));	\
	} while (0)

#define VDS_DEBUG_INIT		0x01
#define VDS_DEBUG_HS		0x02
#define VDS_DEBUG_DATA		0x04
#define VDS_DEBUG_LOCK		0x08
#define VDS_DEBUG_WQ		0x10
#define VDS_DEBUG_MEM		0x20
#define VDS_DEBUG_IOC		0x40
#define VDS_DEBUG_FLUSH		0x80
#define VDS_DEBUG_IO		0x100
#define VDS_DEBUG_BIO		0x200
#define VDS_DEBUG_FIO		0x400

extern int vds_dbg;
extern int vds_dbg_ldc;
extern int vds_dbg_vio;

#define vdsdbg(TYPE, f, a...)						\
	do {								\
		if (vds_dbg & VDS_DEBUG_##TYPE)				\
			pr_info("vds: ID[%lu] %s " f,			\
			    vio->vdev->channel_id, __func__, ## a);	\
	} while (0)

#define	vdsmsg(type, f, a...)					\
	pr_##type("%s: " f, __func__, ## a);
