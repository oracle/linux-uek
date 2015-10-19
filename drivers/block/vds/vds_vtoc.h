/*
 * vds_vtoc.h: LDOM Virtual Disk Server.
 *
 * Copyright (C) 2014 Oracle. All rights reserved.
 *
 * Format of a Sun disk label.
 * Resides in cylinder 0, head 0, sector 0.
 *
 * From Solaris dklabel.h
 *
 */

#define	NDKMAP		8		/* # of logical partitions */
#define	DKL_MAGIC	0xDABE		/* magic number */
#define	LEN_DKL_ASCII	128		/* length of dkl_asciilabel */
#define	LEN_DKL_VVOL	8		/* length of v_volume */


/*
 * partition headers:  section 1
 * Fixed size for on-disk dk_label
 */
struct dk_map32 {
	uint32_t	dkl_cylno;	/* starting cylinder */
	uint32_t	dkl_nblk;	/* number of blocks;  if == 0, */
					/* partition is undefined */
};

/*
 * partition headers:  section 2,
 * brought over from AT&T SVr4 vtoc structure.
 */
struct dk_map2 {
	uint16_t	p_tag;		/* ID tag of partition */
	uint16_t	p_flag;		/* permission flag */
};

/*
 * VTOC inclusions from AT&T SVr4
 * Fixed sized types for on-disk VTOC
 */
struct dk_vtoc {
	uint32_t	v_version;		/* layout version */
	char		v_volume[LEN_DKL_VVOL];	/* volume name */
	uint16_t	v_nparts;		/* number of partitions  */
	struct dk_map2	v_part[NDKMAP];		/* partition hdrs, sec 2 */
	uint32_t	v_bootinfo[3];		/* info needed by mboot */
	uint32_t	v_sanity;		/* to verify vtoc sanity */
	uint32_t	v_reserved[10];		/* free space */
	int32_t		v_timestamp[NDKMAP];	/* partition timestamp */
};

/*
 * define the amount of disk label padding needed to make
 * the entire structure occupy 512 bytes.
 */
#define	LEN_DKL_PAD	(DK_LABEL_SIZE \
			    - ((LEN_DKL_ASCII) + \
			    (sizeof(struct dk_vtoc)) + \
			    (sizeof(struct dk_map32)  * NDKMAP) + \
			    (14 * (sizeof(uint16_t))) + \
			    (2 * (sizeof(uint16_t)))))

struct dk_label {
	char		dkl_asciilabel[LEN_DKL_ASCII]; /* for compatibility */
	struct dk_vtoc	dkl_vtoc;	/* vtoc inclusions from AT&T SVr4 */
	uint16_t	dkl_write_reinstruct;	/* # sectors to skip, writes */
	uint16_t	dkl_read_reinstruct;	/* # sectors to skip, reads */
	char		dkl_pad[LEN_DKL_PAD]; /* unused part of 512 bytes */
	uint16_t	dkl_rpm;	/* rotations per minute */
	uint16_t	dkl_pcyl;	/* # physical cylinders */
	uint16_t	dkl_apc;	/* alternates per cylinder */
	uint16_t	dkl_obs1;	/* obsolete */
	uint16_t	dkl_obs2;	/* obsolete */
	uint16_t	dkl_intrlv;	/* interleave factor */
	uint16_t	dkl_ncyl;	/* # of data cylinders */
	uint16_t	dkl_acyl;	/* # of alternate cylinders */
	uint16_t	dkl_nhead;	/* # of heads in this partition */
	uint16_t	dkl_nsect;	/* # of sectors per track */
	uint16_t	dkl_obs3;	/* obsolete */
	uint16_t	dkl_obs4;	/* obsolete */
	struct dk_map32	dkl_map[NDKMAP]; /* logical partition headers */
	uint16_t	dkl_magic;	/* identifies this label format */
	uint16_t	dkl_cksum;	/* xor checksum of sector */
};

#define	V_NUMPAR	NDKMAP		/* The number of partitions */
					/* (from dkio.h) */

#define	VTOC_SANE	0x600DDEEE	/* Indicates a sane VTOC */
#define	V_VERSION	0x01		/* layout version number */
#define	V_EXTVERSION	V_VERSION	/* extvtoc layout version number */

/*
 * Partition identification tags
 */
#define	V_UNASSIGNED	0x00		/* unassigned partition */
#define	V_BOOT		0x01		/* Boot partition */
#define	V_ROOT		0x02		/* Root filesystem */
#define	V_SWAP		0x03		/* Swap filesystem */
#define	V_USR		0x04		/* Usr filesystem */
#define	V_BACKUP	0x05		/* full disk */
#define	V_STAND		0x06		/* Stand partition */
#define	V_VAR		0x07		/* Var partition */
#define	V_HOME		0x08		/* Home partition */
#define	V_ALTSCTR	0x09		/* Alternate sector partition */
#define	V_CACHE		0x0a		/* Obsolete (was for cachefs) */

/* The following partition identification tags apply to EFI/GPT labels only */
#define	V_RESERVED	0x0b		/* SMI reserved data */
#define	V_SYSTEM	0x0c		/* EFI/GPT system partition */
#define	V_BIOS_BOOT	0x18		/* BIOS Boot partition */

#define	V_UNKNOWN	0xff		/* Unknown partition */

/*
 * Partition permission flags
 */
#define	V_UNMNT		0x01		/* Unmountable partition */
#define	V_RONLY		0x10		/* Read only */
