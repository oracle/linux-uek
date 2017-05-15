/*
 * vds_devid.h: LDOM Virtual Disk Server.
 *
 * Copyright (C) 2017 Oracle. All rights reserved.
 */

/*
 * Device id types
 */
#define	DEVID_NONE		0
#define	DEVID_SCSI3_WWN		1
#define	DEVID_SCSI_SERIAL	2
#define	DEVID_FAB		3
#define	DEVID_ENCAP		4
#define	DEVID_ATA_SERIAL	5
#define	DEVID_SCSI3_VPD_T10	6
#define	DEVID_SCSI3_VPD_EUI	7
#define	DEVID_SCSI3_VPD_NAA	8
#define	DEVID_BLOCK		9
#define	DEVID_PCI_SERIAL	10
#define	DEVID_MAXTYPE		10


/*
 * Layout of stored fabricated device id  (on-disk)
 */
#define DEVID_BLKSIZE        (512)
#define DEVID_SIZE           (DEVID_BLKSIZE - ((sizeof(u8) * 7)))

struct dk_devid {
        u8 dkd_rev_hi;                     /* revision (MSB) */
        u8 dkd_rev_lo;                     /* revision (LSB) */
        u8 dkd_flags;                      /* flags (not used yet) */
	u8 dkd_devid[DEVID_SIZE];          /* devid stored here */
        u8 dkd_checksum3;                  /* checksum (MSB) */
        u8 dkd_checksum2;
        u8 dkd_checksum1;
        u8 dkd_checksum0;                  /* checksum (LSB) */
};

#define	DEVID_TIMEVAL_SIZE	8

#ifdef __LITTLE_ENDIAN
#define lobyte(X)       (((unsigned char *)&(X))[0])
#define hibyte(X)       (((unsigned char *)&(X))[1])
#define loword(X)       (((unsigned short *)&(X))[0])
#define hiword(X)       (((unsigned short *)&(X))[1])
#endif
#ifdef __BIG_ENDIAN
#define lobyte(X)       (((unsigned char *)&(X))[1])
#define hibyte(X)       (((unsigned char *)&(X))[0])
#define loword(X)       (((unsigned short *)&(X))[1])
#define hiword(X)       (((unsigned short *)&(X))[0])
#endif

#define DEVID_GETCHKSUM(dkd)		\
	(((dkd)->dkd_checksum3 << 24) + \
	((dkd)->dkd_checksum2 << 16) +  \
	((dkd)->dkd_checksum1 << 8)  +  \
	((dkd)->dkd_checksum0))

#define DEVID_SETCHKSUM(c, dkd)					\
	do {							\
		(dkd)->dkd_checksum3 = hibyte(hiword((c)));	\
		(dkd)->dkd_checksum2 = lobyte(hiword((c)));	\
		(dkd)->dkd_checksum1 = hibyte(loword((c)));	\
		(dkd)->dkd_checksum0 = lobyte(loword((c)));	\
	} while (0)

/*
 * Device id - Internal definition.
 */
#define DEVID_MAGIC_MSB         0x69
#define DEVID_MAGIC_LSB         0x64
#define DEVID_REV_MSB           0x00
#define DEVID_REV_LSB           0x01
#define DEVID_HINT_SIZE         4

struct devid_info {
        u8 did_magic_hi;                   /* device id magic # (msb) */
        u8 did_magic_lo;                   /* device id magic # (lsb) */
        u8 did_rev_hi;                     /* device id revision # (msb) */
        u8 did_rev_lo;                     /* device id revision # (lsb) */
        u8 did_type_hi;                    /* device id type (msb) */
        u8 did_type_lo;                    /* device id type (lsb) */
        u8 did_len_hi;                     /* length of devid data (msb) */
        u8 did_len_lo;                     /* length of devid data (lsb) */
        char    did_driver[DEVID_HINT_SIZE];    /* driver name - HINT */
        char    did_id[1];                      /* start of device id data */
};

#define NBBY 8

#define DEVID_GETTYPE(devid)            ((u16) \
                                            (((devid)->did_type_hi << NBBY) + \
                                            (devid)->did_type_lo))

#define DEVID_FORMTYPE(devid, type)     (devid)->did_type_hi =          \
                                            ((type) >> NBBY) & 0xFF;    \
                                        (devid)->did_type_lo =          \
                                            (type) & 0xFF;

#define DEVID_GETLEN(devid)             ((u16) \
                                            (((devid)->did_len_hi << NBBY) + \
                                            (devid)->did_len_lo))

#define DEVID_FORMLEN(devid, len)       (devid)->did_len_hi =           \
                                            ((len) >> NBBY) & 0xFF;     \
                                        (devid)->did_len_lo =           \
                                            (len) & 0xFF;

#define DEVID_RET_VALID		0
#define DEVID_RET_INVALID	(-1)

struct efi_uuid {
        u32        time_low;
        u16        time_mid;
        u16        time_hi_and_version;
        u8         clk_node_addr[8];
};

typedef struct efi_uuid efi_uuid_t;

#define EFI_RESERVED    { 0x6a945a3b, 0x1dd2, 0x11b2, \
                            { 0x99, 0xa6, 0x08, 0x00, 0x20, 0x73, 0x66, 0x31 } }

int vds_dskimg_init_devid(struct vds_port *port);
int vds_dskimg_write_devid(struct vds_port *port);
size_t vds_devid_sizeof(struct devid_info *id);
void vds_devid_dump(unsigned char *buf, int count, void *address, char *info);

extern u32 vds_hostid;
extern void do_gettimeofday(struct timeval *tv);
