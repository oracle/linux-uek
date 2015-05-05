#ifndef ASM_REQUEST_H
#define ASM_REQUEST_H

/*
 * ASM Disk info
 */
struct asm_disk_info {
	struct asmfs_inode_info *d_inode;
	struct block_device *d_bdev;	/* Block device we I/O to */
	int d_max_sectors;		/* Maximum sectors per I/O */
	int d_live;			/* Is the disk alive? */
	atomic_t d_ios;			/* Count of in-flight I/Os */
	struct list_head d_open;	/* List of assocated asm_disk_heads */
	struct inode vfs_inode;
};

/* ASM I/O requests */
struct asm_request {
	struct list_head r_list;
	struct asmfs_file_info *r_file;
	struct asm_disk_info *r_disk;
	asm_ioc *r_ioc;				/* User asm_ioc */
	u16 r_status;				/* status_asm_ioc */
	int r_error;
	unsigned long r_elapsed;		/* Start time while in-flight, elapsted time once complete */
	struct bio *r_bio;			/* The I/O */
	size_t r_count;				/* Total bytes */
	atomic_t r_bio_count;			/* Atomic count */
};

#endif
