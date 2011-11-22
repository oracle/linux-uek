#ifndef ASM_REQUEST_H
#define ASM_REQUEST_H

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
