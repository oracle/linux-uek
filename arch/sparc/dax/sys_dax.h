/*
 * Copyright (c) 2017, Oracle and/or its affiliates. All rights reserved.
 *
 * This work is licensed under the terms of the GNU GPL, version 2.
 */

#ifndef _SYS_DAX_H
#define _SYS_DAX_H

#include <linux/types.h>

/* DAXIOC_CCB_EXEC dce_ccb_status */
#define	DAX_SUBMIT_OK				0
#define	DAX_SUBMIT_ERR_RETRY			1
#define	DAX_SUBMIT_ERR_WOULDBLOCK		2
#define	DAX_SUBMIT_ERR_BUSY			3
#define	DAX_SUBMIT_ERR_THR_INIT			4
#define	DAX_SUBMIT_ERR_ARG_INVAL		5
#define	DAX_SUBMIT_ERR_CCB_INVAL		6
#define	DAX_SUBMIT_ERR_NO_CA_AVAIL		7
#define	DAX_SUBMIT_ERR_CCB_ARR_MMU_MISS		8
#define	DAX_SUBMIT_ERR_NOMAP			9
#define	DAX_SUBMIT_ERR_NOACCESS			10
#define	DAX_SUBMIT_ERR_TOOMANY			11
#define	DAX_SUBMIT_ERR_UNAVAIL			12
#define	DAX_SUBMIT_ERR_INTERNAL			13


#define	DAX_DEV "/dev/dax"
#define DAX_DRIVER_VERSION 3

/*
 * dax device ioctl commands
 */
#define	DAXIOC	'D'

/* Deprecated IOCTL numbers */
#define	DAXIOC_CCB_THR_INIT_OLD	_IOWR(DAXIOC, 1, struct dax_ccb_thr_init_arg)
#define	DAXIOC_CA_DEQUEUE_OLD	_IOWR(DAXIOC, 3, struct dax_ca_dequeue_arg)
#define	DAXIOC_CCB_EXEC_OLD	_IOWR(DAXIOC, 4, struct dax_ccb_exec_arg)
#define	PERFCOUNT_GET_NODE_COUNT_OLD		_IOR('p', 0xB0, void *)
#define	PERFCOUNT_DAX_SET_COUNTERS_OLD		_IOW('p', 0xBA, void *)
#define	PERFCOUNT_DAX_GET_COUNTERS_OLD		_IOR('p', 0xBB, void *)
#define	PERFCOUNT_DAX_CLEAR_COUNTERS_OLD	_IOW('p', 0xBC, void *)

/* CCB thread initialization */
#define	DAXIOC_CCB_THR_INIT	_IOWR(DAXIOC, 6, struct dax_ccb_thr_init_arg)
/* free CCB thread resources */
#define	DAXIOC_CCB_THR_FINI	_IO(DAXIOC,   2)
/* CCB CA dequeue */
#define	DAXIOC_CA_DEQUEUE	_IOWR(DAXIOC, 7, struct dax_ca_dequeue_arg)
/* CCB execution */
#define	DAXIOC_CCB_EXEC		_IOWR(DAXIOC, 8, struct dax_ccb_exec_arg)
/* get driver version */
#define DAXIOC_VERSION          _IOWR(DAXIOC, 5, long)

/*
 * Perf Counter defines
 */
#define DAXIOC_PERF_GET_NODE_COUNT	_IOR(DAXIOC, 0xB0, void *)
#define DAXIOC_PERF_SET_COUNTERS	_IOW(DAXIOC, 0xBA, void *)
#define DAXIOC_PERF_GET_COUNTERS	_IOR(DAXIOC, 0xBB, void *)
#define DAXIOC_PERF_CLEAR_COUNTERS	_IOW(DAXIOC, 0xBC, void *)

/*
 * DAXIOC_CCB_THR_INIT
 * dcti_ccb_buf_maxlen - return u32 length
 * dcti_compl_maplen - return u64 mmap length
 * dcti_compl_mapoff - return u64 mmap offset
 */
struct dax_ccb_thr_init_arg {
	__u32 dcti_ccb_buf_maxlen;
	__u64 dcti_compl_maplen;
	__u64 dcti_compl_mapoff;
};

/*
 * DAXIOC_CCB_EXEC
 * dce_ccb_buf_len : user buffer length in bytes
 * *dce_ccb_buf_addr : user buffer address
 * dce_submitted_ccb_buf_len : CCBs in bytes submitted to the DAX HW
 * dce_ca_region_off : return offset to the completion area of the first
 *                     ccb submitted in DAXIOC_CCB_EXEC ioctl
 * dce_ccb_status : return u32 CCB status defined above (see DAX_SUBMIT_*)
 * dce_nomap_va : bad virtual address when ret is NOMAP or NOACCESS
 */
struct dax_ccb_exec_arg {
	__u32	dce_ccb_buf_len;
	void	*dce_ccb_buf_addr;
	__u32	dce_submitted_ccb_buf_len;
	__u64	dce_ca_region_off;
	__u32	dce_ccb_status;
	__u64	dce_nomap_va;
};

/*
 * DAXIOC_CA_DEQUEUE
 * dcd_len_requested : byte len of CA to dequeue
 * dcd_len_dequeued : byte len of CAs dequeued by the driver
 */
struct dax_ca_dequeue_arg {
	__u32 dcd_len_requested;
	__u32 dcd_len_dequeued;
};


/* The number of DAX engines per node */
#define DAX_PER_NODE		(8)

/* The number of performance counters
 * per DAX engine
 */
#define COUNTERS_PER_DAX	(3)

#endif /* _SYS_DAX_H */
