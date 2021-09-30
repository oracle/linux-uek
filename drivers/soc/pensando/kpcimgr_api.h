#ifndef __KPCIMGR_API_H__
#define __KPCIMGR_API_H__

#ifdef __KERNEL__
#include <linux/miscdevice.h>
#include <linux/io.h>
#include <linux/uaccess.h>
#include <linux/module.h>
#include <linux/cdev.h>
#include <linux/timer.h>
#include <linux/reboot.h>
#include <linux/kallsyms.h>
#include <linux/poll.h>
#include <asm/insn.h>
#endif

/*
 * Layout of non-Linux Memory:
 *  C400 0000  HWMEM segment (pciehw_mem_t)   [16Mb]
 *  C500 0000  SHMEM segment (pciehw_shmem_t) [0x942440 bytes ~9.25Mb]
 *  C5F0 0000  kpcimgr state (kstate_t)       [3 * 64k]
 *  C5F3 0000  relocated code                 [Allow 256k]
 *  C5F7 0000  available for stack when in nommu mode (64k)
 *  C5F8 0000  top of stack
 *  C5FF FFFF  end of 1M allotted range
 */
#define PCIEHW_ADDR             0xc4000000
#define PCIEHW_SHMEM_ADDR       0xc5000000
#define SHMEM_KSTATE_OFFSET       0xF00000
#define SHMEM_KSTATE_SIZE          0x30000
#define KSTATE_CODE_OFFSET      (SHMEM_KSTATE_OFFSET + SHMEM_KSTATE_SIZE)
#define SHMEM_KSTATE_ADDR       (PCIEHW_SHMEM_ADDR + SHMEM_KSTATE_OFFSET)
#define SHMEM_CODE_ADDR         (PCIEHW_SHMEM_ADDR + KSTATE_CODE_OFFSET)
#define KSTATE_CODE_SIZE        (256*1024)
#define KSTATE_MAGIC            0x1743BA1F

/* size of trace data arrays */
#define DATA_SIZE 100

/* uart and time related constants */
#define PEN_UART 0x4800
#define UART_THR 0
#define UART_LSR 0x14
#define DATA_READY 1
#define OK_TO_WRITE 0x20

#define TICKS_PER_US 200
#define TICKS_PER_MS  (1000*TICKS_PER_US)
#define TICKS_PER_SEC (1000*TICKS_PER_MS)

#define INDIRECT_TIMER_DELAY msecs_to_jiffies(25)

/* phases */
#define NOMMU 0
#define NORMAL 1
#define NUM_PHASES 2

struct kpcimgr_state_t {
	/* essential state */
	long valid;
	int polling;
	int debug;

	/* timestamps and general trace data */
	long kexec_time;
	long driver_start_time;
	unsigned long trace_data[NUM_PHASES][DATA_SIZE];

	/* addresses */
	void *uart_addr;
	void *code_base;
	void *iomap_fn;

	/* stats for work done */
	int ind_cfgrd, ind_cfgwr;
	int ind_memrd, ind_memwr;
	int ncalls;

	/* offsets into relocated library code */
	int poll_offset;
	int cpu_holding_pen_offset;

	/* Event queue handling */
#define EVENT_QUEUE_LENGTH 1024
#define EVENT_SIZE 128
	int evq_head, evq_tail;
	char evq[EVENT_QUEUE_LENGTH][EVENT_SIZE];
};
typedef struct kpcimgr_state_t kstate_t;
_Static_assert(sizeof(kstate_t) < SHMEM_KSTATE_SIZE,
	       "kstate size insufficient");

/* trace_data[] elements */
#define FIRST_CALL_TIME 0
#define FIRST_SEQNUM 1
#define LAST_SEQNUM 2
#define TAG 3
#define PA_BAD_CNT 4
#define NUM_CHECKS 5
#define NUM_CALLS 6
#define NUM_PENDINGS 7
#define LAST_CALL_TIME 8
#define EARLY_POLL 9
#define MAX_DATA 10

/* kpcimgr ioctl calls */
#define KPCIMGR_DEBUG _IO(0xff, 3)
#define KPCIMGR_START _IO(0xff, 4)
#define KPCIMGR_STOP _IO(0xff, 5)
#define KPCIMGR_GET_KSTATE _IOWR(0xff, 8, void *)
#define KPCIMGR_INVALIDATE _IO(0xff, 14)

#define KPCIMGR_DEV "/dev/kpcimgr"
#define KPCIMGR_NAME "kpcimgr"

#ifdef __KERNEL__
int kpcimgr_module_relocate(struct module *mod, void *code_end);
#define reset_stats(k) \
	kpci_memset(&k->trace_data[0][0], 0, sizeof(k->trace_data))

static inline void set_init_state(kstate_t *k)
{
	k->trace_data[NORMAL][FIRST_CALL_TIME] = 0;
}

#endif

#endif
