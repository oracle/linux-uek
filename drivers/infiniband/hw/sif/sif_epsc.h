/*
 * Copyright (c) 2011, 2015, Oracle and/or its affiliates. All rights reserved.
 *    Author: Knut Omang <knut.omang@oracle.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 *
 * Driver for Oracle Scalable Infiniband Fabric (SIF) Host Channel Adapters
 *
 * sif_epsc.h: API for communication with the EPSC (and EPS-A's)
 */

#ifndef __SIF_EPSC_H
#define __SIF_EPSC_H
#include <linux/pci.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include "sif_eq.h"
#include "psif_hw_data.h"

struct sif_dev;
struct sif_table;
struct psif_epsc_csr_req;
struct psif_epsc_csr_rsp;

struct sif_epsc_data; /* sif_query.h */
enum psif_mbox_type;  /* psif_hw_data.h */
enum sif_tab_type;    /* sif_dev.h */

/* Max number of strings (including final NULL)
 * we expect from the firmware version details:
 */
enum sif_eps_fw_info_idx {
	FWV_EPS_REV_STRING,
	FWV_EPS_GIT_REPO,
	FWV_EPS_GIT_LAST_COMMIT,
	FWV_EPS_GIT_STATUS,
	FWV_EPS_BUILD_USER,
	FWV_EPS_BUILD_GIT_TIME,
	FWV_PSIF_GIT_REPO,
	FWV_PSIF_GIT_COMMIT,
	FWV_PSIF_GIT_STATUS,
	FWV_MAX
};


struct eps_version_data {
#ifdef __LITTLE_ENDIAN
	u16 epsc_minor;
	u16 epsc_major;
	u16 psif_minor;
	u16 psif_major;
#else
	u16 psif_major;
	u16 psif_minor;
	u16 epsc_major;
	u16 epsc_minor;
#endif
	u16 fw_minor;
	u16 fw_major;
	int seq_set_proto; /* Protocol version of the initial setup meta protocol (0 == legacy) */
	struct psif_epsc_csr_config nb_cfg; /* "Network" byte order config storage (see #3804) */
	char *fw_version[FWV_MAX];
};


enum sif_eps_state {
	ES_NOT_RUNNING,  /* EPS core thread not started */
	ES_RUNNING,      /* EPS core thread started but comm.protocol not initiated */
	ES_INIT,	 /* Driver is working to set up tables with this EPS */
	ES_ACTIVE	 /* Communication with this EPS is up and running */
};


struct sif_eps_cqe {
	struct psif_epsc_csr_rsp *rsp;	/* process_cqe places a host order copy of the response here */
	struct completion cmpl;		/* a completion to wait on for response */
	bool need_complete;		/* req was posted with EPSC_FL_NOTIFY */
};


#define EPS_TAG_FROM_HOST  0x8000

#define MAX_LOGDEVNAME 32

/* Internal bookkeeping for sif_epsc.c/h: */
struct sif_eps {
	struct sif_dev *sdev;
	enum psif_mbox_type eps_num; /* Which EPS this is */
	enum sif_eps_state state;  /* Current state of the EPS */
	struct eps_version_data ver; /* Minor/major version info of the epsc firmware */
	spinlock_t lock;/* Serializes CPU access to the epsc hw and sw resources */
	volatile u16 last_seq;    /* Last used sequence number */
	volatile u16 first_seq;   /* First sequence number not seen any completion on */
	u16 mask;	 /* req/rsp table sz - 1 */
	u16 max_reqs; /* Max outstanding reqs seen */
	u16 lowpri_lim;  /* Max number of outstanding low priority reqs */
	u16 last_full_seq; /* notify when queue full was last logged to avoid repeating logs */
	u16 mbox_id; /* ID of the mailbox as provided by EPS */
	atomic_t cur_reqs; /* current outstanding req count */
	atomic_t waiters; /* Number of threads waiting for a slot in the queue */
	unsigned long timeout; /* EPSC resp timeout - rescheduled when new completions observed */
	unsigned long keepalive_interval; /* how long to wait before sending a keepalive */
	unsigned long last_req_posted; /* time the last request was posted */
	struct sif_eps_cqe **cqe; /* An of caller owned pointers indexed by req.index */
	struct sif_epsc_data *data;  /* Ptr to data recv area for EPS/SMA queries */
	dma_addr_t data_dma_hdl; /* DMA address of data area for query device/port etc. */
	struct sif_eq_base eqs; /* Setup of event queues */

	/* log redirection support: */
	struct miscdevice logdev;  /* Device for log rederect from the EPS, if enabled */
	struct file_operations logdev_ops;
	char logdevname[MAX_LOGDEVNAME];
	bool log_redir_en;  /* Set if log is currently redirected */
	atomic_t logdev_use;
	struct completion logdev_more_log; /* elog reader will block on this one */
};

/**** Low level mailbox handling ****/
u64 eps_mailbox_read(struct sif_dev *sdev, u8 epsno);
void eps_mailbox_write(struct sif_dev *sdev, u8 epsno, u64 value);

u64 eps_mailbox_read_data(struct sif_dev *sdev, u8 epsno);
void eps_mailbox_write_data(struct sif_dev *sdev, u8 epsno, u64 value);

/* (De-)initialization necessary to communicate with the EPS */
int sif_eps_init(struct sif_dev *sdev, enum sif_tab_type rsp_type);
int sif_eps_deinit(struct sif_dev *sdev, enum sif_tab_type rsp_type);

const char *eps_name(struct sif_dev *sdev, enum psif_mbox_type eps_num);
const char *eps_suffix(struct sif_dev *sdev, enum psif_mbox_type eps_num);

/* Convert EPSC status code to errno */
int eps_status_to_err(enum psif_epsc_csr_status status);

struct psif_epsc_csr_req *get_eps_csr_req(struct sif_dev *sdev,
	enum psif_mbox_type eps_num, int index);

struct psif_epsc_csr_rsp *get_eps_csr_rsp(struct sif_dev *sdev,
	enum psif_mbox_type eps_num, int index);

/* Returns true if this is the response table for any of the EPSes: */
bool is_eps_rsp_tab(enum sif_tab_type type);

/* Asynchronous post of an EPSC work request to psif.
 * returns nonzero if #of outstanding requests
 * exceed what the hardware offers or if there is no more room
 * in completion queue for a new entry.
 * if @seq_num is nonzero, the sequence number of the posted request will be placed there.
 * If @lcqe is nonzero, a host endian copy of the response will be placed
 * there when detected.
 *
 * If wait is set, it means that the epsc wr should be posted with
 * flag EPSC_FL_NOTIFY to receive an interrupt from the epsc:
 */
int sif_post_eps_wr(struct sif_dev *sdev, enum psif_mbox_type eps_num,
		struct psif_epsc_csr_req *lreq, u16 *seq_num,
		struct sif_eps_cqe *lcqe, bool wait);

int sif_post_epsc_wr(struct sif_dev *sdev, struct psif_epsc_csr_req *lreq,
		u16 *seq_num, struct sif_eps_cqe *lcqe, bool wait);

/* Get the seq.num from a epsc response in host order */
u16 sif_epsc_get_seq(struct psif_epsc_csr_rsp *cqe);

/* Wait up to @timeout ticks
 * for an earlier posted request with ID @seq_num to complete
 * return 0 if success, -errno else. @cqe will be populated with the response
 * from the EPS. Uses EPSC interrupts for wakeup.
 */
int sif_epsc_waitfor_timeout(struct sif_dev *sdev, u16 seq_num,
			unsigned long timeout,
			struct sif_eps_cqe *cqe);

/* Wait for an earlier posted request with ID @seq_num to complete
 * return 0 if success, -errno else. @cqe will be populated with the response
 * from the EPS. Uses EPSC interrupts for wakeup.
 */
int sif_epsc_waitfor(struct sif_dev *sdev, u16 seq_num,
		struct sif_eps_cqe *cqe);

/* Poll waiting for a response - in attach we cannot suspend or sleep..
 * return 0 if a successful operation, eg.EPSC_SUCCESS,
 * otherwise a suitable -errno. @cqe will be populated with the response
 * from the EPS
 */
int sif_epsc_poll_cqe(struct sif_dev *sdev, u16 seq_num,
		struct sif_eps_cqe *cqe);

/* Synchronous post of an EPSC work request.
 * Will wait until request completes. @cqe will be populated with the response
 * from the EPS. Return value: A suitable errno value that also captures the
 * status code from the EPSC operation, if any.
 */
int sif_epsc_wr(struct sif_dev *sdev, struct  psif_epsc_csr_req *req,
		struct psif_epsc_csr_rsp *rsp);

/* Same as sif_epsc_wr but poll for completion */
int sif_epsc_wr_poll(struct sif_dev *sdev, struct  psif_epsc_csr_req *req,
		struct psif_epsc_csr_rsp *rsp);

/* Generic EPS access (any EPS) */
int sif_eps_wr(struct sif_dev *sdev, enum psif_mbox_type eps_num,
	struct  psif_epsc_csr_req *req, struct psif_epsc_csr_rsp *rsp);

int sif_eps_wr_poll(struct sif_dev *sdev, enum psif_mbox_type eps_num,
		struct psif_epsc_csr_req *req, struct psif_epsc_csr_rsp *rsp);

int sif_eps_poll_cqe(struct sif_dev *sdev, enum psif_mbox_type eps_num,
		u16 seq_num, struct sif_eps_cqe *lcqe);

/* EPS-A support */
int sif_activate_epsa(struct sif_dev *sdev, enum psif_mbox_type eps_num);

/* Send a keep-alive request to an EPS */
int sif_eps_send_keep_alive(struct sif_dev *sdev, enum psif_mbox_type eps_num,
			int force);

/**** High level synchronous CSR operations */

/* Read a 64 bit CSR register (local UF mapping) */
u64 sif_read_local_csr(struct sif_dev *sdev, u32 addr);

/* Read a 64 bit CSR register (global PSIF mapping - uf 0 only) */
u64 sif_read_global_csr(struct sif_dev *sdev, u32 addr);

/* Write a 64 bit EPS CSR register (global PSIF mapping - uf 0 only) */
int sif_write_global_csr(struct sif_dev *sdev, u32 addr, u64 val);

/* Helper for dfs iteration */
int sif_eps_next_used(struct sif_table *table, int index);

/* Sysfs entry printers */
void sif_dfs_print_epsc(struct seq_file *s, struct sif_dev *sdev,
			loff_t pos);
void sif_dfs_print_epsa0(struct seq_file *s, struct sif_dev *sdev,
			loff_t pos);
void sif_dfs_print_epsa1(struct seq_file *s, struct sif_dev *sdev,
			loff_t pos);
void sif_dfs_print_epsa2(struct seq_file *s, struct sif_dev *sdev,
			loff_t pos);
void sif_dfs_print_epsa3(struct seq_file *s, struct sif_dev *sdev,
			loff_t pos);

/* completion invocation - called from sif_eq as result of epsc completion event processing */
void epsc_complete(struct sif_dev *sdev, enum psif_mbox_type eps_num, int idx);

/* Report cause for EPSC degraded mode */
void epsc_report_degraded(struct sif_dev *sdev, u64 cause_mask);

/* Set the SIF value to use for the 12 upper bits of a DMA address */
int epsc_set_mmu_upper(struct sif_dev *sdev, u16 value);

#endif
