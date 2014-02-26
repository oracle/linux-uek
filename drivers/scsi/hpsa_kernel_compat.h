/*
 *    Disk Array driver for HP Smart Array SAS controllers
 *    Copyright 2013, Hewlett-Packard Development Company, L.P.
 *
 *    This program is free software; you can redistribute it and/or modify
 *    it under the terms of the GNU General Public License as published by
 *    the Free Software Foundation; version 2 of the License.
 *
 *    This program is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE, GOOD TITLE or
 *    NON INFRINGEMENT.  See the GNU General Public License for more details.
 *
 *    You should have received a copy of the GNU General Public License
 *    along with this program; if not, write to the Free Software
 *    Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 *    Questions/Comments/Bugfixes to iss_storagedev@hp.com
 *
 */

/*
 * The following #defines allow the hpsa driver to be compiled for a 
 * variety of kernels.  Despite having names like RHEL5, SLES11, these
 * are more about the kernel than about the OS.  So for instance, if
 * you're running RHEL5 (typically 2.6.18-ish kernel), but you've compiled
 * a custom 2.6.38 or 3.x kernel and you're running that, then you don't want
 * the RHEL5 define, you probably want the default kernel.org (as of this
 * writing circa March 2012)  If you're running the OS vendor's kernel
 * or a kernel that is of roughly the same vintage as the OS vendor's kernel
 * then you can go by the OS name.
 *
 * If you have some intermediate kernel which doesn't quite match any of
 * the predefined sets of kernel features here, you may have to make your own 
 * define for your particular kernel and mix and match the kernel features
 * to fit the kernel you're compiling for.  How can you tell?  By studying
 * the source of this file and the source of the kernel you're compiling for
 * and understanding which "KFEATURES" your kernel has.
 *
 * Usually, if you get it wrong, it won't compile, but there are no doubt
 * some cases in which, if you get it wrong, it will compile, but won't
 * work right.  In any case, if you're compiling this, you're on your own
 * and likely nobody has tested this particular code with your particular
 * kernel, so, good luck, and pay attention to the compiler warnings.
 *
 */

/* #define SLES11sp1 */
/* #define SLES11sp2plus */
/* #define RHEL5 */
/* #define RHEL5u2 */
/* #define RHEL6 */
/* Default is kernel.org */

#ifdef RHEL5  /************  RHEL5 ************/
#define KFEATURE_HAS_2011_03_INTERRUPT_HANDLER 0
#define KFEATURE_CHANGE_QDEPTH_HAS_REASON 0
#define KFEATURE_HAS_2011_03_STYLE_DEVICE_ATTR 0
#define KFEATURE_HAS_SCSI_QDEPTH_DEFAULT 0
#define KFEATURE_HAS_SCSI_FOR_EACH_SG 0
#define KFEATURE_HAS_SCSI_DEVICE_TYPE 0
#define KFEATURE_SCAN_START_PRESENT 1
#define KFEATURE_SCAN_START_IMPLEMENTED 0
#define KFEATURE_HAS_2011_03_QUEUECOMMAND 0
#define KFEATURE_HAS_SHOST_PRIV 1
#define KFEATURE_HAS_SCSI_DMA_FUNCTIONS 1
#define KFEATURE_HAS_SCSI_SET_RESID 1
#define KFEATURE_HAS_UACCESS_H_FILE 1
#define KFEATURE_HAS_SMP_LOCK_H 1
#define KFEATURE_HAS_NEW_DMA_MAPPING_ERROR 0
#define HPSA_SUPPORTS_STORAGEWORKS_1210m 1
#define SA_CONTROLLERS_GEN6 0
#define SA_CONTROLLERS_GEN8 0
#define SA_CONTROLLERS_GEN8_2 0

#else

#ifdef RHEL5u2  /************  RHEL5u2 ************/
#define KFEATURE_HAS_2011_03_INTERRUPT_HANDLER 0
#define KFEATURE_CHANGE_QDEPTH_HAS_REASON 0
#define KFEATURE_HAS_2011_03_STYLE_DEVICE_ATTR 0
#define KFEATURE_HAS_SCSI_QDEPTH_DEFAULT 0
#define KFEATURE_HAS_SCSI_FOR_EACH_SG 0
#define KFEATURE_HAS_SCSI_DEVICE_TYPE 0
#define KFEATURE_SCAN_START_PRESENT 1
#define KFEATURE_SCAN_START_IMPLEMENTED 0
#define KFEATURE_HAS_2011_03_QUEUECOMMAND 0
#define KFEATURE_HAS_SHOST_PRIV 1
#define KFEATURE_HAS_SCSI_DMA_FUNCTIONS 0
#define KFEATURE_HAS_SCSI_SET_RESID 1
#define KFEATURE_HAS_UACCESS_H_FILE 1
#define KFEATURE_HAS_SMP_LOCK_H 1
#define KFEATURE_HAS_NEW_DMA_MAPPING_ERROR 0
#define HPSA_SUPPORTS_STORAGEWORKS_1210m 0
#define SA_CONTROLLERS_GEN6 0
#define SA_CONTROLLERS_GEN8 0
#define SA_CONTROLLERS_GEN8_2 0

#else

#ifdef RHEL6 /************ RHEL 6 ************/
#define KFEATURE_HAS_2011_03_INTERRUPT_HANDLER 1
#define KFEATURE_CHANGE_QDEPTH_HAS_REASON 1
#define KFEATURE_HAS_2011_03_STYLE_DEVICE_ATTR 1
#define KFEATURE_HAS_SCSI_QDEPTH_DEFAULT 1
#define KFEATURE_HAS_SCSI_FOR_EACH_SG 1
#define KFEATURE_HAS_SCSI_DEVICE_TYPE 1
#define KFEATURE_SCAN_START_PRESENT 1
#define KFEATURE_SCAN_START_IMPLEMENTED 1
#define KFEATURE_HAS_2011_03_QUEUECOMMAND 0
#define KFEATURE_HAS_SHOST_PRIV 1
#define KFEATURE_HAS_SCSI_DMA_FUNCTIONS 1
#define KFEATURE_HAS_SCSI_SET_RESID 1
#define KFEATURE_HAS_UACCESS_H_FILE 1
#define KFEATURE_HAS_SMP_LOCK_H 1
#define KFEATURE_HAS_NEW_DMA_MAPPING_ERROR 1
#define HPSA_SUPPORTS_STORAGEWORKS_1210m 1
#define SA_CONTROLLERS_GEN6 1
#define SA_CONTROLLERS_GEN8 1
#define SA_CONTROLLERS_GEN8_2 1
#define SA_CONTROLLERS_GEN8_5 1

#else

#ifdef SLES11sp1 /************* SLES11 sp1 ********/
#define KFEATURE_HAS_2011_03_INTERRUPT_HANDLER 1
#define KFEATURE_CHANGE_QDEPTH_HAS_REASON 1
#define KFEATURE_HAS_2011_03_STYLE_DEVICE_ATTR 1
#define KFEATURE_HAS_SCSI_QDEPTH_DEFAULT 1
#define KFEATURE_HAS_SCSI_FOR_EACH_SG 1
#define KFEATURE_HAS_SCSI_DEVICE_TYPE 1
#define KFEATURE_SCAN_START_PRESENT 1
#define KFEATURE_SCAN_START_IMPLEMENTED 1
#define KFEATURE_HAS_2011_03_QUEUECOMMAND 0
#define KFEATURE_HAS_SHOST_PRIV 1
#define KFEATURE_HAS_SCSI_DMA_FUNCTIONS 1
#define KFEATURE_HAS_SCSI_SET_RESID 1
#define KFEATURE_HAS_UACCESS_H_FILE 1
#define KFEATURE_HAS_SMP_LOCK_H 1
#define KFEATURE_HAS_NEW_DMA_MAPPING_ERROR 1
#define HPSA_SUPPORTS_STORAGEWORKS_1210m 1
#define SA_CONTROLLERS_GEN6 0
#define SA_CONTROLLERS_GEN8 1
#define SA_CONTROLLERS_GEN8_2 1
#define SA_CONTROLLERS_GEN8_5 1

#else
#ifdef SLES11sp2plus /************* SLES11 sp2 and after ********/
#define KFEATURE_HAS_2011_03_INTERRUPT_HANDLER 1
#define KFEATURE_CHANGE_QDEPTH_HAS_REASON 1
#define KFEATURE_HAS_2011_03_STYLE_DEVICE_ATTR 1
#define KFEATURE_HAS_SCSI_QDEPTH_DEFAULT 1
#define KFEATURE_HAS_SCSI_FOR_EACH_SG 1
#define KFEATURE_HAS_SCSI_DEVICE_TYPE 1
#define KFEATURE_SCAN_START_PRESENT 1
#define KFEATURE_SCAN_START_IMPLEMENTED 1
#define KFEATURE_HAS_2011_03_QUEUECOMMAND 1
#define KFEATURE_HAS_SHOST_PRIV 1
#define KFEATURE_HAS_SCSI_DMA_FUNCTIONS 1
#define KFEATURE_HAS_SCSI_SET_RESID 1
#define KFEATURE_HAS_UACCESS_H_FILE 1
#define KFEATURE_HAS_SMP_LOCK_H 0
#define KFEATURE_HAS_NEW_DMA_MAPPING_ERROR 1
#define HPSA_SUPPORTS_STORAGEWORKS_1210m 1
#define SA_CONTROLLERS_GEN6 0
#define SA_CONTROLLERS_GEN8 1
#define SA_CONTROLLERS_GEN8_2 1
#define SA_CONTROLLERS_GEN8_5 1

#else /* Default, kernel.org */
#define KFEATURE_HAS_2011_03_INTERRUPT_HANDLER 1
#define KFEATURE_CHANGE_QDEPTH_HAS_REASON 1
#define KFEATURE_HAS_2011_03_STYLE_DEVICE_ATTR 1
#define KFEATURE_HAS_SCSI_QDEPTH_DEFAULT 1
#define KFEATURE_HAS_SCSI_FOR_EACH_SG 1
#define KFEATURE_HAS_SCSI_DEVICE_TYPE 1
#define KFEATURE_SCAN_START_PRESENT 1
#define KFEATURE_SCAN_START_IMPLEMENTED 1
#define KFEATURE_HAS_2011_03_QUEUECOMMAND 1
#define KFEATURE_HAS_SHOST_PRIV 1
#define KFEATURE_HAS_SCSI_DMA_FUNCTIONS 1
#define KFEATURE_HAS_SCSI_SET_RESID 1
#define KFEATURE_HAS_UACCESS_H_FILE 1
#define KFEATURE_HAS_SMP_LOCK_H 0 /* include/linux/smp_lock.h removed between 2.6.38 and 2.6.39 */
#define KFEATURE_HAS_NEW_DMA_MAPPING_ERROR 1
#define HPSA_SUPPORTS_STORAGEWORKS_1210m 1
#define SA_CONTROLLERS_GEN6 1
#define SA_CONTROLLERS_GEN8 1
#define SA_CONTROLLERS_GEN8_2 1
#define SA_CONTROLLERS_GEN8_5 1

#endif /* SLES11sp2plus */
#endif /* SLES11sp1 */
#endif /* RHEL6 */
#endif /* RHEL5u2 */
#endif /* RHEL5 */

#if KFEATURE_HAS_2011_03_INTERRUPT_HANDLER
	/* new style interrupt handler */
#	define DECLARE_INTERRUPT_HANDLER(handler) \
		static irqreturn_t handler(int irq, void *queue)
#	define INTERRUPT_HANDLER_TYPE(handler) \
		irqreturn_t (*handler)(int, void *)
#else
	/* old style interrupt handler */
#	define DECLARE_INTERRUPT_HANDLER(handler) \
		static irqreturn_t handler(int irq, void *queue, \
			struct pt_regs *regs)
#	define INTERRUPT_HANDLER_TYPE(handler) \
		irqreturn_t (*handler)(int, void *, struct pt_regs *)
#endif


#if KFEATURE_CHANGE_QDEPTH_HAS_REASON
#	define DECLARE_CHANGE_QUEUE_DEPTH(func) \
	static int func(struct scsi_device *sdev, \
		int qdepth, int reason)
#	define BAIL_ON_BAD_REASON \
		{ if (reason != SCSI_QDEPTH_DEFAULT) \
			return -ENOTSUPP; }
#else
#	define DECLARE_CHANGE_QUEUE_DEPTH(func) \
	static int func(struct scsi_device *sdev, int qdepth)
#	define BAIL_ON_BAD_REASON
#endif


#if KFEATURE_HAS_2011_03_STYLE_DEVICE_ATTR

#	define DECLARE_DEVATTR_SHOW_FUNC(func) \
		static ssize_t func(struct device *dev, \
			struct device_attribute *attr, char *buf)

#	define DECLARE_DEVATTR_STORE_FUNC(func) \
	static ssize_t func(struct device *dev, \
		struct device_attribute *attr, const char *buf, size_t count)

#	define DECLARE_HOST_DEVICE_ATTR(xname, xmode, xshow, xstore) \
		DEVICE_ATTR(xname, xmode, xshow, xstore)

#	define DECLARE_HOST_ATTR_LIST(xlist) \
	static struct device_attribute *xlist[]
#else /* not KFEATURE_HAS_2011_03_STYLE_DEVICE_ATTR */

#	define DECLARE_DEVATTR_SHOW_FUNC(func) \
	static ssize_t func(struct class_device *dev, char *buf)

#	define DECLARE_DEVATTR_STORE_FUNC(func) \
	static ssize_t func(struct class_device *dev, \
		const char *buf, size_t count)

#	define DECLARE_HOST_DEVICE_ATTR(xname, xmode, xshow, xstore) \
	struct class_device_attribute dev_attr_##xname = {\
		.attr = { \
			.name = #xname, \
			.mode = xmode, \
		}, \
		.show = xshow, \
		.store = xstore, \
	};

#	define DECLARE_HOST_ATTR_LIST(xlist) \
	static struct class_device_attribute *xlist[]

#endif /* KFEATURE_HAS_2011_03_STYLE_DEVICE_ATTR */

#ifndef SCSI_QDEPTH_DEFAULT
#	define SCSI_QDEPTH_DEFAULT 0
#endif

#if !KFEATURE_HAS_SCSI_FOR_EACH_SG
#	define scsi_for_each_sg(cmd, sg, nseg, __i) \
	for (__i = 0, sg = scsi_sglist(cmd); __i < (nseg); __i++, (sg)++)
#endif

#if !KFEATURE_HAS_SHOST_PRIV
	static inline void *shost_priv(struct Scsi_Host *shost)
	{
		return (void *) shost->hostdata;
	}
#endif

#if !KFEATURE_HAS_SCSI_DMA_FUNCTIONS
	/* Does not have things like scsi_dma_map, scsi_dma_unmap, scsi_sg_count,
	 * sg_dma_address, sg_dma_len...
	 */

static void hpsa_map_sg_chain_block(struct ctlr_info *h,
	struct CommandList *c);

/* It is not reasonably possible to retrofit the new scsi dma interfaces
 * onto the old code.  So we retrofit at a higher level, at the dma mapping
 * function of the hpsa driver itself.
 *
 * hpsa_scatter_gather takes a struct scsi_cmnd, (cmd), and does the pci
 * dma mapping  and fills in the scatter gather entries of the
 * hpsa command, cp.
 */
static int hpsa_scatter_gather(struct ctlr_info *h,
		struct CommandList *cp,
		struct scsi_cmnd *cmd)
{
	unsigned int len;
	u64 addr64;
	int use_sg, i, sg_index, chained = 0;
	struct SGDescriptor *curr_sg;
	struct scatterlist *sg = (struct scatterlist *) cmd->request_buffer;

	if (!cmd->use_sg) {
		if (cmd->request_bufflen) { /* Just one scatter gather entry */
			addr64 = (__u64) pci_map_single(h->pdev,
				cmd->request_buffer, cmd->request_bufflen,
				cmd->sc_data_direction);

			cp->SG[0].Addr.lower =
				(__u32) (addr64 & (__u64) 0x0FFFFFFFF);
			cp->SG[0].Addr.upper =
				(__u32) ((addr64 >> 32) & (__u64) 0x0FFFFFFFF);
			cp->SG[0].Len = cmd->request_bufflen;
			use_sg = 1;
		} else /* Zero sg entries */
			use_sg = 0;
	} else {
		BUG_ON(cmd->use_sg > h->maxsgentries);

		/* Many sg entries */
		use_sg = pci_map_sg(h->pdev, cmd->request_buffer, cmd->use_sg,
				cmd->sc_data_direction);

		if (use_sg < 0)
			return use_sg;

		sg_index = 0;
		curr_sg = cp->SG;
		use_sg = cmd->use_sg;

		for (i = 0; i < use_sg; i++) {
			if (i == h->max_cmd_sg_entries - 1 &&
				use_sg > h->max_cmd_sg_entries) {
				chained = 1;
				curr_sg = h->cmd_sg_list[cp->cmdindex];
				sg_index = 0;
			}
			addr64 = (__u64) sg_dma_address(&sg[i]);
			len  = sg_dma_len(&sg[i]);
			curr_sg->Addr.lower =
				(u32) (addr64 & 0x0FFFFFFFFULL);
			curr_sg->Addr.upper =
				(u32) ((addr64 >> 32) & 0x0FFFFFFFFULL);
			curr_sg->Len = len;
			curr_sg->Ext = 0;  /* we are not chaining */
			curr_sg++;
		}
	}

	if (use_sg + chained > h->maxSG)
		h->maxSG = use_sg + chained;

	if (chained) {
		cp->Header.SGList = h->max_cmd_sg_entries;
		cp->Header.SGTotal = (u16) (use_sg + 1);
		hpsa_map_sg_chain_block(h, cp);
		return 0;
	}

	cp->Header.SGList = (u8) use_sg;   /* no. SGs contig in this cmd */
	cp->Header.SGTotal = (u16) use_sg; /* total sgs in this cmd list */
	return 0;
}

static void hpsa_unmap_sg_chain_block(struct ctlr_info *h,
	struct CommandList *c);
static void hpsa_scatter_gather_unmap(struct ctlr_info *h,
	struct CommandList *c, struct scsi_cmnd *cmd)
{
	union u64bit addr64;

	if (cmd->use_sg) {
		pci_unmap_sg(h->pdev, cmd->request_buffer, cmd->use_sg,
			cmd->sc_data_direction);
		if (c->Header.SGTotal > h->max_cmd_sg_entries)
			hpsa_unmap_sg_chain_block(h, c);
		return;
	}
	if (cmd->request_bufflen) {
		addr64.val32.lower = c->SG[0].Addr.lower;
		addr64.val32.upper = c->SG[0].Addr.upper;
		pci_unmap_single(h->pdev, (dma_addr_t) addr64.val,
		cmd->request_bufflen, cmd->sc_data_direction);
	}
}

static inline void scsi_dma_unmap(struct scsi_cmnd *cmd)
{
	struct CommandList *c = (struct CommandList *) cmd->host_scribble;

	hpsa_scatter_gather_unmap(c->h, c, cmd);
}

#endif

#if !KFEATURE_HAS_SCSI_DEVICE_TYPE
	/**
	 * scsi_device_type - Return 17 char string indicating device type.
	 * @type: type number to look up
	 */
	const char *scsi_device_type(unsigned type)
	{
		if (type == 0x1e)
			return "Well-known LUN   ";
		if (type == 0x1f)
			return "No Device        ";
		if (type >= ARRAY_SIZE(scsi_device_types))
			return "Unknown          ";
		return scsi_device_types[type];
	}
#endif

#if KFEATURE_SCAN_START_IMPLEMENTED
	/* .scan_start is present in scsi host template AND implemented.
	 * Used to bail out of queuecommand if no scan_start and REPORT_LUNS
	 * encountered
	 */
	static inline int bail_on_report_luns_if_no_scan_start(
		__attribute__((unused)) struct scsi_cmnd *cmd,
		__attribute__((unused)) void (*done)(struct scsi_cmnd *))
	{
		return 0;
	}

	/* RHEL6, kernel.org have functioning ->scan_start() method in kernel
	 * so this is no-op.
	 */
	static inline void hpsa_initial_update_scsi_devices(
		__attribute__((unused)) struct ctlr_info *h)
	{
		return;
	}
#else /* not KFEATURE_SCAN_START_IMPLEMENTED */
	static inline int bail_on_report_luns_if_no_scan_start(
		struct scsi_cmnd *cmd, void (*done)(struct scsi_cmnd *))
	{
		/*
		 * This thing bails out of our queue command early on SCSI
		 * REPORT_LUNS This is needed when the kernel doesn't really
		 * support the scan_start method of the scsi host template.
		 *
		 * Since we do our own mapping in our driver, and we handle
		 * adding/removing of our own devices.
		 *
		 * We want to prevent the mid-layer from doing it's own
		 * adding/removing of drives which is what it would do
		 * if we allow REPORT_LUNS to be processed.
		 *
		 * On RHEL5, scsi mid-layer never calls scan_start and
		 * scan_finished even though they exist in scsi_host_template.
		 *
		 * On RHEL6 we use scan_start and scan_finished to tell
		 * mid-layer that we do our own device adding/removing
		 * therefore we can handle REPORT_LUNS.
		 */

		if (cmd->cmnd[0] == REPORT_LUNS) {
			cmd->result = (DID_OK << 16);           /* host byte */
			cmd->result |= (COMMAND_COMPLETE << 8); /* msg byte */
			cmd->result |= SAM_STAT_CHECK_CONDITION;
			memset(cmd->sense_buffer, 0, sizeof(cmd->sense_buffer));
			cmd->sense_buffer[2] = ILLEGAL_REQUEST;
			done(cmd);
			return 1;
		}
		return 0;
	}

	/* Need this if no functioning ->scan_start() method in kernel. */
	static void hpsa_update_scsi_devices(struct ctlr_info *h, int hostno);
	static inline void hpsa_initial_update_scsi_devices(
				struct ctlr_info *h)
	{
		hpsa_update_scsi_devices(h, -1);
	}
#endif /* KFEATURE_SCAN_START_IMPLEMENTED */

#if KFEATURE_SCAN_START_PRESENT
	/* .scan_start is present in scsi host template */
	#define INITIALIZE_SCAN_START(funcptr) .scan_start = funcptr,
	#define INITIALIZE_SCAN_FINISHED(funcptr) .scan_finished = funcptr,
#else /* .scan start is not even present in scsi host template */
	#define INITIALIZE_SCAN_START(funcptr)
	#define INITIALIZE_SCAN_FINISHED(funcptr)
#endif

#if KFEATURE_HAS_2011_03_QUEUECOMMAND
#	define DECLARE_QUEUECOMMAND(func) \
		static int func##_lck(struct scsi_cmnd *cmd, \
			void (*done)(struct scsi_cmnd *))
#	define DECLARE_QUEUECOMMAND_WRAPPER(func) static DEF_SCSI_QCMD(func)
#else
#	define DECLARE_QUEUECOMMAND(func) \
	static int func(struct scsi_cmnd *cmd, void (*done)(struct scsi_cmnd *))
#	define DECLARE_QUEUECOMMAND_WRAPPER(func)
#endif

#if !KFEATURE_HAS_SCSI_SET_RESID
	static inline void scsi_set_resid(struct scsi_cmnd *cmd, int resid)
	{
		cmd->resid = resid;
	}
#endif

#ifndef DMA_BIT_MASK
#define DMA_BIT_MASK(n) (((n) == 64) ? ~0ULL : ((1ULL<<(n))-1))
#endif

/* Define old style irq flags SA_* if the IRQF_* ones are missing. */
#ifndef IRQF_DISABLED
#define IRQF_DISABLED (SA_INTERRUPT | SA_SAMPLE_RANDOM)
#endif

#if KFEATURE_HAS_UACCESS_H_FILE
#include <linux/uaccess.h>
#endif

#if KFEATURE_HAS_SMP_LOCK_H
#include <linux/smp_lock.h>
#endif

/*
 * Support for packaged storage solutions.
 * Enabled by default for kernel.org 
 * Enable above as required for distros.
 */
#if HPSA_SUPPORTS_STORAGEWORKS_1210m
#define HPSA_STORAGEWORKS_1210m_PCI_IDS \
	{PCI_VENDOR_ID_HP, PCI_DEVICE_ID_HP_CISSE, 0x103C, 0x3233}, \
	{PCI_VENDOR_ID_HP, PCI_DEVICE_ID_HP_CISSF, 0x103C, 0x333F},	\
	{PCI_VENDOR_ID_3PAR,	PCI_DEVICE_ID_3PAR,	0x1590, 0x0076},\
	{PCI_VENDOR_ID_3PAR,	PCI_DEVICE_ID_3PAR,	0x1590, 0x007d},\
	{PCI_VENDOR_ID_3PAR,	PCI_DEVICE_ID_3PAR,	0x1590, 0x0077},\
	{PCI_VENDOR_ID_3PAR,	PCI_DEVICE_ID_3PAR,	0x1590, 0x0087},\
	{PCI_VENDOR_ID_3PAR,	PCI_DEVICE_ID_3PAR,	0x1590, 0x0088},\
	{PCI_VENDOR_ID_3PAR,	PCI_DEVICE_ID_3PAR,	0x1590, 0x0089},

#define HPSA_STORAGEWORKS_1210m_PRODUCT_ENTRIES \
	{0x3233103C, "HP StorageWorks 1210m", &SA5_access}, \
	{0x333F103C, "HP StorageWorks 1210m", &SA5_access}, \
   {0x00761590, "HP Storage P1224 Array Controller", &SA5_access}, \
   {0x007d1590, "HP Storage P1228 Array Controller", &SA5_access}, \
   {0x00771590, "HP Storage P1228m Array Controller", &SA5_access}, \
   {0x00871590, "HP Storage P1224e Array Controller", &SA5_access}, \
   {0x00881590, "HP Storage P1228e Array Controller", &SA5_access}, \
   {0x00891590, "HP Storage P1228em Array Controller", &SA5_access},
   

#else
#define HPSA_STORAGEWORKS_1210m_PCI_IDS	
#define HPSA_STORAGEWORKS_1210m_PRODUCT_ENTRIES
#endif

/* sles10sp4 apparently doesn't have DIV_ROUND_UP.  Normally it comes
 * from include/linux/kernel.h.  Other sles10's have it I think.
 */
#if !defined(DIV_ROUND_UP)
#define DIV_ROUND_UP(n,d) (((n) + (d) - 1) / (d))
#endif

/* Newer dma_mapping_error function takes 2 args, older version only takes 1 arg.
 * This macro makes the code do the right thing depending on which variant we have.
 */
#if KFEATURE_HAS_NEW_DMA_MAPPING_ERROR
#define hpsa_dma_mapping_error(x, y) dma_mapping_error(x, y)
#else
#define hpsa_dma_mapping_error(x, y) dma_mapping_error(y)
#endif


