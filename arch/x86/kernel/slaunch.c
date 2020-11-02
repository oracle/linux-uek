// SPDX-License-Identifier: GPL-2.0
/*
 * Secure Launch late validation/setup, securityfs exposure and
 * finalization support.
 *
 * Copyright (c) 2020, Oracle and/or its affiliates.
 * Copyright (c) 2020 Apertus Solutions, LLC
 *
 * Author(s):
 *     Daniel P. Smith <dpsmith@apertussolutions.com>
 *     Garnet T. Grimm <grimmg@ainfosec.com>
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/fs.h>
#include <linux/init.h>
#include <linux/linkage.h>
#include <linux/mm.h>
#include <linux/io.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/security.h>
#include <linux/memblock.h>
#include <asm/segment.h>
#include <asm/sections.h>
#include <asm/boot.h>
#include <asm/msr.h>
#include <asm/tlbflush.h>
#include <asm/processor-flags.h>
#include <asm/asm-offsets.h>
#include <asm/e820/api.h>
#include <asm/bootparam.h>
#include <asm/setup.h>
#include <linux/slaunch.h>

static u32 sl_flags;
static struct sl_ap_wake_info ap_wake_info;
static u64 evtlog_addr;
static u32 evtlog_size;
static u64 vtd_pmr_lo_size;

/* This should be plenty of room */
static u8 txt_dmar[PAGE_SIZE] __aligned(16);

u32 slaunch_get_flags(void)
{
	return sl_flags;
}
EXPORT_SYMBOL(slaunch_get_flags);

struct sl_ap_wake_info *slaunch_get_ap_wake_info(void)
{
	return &ap_wake_info;
}

struct acpi_table_header *slaunch_get_dmar_table(struct acpi_table_header *dmar)
{
	/* The DMAR is only stashed and provided via TXT on Intel systems */
	if (memcmp(txt_dmar, "DMAR", 4))
		return dmar;

	return (struct acpi_table_header *)(&txt_dmar[0]);
}

static void __init __noreturn slaunch_txt_reset(void __iomem *txt,
						const char *msg, u64 error)
{
	u64 one = 1, val;

	pr_err("%s", msg);

	/*
	 * This performs a TXT reset with a sticky error code. The reads of
	 * TXT_CR_E2STS act as barriers.
	 */
	memcpy_toio(txt + TXT_CR_ERRORCODE, &error, sizeof(u64));
	memcpy_fromio(&val, txt + TXT_CR_E2STS, sizeof(u64));
	memcpy_toio(txt + TXT_CR_CMD_NO_SECRETS, &one, sizeof(u64));
	memcpy_fromio(&val, txt + TXT_CR_E2STS, sizeof(u64));
	memcpy_toio(txt + TXT_CR_CMD_UNLOCK_MEM_CONFIG, &one, sizeof(u64));
	memcpy_fromio(&val, txt + TXT_CR_E2STS, sizeof(u64));
	memcpy_toio(txt + TXT_CR_CMD_RESET, &one, sizeof(u64));

	for ( ; ; )
		asm volatile ("hlt");

	unreachable();
}

/*
 * The TXT heap is too big to map all at once with early_ioremap
 * so it is done a table at a time.
 */
static void __init *txt_early_get_heap_table(void __iomem *txt, u32 type,
					     u32 bytes)
{
	void *heap;
	u64 base, size, offset = 0;
	int i;

	if (type > TXT_SINIT_MLE_DATA_TABLE)
		slaunch_txt_reset(txt,
			"Error invalid table type for early heap walk\n",
			SL_ERROR_HEAP_WALK);

	memcpy_fromio(&base, txt + TXT_CR_HEAP_BASE, sizeof(u64));
	memcpy_fromio(&size, txt + TXT_CR_HEAP_SIZE, sizeof(u64));

	/* Iterate over heap tables looking for table of "type" */
	for (i = 0; i < type; i++) {
		base += offset;
		heap = early_memremap(base, sizeof(u64));
		if (!heap)
			slaunch_txt_reset(txt,
				"Error early_memremap of heap for heap walk\n",
				SL_ERROR_HEAP_WALK);

		offset = *((u64 *)heap);

		/*
		 * After the first iteration, any offset of zero is invalid and
		 * implies the TXT heap is corrupted.
		 */
		if (!offset)
			slaunch_txt_reset(txt,
				"Error invalid 0 offset in heap walk\n",
				SL_ERROR_HEAP_ZERO_OFFSET);

		early_memunmap(heap, sizeof(u64));
	}

	/* Skip the size field at the head of each table */
	base += sizeof(u64);
	heap = early_memremap(base, bytes);
	if (!heap)
		slaunch_txt_reset(txt,
				  "Error early_memremap of heap section\n",
				  SL_ERROR_HEAP_MAP);

	return heap;
}

/*
 * TXT uses a special set of VTd registers to protect all of memory from DMA
 * until the IOMMU can be programmed to protect memory. There is the low
 * memory PMR that can protect all memory up to 4G. The high memory PRM can
 * be setup to protect all memory beyond 4Gb. Validate that these values cover
 * what is expected.
 */
static void __init slaunch_verify_pmrs(void __iomem *txt)
{
	struct txt_os_sinit_data *os_sinit_data;
	unsigned long last_pfn, initrd_extent;
	u32 field_offset, err = 0;
	const char *errmsg = "";

	field_offset = offsetof(struct txt_os_sinit_data, lcp_po_base);
	os_sinit_data = txt_early_get_heap_table(txt, TXT_OS_SINIT_DATA_TABLE,
						 field_offset);

	/* Save a copy */
	vtd_pmr_lo_size = os_sinit_data->vtd_pmr_lo_size;

	last_pfn = e820__end_of_ram_pfn();

	/*
	 * First make sure the hi PMR covers all memory above 4G. In the
	 * unlikely case where there is < 4G on the system, the hi PMR will
	 * not be set.
	 */
	if (os_sinit_data->vtd_pmr_hi_base != 0x0ULL) {
		if (os_sinit_data->vtd_pmr_hi_base != 0x100000000ULL) {
			err = SL_ERROR_HI_PMR_BASE;
			errmsg =  "Error hi PMR base\n";
			goto out;
		}

		if (last_pfn << PAGE_SHIFT >
		    os_sinit_data->vtd_pmr_hi_base +
		    os_sinit_data->vtd_pmr_hi_size) {
			err = SL_ERROR_HI_PMR_SIZE;
			errmsg = "Error hi PMR size\n";
			goto out;
		}
	}

	/* Lo PMR base should always be 0 */
	if (os_sinit_data->vtd_pmr_lo_base != 0x0ULL) {
		err = SL_ERROR_LO_PMR_BASE;
		errmsg = "Error lo PMR base\n";
		goto out;
	}

	/*
	 * Check that if the kernel was loaded below 4G, that it is protected
	 * by the lo PMR. Note this is the decompressed kernel. The ACM would
	 * have ensured the compressed kernel (the MLE image) was protected.
	 */
	if ((__pa_symbol(_end) < 0x100000000ULL) &&
	    (__pa_symbol(_end) > os_sinit_data->vtd_pmr_lo_size)) {
		err = SL_ERROR_LO_PMR_MLE;
		errmsg = "Error lo PMR does not cover MLE kernel\n";
		goto out;
	}

	/* Check that the AP wake block is protected by the lo PMR. */
	if (ap_wake_info.ap_wake_block + PAGE_SIZE >
	    os_sinit_data->vtd_pmr_lo_size) {
		err = SL_ERROR_LO_PMR_MLE;
		errmsg = "Error lo PMR does not cover AP wake block\n";
	}

	/*
	 * If an external initrd is present and loaded below 4G, check
	 * that it is protected by the lo PMR.
	 */
	if (boot_params.hdr.ramdisk_image != 0 &&
	    boot_params.hdr.ramdisk_size != 0) {
		initrd_extent = boot_params.hdr.ramdisk_image +
				boot_params.hdr.ramdisk_size;
		if ((initrd_extent < 0x100000000ULL) &&
		    (initrd_extent > os_sinit_data->vtd_pmr_lo_size)) {
			err = SL_ERROR_LO_PMR_INITRD;
			errmsg = "Error lo PMR does not cover external initrd\n";
			goto out;
		}
	}

out:
	early_memunmap(os_sinit_data, field_offset);

	if (err)
		slaunch_txt_reset(txt, errmsg, err);
}

static void __init slaunch_txt_reserve_range(u64 base, u64 size)
{
	int type;

	type = e820__get_entry_type(base, base + size - 1);
	if (type == E820_TYPE_RAM) {
		pr_info("memblock reserve base: %llx size: %llx\n", base, size);
		memblock_reserve(base, size);
	}
}

/*
 * For Intel, certain regions of memory must be marked as reserved by putting
 * them on the memblock reserved list if they are not already e820 reserved.
 * This includes:
 *  - The TXT HEAP
 *  - The ACM area
 *  - The TXT private register bank
 *  - The MDR list sent to the MLE by the ACM (see TXT specification)
 *  (Normally the above are properly reserved by firmware but if it was not
 *  done, reserve them now)
 *  - The AP wake block
 *  - TPM log external to the TXT heap
 *
 * Also if the low PMR doesn't cover all memory < 4G, any RAM regions above
 * the low PMR must be reservered too.
 */
static void __init slaunch_txt_reserve(void __iomem *txt)
{
	struct txt_sinit_memory_descriptor_record *mdr;
	struct txt_sinit_mle_data *sinit_mle_data;
	void *mdrs;
	u64 base, size, heap_base, heap_size;
	u32 field_offset, mdrnum, mdroffset, mdrslen, i;

	base = TXT_PRIV_CONFIG_REGS_BASE;
	size = TXT_PUB_CONFIG_REGS_BASE - TXT_PRIV_CONFIG_REGS_BASE;
	slaunch_txt_reserve_range(base, size);

	memcpy_fromio(&heap_base, txt + TXT_CR_HEAP_BASE, sizeof(u64));
	memcpy_fromio(&heap_size, txt + TXT_CR_HEAP_SIZE, sizeof(u64));
	slaunch_txt_reserve_range(heap_base, heap_size);

	memcpy_fromio(&base, txt + TXT_CR_SINIT_BASE, sizeof(u64));
	memcpy_fromio(&size, txt + TXT_CR_SINIT_SIZE, sizeof(u64));
	slaunch_txt_reserve_range(base, size);

	field_offset = offsetof(struct txt_sinit_mle_data,
				sinit_vtd_dmar_table_size);
	sinit_mle_data = txt_early_get_heap_table(txt, TXT_SINIT_MLE_DATA_TABLE,
					field_offset);

	mdrnum = sinit_mle_data->num_of_sinit_mdrs;
	mdroffset = sinit_mle_data->sinit_mdrs_table_offset;

	early_memunmap(sinit_mle_data, field_offset);

	if (!mdrnum)
		goto nomdr;

	mdrslen = (mdrnum * sizeof(struct txt_sinit_memory_descriptor_record));

	mdrs = txt_early_get_heap_table(txt, TXT_SINIT_MLE_DATA_TABLE,
					mdroffset + mdrslen - 8);

	mdr = (struct txt_sinit_memory_descriptor_record *)
			(mdrs + mdroffset - 8);

	for (i = 0; i < mdrnum; i++, mdr++) {
		/* Spec says some entries can have length 0, ignore them */
		if (mdr->type > 0 && mdr->length > 0)
			slaunch_txt_reserve_range(mdr->address, mdr->length);
	}

	early_memunmap(mdrs, mdroffset + mdrslen - 8);

nomdr:
	slaunch_txt_reserve_range(ap_wake_info.ap_wake_block,
				  ap_wake_info.ap_wake_block_size);

	if (evtlog_addr < heap_base || evtlog_addr > (heap_base + heap_size))
		slaunch_txt_reserve_range(evtlog_addr, evtlog_size);

	for (i = 0; i < e820_table->nr_entries; i++) {
		base = e820_table->entries[i].addr;
		size = e820_table->entries[i].size;
		if ((base > vtd_pmr_lo_size) && (base < 0x100000000ULL))
			slaunch_txt_reserve_range(base, size);
	}
}

/*
 * TXT stashes a safe copy of the DMAR ACPI table to prevent tampering.
 * It is stored in the TXT heap. Fetch it from there and make it available
 * to the IOMMU driver.
 */
static void __init slaunch_copy_dmar_table(void __iomem *txt)
{
	struct txt_sinit_mle_data *sinit_mle_data;
	void *dmar;
	u32 field_offset, dmar_size, dmar_offset;

	memset(&txt_dmar, 0, PAGE_SIZE);

	field_offset = offsetof(struct txt_sinit_mle_data,
				processor_scrtm_status);
	sinit_mle_data = txt_early_get_heap_table(txt, TXT_SINIT_MLE_DATA_TABLE,
						  field_offset);

	dmar_size = sinit_mle_data->sinit_vtd_dmar_table_size;
	dmar_offset = sinit_mle_data->sinit_vtd_dmar_table_offset;

	early_memunmap(sinit_mle_data, field_offset);

	if (!dmar_size || !dmar_offset)
		slaunch_txt_reset(txt,
				  "Error invalid DMAR table values\n",
				  SL_ERROR_HEAP_INVALID_DMAR);

	if (unlikely(dmar_size > PAGE_SIZE))
		slaunch_txt_reset(txt,
				  "Error DMAR too big to store\n",
				  SL_ERROR_HEAP_DMAR_SIZE);


	dmar = txt_early_get_heap_table(txt, TXT_SINIT_MLE_DATA_TABLE,
					dmar_offset + dmar_size - 8);
	if (!dmar)
		slaunch_txt_reset(txt,
				  "Error early_ioremap of DMAR\n",
				  SL_ERROR_HEAP_DMAR_MAP);

	memcpy(&txt_dmar[0], dmar + dmar_offset - 8, dmar_size);

	early_memunmap(dmar, dmar_offset + dmar_size - 8);
}

/*
 * The location of the safe AP wake code block is stored in the TXT heap.
 * Fetch it here in the early init code for later use in SMP startup.
 *
 * Also get the TPM event log values that may have to be put on the
 * memblock reserve list later.
 */
static void __init slaunch_fetch_os_mle_fields(void __iomem *txt)
{
	struct txt_os_mle_data *os_mle_data;
	u8 *jmp_offset;

	os_mle_data = txt_early_get_heap_table(txt, TXT_OS_MLE_DATA_TABLE,
					       sizeof(struct txt_os_mle_data));

	ap_wake_info.ap_wake_block = os_mle_data->ap_wake_block;
	ap_wake_info.ap_wake_block_size = os_mle_data->ap_wake_block_size;

	jmp_offset = os_mle_data->mle_scratch + SL_SCRATCH_AP_JMP_OFFSET;
	ap_wake_info.ap_jmp_offset = *((u32 *)jmp_offset);

	evtlog_addr = os_mle_data->evtlog_addr;
	evtlog_size = os_mle_data->evtlog_size;

	early_memunmap(os_mle_data, sizeof(struct txt_os_mle_data));
}

/*
 * Intel specific late stub setup and validation.
 */
static void __init slaunch_setup_intel(void)
{
	void __iomem *txt;
	u64 val = 0x1ULL;

	/*
	 * First see if SENTER was done and not by TBOOT by reading the status
	 * register in the public space.
	 */
	txt = early_ioremap(TXT_PUB_CONFIG_REGS_BASE,
			    TXT_NR_CONFIG_PAGES * PAGE_SIZE);
	if (!txt) {
		/* This is really bad, no where to go from here */
		panic("Error early_ioremap of TXT pub registers\n");
	}

	memcpy_fromio(&val, txt + TXT_CR_STS, sizeof(u64));
	early_iounmap(txt, TXT_NR_CONFIG_PAGES * PAGE_SIZE);

	/* Was SENTER done? */
	if (!(val & TXT_SENTER_DONE_STS))
		return;

	/* Was it done by TBOOT? */
	if (boot_params.tboot_addr)
		return;

	/* Now we want to use the private register space */
	txt = early_ioremap(TXT_PRIV_CONFIG_REGS_BASE,
			    TXT_NR_CONFIG_PAGES * PAGE_SIZE);
	if (!txt) {
		/* This is really bad, no where to go from here */
		panic("Error early_ioremap of TXT priv registers\n");
	}

	/*
	 * Try to read the Intel VID from the TXT private registers to see if
	 * TXT measured launch happened properly and the private space is
	 * available.
	 */
	memcpy_fromio(&val, txt + TXT_CR_DIDVID, sizeof(u64));
	if ((u16)(val & 0xffff) != 0x8086) {
		/*
		 * Can't do a proper TXT reset since it appears something is
		 * wrong even though SENTER happened and it should be in SMX
		 * mode.
		 */
		panic("Invalid TXT vendor ID, not in SMX mode\n");
	}

	/* Set flags so subsequent code knows the status of the launch */
	sl_flags |= (SL_FLAG_ACTIVE|SL_FLAG_ARCH_TXT);

	/*
	 * Reading the proper DIDVID from the private register space means we
	 * are in SMX mode and private registers are open for read/write.
	 */

	/* On Intel, have to handle TPM localities via TXT */
	val = 0x1ULL;
	memcpy_toio(txt + TXT_CR_CMD_SECRETS, &val, sizeof(u64));
	memcpy_fromio(&val, txt + TXT_CR_E2STS, sizeof(u64));
	val = 0x1ULL;
	memcpy_toio(txt + TXT_CR_CMD_OPEN_LOCALITY1, &val, sizeof(u64));
	memcpy_fromio(&val, txt + TXT_CR_E2STS, sizeof(u64));

	slaunch_fetch_os_mle_fields(txt);

	slaunch_verify_pmrs(txt);

	slaunch_txt_reserve(txt);

	slaunch_copy_dmar_table(txt);

	early_iounmap(txt, TXT_NR_CONFIG_PAGES * PAGE_SIZE);

	pr_info("Intel TXT setup complete\n");
}

void __init slaunch_setup(void)
{
	u32 vendor[4];

	/* Get manufacturer string with CPUID 0 */
	cpuid(0, &vendor[0], &vendor[1], &vendor[2], &vendor[3]);

	/* Only Intel TXT is supported at this point */
	if (vendor[1] == INTEL_CPUID_MFGID_EBX &&
	    vendor[2] == INTEL_CPUID_MFGID_ECX &&
	    vendor[3] == INTEL_CPUID_MFGID_EDX)
		slaunch_setup_intel();
}

#define SL_FS_ENTRIES		10
/* root directory node must be last */
#define SL_ROOT_DIR_ENTRY	(SL_FS_ENTRIES - 1)
#define SL_TXT_DIR_ENTRY	(SL_FS_ENTRIES - 2)
#define SL_TXT_FILE_FIRST	(SL_TXT_DIR_ENTRY - 1)
#define SL_TXT_ENTRY_COUNT	7

#define DECLARE_TXT_PUB_READ_U(size, fmt, msg_size)			\
static ssize_t txt_pub_read_u##size(unsigned int offset,		\
		loff_t *read_offset,					\
		size_t read_len,					\
		char __user *buf)					\
{									\
	void __iomem *txt;						\
	char msg_buffer[msg_size];					\
	u##size reg_value = 0;						\
	txt = ioremap(TXT_PUB_CONFIG_REGS_BASE,				\
			TXT_NR_CONFIG_PAGES * PAGE_SIZE);		\
	if (IS_ERR(txt))						\
		return PTR_ERR(txt);					\
	memcpy_fromio(&reg_value, txt + offset, sizeof(u##size));	\
	iounmap(txt);							\
	snprintf(msg_buffer, msg_size, fmt, reg_value);			\
	return simple_read_from_buffer(buf, read_len, read_offset,	\
			&msg_buffer, msg_size);				\
}

DECLARE_TXT_PUB_READ_U(8, "%#04x\n", 6);
DECLARE_TXT_PUB_READ_U(32, "%#010x\n", 12);
DECLARE_TXT_PUB_READ_U(64, "%#018llx\n", 20);

#define DECLARE_TXT_FOPS(reg_name, reg_offset, reg_size)		\
static ssize_t txt_##reg_name##_read(struct file *flip,			\
		char __user *buf, size_t read_len, loff_t *read_offset)	\
{									\
	return txt_pub_read_u##reg_size(reg_offset, read_offset,	\
			read_len, buf);					\
}									\
static const struct file_operations reg_name##_ops = {			\
	.read = txt_##reg_name##_read,					\
}

DECLARE_TXT_FOPS(sts, TXT_CR_STS, 64);
DECLARE_TXT_FOPS(ests, TXT_CR_ESTS, 8);
DECLARE_TXT_FOPS(errorcode, TXT_CR_ERRORCODE, 32);
DECLARE_TXT_FOPS(didvid, TXT_CR_DIDVID, 64);
DECLARE_TXT_FOPS(e2sts, TXT_CR_E2STS, 64);
DECLARE_TXT_FOPS(ver_emif, TXT_CR_VER_EMIF, 32);
DECLARE_TXT_FOPS(scratchpad, TXT_CR_SCRATCHPAD, 64);

/*
 * Securityfs exposure
 */
struct memfile {
	char *name;
	void *addr;
	size_t size;
};

static struct memfile sl_evtlog = {"eventlog", 0, 0};
static void *txt_heap;
static struct txt_heap_event_log_pointer2_1_element __iomem *evtlog20;
static DEFINE_MUTEX(sl_evt_log_mutex);

static ssize_t sl_evtlog_read(struct file *file, char __user *buf,
			      size_t count, loff_t *pos)
{
	ssize_t size;

	if (!sl_evtlog.addr)
		return 0;

	mutex_lock(&sl_evt_log_mutex);
	size = simple_read_from_buffer(buf, count, pos, sl_evtlog.addr,
				       sl_evtlog.size);
	mutex_unlock(&sl_evt_log_mutex);

	return size;
}

static ssize_t sl_evtlog_write(struct file *file, const char __user *buf,
				size_t datalen, loff_t *ppos)
{
	char *data;
	ssize_t result;

	if (!sl_evtlog.addr)
		return 0;

	/* No partial writes. */
	result = -EINVAL;
	if (*ppos != 0)
		goto out;

	data = memdup_user(buf, datalen);
	if (IS_ERR(data)) {
		result = PTR_ERR(data);
		goto out;
	}

	mutex_lock(&sl_evt_log_mutex);
	if (evtlog20)
		result = tpm20_log_event(evtlog20, sl_evtlog.addr,
					 datalen, data);
	else
		result = tpm12_log_event(sl_evtlog.addr, datalen, data);
	mutex_unlock(&sl_evt_log_mutex);

	kfree(data);
out:
	return result;
}

static const struct file_operations sl_evtlog_ops = {
	.read = sl_evtlog_read,
	.write = sl_evtlog_write,
	.llseek	= default_llseek,
};

static struct dentry *fs_entries[SL_FS_ENTRIES];

struct sfs_file {
	int parent;
	const char *name;
	const struct file_operations *fops;
};

static const struct sfs_file sl_files[] = {
	{ SL_TXT_DIR_ENTRY, "sts", &sts_ops },
	{ SL_TXT_DIR_ENTRY, "ests", &ests_ops },
	{ SL_TXT_DIR_ENTRY, "errorcode", &errorcode_ops },
	{ SL_TXT_DIR_ENTRY, "didvid", &didvid_ops },
	{ SL_TXT_DIR_ENTRY, "ver_emif", &ver_emif_ops },
	{ SL_TXT_DIR_ENTRY, "scratchpad", &scratchpad_ops },
	{ SL_TXT_DIR_ENTRY, "e2sts", &e2sts_ops }
};

static int sl_create_file(int entry, int parent, const char *name,
		const struct file_operations *ops)
{
	if (entry < 0 || entry > SL_TXT_DIR_ENTRY)
		return -EINVAL;
	fs_entries[entry] = securityfs_create_file(name, 0440,
			fs_entries[parent], NULL, ops);
	if (IS_ERR(fs_entries[entry])) {
		pr_err("Error creating securityfs %s file\n", name);
		return PTR_ERR(fs_entries[entry]);
	}
	return 0;
}

static long slaunch_expose_securityfs(void)
{
	long ret = 0;
	int i = 0;

	fs_entries[SL_ROOT_DIR_ENTRY] = securityfs_create_dir("slaunch", NULL);
	if (IS_ERR(fs_entries[SL_ROOT_DIR_ENTRY])) {
		pr_err("Error creating securityfs slaunch root directory\n");
		ret = PTR_ERR(fs_entries[SL_ROOT_DIR_ENTRY]);
		goto err;
	}

	if (sl_flags & SL_FLAG_ARCH_TXT) {
		fs_entries[SL_TXT_DIR_ENTRY] = securityfs_create_dir("txt",
				fs_entries[SL_ROOT_DIR_ENTRY]);
		if (IS_ERR(fs_entries[SL_TXT_DIR_ENTRY])) {
			pr_err("Error creating securityfs txt directory\n");
			ret = PTR_ERR(fs_entries[SL_TXT_DIR_ENTRY]);
			goto err_dir;
		}

		for (i = 0; i < SL_TXT_ENTRY_COUNT; i++) {
			ret = sl_create_file(SL_TXT_FILE_FIRST - i,
					sl_files[i].parent, sl_files[i].name,
					sl_files[i].fops);
			if (ret)
				goto err_dir;
		}
	}

	if (sl_evtlog.addr > 0) {
		ret = sl_create_file(0, SL_ROOT_DIR_ENTRY, sl_evtlog.name,
				&sl_evtlog_ops);
		if (ret)
			goto err_dir;
	}

	return 0;

err_dir:
	for (i = 0; i <= SL_ROOT_DIR_ENTRY; i++)
		securityfs_remove(fs_entries[i]);
err:
	return ret;
}

static void slaunch_teardown_securityfs(void)
{
	int i;

	for (i = 0; i < SL_FS_ENTRIES; i++)
		securityfs_remove(fs_entries[i]);

	if (sl_flags & SL_FLAG_ARCH_TXT) {
		if (sl_evtlog.addr) {
			memunmap(sl_evtlog.addr);
			sl_evtlog.addr = NULL;
		}
		sl_evtlog.size = 0;
		if (txt_heap) {
			memunmap(txt_heap);
			txt_heap = NULL;
		}
	}
}

static void slaunch_intel_evtlog(void)
{
	void __iomem *config;
	struct txt_os_mle_data *params;
	void *os_sinit_data;
	u64 base, size;

	config = ioremap(TXT_PUB_CONFIG_REGS_BASE, TXT_NR_CONFIG_PAGES *
			 PAGE_SIZE);
	if (!config) {
		pr_err("Error failed to ioremap TXT reqs\n");
		return;
	}

	memcpy_fromio(&base, config + TXT_CR_HEAP_BASE, sizeof(u64));
	memcpy_fromio(&size, config + TXT_CR_HEAP_SIZE, sizeof(u64));
	iounmap(config);

	/* now map TXT heap */
	txt_heap = memremap(base, size, MEMREMAP_WB);
	if (!txt_heap) {
		pr_err("Error failed to memremap TXT heap\n");
		return;
	}

	params = (struct txt_os_mle_data *)txt_os_mle_data_start(txt_heap);

	sl_evtlog.size = params->evtlog_size;
	sl_evtlog.addr = memremap(params->evtlog_addr, params->evtlog_size,
				  MEMREMAP_WB);
	if (!sl_evtlog.addr) {
		pr_err("Error failed to memremap TPM event log\n");
		return;
	}

	/* Determine if this is TPM 1.2 or 2.0 event log */
	if (memcmp(sl_evtlog.addr + sizeof(struct tpm12_pcr_event),
		    TPM20_EVTLOG_SIGNATURE, sizeof(TPM20_EVTLOG_SIGNATURE)))
		return; /* looks like it is not 2.0 */

	/* For TPM 2.0 logs, the extended heap element must be located */
	os_sinit_data = txt_os_sinit_data_start(txt_heap);

	evtlog20 = tpm20_find_log2_1_element(os_sinit_data);

	/*
	 * If this fails, things are in really bad shape. Any attempt to write
	 * events to the log will fail.
	 */
	if (!evtlog20)
		pr_err("Error failed to find TPM20 event log element\n");
}

static int __init slaunch_late_init(void)
{
	/* Check to see if Secure Launch happened */
	if (!(sl_flags & (SL_FLAG_ACTIVE|SL_FLAG_ARCH_TXT)))
		return 0;

	/* Only Intel TXT is supported at this point */
	slaunch_intel_evtlog();

	return slaunch_expose_securityfs();
}

static void __exit slaunch_exit(void)
{
	slaunch_teardown_securityfs();
}

late_initcall(slaunch_late_init);

__exitcall(slaunch_exit);

static inline void smx_getsec_sexit(void)
{
	asm volatile (".byte 0x0f,0x37\n"
		      : : "a" (SMX_X86_GETSEC_SEXIT));
}

void slaunch_finalize(int do_sexit)
{
	void __iomem *config;
	u64 one = 1, val;

	if (!(slaunch_get_flags() & (SL_FLAG_ACTIVE|SL_FLAG_ARCH_TXT)))
		return;

	config = ioremap(TXT_PRIV_CONFIG_REGS_BASE, TXT_NR_CONFIG_PAGES *
			 PAGE_SIZE);
	if (!config) {
		pr_emerg("Error SEXIT failed to ioremap TXT private reqs\n");
		return;
	}

	/* Clear secrets bit for SEXIT */
	memcpy_toio(config + TXT_CR_CMD_NO_SECRETS, &one, sizeof(u64));
	memcpy_fromio(&val, config + TXT_CR_E2STS, sizeof(u64));

	/* Unlock memory configurations */
	memcpy_toio(config + TXT_CR_CMD_UNLOCK_MEM_CONFIG, &one, sizeof(u64));
	memcpy_fromio(&val, config + TXT_CR_E2STS, sizeof(u64));

	/* Close the TXT private register space */
	memcpy_fromio(&val, config + TXT_CR_E2STS, sizeof(u64));
	memcpy_toio(config + TXT_CR_CMD_CLOSE_PRIVATE, &one, sizeof(u64));

	/*
	 * Calls to iounmap are not being done because of the state of the
	 * system this late in the kexec process. Local IRQs are disabled and
	 * iounmap causes a TLB flush which in turn causes a warning. Leaving
	 * thse mappings is not an issue since the next kernel is going to
	 * completely re-setup memory management.
	 */

	/* Map public registers and do a final read fence */
	config = ioremap(TXT_PUB_CONFIG_REGS_BASE, TXT_NR_CONFIG_PAGES *
			 PAGE_SIZE);
	if (!config) {
		pr_emerg("Error SEXIT failed to ioremap TXT public reqs\n");
		return;
	}

	memcpy_fromio(&val, config + TXT_CR_E2STS, sizeof(u64));

	pr_emerg("TXT clear secrets bit and unlock memory complete.");

	if (!do_sexit)
		return;

	if (smp_processor_id() != 0) {
		pr_emerg("Error TXT SEXIT must be called on CPU 0\n");
		return;
	}

	/* Disable SMX mode */
	cr4_set_bits(X86_CR4_SMXE);

	/* Do the SEXIT SMX operation */
	smx_getsec_sexit();

	pr_emerg("TXT SEXIT complete.");
}
