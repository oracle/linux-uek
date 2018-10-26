// SPDX-License-Identifier: GPL-2.0
/*
 * Secure Launch early measurement and validation routines.
 *
 * Copyright (c) 2021, Oracle and/or its affiliates.
 */

#include <linux/init.h>
#include <linux/string.h>
#include <linux/linkage.h>
#include <linux/efi.h>
#include <asm/segment.h>
#include <asm/boot.h>
#include <asm/msr.h>
#include <asm/io.h>
#include <asm/mtrr.h>
#include <asm/processor-flags.h>
#include <asm/asm-offsets.h>
#include <asm/bootparam.h>
#include <asm/efi.h>
#include <asm/bootparam_utils.h>
#include <linux/slaunch.h>
#include <crypto/sha1.h>
#include <crypto/sha2.h>

#include "misc.h"
#include "early_sha1.h"

#define CAPS_VARIABLE_MTRR_COUNT_MASK	0xff

#define SL_TPM12_LOG		1
#define SL_TPM20_LOG		2

#define SL_TPM20_MAX_ALGS	2

#define SL_MAX_EVENT_DATA	64
#define SL_TPM12_LOG_SIZE	(sizeof(struct tcg_pcr_event) + \
				SL_MAX_EVENT_DATA)
#define SL_TPM20_LOG_SIZE	(sizeof(struct tcg_pcr_event2_head) + \
				SHA1_DIGEST_SIZE + SHA256_DIGEST_SIZE + \
				sizeof(struct tcg_event_field) + \
				SL_MAX_EVENT_DATA)

static void *evtlog_base;
static u32 evtlog_size;
static struct txt_heap_event_log_pointer2_1_element *log20_elem;
static u32 tpm_log_ver = SL_TPM12_LOG;
struct tcg_efi_specid_event_algs tpm_algs[SL_TPM20_MAX_ALGS] = {0};

#if !IS_ENABLED(CONFIG_SECURE_LAUNCH_ALT_PCR19)
static u32 pcr_config = SL_DEF_CONFIG_PCR18;
#else
static u32 pcr_config = SL_ALT_CONFIG_PCR19;
#endif

#if !IS_ENABLED(CONFIG_SECURE_LAUNCH_ALT_PCR20)
static u32 pcr_image = SL_DEF_IMAGE_PCR17;
#else
static u32 pcr_image = SL_ALT_IMAGE_PCR20;
#endif

extern u32 sl_cpu_type;
extern u32 sl_mle_start;

u32 slaunch_get_cpu_type(void)
{
	return sl_cpu_type;
}

static u64 sl_txt_read(u32 reg)
{
	return readq((void *)(u64)(TXT_PRIV_CONFIG_REGS_BASE + reg));
}

static void sl_txt_write(u32 reg, u64 val)
{
	writeq(val, (void *)(u64)(TXT_PRIV_CONFIG_REGS_BASE + reg));
}

static void __noreturn sl_txt_reset(u64 error)
{
	/* Reading the E2STS register acts as a barrier for TXT registers */
	sl_txt_write(TXT_CR_ERRORCODE, error);
	sl_txt_read(TXT_CR_E2STS);
	sl_txt_write(TXT_CR_CMD_UNLOCK_MEM_CONFIG, 1);
	sl_txt_read(TXT_CR_E2STS);
	sl_txt_write(TXT_CR_CMD_RESET, 1);

	for ( ; ; )
		asm volatile ("hlt");

	unreachable();
}

static u64 sl_rdmsr(u32 reg)
{
	u64 lo, hi;

	asm volatile ("rdmsr" : "=a" (lo), "=d" (hi) : "c" (reg));

	return (hi << 32) | lo;
}

static void sl_check_pmr_coverage(void *base, u32 size, bool allow_hi)
{
	void *end = base + size;
	struct txt_os_sinit_data *os_sinit_data;
	void *txt_heap;

	if (!(sl_cpu_type & SL_CPU_INTEL))
		return;

	txt_heap = (void *)sl_txt_read(TXT_CR_HEAP_BASE);
	os_sinit_data = txt_os_sinit_data_start(txt_heap);

	if ((end >= (void *)0x100000000ULL) &&
	    (base < (void *)0x100000000ULL))
		sl_txt_reset(SL_ERROR_REGION_STRADDLE_4GB);

	/*
	 * Note that the late stub code validates that the hi PMR covers
	 * all memory above 4G. At this point the code can only check that
	 * regions are within the hi PMR but that is sufficient.
	 */
	if ((end > (void *)0x100000000ULL) &&
	    (base >= (void *)0x100000000ULL)) {
		if (allow_hi) {
			if (end >= (void *)(os_sinit_data->vtd_pmr_hi_base +
					   os_sinit_data->vtd_pmr_hi_size))
				sl_txt_reset(SL_ERROR_BUFFER_BEYOND_PMR);
		} else
			sl_txt_reset(SL_ERROR_REGION_ABOVE_4GB);
	}

	if (end >= (void *)os_sinit_data->vtd_pmr_lo_size)
		sl_txt_reset(SL_ERROR_BUFFER_BEYOND_PMR);
}

/*
 * Some MSRs are modified by the pre-launch code including the MTRRs.
 * The early MLE code has to restore these values. This code validates
 * the values after they are measured.
 */
static void sl_txt_validate_msrs(struct txt_os_mle_data *os_mle_data)
{
	u64 mtrr_caps, mtrr_def_type, mtrr_var, misc_en_msr;
	u32 vcnt, i;
	struct txt_mtrr_state *saved_bsp_mtrrs =
		&(os_mle_data->saved_bsp_mtrrs);

	mtrr_caps = sl_rdmsr(MSR_MTRRcap);
	vcnt = (u32)(mtrr_caps & CAPS_VARIABLE_MTRR_COUNT_MASK);

	if (saved_bsp_mtrrs->mtrr_vcnt > vcnt)
		sl_txt_reset(SL_ERROR_MTRR_INV_VCNT);
	if (saved_bsp_mtrrs->mtrr_vcnt > TXT_OS_MLE_MAX_VARIABLE_MTRRS)
		sl_txt_reset(SL_ERROR_MTRR_INV_VCNT);

	mtrr_def_type = sl_rdmsr(MSR_MTRRdefType);
	if (saved_bsp_mtrrs->default_mem_type != mtrr_def_type)
		sl_txt_reset(SL_ERROR_MTRR_INV_DEF_TYPE);

	for (i = 0; i < saved_bsp_mtrrs->mtrr_vcnt; i++) {
		mtrr_var = sl_rdmsr(MTRRphysBase_MSR(i));
		if (saved_bsp_mtrrs->mtrr_pair[i].mtrr_physbase != mtrr_var)
			sl_txt_reset(SL_ERROR_MTRR_INV_BASE);
		mtrr_var = sl_rdmsr(MTRRphysMask_MSR(i));
		if (saved_bsp_mtrrs->mtrr_pair[i].mtrr_physmask != mtrr_var)
			sl_txt_reset(SL_ERROR_MTRR_INV_MASK);
	}

	misc_en_msr = sl_rdmsr(MSR_IA32_MISC_ENABLE);
	if (os_mle_data->saved_misc_enable_msr != misc_en_msr)
		sl_txt_reset(SL_ERROR_MSR_INV_MISC_EN);
}

static void sl_find_event_log(void)
{
	struct txt_os_mle_data *os_mle_data;
	struct txt_os_sinit_data *os_sinit_data;
	void *txt_heap;

	txt_heap = (void *)sl_txt_read(TXT_CR_HEAP_BASE);

	os_mle_data = txt_os_mle_data_start(txt_heap);
	evtlog_base = (void *)os_mle_data->evtlog_addr;
	evtlog_size = os_mle_data->evtlog_size;

	/*
	 * For TPM 2.0, the event log 2.1 extended data structure has to also
	 * be located and fixed up.
	 */
	os_sinit_data = txt_os_sinit_data_start(txt_heap);

	/*
	 * Only support version 6 and later that properly handle the
	 * list of ExtDataElements in the OS-SINIT structure.
	 */
	if (os_sinit_data->version < 6)
		sl_txt_reset(SL_ERROR_OS_SINIT_BAD_VERSION);

	/* Find the TPM2.0 logging extended heap element */
	log20_elem = tpm20_find_log2_1_element(os_sinit_data);

	/* If found, this implies TPM20 log and family */
	if (log20_elem)
		tpm_log_ver = SL_TPM20_LOG;
}

static void sl_validate_event_log_buffer(void)
{
	void *mle_base = (void *)(u64)sl_mle_start;
	void *mle_end;
	struct txt_os_sinit_data *os_sinit_data;
	void *txt_heap;
	void *txt_heap_end;
	void *evtlog_end;

	if ((u64)evtlog_size > (LLONG_MAX - (u64)evtlog_base))
		sl_txt_reset(SL_ERROR_INTEGER_OVERFLOW);
	evtlog_end = evtlog_base + evtlog_size;

	txt_heap = (void *)sl_txt_read(TXT_CR_HEAP_BASE);
	txt_heap_end = txt_heap + sl_txt_read(TXT_CR_HEAP_SIZE);
	os_sinit_data = txt_os_sinit_data_start(txt_heap);

	mle_end = mle_base + os_sinit_data->mle_size;

	/*
	 * This check is to ensure the event log buffer does not overlap with
	 * the MLE image.
	 */
	if ((evtlog_base >= mle_end) &&
	    (evtlog_end > mle_end))
		goto pmr_check; /* above */

	if ((evtlog_end <= mle_base) &&
	    (evtlog_base < mle_base))
		goto pmr_check; /* below */

	sl_txt_reset(SL_ERROR_MLE_BUFFER_OVERLAP);

pmr_check:
	/*
	 * The TXT heap is protected by the DPR. If the TPM event log is
	 * inside the TXT heap, there is no need for a PMR check.
	 */
	if ((evtlog_base > txt_heap) &&
	    (evtlog_end < txt_heap_end))
		return;

	sl_check_pmr_coverage(evtlog_base, evtlog_size, true);
}

static void sl_find_event_log_algorithms(void)
{
	struct tcg_efi_specid_event_head *efi_head =
		(struct tcg_efi_specid_event_head *)(evtlog_base +
					log20_elem->first_record_offset +
					sizeof(struct tcg_pcr_event));

	if (efi_head->num_algs == 0 || efi_head->num_algs > 2)
		sl_txt_reset(SL_ERROR_TPM_NUMBER_ALGS);

	memcpy(&tpm_algs[0], &efi_head->digest_sizes[0],
	       sizeof(struct tcg_efi_specid_event_algs) * efi_head->num_algs);
}

static void sl_tpm12_log_event(u32 pcr, u32 event_type,
			       const u8 *data, u32 length,
			       const u8 *event_data, u32 event_size)
{
	struct tcg_pcr_event *pcr_event;
	struct sha1_state sctx = {0};
	u32 total_size;
	u8 log_buf[SL_TPM12_LOG_SIZE] = {0};
	u8 sha1_hash[SHA1_DIGEST_SIZE] = {0};

	pcr_event = (struct tcg_pcr_event *)log_buf;
	pcr_event->pcr_idx = pcr;
	pcr_event->event_type = event_type;
	if (length > 0) {
		early_sha1_init(&sctx);
		early_sha1_update(&sctx, data, length);
		early_sha1_final(&sctx, &sha1_hash[0]);
		memcpy(&pcr_event->digest[0], &sha1_hash[0], SHA1_DIGEST_SIZE);
	}
	pcr_event->event_size = event_size;
	if (event_size > 0)
		memcpy((u8 *)pcr_event + sizeof(struct tcg_pcr_event),
		       event_data, event_size);

	total_size = sizeof(struct tcg_pcr_event) + event_size;

	if (tpm12_log_event(evtlog_base, evtlog_size, total_size, pcr_event))
		sl_txt_reset(SL_ERROR_TPM_LOGGING_FAILED);
}

static void sl_tpm20_log_event(u32 pcr, u32 event_type,
			       const u8 *data, u32 length,
			       const u8 *event_data, u32 event_size)
{
	struct tcg_pcr_event2_head *head;
	struct tcg_event_field *event;
	struct sha1_state sctx1 = {0};
	struct sha256_state sctx256 = {0};
	u32 total_size;
	u16 *alg_ptr;
	u8 *dgst_ptr;
	u8 log_buf[SL_TPM20_LOG_SIZE] = {0};
	u8 sha1_hash[SHA1_DIGEST_SIZE] = {0};
	u8 sha256_hash[SHA256_DIGEST_SIZE] = {0};

	head = (struct tcg_pcr_event2_head *)log_buf;
	head->pcr_idx = pcr;
	head->event_type = event_type;
	total_size = sizeof(struct tcg_pcr_event2_head);
	alg_ptr = (u16 *)(log_buf + sizeof(struct tcg_pcr_event2_head));

	for ( ; head->count < 2; head->count++) {
		if (!tpm_algs[head->count].alg_id)
			break;

		*alg_ptr = tpm_algs[head->count].alg_id;
		dgst_ptr = (u8 *)alg_ptr + sizeof(u16);

		if (tpm_algs[head->count].alg_id == TPM_ALG_SHA256 &&
		    length) {
			sha256_init(&sctx256);
			sha256_update(&sctx256, data, length);
			sha256_final(&sctx256, &sha256_hash[0]);
		} else if (tpm_algs[head->count].alg_id == TPM_ALG_SHA1 &&
			   length) {
			early_sha1_init(&sctx1);
			early_sha1_update(&sctx1, data, length);
			early_sha1_final(&sctx1, &sha1_hash[0]);
		}

		if (tpm_algs[head->count].alg_id == TPM_ALG_SHA256) {
			memcpy(dgst_ptr, &sha256_hash[0], SHA256_DIGEST_SIZE);
			total_size += SHA256_DIGEST_SIZE + sizeof(u16);
			alg_ptr = (u16 *)((u8 *)alg_ptr + SHA256_DIGEST_SIZE + sizeof(u16));
		} else if (tpm_algs[head->count].alg_id == TPM_ALG_SHA1) {
			memcpy(dgst_ptr, &sha1_hash[0], SHA1_DIGEST_SIZE);
			total_size += SHA1_DIGEST_SIZE + sizeof(u16);
			alg_ptr = (u16 *)((u8 *)alg_ptr + SHA1_DIGEST_SIZE + sizeof(u16));
		} else
			sl_txt_reset(SL_ERROR_TPM_UNKNOWN_DIGEST);
	}

	event = (struct tcg_event_field *)(log_buf + total_size);
	event->event_size = event_size;
	if (event_size > 0)
		memcpy((u8 *)event + sizeof(struct tcg_event_field),
		       event_data, event_size);
	total_size += sizeof(struct tcg_event_field) + event_size;

	if (tpm20_log_event(log20_elem, evtlog_base, evtlog_size,
	    total_size, &log_buf[0]))
		sl_txt_reset(SL_ERROR_TPM_LOGGING_FAILED);
}

static void sl_tpm_extend_evtlog(u32 pcr, u32 type,
				 const u8 *data, u32 length, const char *desc)
{
	if (tpm_log_ver == SL_TPM20_LOG)
		sl_tpm20_log_event(pcr, type, data, length,
				   (const u8 *)desc, strlen(desc));
	else
		sl_tpm12_log_event(pcr, type, data, length,
				   (const u8 *)desc, strlen(desc));
}

static struct setup_data *sl_handle_setup_data(struct setup_data *curr)
{
	struct setup_data *next;
	struct setup_indirect *ind;

	if (!curr)
		return NULL;

	next = (struct setup_data *)(unsigned long)curr->next;

	/* SETUP_INDIRECT instances have to be handled differently */
	if (curr->type == SETUP_INDIRECT) {
		ind = (struct setup_indirect *)
			((u8 *)curr + offsetof(struct setup_data, data));

		sl_check_pmr_coverage((void *)ind->addr, ind->len, true);

		sl_tpm_extend_evtlog(pcr_config, TXT_EVTYPE_SLAUNCH,
				     (void *)ind->addr, ind->len,
				     "Measured Kernel setup_indirect");

		return next;
	}

	sl_check_pmr_coverage(((u8 *)curr) + sizeof(struct setup_data),
			      curr->len, true);

	sl_tpm_extend_evtlog(pcr_config, TXT_EVTYPE_SLAUNCH,
			     ((u8 *)curr) + sizeof(struct setup_data),
			     curr->len,
			     "Measured Kernel setup_data");

	return next;
}

asmlinkage __visible void sl_check_region(void *base, u32 size)
{
	sl_check_pmr_coverage(base, size, false);
}

asmlinkage __visible void sl_main(void *bootparams)
{
	struct boot_params *bp;
	struct setup_data *data;
	struct txt_os_mle_data *os_mle_data;
	struct txt_os_mle_data os_mle_tmp = {0};
	const char *signature;
	unsigned long mmap = 0;
	void *txt_heap;
	u32 data_count;

	/*
	 * Currently only Intel TXT is supported for Secure Launch. Testing
	 * this value also indicates that the kernel was booted successfully
	 * through the Secure Launch entry point and is in SMX mode.
	 */
	if (!(sl_cpu_type & SL_CPU_INTEL))
		return;

	/* Locate the TPM event log. */
	sl_find_event_log();

	/* Validate the location of the event log buffer before using it */
	sl_validate_event_log_buffer();

	/*
	 * Find the TPM hash algorithms used by the ACM and recorded in the
	 * event log.
	 */
	if (tpm_log_ver == SL_TPM20_LOG)
		sl_find_event_log_algorithms();

	/* Sanitize them before measuring */
	boot_params = (struct boot_params *)bootparams;
	sanitize_boot_params(boot_params);

	/* Place event log NO_ACTION tags before and after measurements */
	sl_tpm_extend_evtlog(17, TXT_EVTYPE_SLAUNCH_START, NULL, 0, "");

	sl_check_pmr_coverage(bootparams, PAGE_SIZE, false);

	/* Measure the zero page/boot params */
	sl_tpm_extend_evtlog(pcr_config, TXT_EVTYPE_SLAUNCH,
			     bootparams, PAGE_SIZE,
			     "Measured boot parameters");

	/* Now safe to use boot params */
	bp = (struct boot_params *)bootparams;

	/* Measure the command line */
	if (bp->hdr.cmdline_size > 0) {
		u64 cmdline = (u64)bp->hdr.cmd_line_ptr;

		if (bp->ext_cmd_line_ptr > 0)
			cmdline = cmdline | ((u64)bp->ext_cmd_line_ptr << 32);

		sl_check_pmr_coverage((void *)cmdline,
				      bp->hdr.cmdline_size, true);

		sl_tpm_extend_evtlog(pcr_config, TXT_EVTYPE_SLAUNCH,
				     (u8 *)cmdline,
				     bp->hdr.cmdline_size,
				     "Measured Kernel command line");
	}

	/*
	 * Measuring the boot params measured the fixed e820 memory map.
	 * Measure any setup_data entries including e820 extended entries.
	 */
	data = (struct setup_data *)(unsigned long)bp->hdr.setup_data;
	while (data)
		data = sl_handle_setup_data(data);

	/* If bootloader was EFI, measure the memory map passed across */
	signature =
		(const char *)&bp->efi_info.efi_loader_signature;

	if (!strncmp(signature, EFI32_LOADER_SIGNATURE, 4))
		mmap =  bp->efi_info.efi_memmap;
	else if (!strncmp(signature, EFI64_LOADER_SIGNATURE, 4))
		mmap = (bp->efi_info.efi_memmap |
			((u64)bp->efi_info.efi_memmap_hi << 32));

	if (mmap)
		sl_tpm_extend_evtlog(pcr_config, TXT_EVTYPE_SLAUNCH,
				     (void *)mmap,
				     bp->efi_info.efi_memmap_size,
				     "Measured EFI memory map");

	/* Measure any external initrd */
	if (bp->hdr.ramdisk_image != 0 && bp->hdr.ramdisk_size != 0) {
		u64 ramdisk = (u64)bp->hdr.ramdisk_image;

		if (bp->ext_ramdisk_size > 0)
			sl_txt_reset(SL_ERROR_INITRD_TOO_BIG);

		if (bp->ext_ramdisk_image > 0)
			ramdisk = ramdisk |
				  ((u64)bp->ext_ramdisk_image << 32);

		sl_check_pmr_coverage((void *)ramdisk,
				      bp->hdr.ramdisk_size, true);

		sl_tpm_extend_evtlog(pcr_image, TXT_EVTYPE_SLAUNCH,
				     (u8 *)(ramdisk),
				     bp->hdr.ramdisk_size,
				     "Measured initramfs");
	}

	/*
	 * Some extra work to do on Intel, have to measure the OS-MLE
	 * heap area.
	 */
	txt_heap = (void *)sl_txt_read(TXT_CR_HEAP_BASE);
	os_mle_data = txt_os_mle_data_start(txt_heap);

	/* Measure only portions of OS-MLE data, not addresses/sizes etc. */
	os_mle_tmp.version = os_mle_data->version;
	os_mle_tmp.saved_misc_enable_msr = os_mle_data->saved_misc_enable_msr;
	os_mle_tmp.saved_bsp_mtrrs = os_mle_data->saved_bsp_mtrrs;

	/* No PMR check is needed, the TXT heap is covered by the DPR */

	sl_tpm_extend_evtlog(pcr_config, TXT_EVTYPE_SLAUNCH,
			     (u8 *)&os_mle_tmp,
			     sizeof(struct txt_os_mle_data),
			     "Measured TXT OS-MLE data");

	sl_tpm_extend_evtlog(17, TXT_EVTYPE_SLAUNCH_END, NULL, 0, "");

	/*
	 * Now that the OS-MLE data is measured, ensure the MTRR and
	 * misc enable MSRs are what we expect.
	 */
	sl_txt_validate_msrs(os_mle_data);
}
