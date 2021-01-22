// SPDX-License-Identifier: GPL-2.0
/*
 * Secure Launch early measurement and validation routines.
 *
 * Copyright (c) 2020, Oracle and/or its affiliates.
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
#ifdef CONFIG_SECURE_LAUNCH_SHA256
#include <linux/sha256.h>
#endif
#ifdef CONFIG_SECURE_LAUNCH_SHA512
#include <linux/sha512.h>
#endif

#include "misc.h"
#include "early_sha1.h"
#include "tpm/tpm_common.h"
#include "tpm/tpm2_constants.h"
#include "tpm/tpm.h"

#define CAPS_VARIABLE_MTRR_COUNT_MASK	0xff

#define SL_MAX_EVENT_DATA	64
#define SL_TPM12_LOG_SIZE	(sizeof(struct tpm12_pcr_event) + \
				SL_MAX_EVENT_DATA)
#define SL_TPM20_LOG_SIZE	(sizeof(struct tpm20_ha) + \
				SHA512_SIZE + \
				sizeof(struct tpm20_digest_values) + \
				sizeof(struct tpm20_pcr_event_head) + \
				sizeof(struct tpm20_pcr_event_tail) + \
				SL_MAX_EVENT_DATA)

static void *evtlog_base;
static u32 evtlog_size;
static struct txt_heap_event_log_pointer2_1_element *log20_elem;

#ifndef CONFIG_SECURE_LAUNCH_ALT_PCRS
static u32 pcr_image = SL_DEF_IMAGE_PCR17;
static u32 pcr_config = SL_DEF_CONFIG_PCR18;
#else
static u32 pcr_image = SL_ALT_IMAGE_PCR20;
static u32 pcr_config = SL_ALT_CONFIG_PCR19;
#endif

extern u32 sl_cpu_type;
extern u32 sl_mle_start;

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

static void sl_find_event_log(struct tpm *tpm)
{
	struct txt_os_mle_data *os_mle_data;
	struct txt_os_sinit_data *os_sinit_data;
	void *txt_heap;

	txt_heap = (void *)sl_txt_read(TXT_CR_HEAP_BASE);

	os_mle_data = txt_os_mle_data_start(txt_heap);
	evtlog_base = (void *)os_mle_data->evtlog_addr;
	evtlog_size = os_mle_data->evtlog_size;

	if (tpm->family != TPM20)
		return;

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

	if (!log20_elem)
		sl_txt_reset(SL_ERROR_TPM_INVALID_LOG20);
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

	if ((evtlog_base >= mle_end) &&
	    (evtlog_end > mle_end))
		goto pmr_check; /* above */

	if ((evtlog_end <= mle_base) &&
	    (evtlog_base < mle_base))
		goto pmr_check; /* below */

	sl_txt_reset(SL_ERROR_MLE_BUFFER_OVERLAP);

pmr_check:
	/*
	 * Have to restrict the event log to below 4G since there is
	 * no easy way to validate the hi PMR values.
	 */
	if ((evtlog_end >= (void *)0x100000000ULL) ||
	    (evtlog_base >= (void *)0x100000000ULL))
		sl_txt_reset(SL_ERROR_REGION_ABOVE_4GB);

	/*
	 * The TXT heap is protected by the DPR. If the TPM event log is
	 * inside the TXT heap, there is no need for a PMR check.
	 */
	if ((evtlog_base > txt_heap) &&
	    (evtlog_end < txt_heap_end))
		return;

	if (evtlog_end > (void *)os_sinit_data->vtd_pmr_lo_size)
		sl_txt_reset(SL_ERROR_BUFFER_BEYOND_PMR);

	/*
 	 * Note that the late stub code validates that the hi PMR covers
	 * all memory above 4G before the event log buffer is ever read.
	 */
}

static void sl_tpm12_log_event(u32 pcr, u8 *digest,
			       const u8 *event_data, u32 event_size)
{
	struct tpm12_pcr_event *pcr_event;
	u32 total_size;
	u8 log_buf[SL_TPM12_LOG_SIZE] = {0};

	pcr_event = (struct tpm12_pcr_event *)log_buf;
	pcr_event->pcr_index = pcr;
	pcr_event->type = TXT_EVTYPE_SLAUNCH;
	memcpy(&pcr_event->digest[0], digest, SHA1_SIZE);
	pcr_event->size = event_size;
	memcpy((u8 *)pcr_event + sizeof(struct tpm12_pcr_event),
	       event_data, event_size);

	total_size = sizeof(struct tpm12_pcr_event) + event_size;

	if (tpm12_log_event(evtlog_base, evtlog_size, total_size, pcr_event))
		sl_txt_reset(SL_ERROR_TPM_LOGGING_FAILED);
}

static void sl_tpm20_log_event(u32 pcr, u8 *digest, u16 algo,
			       const u8 *event_data, u32 event_size)
{
	struct tpm20_pcr_event_head *head;
	struct tpm20_digest_values *dvs;
	struct tpm20_ha *ha;
	struct tpm20_pcr_event_tail *tail;
	u8 *dptr;
	u32 total_size;
	u8 log_buf[SL_TPM20_LOG_SIZE] = {0};

	head = (struct tpm20_pcr_event_head *)log_buf;
	head->pcr_index = pcr;
	head->event_type = TXT_EVTYPE_SLAUNCH;
	dvs = (struct tpm20_digest_values *)
		((u8 *)head + sizeof(struct tpm20_pcr_event_head));
	dvs->count = 1;
	ha = (struct tpm20_ha *)
		((u8 *)dvs + sizeof(struct tpm20_digest_values));
	ha->algorithm_id = algo;
	dptr = (u8 *)ha + sizeof(struct tpm20_ha);

	switch (algo) {
	case TPM_ALG_SHA512:
		memcpy(dptr, digest, SHA512_SIZE);
		tail = (struct tpm20_pcr_event_tail *)
			(dptr + SHA512_SIZE);
		break;
	case TPM_ALG_SHA256:
		memcpy(dptr, digest, SHA256_SIZE);
		tail = (struct tpm20_pcr_event_tail *)
			(dptr + SHA256_SIZE);
		break;
	case TPM_ALG_SHA1:
	default:
		memcpy(dptr, digest, SHA1_SIZE);
		tail = (struct tpm20_pcr_event_tail *)
			(dptr + SHA1_SIZE);
	};

	tail->event_size = event_size;
	memcpy((u8 *)tail + sizeof(struct tpm20_pcr_event_tail),
	       event_data, event_size);

	total_size = (u32)((u8 *)tail - (u8 *)head) +
		sizeof(struct tpm20_pcr_event_tail) + event_size;

	if (tpm20_log_event(log20_elem, evtlog_base, evtlog_size, total_size, &log_buf[0]))
		sl_txt_reset(SL_ERROR_TPM_LOGGING_FAILED);
}

void sl_tpm_extend_pcr(struct tpm *tpm, u32 pcr, const u8 *data, u32 length,
		       const char *desc)
{
	struct sha1_state sctx = {0};
	u8 sha1_hash[SHA1_SIZE] = {0};
	int ret;

	if (tpm->family == TPM20) {
#ifdef CONFIG_SECURE_LAUNCH_SHA256
		struct sha256_state sctx = {0};
		u8 sha256_hash[SHA256_SIZE] = {0};

		sha256_init(&sctx);
		sha256_update(&sctx, data, length);
		sha256_final(&sctx, &sha256_hash[0]);
		ret = tpm_extend_pcr(tpm, pcr, TPM_ALG_SHA256, &sha256_hash[0]);
		if (!ret) {
			sl_tpm20_log_event(pcr, &sha256_hash[0],
					   TPM_ALG_SHA256,
					   (const u8 *)desc, strlen(desc));
			return;
		} else
			sl_txt_reset(SL_ERROR_TPM_EXTEND);
#endif
#ifdef CONFIG_SECURE_LAUNCH_SHA512
		struct sha512_state sctx = {0};
		u8 sha512_hash[SHA512_SIZE] = {0};

		sha512_init(&sctx);
		sha512_update(&sctx, data, length);
		sha512_final(&sctx, &sha512_hash[0]);
		ret = tpm_extend_pcr(tpm, pcr, TPM_ALG_SHA512, &sha512_hash[0]);
		if (!ret) {
			sl_tpm20_log_event(pcr, &sha512_hash[0],
					   TPM_ALG_SHA512,
					   (const u8 *)desc, strlen(desc));
			return;
		} else
			sl_txt_reset(SL_ERROR_TPM_EXTEND);
#endif
	}

	early_sha1_init(&sctx);
	early_sha1_update(&sctx, data, length);
	early_sha1_final(&sctx, &sha1_hash[0]);
	ret = tpm_extend_pcr(tpm, pcr, TPM_ALG_SHA1, &sha1_hash[0]);
	if (ret)
		sl_txt_reset(SL_ERROR_TPM_EXTEND);

	if (tpm->family == TPM20)
		sl_tpm20_log_event(pcr, &sha1_hash[0], TPM_ALG_SHA1,
				   (const u8 *)desc, strlen(desc));
	else
		sl_tpm12_log_event(pcr, &sha1_hash[0],
				   (const u8 *)desc, strlen(desc));
}

asmlinkage __visible void sl_check_region(void *base, u32 size)
{
	void *end = base + size;
	struct txt_os_sinit_data *os_sinit_data;
	void *txt_heap;

	txt_heap = (void *)sl_txt_read(TXT_CR_HEAP_BASE);
	os_sinit_data = txt_os_sinit_data_start(txt_heap);

	if ((end >= (void *)0x100000000ULL) ||
	    (base >= (void *)0x100000000ULL))
		sl_txt_reset(SL_ERROR_REGION_ABOVE_4GB);

	if (end > (void *)os_sinit_data->vtd_pmr_lo_size)
		sl_txt_reset(SL_ERROR_BUFFER_BEYOND_PMR);
}

asmlinkage __visible void sl_main(void *bootparams)
{
	struct tpm *tpm;
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

	/*
	 * If enable_tpm fails there is no point going on. The entire secure
	 * environment depends on this and the other TPM operations succeeding.
	 */
	tpm = enable_tpm();
	if (!tpm)
		sl_txt_reset(SL_ERROR_TPM_INIT);

	/* Locate the TPM event log. */
	sl_find_event_log(tpm);

	/* Validate the location of the event log buffer before using it */
	sl_validate_event_log_buffer();

	/*
	 * Locality 2 is being opened so that the DRTM PCRs can be updated,
	 * specifically 17 and 18. These measurements can also be sent to
	 * DRTM PCRs 19 and 20 if the kernel is configured for this.
	 */
	if (tpm_request_locality(tpm, 2) == TPM_NO_LOCALITY)
		sl_txt_reset(SL_ERROR_TPM_GET_LOC);

	/* Sanitize them before measuring */
	boot_params = (struct boot_params*)bootparams;
	sanitize_boot_params(boot_params);

	/* Measure the zero page/boot params */
	sl_tpm_extend_pcr(tpm, pcr_config, bootparams, PAGE_SIZE,
			  "Measured boot parameters");

	/* Now safe to use boot params */
	bp = (struct boot_params *)bootparams;

	/* Measure the command line */
	sl_tpm_extend_pcr(tpm, pcr_config,
			  (u8 *)((unsigned long)bp->hdr.cmd_line_ptr),
			  bp->hdr.cmdline_size,
			  "Measured Kernel command line");

	/*
	 * Measuring the boot params measured the fixed e820 memory map.
	 * Measure any setup_data entries including e820 extended entries.
	 */
	data = (struct setup_data *)(unsigned long)bp->hdr.setup_data;
	while (data) {
		sl_tpm_extend_pcr(tpm, pcr_config,
				  ((u8 *)data) + sizeof(struct setup_data),
				  data->len,
				  "Measured Kernel setup_data");

		data = (struct setup_data *)(unsigned long)data->next;
	}

	/* If bootloader was EFI, measure the memory map passed across */
	signature =
		(const char *)&bp->efi_info.efi_loader_signature;

	if (!strncmp(signature, EFI32_LOADER_SIGNATURE, 4))
		mmap =  bp->efi_info.efi_memmap;
	else if (!strncmp(signature, EFI64_LOADER_SIGNATURE, 4))
		mmap = (bp->efi_info.efi_memmap |
			((u64)bp->efi_info.efi_memmap_hi << 32));

	if (mmap)
		sl_tpm_extend_pcr(tpm, pcr_config, (void *)mmap,
				  bp->efi_info.efi_memmap_size,
				  "Measured EFI memory map");

	/* Measure any external initrd */
	if (bp->hdr.ramdisk_image != 0 && bp->hdr.ramdisk_size != 0)
		sl_tpm_extend_pcr(tpm, pcr_image,
				  (u8 *)((u64)bp->hdr.ramdisk_image),
				  bp->hdr.ramdisk_size,
				  "Measured initramfs");

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

	sl_tpm_extend_pcr(tpm, pcr_config, (u8 *)&os_mle_tmp,
			  sizeof(struct txt_os_mle_data),
			  "Measured TXT OS-MLE data");

	/*
	 * Now that the OS-MLE data is measured, ensure the MTRR and
	 * misc enable MSRs are what we expect.
	 */
	sl_txt_validate_msrs(os_mle_data);

	tpm_relinquish_locality(tpm);
	free_tpm(tpm);
}
