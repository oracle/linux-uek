// SPDX-License-Identifier: GPL-2.0
/*
 * Secure Launch early measurement and validation routines.
 *
 * Copyright (c) 2024, Oracle and/or its affiliates.
 */

#include <linux/init.h>
#include <linux/string.h>
#include <linux/linkage.h>
#include <asm/segment.h>
#include <asm/boot.h>
#include <asm/msr.h>
#include <asm/mtrr.h>
#include <asm/processor-flags.h>
#include <asm/asm-offsets.h>
#include <asm/bootparam.h>
#include <asm/bootparam_utils.h>
#include <linux/slr_table.h>
#include <linux/slaunch.h>
#include <crypto/sha1.h>
#include <crypto/sha2.h>

#define CAPS_VARIABLE_MTRR_COUNT_MASK	0xff

#define SL_TPM_LOG		1
#define SL_TPM2_LOG		2

#define SL_TPM2_MAX_ALGS	2

#define SL_MAX_EVENT_DATA	64
#define SL_TPM_LOG_SIZE		(sizeof(struct tcg_pcr_event) + \
				SL_MAX_EVENT_DATA)
#define SL_TPM2_LOG_SIZE	(sizeof(struct tcg_pcr_event2_head) + \
				SHA1_DIGEST_SIZE + SHA256_DIGEST_SIZE + \
				sizeof(struct tcg_event_field) + \
				SL_MAX_EVENT_DATA)

static void *evtlog_base;
static u32 evtlog_size;
static struct txt_heap_event_log_pointer2_1_element *log21_elem;
static u32 tpm_log_ver = SL_TPM_LOG;
static struct tcg_efi_specid_event_algs tpm_algs[SL_TPM2_MAX_ALGS] = {0};

extern u32 sl_cpu_type;
extern u32 sl_mle_start;

void __cold __noreturn __fortify_panic(const u8 reason, const size_t avail, const size_t size)
{
	asm volatile ("ud2");

	unreachable();
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

static struct slr_table *sl_locate_and_validate_slrt(void)
{
	struct txt_os_mle_data *os_mle_data;
	struct slr_table *slrt;
	void *txt_heap;

	txt_heap = (void *)sl_txt_read(TXT_CR_HEAP_BASE);
	os_mle_data = txt_os_mle_data_start(txt_heap);

	if (!os_mle_data->slrt)
		sl_txt_reset(SL_ERROR_INVALID_SLRT);

	slrt = (struct slr_table *)os_mle_data->slrt;

	if (slrt->magic != SLR_TABLE_MAGIC)
		sl_txt_reset(SL_ERROR_INVALID_SLRT);

	if (slrt->architecture != SLR_INTEL_TXT)
		sl_txt_reset(SL_ERROR_INVALID_SLRT);

	return slrt;
}

static void sl_check_pmr_coverage(void *base, u32 size, bool allow_hi)
{
	struct txt_os_sinit_data *os_sinit_data;
	void *end = base + size;
	void *txt_heap;

	if (!(sl_cpu_type & SL_CPU_INTEL))
		return;

	txt_heap = (void *)sl_txt_read(TXT_CR_HEAP_BASE);
	os_sinit_data = txt_os_sinit_data_start(txt_heap);

	if ((u64)end >= SZ_4G && (u64)base < SZ_4G)
		sl_txt_reset(SL_ERROR_REGION_STRADDLE_4GB);

	/*
	 * Note that the late stub code validates that the hi PMR covers
	 * all memory above 4G. At this point the code can only check that
	 * regions are within the hi PMR but that is sufficient.
	 */
	if ((u64)end > SZ_4G && (u64)base >= SZ_4G) {
		if (allow_hi) {
			if (end >= (void *)(os_sinit_data->vtd_pmr_hi_base +
					   os_sinit_data->vtd_pmr_hi_size))
				sl_txt_reset(SL_ERROR_BUFFER_BEYOND_PMR);
		} else {
			sl_txt_reset(SL_ERROR_REGION_ABOVE_4GB);
		}
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
	struct slr_txt_mtrr_state *saved_bsp_mtrrs;
	u64 mtrr_caps, mtrr_def_type, mtrr_var;
	struct slr_entry_intel_info *txt_info;
	u64 misc_en_msr;
	u32 vcnt, i;

	txt_info = (struct slr_entry_intel_info *)os_mle_data->txt_info;
	saved_bsp_mtrrs = &txt_info->saved_bsp_mtrrs;

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
	if (txt_info->saved_misc_enable_msr != misc_en_msr)
		sl_txt_reset(SL_ERROR_MSR_INV_MISC_EN);
}

static void sl_find_drtm_event_log(struct slr_table *slrt)
{
	struct txt_os_sinit_data *os_sinit_data;
	struct slr_entry_log_info *log_info;
	void *txt_heap;

	log_info = slr_next_entry_by_tag(slrt, NULL, SLR_ENTRY_LOG_INFO);
	if (!log_info)
		sl_txt_reset(SL_ERROR_SLRT_MISSING_ENTRY);

	evtlog_base = (void *)log_info->addr;
	evtlog_size = log_info->size;

	txt_heap = (void *)sl_txt_read(TXT_CR_HEAP_BASE);

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
	log21_elem = tpm2_find_log2_1_element(os_sinit_data);

	/* If found, this implies TPM2 log and family */
	if (log21_elem)
		tpm_log_ver = SL_TPM2_LOG;
}

static void sl_validate_event_log_buffer(void)
{
	struct txt_os_sinit_data *os_sinit_data;
	void *txt_heap, *txt_end;
	void *mle_base, *mle_end;
	void *evtlog_end;

	if ((u64)evtlog_size > (LLONG_MAX - (u64)evtlog_base))
		sl_txt_reset(SL_ERROR_INTEGER_OVERFLOW);
	evtlog_end = evtlog_base + evtlog_size;

	txt_heap = (void *)sl_txt_read(TXT_CR_HEAP_BASE);
	txt_end = txt_heap + sl_txt_read(TXT_CR_HEAP_SIZE);
	os_sinit_data = txt_os_sinit_data_start(txt_heap);

	mle_base = (void *)(u64)sl_mle_start;
	mle_end = mle_base + os_sinit_data->mle_size;

	/*
	 * This check is to ensure the event log buffer does not overlap with
	 * the MLE image.
	 */
	if (evtlog_base >= mle_end && evtlog_end > mle_end)
		goto pmr_check; /* above */

	if (evtlog_end <= mle_base && evtlog_base < mle_base)
		goto pmr_check; /* below */

	sl_txt_reset(SL_ERROR_MLE_BUFFER_OVERLAP);

pmr_check:
	/*
	 * The TXT heap is protected by the DPR. If the TPM event log is
	 * inside the TXT heap, there is no need for a PMR check.
	 */
	if (evtlog_base > txt_heap && evtlog_end < txt_end)
		return;

	sl_check_pmr_coverage(evtlog_base, evtlog_size, true);
}

static void sl_find_event_log_algorithms(void)
{
	struct tcg_efi_specid_event_head *efi_head =
		(struct tcg_efi_specid_event_head *)(evtlog_base +
					log21_elem->first_record_offset +
					sizeof(struct tcg_pcr_event));

	if (efi_head->num_algs == 0 || efi_head->num_algs > SL_TPM2_MAX_ALGS)
		sl_txt_reset(SL_ERROR_TPM_NUMBER_ALGS);

	memcpy(&tpm_algs[0], &efi_head->digest_sizes[0],
	       sizeof(struct tcg_efi_specid_event_algs) * efi_head->num_algs);
}

static void sl_tpm_log_event(u32 pcr, u32 event_type,
			     const u8 *data, u32 length,
			     const u8 *event_data, u32 event_size)
{
	u8 sha1_hash[SHA1_DIGEST_SIZE] = {0};
	u8 log_buf[SL_TPM_LOG_SIZE] = {0};
	struct tcg_pcr_event *pcr_event;
	u32 total_size;

	pcr_event = (struct tcg_pcr_event *)log_buf;
	pcr_event->pcr_idx = pcr;
	pcr_event->event_type = event_type;
	if (length > 0) {
		sha1(data, length, &sha1_hash[0]);
		memcpy(&pcr_event->digest[0], &sha1_hash[0], SHA1_DIGEST_SIZE);
	}
	pcr_event->event_size = event_size;
	if (event_size > 0)
		memcpy((u8 *)pcr_event + sizeof(*pcr_event),
		       event_data, event_size);

	total_size = sizeof(*pcr_event) + event_size;

	if (tpm_log_event(evtlog_base, evtlog_size, total_size, pcr_event))
		sl_txt_reset(SL_ERROR_TPM_LOGGING_FAILED);
}

static void sl_tpm2_log_event(u32 pcr, u32 event_type,
			      const u8 *data, u32 length,
			      const u8 *event_data, u32 event_size)
{
	u8 sha256_hash[SHA256_DIGEST_SIZE] = {0};
	u8 sha1_hash[SHA1_DIGEST_SIZE] = {0};
	u8 log_buf[SL_TPM2_LOG_SIZE] = {0};
	struct sha256_state sctx256 = {0};
	struct tcg_pcr_event2_head *head;
	struct tcg_event_field *event;
	u32 total_size, alg_idx;
	u16 *alg_ptr;
	u8 *dgst_ptr;

	head = (struct tcg_pcr_event2_head *)log_buf;
	head->pcr_idx = pcr;
	head->event_type = event_type;
	total_size = sizeof(*head);
	alg_ptr = (u16 *)(log_buf + sizeof(*head));

	for (alg_idx = 0; alg_idx < SL_TPM2_MAX_ALGS; alg_idx++) {
		if (!tpm_algs[alg_idx].alg_id)
			break;

		*alg_ptr = tpm_algs[alg_idx].alg_id;
		dgst_ptr = (u8 *)alg_ptr + sizeof(u16);

		if (tpm_algs[alg_idx].alg_id == TPM_ALG_SHA256) {
			sha256_init(&sctx256);
			sha256_update(&sctx256, data, length);
			sha256_final(&sctx256, &sha256_hash[0]);
			memcpy(dgst_ptr, &sha256_hash[0], SHA256_DIGEST_SIZE);
			total_size += SHA256_DIGEST_SIZE + sizeof(u16);
			alg_ptr = (u16 *)((u8 *)alg_ptr + SHA256_DIGEST_SIZE + sizeof(u16));
		} else if (tpm_algs[alg_idx].alg_id == TPM_ALG_SHA1) {
			sha1(data, length, &sha1_hash[0]);
			memcpy(dgst_ptr, &sha1_hash[0], SHA1_DIGEST_SIZE);
			total_size += SHA1_DIGEST_SIZE + sizeof(u16);
			alg_ptr = (u16 *)((u8 *)alg_ptr + SHA1_DIGEST_SIZE + sizeof(u16));
		} else {
			sl_txt_reset(SL_ERROR_TPM_UNKNOWN_DIGEST);
		}

		head->count++;
	}

	event = (struct tcg_event_field *)(log_buf + total_size);
	event->event_size = event_size;
	if (event_size > 0)
		memcpy((u8 *)event + sizeof(*event), event_data, event_size);
	total_size += sizeof(*event) + event_size;

	if (tpm2_log_event(log21_elem, evtlog_base, evtlog_size, total_size, &log_buf[0]))
		sl_txt_reset(SL_ERROR_TPM_LOGGING_FAILED);
}

static void sl_tpm_extend_evtlog(u32 pcr, u32 type,
				 const u8 *data, u32 length, const char *desc)
{
	if (tpm_log_ver == SL_TPM2_LOG)
		sl_tpm2_log_event(pcr, type, data, length,
				  (const u8 *)desc, strlen(desc));
	else
		sl_tpm_log_event(pcr, type, data, length,
				 (const u8 *)desc, strlen(desc));
}

static struct setup_data *sl_handle_setup_data(struct setup_data *curr,
					       struct slr_policy_entry *entry)
{
	struct setup_indirect *ind;
	struct setup_data *next;

	if (!curr)
		return NULL;

	next = (struct setup_data *)(unsigned long)curr->next;

	/* SETUP_INDIRECT instances have to be handled differently */
	if (curr->type == SETUP_INDIRECT) {
		ind = (struct setup_indirect *)((u8 *)curr + offsetof(struct setup_data, data));

		sl_check_pmr_coverage((void *)ind->addr, ind->len, true);

		sl_tpm_extend_evtlog(entry->pcr, TXT_EVTYPE_SLAUNCH,
				     (void *)ind->addr, ind->len,
				     entry->evt_info);

		return next;
	}

	sl_check_pmr_coverage(((u8 *)curr) + sizeof(*curr),
			      curr->len, true);

	sl_tpm_extend_evtlog(entry->pcr, TXT_EVTYPE_SLAUNCH,
			     ((u8 *)curr) + sizeof(*curr),
			     curr->len,
			     entry->evt_info);

	return next;
}

static void sl_extend_setup_data(struct slr_policy_entry *entry)
{
	struct setup_data *data;

	/*
	 * Measuring the boot params measured the fixed e820 memory map.
	 * Measure any setup_data entries including e820 extended entries.
	 */
	data = (struct setup_data *)(unsigned long)entry->entity;
	while (data)
		data = sl_handle_setup_data(data, entry);
}

static void sl_extend_slrt(struct slr_policy_entry *entry)
{
	struct slr_table *slrt = (struct slr_table *)entry->entity;
	struct slr_entry_intel_info *intel_info;

	/*
	 * In revision one of the SLRT, the only table that needs to be
	 * measured is the Intel info table. Everything else is meta-data,
	 * addresses and sizes. Note the size of what to measure is not set.
	 * The flag SLR_POLICY_IMPLICIT_SIZE leaves it to the measuring code
	 * to sort out.
	 */
	if (slrt->revision == 1) {
		intel_info = slr_next_entry_by_tag(slrt, NULL, SLR_ENTRY_INTEL_INFO);
		if (!intel_info)
			sl_txt_reset(SL_ERROR_SLRT_MISSING_ENTRY);

		sl_tpm_extend_evtlog(entry->pcr, TXT_EVTYPE_SLAUNCH,
				     (void *)entry->entity, sizeof(*intel_info),
				     entry->evt_info);
	}
}

static void sl_extend_txt_os2mle(struct slr_policy_entry *entry)
{
	struct txt_os_mle_data *os_mle_data;
	void *txt_heap;

	txt_heap = (void *)sl_txt_read(TXT_CR_HEAP_BASE);
	os_mle_data = txt_os_mle_data_start(txt_heap);

	/*
	 * Version 1 of the OS-MLE heap structure has no fields to measure. It just
	 * has addresses and sizes and a scratch buffer.
	 */
	if (os_mle_data->version == 1)
		return;
}

/*
 * Process all policy entries and extend the measurements to the evtlog
 */
static void sl_process_extend_policy(struct slr_table *slrt)
{
	struct slr_entry_policy *policy;
	u16 i;

	policy = slr_next_entry_by_tag(slrt, NULL, SLR_ENTRY_ENTRY_POLICY);
	if (!policy)
		sl_txt_reset(SL_ERROR_SLRT_MISSING_ENTRY);

	for (i = 0; i < policy->nr_entries; i++) {
		switch (policy->policy_entries[i].entity_type) {
		case SLR_ET_SETUP_DATA:
			sl_extend_setup_data(&policy->policy_entries[i]);
			break;
		case SLR_ET_SLRT:
			sl_extend_slrt(&policy->policy_entries[i]);
			break;
		case SLR_ET_TXT_OS2MLE:
			sl_extend_txt_os2mle(&policy->policy_entries[i]);
			break;
		case SLR_ET_UNUSED:
			continue;
		default:
			sl_tpm_extend_evtlog(policy->policy_entries[i].pcr, TXT_EVTYPE_SLAUNCH,
					     (void *)policy->policy_entries[i].entity,
					     policy->policy_entries[i].size,
					     policy->policy_entries[i].evt_info);
		}
	}
}

/*
 * Process all EFI config entries and extend the measurements to the evtlog
 */
static void sl_process_extend_uefi_config(struct slr_table *slrt)
{
	struct slr_entry_uefi_config *uefi_config;
	u16 i;

	uefi_config = slr_next_entry_by_tag(slrt, NULL, SLR_ENTRY_UEFI_CONFIG);

	/* Optionally here depending on how SL kernel was booted */
	if (!uefi_config)
		return;

	for (i = 0; i < uefi_config->nr_entries; i++) {
		sl_tpm_extend_evtlog(uefi_config->uefi_cfg_entries[i].pcr, TXT_EVTYPE_SLAUNCH,
				     (void *)uefi_config->uefi_cfg_entries[i].cfg,
				     uefi_config->uefi_cfg_entries[i].size,
				     uefi_config->uefi_cfg_entries[i].evt_info);
	}
}

asmlinkage __visible void sl_check_region(void *base, u32 size)
{
	sl_check_pmr_coverage(base, size, false);
}

asmlinkage __visible void sl_main(void *bootparams)
{
	struct boot_params *bp  = (struct boot_params *)bootparams;
	struct txt_os_mle_data *os_mle_data;
	struct slr_table *slrt;
	void *txt_heap;

	/*
	 * Ensure loadflags do not indicate a secure launch was done
	 * unless it really was.
	 */
	bp->hdr.loadflags &= ~SLAUNCH_FLAG;

	/*
	 * Currently only Intel TXT is supported for Secure Launch. Testing
	 * this value also indicates that the kernel was booted successfully
	 * through the Secure Launch entry point and is in SMX mode.
	 */
	if (!(sl_cpu_type & SL_CPU_INTEL))
		return;

	slrt = sl_locate_and_validate_slrt();

	/* Locate the TPM event log. */
	sl_find_drtm_event_log(slrt);

	/* Validate the location of the event log buffer before using it */
	sl_validate_event_log_buffer();

	/*
	 * Find the TPM hash algorithms used by the ACM and recorded in the
	 * event log.
	 */
	if (tpm_log_ver == SL_TPM2_LOG)
		sl_find_event_log_algorithms();

	/*
	 * Sanitize them before measuring. Set the SLAUNCH_FLAG early since if
	 * anything fails, the system will reset anyway.
	 */
	sanitize_boot_params(bp);
	bp->hdr.loadflags |= SLAUNCH_FLAG;

	sl_check_pmr_coverage(bootparams, PAGE_SIZE, false);

	/* Place event log SL specific tags before and after measurements */
	sl_tpm_extend_evtlog(17, TXT_EVTYPE_SLAUNCH_START, NULL, 0, "");

	sl_process_extend_policy(slrt);

	sl_process_extend_uefi_config(slrt);

	sl_tpm_extend_evtlog(17, TXT_EVTYPE_SLAUNCH_END, NULL, 0, "");

	/* No PMR check is needed, the TXT heap is covered by the DPR */
	txt_heap = (void *)sl_txt_read(TXT_CR_HEAP_BASE);
	os_mle_data = txt_os_mle_data_start(txt_heap);

	/*
	 * Now that the OS-MLE data is measured, ensure the MTRR and
	 * misc enable MSRs are what we expect.
	 */
	sl_txt_validate_msrs(os_mle_data);
}
