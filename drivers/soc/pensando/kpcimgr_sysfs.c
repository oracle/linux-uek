// SPDX-License-Identifier: GPL-2.0
/*
 * Kernel PCIE Manager SYSFS functions
 *
 * Copyright (c) 2021, 2022, Oracle and/or its affiliates.
 */

#include "kpcimgr_api.h"

#include <linux/elf.h>
#include <linux/stacktrace.h>
#include <linux/panic_notifier.h>
#include <linux/module_signature.h>
#include <linux/verification.h>
#include <linux/security.h>
#include <linux/firmware.h>

int kpcimgr_active_port;

/*
 * Check if an offset falls within the provided firmware's text section
 */
static int within_fw_text(struct fw_info_t *fw, unsigned long offset)
{
	if (offset >= fw->text_off && offset < ALIGN(fw->text_off + fw->text_size, PAGE_SIZE))
		return 1;
	else
		return 0;
}

/*
 * Return a formatted string for the function containing the provided address.
 */
static char *firmware_format_sym(unsigned long panic_addr)
{
	static char buffer[KSYM_SYMBOL_LEN];
	kstate_t *ks = get_kstate();
	Elf64_Sym *iter, *candidate;
	unsigned long panic_off;
	struct fw_info_t *fw;
	int i;

	fw = get_fw_info(ks->code_base);

	/* Calculate offset from ks->code_base and check if it falls within firmware text */
	panic_off = panic_addr - (unsigned long) ks->code_base;
	if (!within_fw_text(fw, panic_off)) {
		sprint_symbol(buffer, panic_addr);
		return buffer;
	}

	candidate = ks->code_base + fw->symtab_off;

	/* Locate the function containing the panic address */
	for (i = 0, iter = candidate; i < fw->n_syms; i++, iter++) {
		if ((iter->st_info & STT_FUNC) == 0)
			continue;

		if (iter->st_value > candidate->st_value && iter->st_value <= panic_off)
			candidate = iter;
	}

	/* Format elf data into string for panic dump */
	snprintf(buffer, KSYM_SYMBOL_LEN, "%s+%#lx/%#lx [pciesvc.lib]",
		 (char *)((unsigned long)ks->code_base + fw->strtab_off + candidate->st_name),
		 panic_off - (unsigned long) candidate->st_value,
		 (unsigned long) candidate->st_size);

	return buffer;
}

/*
 * Check whether the firmware code appears anywhere in the panic stack trace.
 */
static int fw_code_on_stack(unsigned long entries[], int nr_entries)
{
	kstate_t *ks = get_kstate();
	struct fw_info_t *fw;
	int i;

	if (!ks->valid)
		return 0;

	fw = get_fw_info(ks->code_base);
	if (fw->valid != FW_INFO_MAGIC_V1 && fw->valid != FW_INFO_MAGIC_V2)
		return 0;

	for (i = 0; i < nr_entries; i++) {
		if (within_fw_text(fw, entries[i] - (unsigned long) ks->code_base))
			return 1;
	}

	return 0;
}

/*
 * Panic hook. On systems with kdump enabled, this won't get called unless you put
 * "crash_kexec_post_notifiers" on the boot command line.
 */
static int firmware_panic(struct notifier_block *nb, unsigned long code, void *unused)
{
	unsigned long entries[48];
	int i, nr_entries;

	nr_entries = stack_trace_save(entries, ARRAY_SIZE(entries), 0);

	if (fw_code_on_stack(entries, nr_entries)) {
		pr_emerg("====== kpcimgr firmware stack trace: ======\n");
		for (i = 0; i < nr_entries; i++)
			pr_emerg("%s\n", firmware_format_sym(entries[i]));
	}

	return NOTIFY_DONE;
}

/*
 * Check if the provided elf section will overlap the firmware's text section in any way.
 */
static int sect_overlaps_text(struct fw_info_t *fw, Elf64_Shdr *sh)
{
	unsigned long section_end = sh->sh_offset + sh->sh_size;

	if (within_fw_text(fw, sh->sh_offset))
		return 1;

	if (within_fw_text(fw, section_end))
		return 1;

	if (sh->sh_offset <= fw->text_off &&
	    section_end >= ALIGN(fw->text_off + fw->text_size, PAGE_SIZE)) {
		return 1;
	}

	return 0;
}

/*
 * Check library signature
 */
static int verify_firmware(void *image, ssize_t image_size)
{
	const unsigned long markerlen = sizeof(MODULE_SIG_STRING) - 1;
	size_t sig_len, modlen = image_size;
	const struct module_signature *ms;
	const char *reason;
	int err;

	if (modlen <= markerlen) {
		pr_info("KPCIMGR: invalid image length\n");
		return 1;
	}

	if (memcmp(image + modlen - markerlen, MODULE_SIG_STRING, markerlen)) {
		pr_info("KPCIMGR: invalid signature marker\n");
		return 1;
	}

	modlen -= markerlen;
	if (modlen <= sizeof(ms)) {
		pr_info("KPCIMGR: invalid image length\n");
		return 1;
	}

	ms = (const struct module_signature *) (image + modlen - sizeof(*ms));
	if (mod_check_sig(ms, modlen, "KPCIMGR")) {
		return 1;
	}

	sig_len = be32_to_cpu(ms->sig_len);
	modlen -= sig_len + sizeof(*ms);

	pr_info("KPCIMGR: verify_firmware(0x%lx, %lx), sig_len=%lx, modlen=%lx\n",
		(long) image, image_size, sig_len, modlen);

	err = verify_pkcs7_signature(image, modlen, image + modlen, sig_len,
				     VERIFY_USE_SECONDARY_KEYRING,
				     VERIFYING_MODULE_SIGNATURE,
				     NULL, NULL);

	switch (err) {
	case 0:
		pr_info("KPCIMGR: signature check ok\n");
		return 0;
	case -EKEYREJECTED:
		reason = "module with invalid key";
		break;
        case -ENODATA:
                reason = "unsigned module";
                break;
        case -ENOPKG:
                reason = "module with unsupported crypto";
                break;
        case -ENOKEY:
                reason = "module with unavailable key";
                break;

        default:
		pr_info("KPCIMGR: err=%d from verify_pkcs7_signature\n", err);
		return err;
	}

	pr_notice("KPCIMGR: Loading of %s\n", reason);
	return err;
}

/*
 * Perform checks on ELF object obtained via request_firmware(). As
 * checks are performed, the fw_info_t stored in the .pciesvc_info
 * section will be filled out to provide immediate access to important
 * areas in the future.
 */
static int prepare_firmware(void *fw_image, ssize_t image_size)
{
	struct fw_info_t *fw;
	char *sh_strtbl;
	Elf64_Shdr *sh;
	Elf64_Ehdr *h;
	void *image;
	int i, ret;

	if (fw_image == NULL || image_size == 0) {
		pr_info("KPCIMGR: no firmware staged for running\n");
		return -EINVAL;
	}

	if (image_size < FW_INFO_OFFSET + FW_INFO_MAX_SIZE) {
		pr_info("KPCIMGR: firmware size is too small\n");
		return -EINVAL;
	}

	/* must make copy of elf object since release_firmware() will free it */
	image = module_alloc(image_size);
	if (image == NULL) {
		pr_err("KPCIMGR: firmware module_alloc\n");
		return -ENOMEM;
	}
	memcpy(image, fw_image, image_size);

	h = image;
	/* Check for ELF magic, correct architecture and endianness */
	if ((memcmp(h->e_ident, ELFMAG, SELFMAG) != 0) || (h->e_machine != EM_AARCH64) ||
	    (h->e_ident[EI_DATA] != ELFDATA2LSB)) {
		pr_info("KPCIMGR: firmware is not a valid ELF file\n");
		ret = -EINVAL;
		goto out;
	}

	/*
	 * The ordering of first few sections of the firmware are expected to be as follows:
	 * sh[0] = NULL section (and is thus skipped)
	 * sh[1] = .pciesvc_info
	 * sh[2] = .text
	 * sh[...] = order doesn't matter
	 */

	if (h->e_shoff > image_size) {
		pr_info("KPCIMGR: firmware is not a valid ELF file, e_shoff out of range\n");
		ret = -EINVAL;
		goto out;
	}

	sh = image + h->e_shoff;
	if ((void *) &sh[h->e_shstrndx + 1] > image + image_size) {
		pr_info("KPCIMGR: firmware is not a valid ELF file, e_shstrndx out of range\n");
		ret = -EINVAL;
		goto out;
	}

	if (sh[h->e_shstrndx].sh_size == 0 ||
	    sh[h->e_shstrndx].sh_size + sh[h->e_shstrndx].sh_offset > image_size) {
		pr_info("KPCIMGR: firmware is not a valid ELF file, sh_strtbl out of range\n");
		ret = -EINVAL;
		goto out;
	}

	sh_strtbl = image + sh[h->e_shstrndx].sh_offset;
	if (sh_strtbl[sh[h->e_shstrndx].sh_size - 1] != '\0') {
		pr_info("KPCIMGR: firmware sh_strtbl not NULL terminated\n");
		ret = -EINVAL;
		goto out;
	}

	/* Skip over NULL section and validate .pciesvc_info section */
	sh++;
	if ((void *)(sh + 1) > image + image_size) {
		pr_info("KPCIMGR: firmware is not a valid ELF file, section 1 out of range\n");
		ret = -EINVAL;
		goto out;
	}

	if (sh->sh_offset != FW_INFO_OFFSET ||
	    strcmp(sh_strtbl + sh->sh_name, ".pciesvc_info") ||
	    sh->sh_size != sizeof(struct fw_info_t)) {
		pr_info("KPCIMGR: .pciesvc_info section not found or incorrect\n");
		ret = -EINVAL;
		goto out;
	}

	fw = get_fw_info(image);
	if (fw->valid != FW_INFO_MAGIC_V1 && fw->valid != FW_INFO_MAGIC_V2) {
		pr_info("KPCIMGR: firmware magic number is incorrect (0x%x)\n", fw->valid);
		ret = -EINVAL;
		goto out;
	}

	fw->image_size = image_size;

	/* Validate the .text section */
	sh++;
	if ((void *)(sh + 1) > image + image_size) {
		pr_info("KPCIMGR: firmware is not a valid ELF file, section 2 out of range\n");
		ret = -EINVAL;
		goto out;
	}

	if (strcmp(sh_strtbl + sh->sh_name, ".text") != 0) {
		pr_info("KPCIMGR: First section was not .text\n");
		ret = -EINVAL;
		goto out;
	}

	if (sh->sh_addr != sh->sh_offset) {
		pr_info("KPCIMGR: ELF section offset and address do not match\n");
		ret = -EINVAL;
		goto out;
	}

	if (sh->sh_offset & ~PAGE_MASK) {
		pr_info("KPCIMGR: firmware text start is not aligned\n");
		ret = -EINVAL;
		goto out;
	}

	if (contains_external_refs((unsigned long) image, (unsigned long) image + image_size,
	    (unsigned long) image + sh->sh_offset,
	    (unsigned long) image + sh->sh_offset + sh->sh_size)) {
		pr_info("KPCIMGR: firmware contains external references\n");
		ret = -EINVAL;
		goto out;
	}

	fw->text_off = sh->sh_offset;
	fw->text_size = sh->sh_size;

	/* Check that all function offsets are within the image */
	for (i = 0; i < K_NUM_ENTRIES; i++) {
		if (!within_fw_text(fw, (unsigned long) fw->code_offsets[i])) {
			pr_info("KPCIMGR: code_offsets[%d] extends beyond image\n", i);
			ret = -EINVAL;
			goto out;
		}
	}

	fw->symtab_off = 0;
	fw->strtab_off = 0;
	fw->n_syms = 0;
	sh++;

	/* Go through the rest of the ELF sections and save interesting data to the info struct */
	for (i = 3; i < h->e_shnum; i++, sh++) {

		if ((void *)(sh + 1) > image + image_size) {
			pr_info("KPCIMGR: section %d out of range\n", i);
			ret = -EINVAL;
			goto out;
		}

		if (sh->sh_offset > image_size || sh->sh_size > image_size ||
		    sh->sh_offset > image_size - sh->sh_size) {
			pr_info("KPCIMGR: ELF section extends beyond end of file\n");
			ret = -EINVAL;
			goto out;
		}

		if (sect_overlaps_text(fw, sh)) {
			pr_info("KPCIMGR: section %d overlaps .text\n", i);
			ret = -EINVAL;
			goto out;
		}

		/* The firmware executes in place so disallow sections that need to be moved */
		if (sh->sh_flags & SHF_ALLOC && (sh->sh_addr != sh->sh_offset)) {
			pr_info("KPCIMGR: ELF section offset and address do not match\n");
			ret = -EINVAL;
			goto out;
		}

		if (sh->sh_flags & SHF_EXECINSTR) {
			pr_info("KPCIMGR: Found executable section other than .text\n");
			ret = -EINVAL;
			goto out;
		}

		if (strcmp(sh_strtbl + sh->sh_name, ".symtab") == 0) {
			fw->symtab_off = sh->sh_offset;
			fw->n_syms = sh->sh_size / sh->sh_entsize;
		}

		if (strcmp(sh_strtbl + sh->sh_name, ".strtab") == 0)
			fw->strtab_off = sh->sh_offset;
	}

	if (fw->symtab_off == 0 || fw->strtab_off == 0) {
		pr_info("KPCIMGR: firmware symbol table or string table not found\n");
		ret = -EINVAL;
		goto out;
	}

	flush_icache_range((unsigned long)image + fw->text_off,
			   (unsigned long)image + fw->text_off + fw->text_size);
	set_memory_x((unsigned long)image + fw->text_off,
		     (fw->text_size + PAGE_SIZE - 1) >> PAGE_SHIFT);

	ret = load_firmware(image);
out:
	if (ret) {
		pr_err("KPCIMGR: failed to load firmware\n");
		module_memfree(image);
	}

	return ret;
}

/* 'valid' read returns value of valid field */
static ssize_t valid_show(struct device *dev,
			  struct device_attribute *attr,
			  char *buf)
{
	kstate_t *ks = get_kstate();

	return sprintf(buf, "%x\n", ks->valid);
}

/* 'valid' write causes invalidation, regardless of value written */
static ssize_t valid_store(struct device *dev,
			   struct device_attribute *attr,
			   const char *buf,
			   size_t count)
{
	kstate_t *ks = get_kstate();

	if (ks->running) {
		kpcimgr_stop_running();
		pr_info("%s: kpcimgr has stopped running\n", __func__);
	}
	ks->valid = 0;
	ks->debug = 0;
	if (ks->mod) {
		module_put(ks->mod);
		ks->mod = NULL;
	} else {
		module_memfree(ks->code_base);
	}

	ks->code_base = NULL;
	ks->code_size = 0;

	pr_info("%s: code unloaded\n", __func__);
	return count;
}

static ssize_t running_show(struct device *dev,
			    struct device_attribute *attr,
			    char *buf)
{
	kstate_t *ks = get_kstate();

	return sprintf(buf, "%x\n", ks->running | ks->debug);
}

static ssize_t running_store(struct device *dev,
			     struct device_attribute *attr,
			     const char *buf,
			     size_t count)
{
	kstate_t *ks = get_kstate();
	ssize_t rc;
	long val;

	rc = kstrtol(buf, 0, &val);
	if (rc)
		return rc;

	if (!ks->valid)
		return -EINVAL;

	if (val == 0) {
		if (ks->running) {
			kpcimgr_stop_running();
			pr_info("%s: kpcimgr has stopped polling\n", __func__);
		}
	} else {
		if (ks->running) {
			pr_info("%s: kpcimgr is already running\n", __func__);
		} else {
			/*
			 * For compatibility with older versions of the pciesvc module,
			 * we are setting active_port_compat to the actual port number.
			 * For newer versions with bifurcation support, we have  active_port_mask
			*/
			ks->active_port_compat = ffs(kpcimgr_active_port) - 1;
			ks->active_port_mask = kpcimgr_active_port;
			pr_info("%s: kpcimgr will begin running with port mask 0x%x\n",
				__func__, ks->active_port_mask);
			kpcimgr_start_running();
		}
		ks->debug = val & 0xfff0;
	}

	return count;
}

static ssize_t cfgval_show(struct device *dev,
			   struct device_attribute *attr,
			   char *buf)
{
	kstate_t *ks = get_kstate();

	return sprintf(buf, "%x\n", ks->cfgval);
}

static ssize_t cfgval_store(struct device *dev,
			    struct device_attribute *attr,
			    const char *buf,
			    size_t count)
{
	kstate_t *ks = get_kstate();
	ssize_t rc;
	long val;

	rc = kstrtol(buf, 0, &val);
	if (rc)
		return rc;

	if (!ks->valid)
		return -EINVAL;

	ks->cfgval = val;
	return count;
}

static ssize_t range_store(struct device *dev,
			   struct device_attribute *attr,
			   const char *buf,
			   size_t count)
{
	unsigned long range_start, flags;
	kstate_t *ks = get_kstate();
	struct mem_range_t *mr;
	ssize_t size;
	int i = 0;

	if (sscanf(buf, " 0x%lx , 0x%lx ", &range_start, &size) != 2)
		return -EINVAL;

	/* Remove the range if size == 0 */
	if (size == 0) {
		/* Locate target range and remove it */
		for (i = 0, mr = &ks->mem_ranges[0]; i < ks->nranges; i++, mr++) {
			if (mr->base == range_start) {
				spin_lock_irqsave(&kpcimgr_lock, flags);
				iounmap(mr->vaddr);
				ks->nranges--;
				memcpy(mr, &ks->mem_ranges[ks->nranges],
				       sizeof(struct mem_range_t));
				spin_unlock_irqrestore(&kpcimgr_lock, flags);
				return count;
			}
		}
		return -EINVAL;
	}

	/* size != 0, so start the process to add a new range */
	if (ks->nranges == NUM_MEMRANGES)
		return -ENOSPC;

	/* Verify the new range doesn't overlap any existing regions */
	for (i = 0, mr = &ks->mem_ranges[0]; i < ks->nranges; i++, mr++) {
		if ((mr->base <= range_start && range_start < mr->end) ||
			(range_start < mr->base && mr->base < range_start + size))
			return -EINVAL;
	}

	mr->base = range_start;
	mr->end = range_start + size;
	mr->vaddr = ioremap(range_start, size);

	if (!mr->vaddr)
		return -ENOMEM;

	ks->nranges++;
	return count;

}

static ssize_t ranges_show(struct device *dev,
			   struct device_attribute *attr,
			   char *buf)
{
	kstate_t *ks = get_kstate();
	struct mem_range_t *range;
	ssize_t len = 0;
	int i;

	for (i = 0, range = &ks->mem_ranges[0]; i < ks->nranges; i++, range++)
		len += sysfs_emit_at(buf, len, "0x%lx,0x%lx\n", range->base,
				     range->end - range->base);

	return len;
}

static ssize_t lib_version_show(struct device *dev,
				struct device_attribute *attr,
				char *buf)
{
	kstate_t *ks = get_kstate();

	if (!ks->valid)
		return -ENODEV;

	return sprintf(buf, "%d.%d\n", ks->lib_version_major,
		       ks->lib_version_minor);
}

static ssize_t mgr_version_show(struct device *dev,
				struct device_attribute *attr,
				char *buf)
{
	return sprintf(buf, "%d\n", KPCIMGR_KERNEL_VERSION);
}

static ssize_t command_read(struct file *file, struct kobject *kobj,
			    struct bin_attribute *attr, char *out,
			    loff_t off, size_t count)
{
	int (*cmd_read)(kstate_t *, char *, loff_t, size_t, int *);
	kstate_t *ks = get_kstate();
	int ret, success = 0;
	unsigned long flags;

	if (!ks->valid)
		return -ENODEV;
	cmd_read = ks->code_base + ks->code_offsets[K_ENTRY_CMD_READ];
	spin_lock_irqsave(&kpcimgr_lock, flags);
	ret = cmd_read(ks, out, off, count, &success);
	spin_unlock_irqrestore(&kpcimgr_lock, flags);
	if (success)
		return ret;
	else
		return 0;
}

static ssize_t command_write(struct file *filp, struct kobject *kobj,
			     struct bin_attribute *bin_attr, char *buf,
			     loff_t off, size_t count)
{
	int (*cmd_write)(kstate_t *, const char *, loff_t, size_t, int *);
	kstate_t *ks = get_kstate();
	int ret, success = 0;
	unsigned long flags;

	if (!ks->valid)
		return -ENODEV;
	cmd_write = ks->code_base + ks->code_offsets[K_ENTRY_CMD_WRITE];
	spin_lock_irqsave(&kpcimgr_lock, flags);
	ret = cmd_write(ks, buf, off, count, &success);
	spin_unlock_irqrestore(&kpcimgr_lock, flags);
	if (success)
		return ret;
	else
		return count;
}

/* event queue peek */
static ssize_t event_queue_read(struct file *file, struct kobject *kobj,
				struct bin_attribute *attr, char *out,
				loff_t off, size_t count)
{
	kstate_t *ks = get_kstate();

	/* is queue empty? */
	if (ks->evq_head == ks->evq_tail)
		return 0;

	kpci_memcpy(out, (void *)ks->evq[ks->evq_tail], EVENT_SIZE);
	return EVENT_SIZE;
}

/*
 * This function is for testing. It injects an event onto the
 * event queue, simulating an event notification from h/w.
 */
static ssize_t event_queue_write(struct file *filp, struct kobject *kobj,
				 struct bin_attribute *bin_attr, char *buf,
				 loff_t off, size_t count)
{
	kstate_t *ks = get_kstate();

	if (count != EVENT_SIZE)
		return -EINVAL;

	if ((ks->evq_head + 1) % EVENT_QUEUE_LENGTH == ks->evq_tail)
		return -ENOSPC;

	kpci_memcpy((void *)ks->evq[ks->evq_head], buf, EVENT_SIZE);
	ks->evq_head = (ks->evq_head + 1) % EVENT_QUEUE_LENGTH;
	wake_up_event_queue();

	return EVENT_SIZE;
}

static ssize_t kstate_read(struct file *file, struct kobject *kobj,
			   struct bin_attribute *attr, char *out,
			   loff_t off, size_t count)
{
	kstate_t *ks = get_kstate();

	kpci_memcpy(out, (void *)ks + off, count);
	return count;
}

/*
 * Read firmware from /lib/firmware/pciesvc.lib, verify signature, and
 * prepare it for execution within kpcimgr.
 */
static ssize_t fwload_store(struct device *dev,
			    struct device_attribute *attr,
			    const char *buf,
			    size_t count)
{
	struct platform_device *pfdev;
	const struct firmware *fw;
	kstate_t *ks;
	int ret;

	ks = get_kstate();
	if (!ks)
		return -ENODEV;
	pfdev = (struct platform_device *)ks->pfdev;

	if (request_firmware(&fw, "pciesvc.lib", &pfdev->dev))
		return -ENOMEM;

	if (verify_firmware((void *)fw->data, fw->size)) {
		if (is_module_sig_enforced()) {
			pr_info("KPCIMGR: rejecting module with err=%d\n", ret);
			ret = -EKEYREJECTED;
			goto out;
		}

		if (security_locked_down(LOCKDOWN_MODULE_SIGNATURE)) {
			pr_err("KPCIMGR: security locked down\n");
			ret = -EKEYREJECTED;
			goto out;
		}
	}
	pr_info("KPCIMGR: accepting module signature\n");

	ret = prepare_firmware((void *)fw->data, fw->size);
out:
	release_firmware(fw);
	if (ret)
		return ret;
	else
		return count;
}

static DEVICE_ATTR_RW(valid);
static DEVICE_ATTR_RW(running);
static DEVICE_ATTR_RW(cfgval);
static DEVICE_ATTR_WO(range);
static DEVICE_ATTR_WO(fwload);
static DEVICE_ATTR_RO(ranges);
static DEVICE_ATTR_RO(lib_version);
static DEVICE_ATTR_RO(mgr_version);
static DEVICE_INT_ATTR(active_port, 0644, kpcimgr_active_port);
static BIN_ATTR_RO(kstate, sizeof(kstate_t));
static BIN_ATTR_RW(event_queue, EVENT_SIZE);
static BIN_ATTR_RW(command, CMD_SIZE);

static struct attribute *dev_attrs[] = {
	&dev_attr_valid.attr,
	&dev_attr_running.attr,
	&dev_attr_cfgval.attr,
	&dev_attr_fwload.attr,
	&dev_attr_range.attr,
	&dev_attr_ranges.attr,
	&dev_attr_active_port.attr.attr,
	&dev_attr_lib_version.attr,
	&dev_attr_mgr_version.attr,
	NULL,
};

static struct bin_attribute *dev_bin_attrs[] = {
	&bin_attr_kstate,
	&bin_attr_event_queue,
	&bin_attr_command,
	NULL,
};

const struct attribute_group kpci_attr_group = {
	.attrs = dev_attrs,
	.bin_attrs = dev_bin_attrs,
};

void kpcimgr_sysfs_setup(struct platform_device *pfdev)
{
	static struct notifier_block panic_notifier = {
		.notifier_call = firmware_panic,
	};

	if (sysfs_create_group(&pfdev->dev.kobj, &kpci_attr_group)) {
		pr_err("KPCIMGR:sysfs_create_group failed\n");
		return;
	}

	if (sysfs_create_link(kernel_kobj, &pfdev->dev.kobj, "kpcimgr")) {
		pr_err("KPCIMGR: failed to create sysfs link\n");
		return;
	}

	/* register panic notifier */
	atomic_notifier_chain_register(&panic_notifier_list, &panic_notifier);
}
