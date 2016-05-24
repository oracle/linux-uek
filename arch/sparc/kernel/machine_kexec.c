#include <linux/kernel.h>
#include <linux/kexec.h>
#include <linux/delay.h>
#include <linux/irq.h>
#include <linux/cpu.h>
#include <asm/spitfire.h>
#include <asm/pgtable_64.h>
#include <asm/head_64.h>
#include <asm/io_64.h>
#include <asm/nmi.h>
#include "kernel.h"

static atomic_t kexec_strand_wait;
static const unsigned int tte_order = 9U;

static int kexec_disable_irq;
static int __init setup_kexec_disable_irq(char *str)
{
	kexec_disable_irq = 1;
	return 0;
}
__setup("kexec_disable_irq=", setup_kexec_disable_irq);

static void machine_kexec_disable_irq(void)
{
	struct irq_desc *desc;
	unsigned int i;

	if (!kexec_disable_irq)
		return;

	for_each_irq_desc(i, desc) {
		struct irq_chip *chip;

		chip = irq_desc_get_chip(desc);
		if (!chip)
			continue;

		if (chip->irq_disable)
			chip->irq_disable(&desc->irq_data);
	}
}

static unsigned long kexec_tte(unsigned long paddr)
{
	unsigned long val;

	val = (_PAGE_VALID | _PAGE_SZ64K_4V |
		_PAGE_CP_4V | _PAGE_CV_4V | _PAGE_P_4V |
		_PAGE_EXEC_4V | _PAGE_W_4V);

	return val | paddr;
}

static unsigned long compute_nr_tte(unsigned long memsz)
{
	return  (memsz + ((1UL << (PAGE_SHIFT + tte_order)) - 1)) >>
		(PAGE_SHIFT + tte_order);
}

static unsigned long kexec_nucleus_tte(unsigned long paddr)
{
	unsigned long val;

	val = (_PAGE_VALID | _PAGE_SZ4MB_4V |
		_PAGE_CP_4V | _PAGE_CV_4V | _PAGE_P_4V |
		_PAGE_EXEC_4V | _PAGE_W_4V);

	return val | paddr;
}

static int kexec_tte_lock(unsigned long tte, unsigned long mmu)
{
	unsigned long rc = sun4v_mmu_map_perm_addr(KEXEC_BASE, 0, tte, mmu);

	if (rc) {
		pr_err("kexec_tte_lock: %ld\n", rc);
		return -EIO;
	} else
		return 0;
}

static unsigned long kexec_map_shim(void)
{
	struct sparc64_kexec_shim *shimp = kexec_shim();
	unsigned long tte_data;
	unsigned long phys_addr;
	int rc;

	phys_addr = kimage_addr_to_ra(shimp);
	tte_data = kexec_tte(phys_addr);

	rc = kexec_tte_lock(tte_data, HV_MMU_DMMU);
	if (rc)
		goto out;

	rc = kexec_tte_lock(tte_data, HV_MMU_IMMU);
	if (rc)
		goto out;

	phys_addr = kimage_addr_to_ra(&shimp->hv_fault);
out:
	return phys_addr;
}

int machine_kexec_prepare(struct kimage *image)
{
	struct sparc64_kexec_shim *shimp = kexec_shim();
	int rc = -ENODEV;

	if (tlb_type != hypervisor) {
		pr_err("machine_kexec_prepare: kexec is supported only on sun4v.\n");
		goto out;
	} else if (image->type == KEXEC_TYPE_CRASH) {
		unsigned long nr_tte = compute_nr_tte(image->segment[0].memsz);

		if (crashk_res.start == 0ULL) {
			pr_err("machine_kexec_prepare: kexec crash requires crashkernel boot parameter.\n");
			goto out;
		}

		if (nr_tte >= NR_KEXEC_TTE) {
			pr_err("machine_kexec_prepare:vmlinuz is too large.\n");
			rc = -ENOMEM;
			goto out;
		}
	}

	rc = 0;
	shimp->nr_tte = (unsigned long) num_kernel_image_mappings;
out:
	return rc;
}

static void mondo_tear_down(void)
{
	int cpu = smp_processor_id();
	unsigned long hverror;

	hverror = sun4v_cpu_qconf(HV_CPU_QUEUE_CPU_MONDO, 0UL, 0UL) |
		sun4v_cpu_qconf(HV_CPU_QUEUE_DEVICE_MONDO, 0UL, 0UL) |
		sun4v_cpu_qconf(HV_CPU_QUEUE_RES_ERROR, 0UL, 0UL) |
		sun4v_cpu_qconf(HV_CPU_QUEUE_NONRES_ERROR, 0UL, 0UL);
	if (hverror)
		pr_err("mondo_tead_down failed %ld for cpu %d.\n",
			hverror, cpu);
}

static void stop_strands(void)
{
	unsigned long hverror;
	int cpu;

	for_each_online_cpu(cpu) {
		if (cpu == smp_processor_id())
			continue;

		hverror = sun4v_cpu_stop(cpu);
		if (hverror)
			pr_err("machine_crash_shutdown failed with error %ld for cpu= %d.\n",
			       hverror,  cpu);
	}
}

static void machine_capture_other_strands(void *ignore)
{
	crash_save_cpu(get_irq_regs(), smp_processor_id());
	__asm__ __volatile__("flushw");
	if (atomic_read(&nmi_active) > 0)
		stop_nmi_watchdog(NULL);
	mondo_tear_down();
	atomic_dec(&kexec_strand_wait);
}

static void destroy_nucleus_tsb(void)
{
	unsigned long hverror = sun4v_mmu_tsb_ctx0(0UL, 0UL);

	if (hverror)
		pr_err("destroy_nucleus_tsb: failed with sun4v_mmu_tsb_ctx0 error %ld\n",
		       hverror);
}

void machine_crash_shutdown(struct pt_regs *regs)
{
	unsigned long msecs;

	if (atomic_read(&nmi_active) > 0)
		stop_nmi_watchdog(NULL);
	atomic_set(&kexec_strand_wait, num_online_cpus() - 1);
	smp_call_function(machine_capture_other_strands, NULL, false);
	msecs = 1000;
	while ((atomic_read(&kexec_strand_wait) > 0) && msecs) {
		mdelay(1);
		msecs--;
	}
	if (atomic_read(&kexec_strand_wait) > 0)
		pr_warn("Strand(s) didn't accept IPI for kexec\n");

	local_irq_disable();
	stop_strands();
	machine_kexec_disable_irq();
	destroy_nucleus_tsb();
	crash_save_cpu(regs, smp_processor_id());
}

void machine_kexec_cleanup(struct kimage *image)
{
}

static void machine_strand_mondo_rip(void *ignore)
{
	if (atomic_read(&nmi_active) > 0)
		stop_nmi_watchdog(NULL);
	mondo_tear_down();
	atomic_dec(&kexec_strand_wait);
}

void machine_shutdown(void)
{
	unsigned long msecs;

	if (atomic_read(&nmi_active) > 0)
		stop_nmi_watchdog(NULL);
	atomic_set(&kexec_strand_wait, num_online_cpus() - 1);
	smp_call_function(machine_strand_mondo_rip, NULL, false);
	msecs = 1000;
	while ((atomic_read(&kexec_strand_wait) > 0) && msecs) {
		mdelay(1);
		msecs--;
	}

	local_irq_disable();
	stop_strands();
	machine_kexec_disable_irq();
	destroy_nucleus_tsb();
}

static int kimage_arch_load_user_data(struct kimage *image,
		struct kexec_region *regp, struct kexec_segment *segment,
		int (*add_phys_addr)(struct kimage *image, unsigned long page))
{
	unsigned char __user *buf = segment->buf;
	size_t order_size = 1UL << (PAGE_SHIFT + tte_order);
	size_t mbytes = segment->bufsz;
	unsigned long nr = 0UL;
	int rc = -ENOMEM;
	struct page *page;
	unsigned long p;
	int error;
	size_t csize;

	while (mbytes) {
		page = kimage_alloc_pages(GFP_KERNEL, tte_order);
		if (!page)
			goto out;

		p = page_to_pfn(page) << PAGE_SHIFT;

		error = add_phys_addr(image, p);
		if (error) {
			__free_pages(page, tte_order);
			goto out;
		}

		csize = min_t(size_t, order_size, mbytes);
		error = copy_from_user((void *) __va(p), buf, csize);
		if (error)
			goto out;

		buf = buf + csize;
		mbytes = mbytes - csize;
		regp->tte[nr] = p;
		nr++;
	}
	rc = 0;
	regp->nr_tte = nr;
out:
	return rc;
}

static int kimage_arch_load_normal_segment_initrd(struct kimage *image,
		struct kexec_segment *segment,
		int (*add_phys_addr)(struct kimage *image, unsigned long page))
{
	unsigned long nr_tte;
	int rc = -ENOMEM;

	nr_tte = compute_nr_tte(segment->memsz);

	if (nr_tte > NR_KEXEC_TTE) {
		pr_err("kexec: initrd is too large.\n");
		goto out;
	}

	rc = kimage_arch_load_user_data(image, &image->arch.ki_initrd,
				segment, add_phys_addr);
out:
	return rc;
}

static int kimage_arch_load_normal_segment_kernel(struct kimage *image,
		struct kexec_segment *segment,
		int (*add_phys_addr)(struct kimage *image, unsigned long page))
{
	int i;
	unsigned long order_size = 1UL << (PAGE_SHIFT + tte_order);
	unsigned long nr_tte;
	unsigned int order;
	struct page *page;
	unsigned long p;
	struct kexec_region *regp = &image->arch.ki_kernel;
	int rc = -ENOMEM;

	nr_tte = compute_nr_tte(segment->memsz);

	/* For the kernel we need to reserve one pinned TTE for shim. */
	if (nr_tte >= NR_KEXEC_TTE) {
		pr_err("kexec: vmlinuz is too large.\n");
		goto out;
	}

	/*
	 * Simple kernel mapping requires contiguous memory
	 */
	order = tte_order + ilog2(roundup_pow_of_two(nr_tte));

	page = kimage_alloc_pages(GFP_KERNEL, order);

	if (!page)
		goto out;
	p = page_to_pfn(page) << PAGE_SHIFT;

	rc = add_phys_addr(image, p);
	if (rc) {
		__free_pages(page, order);
		goto out;
	}

	rc = copy_from_user(__va(p), segment->buf, segment->bufsz);
	if (rc)
		goto out;

	memset((void *)(__va(p) + segment->bufsz), 0,
	       segment->memsz - segment->bufsz);

	for (i = 0; i < nr_tte; i++) {
		regp->tte[i] = kexec_nucleus_tte(p);
		p += order_size;
	}
	regp->nr_tte = nr_tte;
out:
	return rc;
}

int kimage_arch_load_normal_segment(struct kimage *image,
		struct kexec_segment *segment, int *arch_status,
		int (*add_phys_addr)(struct kimage *image, unsigned long page))
{
	int rc;

	if (image->arch.ki_kernel.nr_tte)
		rc = kimage_arch_load_normal_segment_initrd(image,
				segment, add_phys_addr);
	else
		rc = kimage_arch_load_normal_segment_kernel(image,
				segment, add_phys_addr);

	*arch_status = rc;
	return 0;
}

/* All state we require is in the image's arch member. Transfer it to shim. */
static void machine_shim_load_kexec(struct kimage *image)
{
	struct sparc64_kexec_shim *shimp = kexec_shim();

	memcpy(&shimp->kernel, &image->arch.ki_kernel,
		sizeof(struct kexec_region));
	memcpy(&shimp->initrd, &image->arch.ki_initrd,
		sizeof(struct kexec_region));
}

/* We need to compute the ttes for the vmlinuz and transfer to shim. */
static void machine_shim_load_kexec_crash(struct kimage *image)
{
	unsigned long order_size = 1UL << (PAGE_SHIFT + tte_order);
	unsigned long tte = kexec_nucleus_tte(image->segment[0].mem);
	unsigned long nr_tte = compute_nr_tte(image->segment[0].memsz);
	struct sparc64_kexec_shim *shimp = kexec_shim();
	unsigned long nr;

	shimp->initrd.nr_tte = 0UL;
	shimp->kernel.nr_tte = nr_tte;
	for (nr = 0UL; nr != nr_tte; nr++) {
		shimp->kernel.tte[nr] = tte;
		tte += order_size;
	}
}

void machine_kexec(struct kimage *image)
{
	unsigned long fault_area;
	void (*shim_start)(void *, unsigned long);
	void *trap_table = &sparc64_kexec_trap_tl0;
	void *kexec_startp = &kexec_start;
	unsigned long distance = (unsigned long) (kexec_startp - trap_table);

	mondo_tear_down();
	if (image == kexec_image)
		machine_shim_load_kexec(image);
	else
		machine_shim_load_kexec_crash(image);
	shim_start = (void (*)(void *, unsigned long)) (KEXEC_BASE + distance);
	fault_area = kexec_map_shim();
	shim_start((void *) KEXEC_BASE, fault_area);
	__builtin_unreachable();
}

void arch_crash_save_vmcoreinfo(void)
{
#ifdef CONFIG_NUMA
	VMCOREINFO_SYMBOL(node_data);
	VMCOREINFO_LENGTH(node_data, MAX_NUMNODES);
#endif
}

unsigned long  paddr_vmcoreinfo_note(void)
{
	return kimage_addr_to_ra(&vmcoreinfo_note);
}
