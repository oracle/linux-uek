/*
 * Xen microcode update driver
 *
 * Xen does most of the work here.  We just pass the whole blob into
 * Xen, and it will apply it to all CPUs as appropriate.  Xen will
 * worry about how different CPU models are actually updated.
 */
#include <linux/sched.h>
#include <linux/module.h>
#include <linux/firmware.h>
#include <linux/vmalloc.h>
#include <linux/uaccess.h>

#include <asm/microcode.h>

#include <xen/xen.h>
#include <xen/interface/platform.h>
#include <xen/interface/xen.h>

#include <asm/xen/hypercall.h>
#include <asm/xen/hypervisor.h>

MODULE_DESCRIPTION("Xen microcode update driver");
MODULE_LICENSE("GPL");

struct xen_microcode {
	size_t len;
	char data[0];
};

static int xen_microcode_update(int cpu)
{
	int err;
	struct xen_platform_op op;
	struct ucode_cpu_info *uci = ucode_cpu_info + cpu;
	struct xen_microcode *uc = uci->mc;

	if (uc == NULL || uc->len == 0) {
		/*
		 * We do all cpus at once, so we don't need to do
		 * other cpus explicitly (besides, these vcpu numbers
		 * have no relationship to underlying physical cpus).
		 */
		return 0;
	}

	op.cmd = XENPF_microcode_update;
	set_xen_guest_handle(op.u.microcode.data, uc->data);
	op.u.microcode.length = uc->len;

	err = HYPERVISOR_dom0_op(&op);

	if (err != 0)
		printk(KERN_WARNING "microcode_xen: microcode update failed: %d\n", err);

	return err;
}

static enum ucode_state xen_request_microcode_fw(int cpu, struct device *device)
{
	char name[36];
	struct cpuinfo_x86 *c = &cpu_data(cpu);
	const struct firmware *firmware;
	struct ucode_cpu_info *uci = ucode_cpu_info + cpu;
	enum ucode_state ret;
	struct xen_microcode *uc;
	size_t size;
	int err;

	switch (c->x86_vendor) {
	case X86_VENDOR_INTEL:
		snprintf(name, sizeof(name), "intel-ucode/%02x-%02x-%02x",
			 c->x86, c->x86_model, c->x86_mask);
		break;

	case X86_VENDOR_AMD:
		/* Beginning with family 15h AMD uses family-specific firmware files. */
		if (c->x86 >= 0x15)
			snprintf(name, sizeof(name), "amd-ucode/microcode_amd_fam%.2xh.bin", c->x86);
		else
			snprintf(name, sizeof(name), "amd-ucode/microcode_amd.bin");
		break;

	default:
		return UCODE_NFOUND;
	}

	err = request_firmware(&firmware, name, device);
	if (err) {
		pr_debug("microcode: data file %s load failed\n", name);
		return UCODE_NFOUND;
	}

	/*
	 * Only bother getting real firmware for cpu 0; the others get
	 * dummy placeholders.
	 */
	if (cpu == 0)
		size = firmware->size;
	else
		size = 0;

	if (uci->mc != NULL) {
		vfree(uci->mc);
		uci->mc = NULL;
	}

	ret = UCODE_ERROR;
	uc = vmalloc(sizeof(*uc) + size);
	if (uc == NULL)
		goto out;

	ret = UCODE_OK;
	uc->len = size;
	memcpy(uc->data, firmware->data, uc->len);

	uci->mc = uc;

out:
	release_firmware(firmware);

	return ret;
}

static enum ucode_state xen_request_microcode_user(int cpu,
						   const void __user *buf, size_t size)
{
	struct ucode_cpu_info *uci = ucode_cpu_info + cpu;
	struct xen_microcode *uc;
	enum ucode_state ret;
	size_t unread;

	if (cpu != 0) {
		/* No real firmware for non-zero cpus; just store a
		   placeholder */
		size = 0;
	}

	if (uci->mc != NULL) {
		vfree(uci->mc);
		uci->mc = NULL;
	}

	ret = UCODE_ERROR;
	uc = vmalloc(sizeof(*uc) + size);
	if (uc == NULL)
		goto out;

	uc->len = size;

	ret = UCODE_NFOUND;

	unread = copy_from_user(uc->data, buf, size);

	if (unread != 0) {
		printk(KERN_WARNING "failed to read %zd of %zd bytes at %p -> %p\n",
		       unread, size, buf, uc->data);
		goto out;
	}

	ret = UCODE_OK;

out:
	if (ret == UCODE_OK)
		uci->mc = uc;
	else
		vfree(uc);

	return ret;
}

static void xen_microcode_fini_cpu(int cpu)
{
	struct ucode_cpu_info *uci = ucode_cpu_info + cpu;

	vfree(uci->mc);
	uci->mc = NULL;
}

static int xen_collect_cpu_info(int cpu, struct cpu_signature *sig)
{
	sig->sig = 0;
	sig->pf = 0;
	sig->rev = 0;

	return 0;
}

static struct microcode_ops microcode_xen_ops = {
	.request_microcode_user		  = xen_request_microcode_user,
	.request_microcode_fw             = xen_request_microcode_fw,
	.collect_cpu_info                 = xen_collect_cpu_info,
	.apply_microcode                  = xen_microcode_update,
	.microcode_fini_cpu               = xen_microcode_fini_cpu,
};

struct microcode_ops * __init init_xen_microcode(void)
{
	if (!xen_initial_domain())
		return NULL;
	return &microcode_xen_ops;
}
