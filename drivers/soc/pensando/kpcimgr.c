// SPDX-License-Identifier: GPL-2.0
/*
 * Kernel PCIE Manager Infrastructure
 *
 * This driver enables the relocation of module code to handle
 * Pensando/Elba indirect PCIe transactions. The purpose is to allow
 * code to persist and run during a kexec reboot. The loaded code runs
 * in physical mode during arm64_relocate_new_kernel and also during
 * the early boot phase before traditional driver code can run. This
 * is all to provide extremely low latency response to indirect
 * transactions, which must be serviced within 200ms.
 *
 * Copyright (c) 2021, 2022, Oracle and/or its affiliates.
 */

#include "kpcimgr_api.h"
#include "penpcie_dev.h"

MODULE_LICENSE("GPL");

kstate_t *kstate;
DEFINE_SPINLOCK(kpcimgr_lock);
static DECLARE_WAIT_QUEUE_HEAD(event_queue);

void wake_up_event_queue(void)
{
	wake_up_interruptible(&event_queue);
}

/*
 * We need our own memset/memcpy to avoid using
 * any arm instructions that affect the memory cache.
 * The memory used for kstate/code/etc is uncached.
 */
void *kpci_memset(void *s, int c, size_t n)
{
	if (((uintptr_t)s & 0x3) == 0 && (n & 0x3) == 0) {
		u32 *p;
		int i;

		c &= 0xff;
		c = ((c << 0) |
		     (c << 8) |
		     (c << 16) |
		     (c << 24));
		for (p = s, i = 0; i < n >> 2; i++, p++)
			*p = c;
	} else {
		u8 *p;
		int i;

		for (p = s, i = 0; i < n; i++, p++)
			*p = c;
	}

	return s;
}

void *kpci_memcpy(void *dst, const void *src, size_t n)
{
	u8 *d = dst;
	const u8 *s = src;
	int i;

	for (i = 0; i < n; i++)
		*d++ = *s++;

	return dst;
}

/*
 * Normal poll
 */
void kpcimgr_normal_poll(void)
{
	static void (*poll_fn)(kstate_t *, int, int);
	kstate_t *ks = get_kstate();
	unsigned long flags;

	spin_lock_irqsave(&kpcimgr_lock, flags);
	if (ks->valid == KSTATE_MAGIC) {
		poll_fn = ks->code_base + ks->code_offsets[K_ENTRY_POLL];
		poll_fn(ks, 0, NORMAL);
	}
	spin_unlock_irqrestore(&kpcimgr_lock, flags);
}

void kpcimgr_start_running(void)
{
	kstate_t *ks = get_kstate();
	void (*init_fn)(kstate_t *ks);
	unsigned long flags;

	spin_lock_irqsave(&kpcimgr_lock, flags);
	if (ks->valid == KSTATE_MAGIC) {
		init_fn = ks->code_base + ks->code_offsets[K_ENTRY_INIT_INTR];
		ks->running = 1;
		init_fn(ks);
	}
	spin_unlock_irqrestore(&kpcimgr_lock, flags);
}

void kpcimgr_stop_running(void)
{
	kstate_t *ks = get_kstate();
	void (*shut_fn)(int n);
	unsigned long flags;

	spin_lock_irqsave(&kpcimgr_lock, flags);
	if (ks->valid == KSTATE_MAGIC) {
		shut_fn = ks->code_base + ks->code_offsets[K_ENTRY_SHUT];
		shut_fn(ks->active_port);
	}
	spin_unlock_irqrestore(&kpcimgr_lock, flags);

	ks->running = 0;
}

/*
 * Read event(s) from the event queue. Used by pciemgrd to find out
 * about h/w event notifications that arrived during times when
 * pciemgrd is not running (ie, during a kexec).
 *
 * Standard event queue semantics:
 *  evq_head = index of slot used for next insertion
 *  evq_tail = index of slot used for next removal
 *  queue is empty when head == tail
 *  queue is full when (head + 1) % queue_size == tail
 *  queue is nearly full when (head + 2) % queue_size == tail
 *
 * Only tail is modified here, and the event handler only
 * modifies head, so theoretically no race can exist between
 * queue insertion/removal. The spinlocks here are only to
 * cover the case of multiple readers.
 */
static ssize_t
read_kpcimgr(struct file *file, char __user *buf, size_t nbytes, loff_t *ppos)
{
	kstate_t *ks = get_kstate();
	char localmem[EVENT_SIZE];
	ssize_t n = 0;

	spin_lock(&kpcimgr_lock);
	while (nbytes >= EVENT_SIZE) {
		/* is queue empty? */
		if (ks->evq_head == ks->evq_tail)
			break;

		/*
		 * intermediate copy since we cannot prevent copy_to_user
		 * from doing cache operations
		 */
		kpci_memcpy(localmem,
			    (void *)ks->evq[ks->evq_tail], EVENT_SIZE);

		if (copy_to_user(buf + n, localmem, EVENT_SIZE)) {
			spin_unlock(&kpcimgr_lock);
			return -EFAULT;
		}

		ks->evq_tail = (ks->evq_tail + 1) % EVENT_QUEUE_LENGTH;
		n = n + EVENT_SIZE;
		nbytes = nbytes - EVENT_SIZE;
	}
	spin_unlock(&kpcimgr_lock);

	return n;
}

/*
 * pciemgrd wants to select() on /dev/kpcimgr to discover
 * if there are events in the event queue.
 */
static unsigned int
poll_kpcimgr(struct file *file, poll_table *wait)
{
	kstate_t *ks = get_kstate();

	poll_wait(file, &event_queue, wait);
	if (ks->evq_head != ks->evq_tail)
		return POLLIN | POLLRDNORM;
	else
		return 0;
}

static int mmap_kpcimgr(struct file *file, struct vm_area_struct *vma)
{
	phys_addr_t offset = (phys_addr_t)vma->vm_pgoff << PAGE_SHIFT;
	size_t size = vma->vm_end - vma->vm_start;
	pgprot_t pgprot = vma->vm_page_prot;
	kstate_t *ks = get_kstate();
	unsigned long pfn, start;
	void *pos;

	if (offset + size > ks->shmem_size)
		return -EINVAL;

	if (ks->shmembase) {
		pfn = (ks->shmembase + offset) >> PAGE_SHIFT;
		pgprot = pgprot_device(pgprot);

		if (!(file->f_flags & O_SYNC))
			return -EINVAL;

		pgprot = pgprot_writecombine(pgprot);
		vma->vm_page_prot = pgprot;
		if (remap_pfn_range(vma, vma->vm_start, pfn,
				    size, vma->vm_page_prot))
			return -EINVAL;
	} else {
		for (start = vma->vm_start, pos = ks->shmemva + offset;
		     size > 0;
		     start += PAGE_SIZE, pos += PAGE_SIZE, size -= PAGE_SIZE) {
			pfn = vmalloc_to_pfn(pos);
			if (remap_pfn_range(vma, start, pfn,
					    PAGE_SIZE, vma->vm_page_prot))
				return -EINVAL;
		}
	}

	return 0;
}

/*
 * Semantics of open(): if no code is loaded then open fails.
 */
static int open_kpcimgr(struct inode *inode, struct file *filp)
{
	kstate_t *ks = get_kstate();

	if (ks->valid == KSTATE_MAGIC)
		return 0;
	else
		return -ENODEV;
}

/*
 * Examine code and look for calls (BL insn) and data references
 * (ADRP) to memory addresses outside of the bounds of the module. If
 * any are found, report them and return an error.
 */
int contains_external_refs(struct module *mod, void *code_end)
{
	unsigned long start = (unsigned long)mod->core_layout.base;
	char code_loc[KSYM_SYMBOL_LEN], target_ref[KSYM_SYMBOL_LEN];
	int insn_count, call_count, adrp_count;
	unsigned long size, target, insn_addr;
	s32 offset;
	u32 insn;

	size = (unsigned long)code_end - start;

	for (insn_addr = start, insn_count = 0, call_count = 0, adrp_count = 0;
	     insn_addr < start + size;
	     insn_addr += sizeof(u32)) {
		if (aarch64_insn_read((void *)insn_addr, &insn)) {
			pr_err("Failed to read insn @ %lx\n", insn_addr);
			return 1;
		}
		insn_count++;

		if (aarch64_insn_is_bl(insn)) {
			offset = aarch64_get_branch_offset(insn);
			target = insn_addr + offset;

			if (within_module(target, mod))
				continue;

			sprint_symbol(code_loc, insn_addr);
			sprint_symbol(target_ref, target);
			pr_err("Found call to %s at %s\n",
			       target_ref, code_loc);

			call_count++;
		}

		if (aarch64_insn_is_adrp(insn)) {
			offset = aarch64_insn_adrp_get_offset(insn);
			target = (insn_addr & PAGE_MASK) + offset;

			if (within_module(target, mod))
				continue;

			sprint_symbol(code_loc, insn_addr);
			sprint_symbol(target_ref, target);
			pr_err("Found approximate reference to %s at %s\n",
			       target_ref, code_loc);
			pr_err(" (Please check object file for exact reference)\n");
			adrp_count++;
		}
	}
	pr_info("processed %d insns, %d extern calls, %d extern adrps\n",
		insn_count, call_count, adrp_count);

	if (call_count > 0 || adrp_count > 0)
		return 1;
	else
		return 0;
}

/*
 * module_register
 *
 * Register module code/data to be used with kpcimgr. If requested, we
 * relocate module code to "non-linux memory". The struct module
 * pointer is not quite enough to do this, and we require a pointer
 * to the end of the module code section. This is because we need to
 * examine the code for certain instructions, and we don't want to
 * look beyond the end of the code since that will be data which
 * might contain values which just look like instructions.
 *
 * If the code contains no external references, then we can freely
 * relocate the code repeatedly without relinking.
 *
 * We shut down service and then copy the module in its entirety to
 * non-linux memory which we have previously mapped executable.
 *
 * We can also run with the module code unrelocated, but this is only
 * for debugging, as it preserves the modules symbols in kallsyms, so
 * any stack trace will show useful function names instead of raw hex
 * addresses.
 *
 * After the copy, we restart the service if necessary.
 */
int kpcimgr_module_register(struct module *mod,
			    struct kpcimgr_entry_points_t *ep, int relocate)
{
	void *code_end = ep->code_end;
	kstate_t *ks = get_kstate();
	unsigned long start_addr, iflags;
	int i, was_running;

	start_addr = (unsigned long)mod->core_layout.base;

	if (ep->expected_mgr_version != KPCIMGR_KERNEL_VERSION) {
		pr_err("KPCIMGR: module expects kernel version %d, incompatible with version %d\n",
		       ep->expected_mgr_version, KPCIMGR_KERNEL_VERSION);
		return -EINVAL;
	}

	if (contains_external_refs(mod, code_end))
		return -ENXIO;

	pr_info("KPCIMGR: start=%lx, end=%lx, size=%d\n", start_addr,
		start_addr + mod->core_layout.size, mod->core_layout.size);

	if (mod->core_layout.size > KSTATE_CODE_SIZE)
		return -EFBIG;

	was_running = ks->running;
	if (was_running) {
		pr_info("%s: kpcimgr has stopped running\n", __func__);
		kpcimgr_stop_running();
	}
	spin_lock_irqsave(&kpcimgr_lock, iflags);
	ks->valid = 0;

	if (ks->mod) {
		module_put(ks->mod);
		ks->mod = NULL;
		ks->code_base = NULL;
	}

	if (ks->code_base)
		module_memfree(ks->code_base);

	if (relocate) {
		ks->code_base = module_alloc(mod->core_layout.size);

		if (ks->code_base == NULL) {
			pr_err("KPCIMGR: module_alloc(%x)\n",
			       mod->core_layout.size);
			return -ENOMEM;
		}
		kpci_memcpy(ks->code_base, mod->core_layout.base,
			    mod->core_layout.size);
		set_memory_x((unsigned long)ks->code_base,
			     mod->core_layout.size >> PAGE_SHIFT);
	} else {
		try_module_get(mod);
		ks->mod = mod;
		ks->code_base = mod->core_layout.base;
	}
	ks->code_size = mod->core_layout.size;

	for (i = 0; i < K_NUM_ENTRIES; i++)
		ks->code_offsets[i] = (unsigned long)ep->entry_point[i]
			- start_addr;

	set_init_state(ks);
	ks->valid = KSTATE_MAGIC;
	ks->lib_version_major = ep->lib_version_major;
	ks->lib_version_minor = ep->lib_version_minor;

	spin_unlock_irqrestore(&kpcimgr_lock, iflags);
	if (was_running) {
		kpcimgr_start_running();
		pr_info("%s: kpcimgr will begin running\n", __func__);
	} else {
		reset_stats(ks);
	}

	return 0;
}
EXPORT_SYMBOL(kpcimgr_module_register);

static void unmap_resources(void)
{
	kstate_t *ks = get_kstate();

	int i;

	for (i = 0; i < ks->nranges; i++) {
		if (ks->mem_ranges[i].vaddr)
			iounmap(ks->mem_ranges[i].vaddr);
	}

	if (ks->uart_addr)
		iounmap(ks->uart_addr);

	if (ks->have_persistent_mem) {
		if (ks->persistent_base)
			iounmap(ks->persistent_base);
		if (ks->shmemva)
			iounmap(ks->shmemva);
		iounmap(ks);
	} else {
		vfree(ks->shmemva);
		vfree((void *)ks);
	}
}

static int map_resources(struct platform_device *pfdev)
{
	struct device_node *dn = pfdev->dev.of_node;
	u32 shmem_idx, hwmem_idx;
	struct resource res;
	kstate_t *ks;
	void *shmem;
	int i, err;

	err = of_property_read_u32(dn, "hwmem-index", &hwmem_idx);
	if (err) {
		pr_err("KPCIMGR: no hwmem-index value found\n");
		return -ENOMEM;
	}

	err = of_property_read_u32(dn, "shmem-index", &shmem_idx);
	if (err) {
		pr_err("KPCIMGR: no shmem-index value found\n");
		return -ENOMEM;
	}

	err = of_address_to_resource(dn, shmem_idx, &res);
	if (err) {
		pr_err("KPCIMGR: no resource found for shmem-index=%d\n",
		       shmem_idx);
		return -ENOMEM;
	}

	if (res.start == 0) {
		/* indicates no persistent memory */
		pr_info("KPCIMGR: no persistent memory\n");
		ks = vmalloc(sizeof(kstate_t));
		if (ks == NULL)
			return -ENOMEM;
		memset((void *)ks, 0, sizeof(kstate_t));
		ks->active_port = -1;
		ks->have_persistent_mem = 0;
		shmem = vmalloc(resource_size(&res));
		if (shmem == NULL) {
			vfree((void *)ks);
			return -ENOMEM;
		}
		ks->shmembase = 0;
		ks->shmem_size = resource_size(&res);
	} else {
		if (resource_size(&res) > SHMEM_KSTATE_OFFSET) {
			pr_err("KPCIMGR: shmem size overlaps kstate\n");
			return -ENODEV;
		}
		shmem = ioremap(res.start, resource_size(&res));
		if (shmem == NULL) {
			pr_err("KPCIMGR: failed to map shmem\n");
			return -ENODEV;
		}

		ks = ioremap(res.start + SHMEM_KSTATE_OFFSET, sizeof(kstate_t));
		if (ks == NULL) {
			pr_err("KPCIMGR: failed to map kstate\n");
			iounmap(shmem);
			return -ENOMEM;
		}
		if (ks->valid != KSTATE_MAGIC) {
			kpci_memset((void *)ks, 0, sizeof(kstate_t));
			ks->active_port = -1;
		}

		ks->have_persistent_mem = 1;
		ks->shmembase = res.start;
		ks->shmem_size = resource_size(&res);
		pr_info("KPCIMGR: kstate mapped %llx at %lx\n",
			res.start + SHMEM_KSTATE_OFFSET, (long)ks);

		ks->persistent_base = ioremap(res.start + KSTATE_CODE_OFFSET,
					      KSTATE_CODE_SIZE);
		if (ks->persistent_base == NULL) {
			pr_err("KPCIMGR: failed to map shmem code space\n");
			goto errout;
		}

		if (ks->valid == KSTATE_MAGIC) {
			ks->code_base = module_alloc(ks->code_size);
			if (ks->code_base == NULL) {
				pr_err("KPCIMGR: module_alloc(%lx) failed\n",
				       ks->code_size);
				goto errout;
			}
			kpci_memcpy(ks->code_base, ks->persistent_base,
				    ks->code_size);
			set_memory_x((unsigned long)ks->code_base,
				     ks->code_size >> PAGE_SHIFT);
		}
	}

	kstate = ks;
	ks->shmemva = shmem;

	ks->uart_addr = ioremap(PEN_UART, 0x1000);
	if (ks->uart_addr == NULL) {
		pr_err("KPCIMGR: failed to map elba uart\n");
		goto errout;
	}
	ks->driver_start_time = read_sysreg(cntvct_el0);

	ks->nranges = 0;
	for (i = 0; i < NUM_MEMRANGES; i++) {
		struct mem_range_t *mr = &ks->mem_ranges[ks->nranges];

		if (i == shmem_idx)
			continue;

		err = of_address_to_resource(dn, i, &res);
		if (err)
			break;

		mr->base = res.start;
		mr->end = res.start + resource_size(&res);
		mr->vaddr = ioremap(res.start, resource_size(&res));
		if (IS_ERR(mr->vaddr)) {
			pr_err(PFX "iomap resource %d failed\n", i);
			goto errout;
		}
		if (i == hwmem_idx)
			ks->hwmem_idx = ks->nranges;
		ks->nranges++;
	}
	return 0;

 errout:
	unmap_resources();
	return -ENOMEM;
}

/*
 * ISR for indirect transaction
 */
static irqreturn_t kpcimgr_indirect_intr(int irq, void *arg)
{
	static int (*intr_fn)(kstate_t *, int);
	kstate_t *ks = (kstate_t *)arg;
	int port, r = 0;

	spin_lock(&kpcimgr_lock);
	if (ks->valid == KSTATE_MAGIC) {
		ks->ind_intr++;
		intr_fn = ks->code_base +
			ks->code_offsets[K_ENTRY_INDIRECT_INTR];

		port = ks->active_port;
		if (port >= 0)
			r = intr_fn(ks, port);
	}
	spin_unlock(&kpcimgr_lock);

	return r ? IRQ_HANDLED : IRQ_NONE;
}

/*
 * ISR for notify transaction
 */
static irqreturn_t kpcimgr_notify_intr(int irq, void *arg)
{
	static int (*intr_fn)(kstate_t *, int);
	kstate_t *ks = (kstate_t *)arg;
	int port, r = 0;

	spin_lock(&kpcimgr_lock);
	if (ks->valid == KSTATE_MAGIC) {
		ks->not_intr++;
		intr_fn = ks->code_base + ks->code_offsets[K_ENTRY_NOTIFY_INTR];

		port = ks->active_port;
		if (port >= 0)
			r = intr_fn(ks, port);
	}
	spin_unlock(&kpcimgr_lock);

	return r ? IRQ_HANDLED : IRQ_NONE;
}

u64 kpcimgr_preg_read(u64 pa)
{
	u32 val;

	pciep_regrd32((uint64_t)pa, &val);
	return (u64)val;
}

static u64 kpcimgr_upcall(int req, u64 arg1, u64 arg2, u64 arg3)
{
	kstate_t *ks = get_kstate();

	if (ks->valid != KSTATE_MAGIC)		/* no code loaded */
		return 1;

	switch (req) {
	case WAKE_UP_EVENT_QUEUE:
		ks->event_intr++;
		wake_up_event_queue();
		break;
	case PRINT_LOG_MSG:
		printk((char *)arg1); /* KERN_LEVEL provided by arg1 */
		break;
	case PREG_READ:
		return kpcimgr_preg_read(arg1);
	default:
		return 1;
	}
	return 0;
}

static void set_msi_msg(struct msi_desc *desc, struct msi_msg *msg)
{
	kstate_t *ks = get_kstate();
	struct msi_info *msi = &ks->msi[desc->platform.msi_index];

	msi->msgaddr = ((u64)msg->address_hi << 32) | msg->address_lo;
	msi->msgdata = msg->data;
}

static void free_intrs(struct platform_device *pfdev)
{
	kstate_t *ks = get_kstate();
	struct device *dev = &pfdev->dev;
	struct msi_desc *desc;

	for_each_msi_entry(desc, dev)
		free_irq(desc->irq, (void *)ks);

	platform_msi_domain_free_irqs(&pfdev->dev);
}

struct {
	irqreturn_t (*isr)(int irq, void *arg);
	char *name;
} kpcimgr_irq_table[] = {
	{ kpcimgr_indirect_intr, "kpcimgr-indirect"},
	{ kpcimgr_notify_intr,   "kpcimgr-notify"  },
};

static int alloc_intrs(struct platform_device *pfdev)
{
	irqreturn_t (*isr)(int irq, void *arg);
	struct device *dev = &pfdev->dev;
	kstate_t *ks = get_kstate();
	struct msi_desc *desc;
	char *name;
	int r;

	r = platform_msi_domain_alloc_irqs(dev, MSI_NVECTORS, set_msi_msg);
	if (r)
		return r;

	for_each_msi_entry(desc, dev) {
		isr = kpcimgr_irq_table[desc->platform.msi_index].isr;
		name = kpcimgr_irq_table[desc->platform.msi_index].name;
		r = devm_request_irq(dev, desc->irq, isr, 0, name, (void *)ks);
		if (r)
			goto err_out;
	}
	return 0;

 err_out:
	free_intrs(pfdev);
	return r;
}

/*
 * Called when a kexec is about to happen
 */
static int kpcimgr_notify_reboot(struct notifier_block *this,
				 unsigned long code,
				 void *unused)
{
	kstate_t *ks = get_kstate();
	int was_running = ks->running;

	/* stop running regardless of why a reboot is happening */
	free_intrs(ks->pfdev);
	if (was_running)
		kpcimgr_stop_running();

	if (!ks->code_base) {
		pr_err("KPCIMGR: halting since no code is loaded\n");
		ks->valid = 0;
		return NOTIFY_DONE;
	}

	if (!ks->have_persistent_mem) {
		pr_err("KPCIMGR: halting since code is not persistent\n");
		ks->valid = 0;
		return NOTIFY_DONE;
	}

	/* relocate code to "persistent" memory */
	kpci_memcpy(ks->persistent_base, ks->code_base, ks->code_size);

	if (code == SYS_DOWN) {
		pr_err("KPCIMGR: going down at tick %lld\n",
		       read_sysreg(cntvct_el0));

		if (was_running)
			ks->running = 1;

		reset_stats(ks);
		ks->ncalls = 0;
		ks->kexec_time = read_sysreg(cntvct_el0);
	}
	return NOTIFY_DONE;
}

/*
 * Driver Initialization
 */
static const struct file_operations __maybe_unused kpcimgr_fops = {
	.owner          = THIS_MODULE,
	.read           = read_kpcimgr,
	.poll           = poll_kpcimgr,
	.open           = open_kpcimgr,
	.mmap           = mmap_kpcimgr,
};

static struct miscdevice kpcimgr_dev = {
	MISC_DYNAMIC_MINOR,
	KPCIMGR_NAME,
	&kpcimgr_fops
};

static int kpcimgr_probe(struct platform_device *pfdev)
{
	kstate_t *ks;
	int err;

	err = map_resources(pfdev);
	if (err)
		goto errout;

	ks = get_kstate();
	ks->pfdev = pfdev;

	err = alloc_intrs(ks->pfdev);
	if (err) {
		pr_err(PFX "alloc intrs: %d\n", err);
		goto errout_unmap;
	}

	err = misc_register(&kpcimgr_dev);
	if (err) {
		pr_err(PFX "register pciemgr_dev failed: %d\n", err);
		goto errout_free_intrs;
	}

	ks->upcall = (void *)kpcimgr_upcall;
	if (ks->valid == KSTATE_MAGIC && ks->running) {
		ks->mod = NULL;
		kpcimgr_start_running();
		kpcimgr_normal_poll();
		pr_err("KPCIMGR: initialized and running.\n");
	}
	if (ks->have_persistent_mem) {
		static struct notifier_block kpcimgr_nb = {
			.notifier_call = kpcimgr_notify_reboot,
			.next = NULL,
			.priority = 0,
		};
		register_reboot_notifier(&kpcimgr_nb);
	}

	pr_info("KPCIMGR: kstate mapped at %lx, code at %lx\n",
		(long)ks, (long)ks->code_base);

	kpcimgr_sysfs_setup(pfdev);
	return 0;

 errout_free_intrs:
	free_intrs(pfdev);

 errout_unmap:
	unmap_resources();

 errout:
	return err;
}

static const struct of_device_id kpcimgr_of_match[] = {
	{ .compatible = "pensando,kpcimgr" },
	{ /* end of table */ }
};

static struct platform_driver kpcimgr_driver = {
	.probe = kpcimgr_probe,
	.driver = {
		.name = "pensando-kpcimgr",
		.owner = THIS_MODULE,
		.of_match_table = kpcimgr_of_match,
	},
};
builtin_platform_driver(kpcimgr_driver);

/*
 * Get entry point for pciesvc specific secondary cpu holding pen.
 * Called from arch/arm64/kernel/smp_spin_table.c
 * We choose the first cpu to arrive here. They will all try
 * concurrently, but only one will be hijacked and the rest
 * will go to their default holding pens.
 */
unsigned long kpcimgr_get_entry(unsigned long old_entry, unsigned int cpu)
{
	unsigned long (*entry_fn)(unsigned long entry, unsigned int cpu);
	static DEFINE_SPINLOCK(choose_cpu_lock);
	kstate_t *ks = get_kstate();
	unsigned long entry;

	if (ks == NULL || ks->valid != KSTATE_MAGIC ||
	    !ks->running || !ks->have_persistent_mem)
		return old_entry;

	entry_fn = ks->code_base + ks->code_offsets[K_ENTRY_HOLDING_PEN];

	spin_lock(&choose_cpu_lock);
	entry = entry_fn(old_entry, cpu);
	spin_unlock(&choose_cpu_lock);

	return entry;
}
