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
#include <linux/of_fdt.h>
#include <linux/delay.h>
#include <asm/cpu_ops.h>

MODULE_LICENSE("GPL");

kstate_t *kstate;
DEFINE_SPINLOCK(kpcimgr_lock);
static DECLARE_WAIT_QUEUE_HEAD(event_queue);

/*
 * get_uart_addr
 *
 * The uart physical address changes if we're booted as a virtual machine,
 * so we must dig it out of the device tree
 */
static long get_uart_addr(void)
{
	struct device_node *dn;
	struct resource res;
	int err;

	dn = of_find_node_by_path("/soc/serial@4800");
	if (!dn)
		dn = of_find_node_by_path("/sbsa-uart@5000");
	if (!dn) {
		pr_info("KPCIMGR: found no uarts\n");
		return 0;
	}
	err = of_address_to_resource(dn, 0, &res);
	if (err) {
		pr_info("KPCIMGR: could not read uart resource\n");
		return 0;
	}
	pr_info("KPCIMGR: uart found at %llx/%llx\n", res.start, resource_size(&res));
	return (long)res.start;
}

/*
 * Simple function to tell us if we're booted as a virtual machine.
 * There is probably a nicer way, but this method is simple: check for
 * the existence of a "passthrough" node in the device tree.
 */
static void *booted_as_guest(void)
{
	return of_find_node_by_path("/passthrough");
}

/*
 * Simple check for PSCI is to just look for a "psci" node in the
 * device tree.
 */
static void *booted_with_psci(void)
{
	return of_find_node_by_path("/psci");
}

void wake_up_event_queue(void)
{
	wake_up_interruptible(&event_queue);
}

/*
 * We need our own memset/memcpy to avoid using
 * any arm instructions that affect the memory cache.
 * The memory used for kstate/code/etc is uncached.
 */
static void *kpci_memset(void *s, int c, size_t n)
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
static void kpcimgr_normal_poll(void)
{
	void (*poll_fn)(kstate_t *, int, int);
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
 * queue insertion/removal. The mutex is here only to
 * cover the case of multiple readers.
 */
static ssize_t
read_kpcimgr(struct file *file, char __user *buf, size_t nbytes, loff_t *ppos)
{
	static DEFINE_MUTEX(evq_lock);
	kstate_t *ks = get_kstate();
	char localmem[EVENT_SIZE];
	ssize_t n = 0;
	int tail;

	mutex_lock(&evq_lock);
	tail = ks->evq_tail;

	while (nbytes >= EVENT_SIZE && ks->evq_head != tail) {
		/*
		 * intermediate copy since we cannot prevent copy_to_user
		 * from doing cache operations
		 */
		kpci_memcpy(localmem, (void *)ks->evq[tail], EVENT_SIZE);

		if (copy_to_user(buf + n, localmem, EVENT_SIZE)) {
			mutex_unlock(&evq_lock);
			return -EFAULT;
		}

		tail = (tail + 1) % EVENT_QUEUE_LENGTH;
		n = n + EVENT_SIZE;
		nbytes = nbytes - EVENT_SIZE;
	}
	ks->evq_tail = tail;
	mutex_unlock(&evq_lock);

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
			pr_err("Found call to %s at %s (offset 0x%lx)\n",
			       target_ref, code_loc, insn_addr - start);

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
			pr_err(" (Please check object file offset 0x%lx for exact reference)\n",
				insn_addr - start);
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
 * feature_check
 *
 * Ensure pciesvc library supports features we need. Currently we
 * only are concerned with PSCI and GUEST, and in both cases we need
 * to disallow kexec if the library doesn't know about these, otherwise
 * it will either crash quickly or never return.
 */
static int feature_check(long features)
{
	kstate_t *ks = get_kstate();

	if (!ks->have_persistent_mem)
		return 0;

	ks->features |= FLAG_KEXEC;
	if ((ks->features & FLAG_PSCI) && (features & FLAG_PSCI) == 0) {
		pr_err("KPCIMGR: module does not provide required PSCI support\n");
		pr_err("KPCIMGR: kexec capability is disabled\n");
		ks->features &= ~FLAG_KEXEC;
	}

	if ((ks->features & FLAG_GUEST) && (features & FLAG_GUEST) == 0) {
		pr_err("KPCIMGR: module does not provide required GUEST support\n");
		pr_err("KPCIMGR: kexec capability is disabled\n");
		ks->features &= ~FLAG_KEXEC;
	}

	if (ks->features & FLAG_KEXEC)
		pr_err("KPCIMGR: kexec capability enabled\n");

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
	unsigned long start_addr, iflags, module_cap;
	void (*features)(long *modcap, long resv1, long resv2, long resv3);
	void *code_end = ep->code_end;
	kstate_t *ks = get_kstate();
	void (*init_fn)(kstate_t *ks);
	void (*version_fn)(char **);
	char *mod_buildtime;
	int i, was_running;

	if (ks == NULL) {
		pr_info("KPCIMGR: failure to start\n");
		return -ENODEV;
	}

	start_addr = (unsigned long)mod->core_layout.base;

	if (ep->expected_mgr_version != KPCIMGR_KERNEL_VERSION) {
		pr_info("KPCIMGR: '%s' expects kernel version %d, incompatible with version %d\n",
			mod->name, ep->expected_mgr_version, KPCIMGR_KERNEL_VERSION);
		return -EINVAL;
	}

	if (contains_external_refs(mod, code_end)) {
		pr_err("KPCIMGR: relocation failed for '%s'\n", mod->name);
		return -ENXIO;
	}

	if (mod->core_layout.size > KSTATE_CODE_SIZE) {
		pr_err("KPCIMGR: module '%s' too large\n", mod->name);
		return -EFBIG;
	}

	init_fn = ep->entry_point[K_ENTRY_INIT_FN];
	init_fn(ks);

	version_fn = ep->entry_point[K_ENTRY_GET_VERSION];
	mod_buildtime = "";
	version_fn(&mod_buildtime);

	/* Ensure the module supports PSCI if we are booted with it */
	features = ep->entry_point[K_ENTRY_FEATURES];
	module_cap = 0;
	features(&module_cap, 0, 0, 0);

	if (feature_check(module_cap))
		return -EINVAL;

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
		flush_icache_range((long)ks->code_base, (long)ks->code_base + mod->core_layout.size);
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

	pr_info("KPCIMGR: module '%s: %s', start=%lx, end=%lx, size=%d\n",
		mod->name, mod_buildtime, start_addr,
		start_addr + mod->core_layout.size, mod->core_layout.size);

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

/*
 * check_borrowed_cpu()
 *
 * When we're booting up after a kexec, we might have "borrowed"
 * a cpu to run pciesvc during the reboot. In spin table mode,
 * the borrowed cpu monitors the spin table release address,
 * which tells it to return to the system.
 *
 * In PSCI mode, we have to signal the borrowed cpu to stop
 * executing the pciesvc code. We do this by setting
 * FLAG_PSCI_CPU_RELEASE in ks->features, and the cpu
 * responds by setting FLAG_PSCI_CPU_RELEASED and then
 * executing the psci cpu_die() firmware call. In this case
 * the system won't be able to activate the borrowed cpu
 * during secondary cpu activation, so we do this here.
 */

void check_borrowed_cpu(kstate_t *ks)
{
	const struct cpu_operations *cpu_ops;
	unsigned long start, end;

	/* if not booted with psci, then nothing to do here */
	if (!(ks->features & FLAG_PSCI))
		return;

	/* if pciesvc not running, then nothing to do here */
	if (!ks->running)
		return;

	/* if cpu already released, then nothing to do here */
	if (ks->features & FLAG_PSCI_CPU_RELEASED)
		return;

	cpu_ops = get_cpu_ops(ks->running);
	pr_info("KPCIMGR: releasing borrowed CPU#%d\n", ks->running);

	/* send the release signal */
	ks->features |= FLAG_PSCI_CPU_RELEASE;

	/* wait for pciesvc to respond */
	start = jiffies;
	end = start + msecs_to_jiffies(50);
	do {
		if (ks->features & FLAG_PSCI_CPU_RELEASED)
			break;
		cpu_relax();
	} while (time_before(jiffies, end));

	pr_info("KPCIMGR: %s response from CPU#%d after %dms\n",
		(ks->features & FLAG_PSCI_CPU_RELEASED) ? "got" : "no",
		ks->running, jiffies_to_msecs(jiffies - start));

	/* wait until cpu makes it to the off state */
	pr_info("KPCIMGR: returning CPU#%d to system\n", ks->running);
	if (cpu_ops && cpu_ops->cpu_kill)
		cpu_ops->cpu_kill(ks->running);  /* this could poll for 100ms */
	else
		mdelay(5);	/* 3ms consistently fails, while 4 works */

	/* finally, activate the borrowed cpu */
	add_cpu(ks->running);
	pr_info("KPCIMGR: return of CPU#%d complete\n", ks->running);
}

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

	if (ks->code_base && !ks->mod)
		module_memfree(ks->code_base);

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
	u32 shmem_idx, hwmem_idx, kstate_idx = -1;
	struct resource res, kstate_res;
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

	/* if no kstate index, fall back to old scheme */
	err = of_property_read_u32(dn, "kstate-index", &kstate_idx);
	if (err) {
		pr_err("KPCIMGR: using default kstate offset\n");
		kstate_res.start = res.start + COMPAT_SHMEM_KSTATE_OFFSET;
	} else {
		err = of_address_to_resource(dn, kstate_idx, &kstate_res);
		if (err) {
			pr_err("KPCIMGR: no kstate resource\n");
			return -ENOMEM;
		}
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
		shmem = ioremap(res.start, resource_size(&res));
		if (shmem == NULL) {
			pr_err("KPCIMGR: failed to map shmem\n");
			return -ENODEV;
		}

		ks = ioremap(kstate_res.start, sizeof(kstate_t));
		if (ks == NULL) {
			pr_err("KPCIMGR: failed to map kstate\n");
			iounmap(shmem);
			return -ENOMEM;
		}
		if (ks->valid != KSTATE_MAGIC) {
			kpci_memset((void *)ks, 0, sizeof(kstate_t));
			ks->active_port = -1;
		}

		ks->kstate_paddr = kstate_res.start;
		ks->have_persistent_mem = 1;
		ks->shmembase = res.start;
		ks->shmem_size = resource_size(&res);
		pr_info("KPCIMGR: kstate mapped %llx at %lx\n",
			kstate_res.start, (long)ks);

		ks->persistent_base = ioremap(ks->kstate_paddr + KSTATE_CODE_OFFSET,
					      KSTATE_CODE_SIZE);
		if (ks->persistent_base == NULL) {
			pr_err("KPCIMGR: failed to map shmem code space\n");
			goto errout;
		}

		if (ks->valid == KSTATE_MAGIC) {
			check_borrowed_cpu(ks);
			ks->code_base = module_alloc(ks->code_size);
			if (ks->code_base == NULL) {
				pr_err("KPCIMGR: module_alloc(%lx) failed\n",
				       ks->code_size);
				goto errout;
			}
			if (ks->features_valid == KSTATE_MAGIC) {
				kpci_memcpy(ks->code_base, ks->persistent_base, ks->code_size);
			} else {
				/* we were kexec'd from an old kernel, so code is at old address */
				void *old_code = ioremap(ks->kstate_paddr + SHMEM_KSTATE_SIZE_OLD,
							 ks->code_size);
				if (old_code == NULL) {
					pr_err("KPCIMGR: failed to map old code area\n");
					goto errout;
				}
				kpci_memcpy(ks->code_base, old_code, ks->code_size);
				iounmap(old_code);
			}
			flush_icache_range((long)ks->code_base, (long)ks->code_base + ks->code_size);
			set_memory_x((unsigned long)ks->code_base,
				     ks->code_size >> PAGE_SHIFT);
		}
	}

	kstate = ks;
	ks->shmemva = shmem;

	ks->uart_paddr = get_uart_addr();
	if (ks->uart_paddr)
		ks->uart_addr = ioremap(ks->uart_paddr, 0x1000);
	if (ks->uart_addr == NULL) {
		pr_err("KPCIMGR: failed to map uart@%lx\n", ks->uart_paddr);
		goto errout;
	}

	ks->driver_start_time = read_sysreg(cntvct_el0);

	ks->nranges = 0;
	for (i = 0; i < NUM_MEMRANGES; i++) {
		struct mem_range_t *mr = &ks->mem_ranges[ks->nranges];

		if (i == shmem_idx || i == kstate_idx)
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

	if (booted_as_guest())
		ks->features |= FLAG_GUEST;
	if (booted_with_psci())
		ks->features |= FLAG_PSCI;
	ks->features_valid = KSTATE_MAGIC;
	pr_info("KPCIMGR: features guest=%s, psci=%s\n",
		(ks->features & FLAG_GUEST)  ? "yes" : "no",
		(ks->features & FLAG_PSCI) ? "yes" : "no");

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
	int (*intr_fn)(kstate_t *, int);
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
	int (*intr_fn)(kstate_t *, int);
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
	struct msi_info *msi = &ks->msi[desc->msi_index];

	msi->msgaddr = ((u64)msg->address_hi << 32) | msg->address_lo;
	msi->msgdata = msg->data;
}

static void free_intrs(struct platform_device *pfdev)
{
	kstate_t *ks = get_kstate();
	struct device *dev = &pfdev->dev;
	struct msi_desc *desc;

	msi_for_each_desc(desc, dev, MSI_DESC_ALL)
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

	msi_for_each_desc(desc, dev, MSI_DESC_ALL) {
		isr = kpcimgr_irq_table[desc->msi_index].isr;
		name = kpcimgr_irq_table[desc->msi_index].name;
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
	void (*reboot_fn)(long resv0, long resv1, long resv2, long resv3);

	/* stop running regardless of why a reboot is happening */
	free_intrs(ks->pfdev);
	if (ks->valid != KSTATE_MAGIC) {
		pr_err("KPCIMGR: halting due to invalid kstate\n");
		ks->valid = 0;
		return NOTIFY_DONE;
	}

	if (!ks->running) {
		pr_err("KPCIMGR: halting since kpcimgr not running\n");
		ks->valid = 0;
		return NOTIFY_DONE;
	}
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

	if (!(ks->features & FLAG_KEXEC)) {
		pr_err("KPCIMGR: halting since kexec not allowed for loaded library\n");
		ks->valid = 0;
		return NOTIFY_DONE;
	}

	if (ks->uart_paddr == 0) {
		pr_err("KPCIMGR: no uart so service cannot persist\n");
		return NOTIFY_DONE;
	}
	reboot_fn = (void *)ks->code_base + ks->code_offsets[K_ENTRY_REBOOT];
	reboot_fn(0, 0, 0, 0); /* must be done before memcpy below */

	/* relocate code to "persistent" memory */
	kpci_memcpy(ks->persistent_base, ks->code_base, ks->code_size);

	if (code == SYS_DOWN) {
		pr_err("KPCIMGR: going down at tick %lld\n",
		       read_sysreg(cntvct_el0));

		ks->running = 1;

		reset_stats(ks);
		ks->ncalls = 0;
		ks->kexec_time = read_sysreg(cntvct_el0);
		ks->features &= ~(FLAG_PSCI_CPU_RELEASE | FLAG_PSCI_CPU_RELEASED);
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
	ks->mod = NULL;
	if (ks->valid == KSTATE_MAGIC && ks->running) {
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
 * Called from arch/arm64/kernel/smp_spin_table.c and
 * arch/arm64/kernel/psci.c
 *
 * We choose the first cpu to arrive here. They will all try
 * concurrently, but only one will be hijacked and the rest
 * will go to their default holding pens. Since the physical
 * address of kstate can no longer be derived from the physical
 * address of shmem, we need to convey kstate_paddr directly
 * to the holding pen function. This method must be kept
 * to retain compatibility with old pciesvc library code.
 * For newer library code, we pass the kstate paddr in via
 * the feature() call which always occurs before the code
 * is copied out to persistent memory. This means that kstate_paddr
 * is part of the module's data at the time of the copy, so
 * no further work is necessary. n.b. kpcimgr_get_entry() is called
 * after the copy to persistent memory, so any change to the module's
 * data won't affect the data in persistent memory.
 */
unsigned long kpcimgr_get_entry(unsigned long old_entry, unsigned int cpu)
{
	unsigned long (*entry_fn)(unsigned long entry, unsigned int cpu,
				  unsigned long kstate_paddr);
	static DEFINE_SPINLOCK(choose_cpu_lock);
	kstate_t *ks = get_kstate();
	unsigned long entry;

	if (ks == NULL || ks->valid != KSTATE_MAGIC ||
	    !ks->running || !ks->have_persistent_mem)
		return old_entry;

	entry_fn = ks->code_base + ks->code_offsets[K_ENTRY_HOLDING_PEN];

	spin_lock(&choose_cpu_lock);
	entry = entry_fn(old_entry, cpu, ks->kstate_paddr);
	spin_unlock(&choose_cpu_lock);

	return entry;
}
