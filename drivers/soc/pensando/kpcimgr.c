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
 */

#include "kpcimgr_api.h"

MODULE_LICENSE("GPL");

static kstate_t *kstate;

kstate_t *get_kstate(void)
{
	return kstate;
}

void set_kstate(kstate_t *ks)
{
	kstate = ks;
}

/*
 * We need our own memset/memcpy to avoid using
 * any arm instructions that affect the memory cache.
 * The memory used for kstate/code/etc is uncached.
 */
void *kpci_memset(void *s, int c, size_t n)
{
	if (((uintptr_t)s & 0x3) == 0 && (n & 0x3) == 0) {
		u_int32_t *p;
		int i;

		c &= 0xff;
		c = ((c << 0) |
		     (c << 8) |
		     (c << 16) |
		     (c << 24));
		for (p = s, i = 0; i < n >> 2; i++, p++)
			*p = c;
	} else {
		u_int8_t *p;
		int i;

		for (p = s, i = 0; i < n; i++, p++)
			*p = c;
	}

	return s;
}

void *kpci_memcpy(void *dst, const void *src, size_t n)
{
	u_int8_t *d = dst;
	const u_int8_t *s = src;
	int i;

	for (i = 0; i < n; i++)
		*d++ = *s++;

	return dst;
}

/*
 * Notifier block to enable a callback just before a kexec takes place
 */
static int kpcimgr_notify_reboot(struct notifier_block *this,
				 unsigned long code,
				 void *unused);

static struct notifier_block kpcimgr_nb = {
	.notifier_call = kpcimgr_notify_reboot,
	.next = NULL,
	.priority = 0,
};

/*
 * Timers, periodic polling, and work queue definitions
 *
 * Whenever polling is active, start_polling() arms a timer which
 * invokes periodic_poll().
 *
 * periodic_poll() schedules kpcimgr_work() to run, which
 * performs the actuall PCIe poll, checks the event queue, and
 * rearms the timer.
 */

static void periodic_poll(unsigned long);
static DEFINE_TIMER(indirect_timer, periodic_poll, 0, 0);
static struct work_struct indirect_work;
static DECLARE_WAIT_QUEUE_HEAD(event_queue);

/*
 * Normal poll
 */
void kpcimgr_normal_poll(void)
{
	static void (*poll_fn)(kstate_t *, int, int);
	kstate_t *ks = get_kstate();

	if (ks->valid != KSTATE_MAGIC)		/* no code loaded */
		return;

	poll_fn = ks->code_base + ks->poll_offset;
	poll_fn(ks, 0, NORMAL);
}

static void start_polling(void)
{
	mod_timer(&indirect_timer, jiffies + INDIRECT_TIMER_DELAY);
}

static void stop_polling(void)
{
	kstate_t *ks = get_kstate();

	ks->polling = 0;
	del_timer_sync(&indirect_timer);
	cancel_work_sync(&indirect_work);
}

static void kpcimgr_work(struct work_struct *work)
{
	kstate_t *ks = get_kstate();

	kpcimgr_normal_poll();

	/* check for events; see comments for read_kpcimgr() */
	if (ks->evq_head != ks->evq_tail)
		wake_up_interruptible(&event_queue);
	start_polling();
}

void periodic_poll(unsigned long unused)
{
	kstate_t *ks = get_kstate();

	if (ks->polling)
		schedule_work(&indirect_work);
}

/*
 * This function is for testing. It injects an event onto the
 * event queue, simulating an event notification from h/w.
 */
static ssize_t
write_kpcimgr(struct file *file, const char __user *buf,
	      size_t count, loff_t *ppos)
{
	kstate_t *ks = get_kstate();
	char localmem[EVENT_SIZE];

	if ((ks->evq_head + 1) % EVENT_QUEUE_LENGTH == ks->evq_tail)
		return -ENOSPC;

	if (copy_from_user(localmem, buf, EVENT_SIZE))
		return -EFAULT;
	kpci_memcpy(ks->evq[ks->evq_head], localmem, EVENT_SIZE);
	ks->evq_head = (ks->evq_head + 1) % EVENT_QUEUE_LENGTH;
	return EVENT_SIZE;
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
 * modifies head, so theoretically no race can exist. It is
 * possible for the reader to see an empty queue momentarily
 * or the handler to see a full queue momentarily, but these
 * situations do not justify adding locks.
 */
static ssize_t
read_kpcimgr(struct file *file, char __user *buf, size_t nbytes, loff_t *ppos)
{
	kstate_t *ks = get_kstate();
	char localmem[EVENT_SIZE];
	ssize_t n = 0;

	while (nbytes >= EVENT_SIZE) {

		/* is queue empty? */
		if (ks->evq_head == ks->evq_tail)
			break;

		/*
		 * intermediate copy since we cannot prevent copy_to_user
		 * from doing cache operations
		 */
		kpci_memcpy(localmem, ks->evq[ks->evq_tail], EVENT_SIZE);

		if (copy_to_user(buf + n, localmem, EVENT_SIZE))
			return -EFAULT;

		ks->evq_tail = (ks->evq_tail + 1) % EVENT_QUEUE_LENGTH;
		n = n + EVENT_SIZE;
		nbytes = nbytes - EVENT_SIZE;
	}

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

static long ioctl_kpcimgr(struct file *file,
			  unsigned int cmd, unsigned long arg)
{
	void __user *p = (void __user *)arg;
	kstate_t *kstate = get_kstate();

	switch (cmd) {
	case KPCIMGR_INVALIDATE:
		if (kstate->polling)
			pr_info("%s: kernel has stopped polling\n", __func__);
		stop_polling();
		kstate->valid = 0;
		kstate->debug = 0;
		pr_info("%s: code unloaded\n", __func__);
		return 0;

	case KPCIMGR_STOP:
		if (kstate->polling)
			pr_info("%s: kernel has stopped polling\n", __func__);
		stop_polling();
		return 0;

	case KPCIMGR_START:
		if (kstate->polling) {
			pr_info("%s: kernel is already polling\n", __func__);
			return 0;
		}

		pr_info("%s: kernel will begin polling\n", __func__);
		kstate->polling = 1;
		start_polling();
		return 0;

	case KPCIMGR_DEBUG:
		kstate->debug = 1;
		break;

	case KPCIMGR_GET_KSTATE:
		/* for various tools to report system information */
		if (copy_to_user(p, kstate, sizeof(kstate_t)))
			return -EFAULT;
		return 0;

	default:
		return -ENOTTY;
	}

	return 0;
}

/*
 * It would be nice if we could simply save a function pointer
 * directly to ioremap_nocache, etc, but unfortunately it is a macro
 * whose expansion includes a reference to the global cpu_hwcaps, and
 * we cannot access that in pciesvc. So we provide a little wrapper
 * for it here.
 */
static void *kpcimgr_ioremap(phys_addr_t phys_addr, size_t size)
{
	return ioremap_nocache(phys_addr, size);
}

/*
 * Examine code and look for calls (BL insn) and data references
 * (ADRP) to memory addresses outside of the bounds of the module. If
 * any are found, report them and return an error.
 */
int contains_external_refs(struct module *mod, void *code_end)
{
	unsigned long start = (unsigned long) mod->core_layout.base;
	char code_loc[KSYM_SYMBOL_LEN], target_ref[KSYM_SYMBOL_LEN];
	int insn_count = 0, call_count = 0, adrp_count = 0;
	unsigned long size, target, insn_addr;
	s32 offset;
	u32 insn;

	size = (unsigned long) code_end - start;
	pr_debug("Examining code from %lx - %lxp\n", start, start + size);

	for (insn_addr = start;
	     insn_addr < start + size;
	     insn_addr += sizeof(u32)) {

		if (aarch64_insn_read((void *)insn_addr, &insn)) {
			pr_debug("Failed to read insn @ %lx\n", insn_addr);
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
			pr_debug("Found call to %s at %s\n",
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
			pr_debug("Found reference to %s at %s\n",
				 target_ref, code_loc);
			adrp_count++;
		}
	}
	pr_debug("processed %d insns, %d calls, %d adrps\n",
		 insn_count, call_count, adrp_count);

	if (call_count > 0 || adrp_count > 0)
		return 1;
	else
		return 0;
}

/*
 * module_relocate
 *
 * Relocate module code to "non-linux memory". The struct module
 * pointer is not quite enough to do this, and we require a pointer
 * to the end of the module code section. This is because we need to
 * examine the code for certain instructions, and we don't want to
 * look beyond the end of the code since that will be data which
 * might contain values which just look like instructions.
 *
 * If the code contains no external references, then we can freely
 * relocate the code repeatedly without relinking.
 *
 * We stop any polling that is happening, and then copy the module
 * in its entirety to non-linux memory which we have previously
 * mapped executable.
 *
 * After the copy, we restart polling if necessary.
 */
int kpcimgr_module_relocate(struct module *mod, void *code_end)
{
	kstate_t *ks = get_kstate();
	long relocate_size;
	void *start_addr;
	int was_polling;

	if (contains_external_refs(mod, code_end))
		return -ENXIO;

	start_addr = mod->core_layout.base;
	relocate_size = mod->core_layout.size;
	pr_debug("KPCIMGR: start=%p, end=%p, size=%ld\n",
		 start_addr, start_addr+relocate_size, relocate_size);
	if (relocate_size > KSTATE_CODE_SIZE)
		return -EFBIG;

	was_polling = ks->polling;
	stop_polling();
	if (was_polling)
		pr_debug("%s: kernel has stopped polling\n", __func__);

	kpci_memcpy(ks->code_base, (void *) start_addr, relocate_size);
	ks->valid = KSTATE_MAGIC;
	ks->ncalls = 0;
	set_init_state(ks);

	pr_debug("KPCIMGR: relocation done.\n");

	if (was_polling) {
		ks->polling = 1;
		start_polling();
		pr_info("%s: kernel will begin polling\n", __func__);
	} else
		reset_stats(ks);

	return 0;
}
EXPORT_SYMBOL(kpcimgr_module_relocate);

/*
 * Semantics of open(): if no code is loaded then open normally fails.
 * This alerts pciemgrd that it should poll for pcie transactions
 * itself and not rely on the driver. Opening with O_NONBLOCK
 * provides an exception so that various tools can still perform
 * ioctls etc.
 */
static int open_kpcimgr(struct inode *inode, struct file *filp)
{
	kstate_t *ks = get_kstate();

	if (ks->valid == KSTATE_MAGIC || (filp->f_flags & O_NONBLOCK))
		return 0;
	else
		return -ENODEV;
}

static kstate_t *  __init kpcimgr_setup_state(void)
{
	kstate_t *ks = (kstate_t *) ioremap(SHMEM_KSTATE_ADDR,
					    sizeof(kstate_t));

	if (ks == NULL) {
		pr_err("KPCIMGR: failed to map kstate\n");
		return 0;
	}

	if (ks->valid != KSTATE_MAGIC)
		kpci_memset(ks, 0, sizeof(kstate_t));

	/* Map without PTE_PXN so the relocated code can be executed */
	ks->code_base = __ioremap(SHMEM_CODE_ADDR, KSTATE_CODE_SIZE,
				  __pgprot(PROT_NORMAL_NC & ~PTE_PXN));
	if (ks->code_base == NULL) {
		pr_err("KPCIMGR: failed to map shmem code space\n");
		iounmap(ks);
		return 0;
	}

	ks->uart_addr = ioremap_nocache(PEN_UART, 0x1000);
	if (ks->uart_addr == NULL) {
		pr_err("KPCIMGR: failed to map elba uart\n");
		iounmap(ks->code_base);
		iounmap(ks);
		return 0;
	}

	ks->driver_start_time = read_sysreg(cntvct_el0);
	ks->iomap_fn = kpcimgr_ioremap;
	set_kstate(ks);

	return ks;
}

static const struct file_operations __maybe_unused kpcimgr_fops = {
	.owner          = THIS_MODULE,
	.unlocked_ioctl	= ioctl_kpcimgr,
	.read           = read_kpcimgr,
	.write          = write_kpcimgr,
	.poll           = poll_kpcimgr,
	.open           = open_kpcimgr,
};

static struct miscdevice kpcimgr_dev = {
	MISC_DYNAMIC_MINOR,
	KPCIMGR_NAME,
	&kpcimgr_fops
};

static int __init kpcimgr_dev_init(void)
{
	kstate_t *ks;
	int ret;

	pr_info("KPCIMGR: loading\n");
	ks = kpcimgr_setup_state();
	if (ks == NULL) {
		pr_err("KPCIMGR: not started\n");
		return -ENODEV;
	}

	INIT_WORK(&indirect_work, &kpcimgr_work);
	ret = misc_register(&kpcimgr_dev);
	if (ret == 0) {
		if (ks->valid == KSTATE_MAGIC && ks->polling) {
			kpcimgr_normal_poll();
			start_polling();
			pr_info("KPCIMGR: initialized and polling.\n");
		}
		register_reboot_notifier(&kpcimgr_nb);
	}

	pr_info("KPCIMGR: kstate mapped at %p, code at %p\n", ks,
		ks->code_base);

	if (ret == 0)
		pr_err("KPCIMGR: Registered\n");
	else
		pr_err("KPCIMGR: Registration failure\n");

	return ret;
}
module_init(kpcimgr_dev_init);

/*
 * Called when a kexec is about to happen
 */
static int kpcimgr_notify_reboot(struct notifier_block *this,
				 unsigned long code,
				 void *unused)
{
	kstate_t *ks = get_kstate();
	int was_polling = ks->polling;

	/* stop polling regardless of why a reboot is happening */
	stop_polling();
	if (code == SYS_DOWN) {
		pr_debug("KPCIMGR: going down at tick %lld\n",
			 read_sysreg(cntvct_el0));

		if (was_polling) {
			pr_debug("KPCIMGR: last poll\n");
			ks->polling = 1;
			kpcimgr_normal_poll();
		}

		reset_stats(ks);
		ks->ncalls = 0;
		ks->kexec_time = read_sysreg(cntvct_el0);
	}
	return NOTIFY_DONE;
}

/*
 * Get entry point for pciesvc specific secondary cpu holding pen.
 * Called from arch/arm64/kernel/smp_spin_table.c
 * We choose the first cpu to arrive here. They will all try
 * concurrently, but only one will be hijacked and the rest
 * will go to their default holding pens.
 */
unsigned long kpcimgr_get_entry(unsigned long old_entry, unsigned int cpu)
{
	static DEFINE_SPINLOCK(choose_cpu_lock);
	unsigned long entry = old_entry;
	kstate_t *ks = get_kstate();
	static int cpu_chosen;

	if (ks == NULL || ks->valid != KSTATE_MAGIC || !ks->polling)
		return entry;

	spin_lock(&choose_cpu_lock);

	if (cpu && !cpu_chosen) {
		cpu_chosen = cpu;
		pr_info("kpcimgr_cpu_holding_pen will run on cpu %d\n", cpu);
		entry =  SHMEM_CODE_ADDR + ks->cpu_holding_pen_offset;
	}

	spin_unlock(&choose_cpu_lock);
	return entry;
}
