/*
 * pcpu.c - management physical cpu in dom0 environment
 */
#include <linux/interrupt.h>
#include <linux/spinlock.h>
#include <asm/xen/hypervisor.h>
#include <asm/xen/hypercall.h>
#include <linux/cpu.h>
#include <xen/xenbus.h>
#include <xen/pcpu.h>
#include <xen/events.h>
#include <xen/acpi.h>

static struct sysdev_class xen_pcpu_sysdev_class = {
	.name = "xen_pcpu",
};

static DEFINE_MUTEX(xen_pcpu_lock);
static RAW_NOTIFIER_HEAD(xen_pcpu_chain);

/* No need for irq disable since hotplug notify is in workqueue context */
#define get_pcpu_lock() mutex_lock(&xen_pcpu_lock);
#define put_pcpu_lock() mutex_unlock(&xen_pcpu_lock);

struct xen_pcpus {
	struct list_head list;
	int present;
};
static struct xen_pcpus xen_pcpus;

int register_xen_pcpu_notifier(struct notifier_block *nb)
{
	int ret;

	/* All refer to the chain notifier is protected by the pcpu_lock */
	get_pcpu_lock();
	ret = raw_notifier_chain_register(&xen_pcpu_chain, nb);
	put_pcpu_lock();
	return ret;
}
EXPORT_SYMBOL_GPL(register_xen_pcpu_notifier);

void unregister_xen_pcpu_notifier(struct notifier_block *nb)
{
	get_pcpu_lock();
	raw_notifier_chain_unregister(&xen_pcpu_chain, nb);
	put_pcpu_lock();
}
EXPORT_SYMBOL_GPL(unregister_xen_pcpu_notifier);

static int xen_pcpu_down(uint32_t xen_id)
{
	int ret;
	xen_platform_op_t op = {
		.cmd			= XENPF_cpu_offline,
		.interface_version	= XENPF_INTERFACE_VERSION,
		.u.cpu_ol.cpuid	= xen_id,
	};

	ret = HYPERVISOR_dom0_op(&op);
	return ret;
}

static int xen_pcpu_up(uint32_t xen_id)
{
	int ret;
	xen_platform_op_t op = {
		.cmd			= XENPF_cpu_online,
		.interface_version	= XENPF_INTERFACE_VERSION,
		.u.cpu_ol.cpuid	= xen_id,
	};

	ret = HYPERVISOR_dom0_op(&op);
	return ret;
}

static ssize_t show_online(struct sys_device *dev,
			struct sysdev_attribute *attr,
			char *buf)
{
	struct pcpu *cpu = container_of(dev, struct pcpu, sysdev);

	return sprintf(buf, "%u\n", !!(cpu->flags & XEN_PCPU_FLAGS_ONLINE));
}

static ssize_t __ref store_online(struct sys_device *dev,
				  struct sysdev_attribute *attr,
				  const char *buf, size_t count)
{
	struct pcpu *cpu = container_of(dev, struct pcpu, sysdev);
	ssize_t ret;

	switch (buf[0]) {
	case '0':
		ret = xen_pcpu_down(cpu->xen_id);
		break;
	case '1':
		ret = xen_pcpu_up(cpu->xen_id);
		break;
	default:
		ret = -EINVAL;
	}

	if (ret >= 0)
		ret = count;
	return ret;
}

static SYSDEV_ATTR(online, 0644, show_online, store_online);

static ssize_t show_apicid(struct sys_device *dev,
			struct sysdev_attribute *attr,
			char *buf)
{
	struct pcpu *cpu = container_of(dev, struct pcpu, sysdev);

	return sprintf(buf, "%u\n", cpu->apic_id);
}

static ssize_t show_acpiid(struct sys_device *dev,
			struct sysdev_attribute *attr,
			char *buf)
{
	struct pcpu *cpu = container_of(dev, struct pcpu, sysdev);

	return sprintf(buf, "%u\n", cpu->acpi_id);
}
static SYSDEV_ATTR(apic_id, 0444, show_apicid, NULL);
static SYSDEV_ATTR(acpi_id, 0444, show_acpiid, NULL);

static int xen_pcpu_free(struct pcpu *pcpu)
{
	if (!pcpu)
		return 0;

	sysdev_remove_file(&pcpu->sysdev, &attr_online);
	sysdev_unregister(&pcpu->sysdev);
	list_del(&pcpu->pcpu_list);
	kfree(pcpu);

	return 0;
}

static inline int same_pcpu(struct xenpf_pcpuinfo *info,
			    struct pcpu *pcpu)
{
	return (pcpu->apic_id == info->apic_id) &&
		(pcpu->xen_id == info->xen_cpuid);
}

/*
 * Return 1 if online status changed
 */
static int xen_pcpu_online_check(struct xenpf_pcpuinfo *info,
				 struct pcpu *pcpu)
{
	int result = 0;

	if (info->xen_cpuid != pcpu->xen_id)
		return 0;

	if (xen_pcpu_online(info->flags) && !xen_pcpu_online(pcpu->flags)) {
		/* the pcpu is onlined */
		pcpu->flags |= XEN_PCPU_FLAGS_ONLINE;
		kobject_uevent(&pcpu->sysdev.kobj, KOBJ_ONLINE);
		raw_notifier_call_chain(&xen_pcpu_chain,
			XEN_PCPU_ONLINE, (void *)(long)pcpu->xen_id);
		result = 1;
	} else if (!xen_pcpu_online(info->flags) &&
		 xen_pcpu_online(pcpu->flags))  {
		/* The pcpu is offlined now */
		pcpu->flags &= ~XEN_PCPU_FLAGS_ONLINE;
		kobject_uevent(&pcpu->sysdev.kobj, KOBJ_OFFLINE);
		raw_notifier_call_chain(&xen_pcpu_chain,
			XEN_PCPU_OFFLINE, (void *)(long)pcpu->xen_id);
		result = 1;
	}

	return result;
}

static int pcpu_sysdev_init(struct pcpu *cpu)
{
	int error;

	error = sysdev_register(&cpu->sysdev);
	if (error) {
		printk(KERN_WARNING "xen_pcpu_add: Failed to register pcpu\n");
		kfree(cpu);
		return -1;
	}
	sysdev_create_file(&cpu->sysdev, &attr_online);
	sysdev_create_file(&cpu->sysdev, &attr_apic_id);
	sysdev_create_file(&cpu->sysdev, &attr_acpi_id);
	return 0;
}

static struct pcpu *get_pcpu(int xen_id)
{
	struct pcpu *pcpu = NULL;

	list_for_each_entry(pcpu, &xen_pcpus.list, pcpu_list) {
		if (pcpu->xen_id == xen_id)
			return pcpu;
	}
	return NULL;
}

static struct pcpu *init_pcpu(struct xenpf_pcpuinfo *info)
{
	struct pcpu *pcpu;

	if (info->flags & XEN_PCPU_FLAGS_INVALID)
		return NULL;

	/* The PCPU is just added */
	pcpu = kzalloc(sizeof(struct pcpu), GFP_KERNEL);
	if (!pcpu)
		return NULL;

	INIT_LIST_HEAD(&pcpu->pcpu_list);
	pcpu->xen_id = info->xen_cpuid;
	pcpu->apic_id = info->apic_id;
	pcpu->acpi_id = info->acpi_id;
	pcpu->flags = info->flags;

	pcpu->sysdev.cls = &xen_pcpu_sysdev_class;
	pcpu->sysdev.id = info->xen_cpuid;

	if (pcpu_sysdev_init(pcpu)) {
		kfree(pcpu);
		return NULL;
	}

	list_add_tail(&pcpu->pcpu_list, &xen_pcpus.list);
	raw_notifier_call_chain(&xen_pcpu_chain,
				XEN_PCPU_ADD,
				(void *)(long)pcpu->xen_id);
	return pcpu;
}

#define PCPU_NO_CHANGE			0
#define PCPU_ADDED			1
#define PCPU_ONLINE_OFFLINE		2
#define PCPU_REMOVED			3
/*
 * Caller should hold the pcpu lock
 * < 0: Something wrong
 * 0: No changes
 * > 0: State changed
 */
static struct pcpu *_sync_pcpu(int cpu_num, int *max_id, int *result)
{
	struct pcpu *pcpu = NULL;
	struct xenpf_pcpuinfo *info;
	xen_platform_op_t op = {
		.cmd            = XENPF_get_cpuinfo,
		.interface_version  = XENPF_INTERFACE_VERSION,
	};
	int ret;

	*result = -1;

	info = &op.u.pcpu_info;
	info->xen_cpuid = cpu_num;

	ret = HYPERVISOR_dom0_op(&op);
	if (ret)
		return NULL;

	if (max_id)
		*max_id = op.u.pcpu_info.max_present;

	pcpu = get_pcpu(cpu_num);

	if (info->flags & XEN_PCPU_FLAGS_INVALID) {
		/* The pcpu has been removed */
		*result = PCPU_NO_CHANGE;
		if (pcpu) {
			raw_notifier_call_chain(&xen_pcpu_chain,
			  XEN_PCPU_REMOVE,
			  (void *)(long)pcpu->xen_id);
			xen_pcpu_free(pcpu);
			*result = PCPU_REMOVED;
		}
		return NULL;
	}


	if (!pcpu) {
		*result = PCPU_ADDED;
		pcpu = init_pcpu(info);
		if (pcpu == NULL) {
			printk(KERN_WARNING "Failed to init pcpu %x\n",
			  info->xen_cpuid);
			  *result = -1;
		}
	} else {
		*result = PCPU_NO_CHANGE;
		/*
		 * Old PCPU is replaced with a new pcpu, this means
		 * several virq is missed, will it happen?
		 */
		if (!same_pcpu(info, pcpu)) {
			printk(KERN_WARNING "Pcpu %x changed!\n",
			  pcpu->xen_id);
			pcpu->apic_id = info->apic_id;
			pcpu->acpi_id = info->acpi_id;
		}
		if (xen_pcpu_online_check(info, pcpu))
			*result = PCPU_ONLINE_OFFLINE;
	}
	return pcpu;
}

int xen_pcpu_index(uint32_t id, int is_acpiid)
{
	int cpu_num = 0, max_id = 0, ret;
	xen_platform_op_t op = {
		.cmd            = XENPF_get_cpuinfo,
		.interface_version  = XENPF_INTERFACE_VERSION,
	};
	struct xenpf_pcpuinfo *info = &op.u.pcpu_info;

	info->xen_cpuid = 0;
	ret = HYPERVISOR_dom0_op(&op);
	if (ret)
		return -1;
	max_id = op.u.pcpu_info.max_present;

	while ((cpu_num <= max_id)) {
		info->xen_cpuid = cpu_num;
		ret = HYPERVISOR_dom0_op(&op);
		if (ret)
			continue;

		if (op.u.pcpu_info.max_present > max_id)
			max_id = op.u.pcpu_info.max_present;
		if (id == (is_acpiid ? info->acpi_id : info->apic_id))
			return cpu_num;
		cpu_num++;
	}

    return -1;
}
EXPORT_SYMBOL(xen_pcpu_index);

/*
 * Sync dom0's pcpu information with xen hypervisor's
 */
static int xen_sync_pcpus(void)
{
	/*
	 * Boot cpu always have cpu_id 0 in xen
	 */
	int cpu_num = 0, max_id = 0, result = 0, present = 0;
	struct list_head *elem, *tmp;
	struct pcpu *pcpu;

	get_pcpu_lock();

	while ((result >= 0) && (cpu_num <= max_id)) {
		pcpu = _sync_pcpu(cpu_num, &max_id, &result);

		printk(KERN_DEBUG "sync cpu %x get result %x max_id %x\n",
			cpu_num, result, max_id);

		switch (result)	{
		case PCPU_NO_CHANGE:
			if (pcpu)
				present++;
			break;
		case PCPU_ADDED:
		case PCPU_ONLINE_OFFLINE:
			present++;
		case PCPU_REMOVED:
			break;
		default:
			printk(KERN_WARNING "Failed to sync pcpu %x\n",
			  cpu_num);
			break;

		}
		cpu_num++;
	}

	if (result < 0) {
		list_for_each_safe(elem, tmp, &xen_pcpus.list) {
			pcpu = list_entry(elem, struct pcpu, pcpu_list);
			xen_pcpu_free(pcpu);
		}
		present = 0;
	}

	xen_pcpus.present = present;

	put_pcpu_lock();

	return 0;
}

static void xen_pcpu_dpc(struct work_struct *work)
{
	if (xen_sync_pcpus() < 0)
		printk(KERN_WARNING
			"xen_pcpu_dpc: Failed to sync pcpu information\n");
}
static DECLARE_WORK(xen_pcpu_work, xen_pcpu_dpc);

int xen_pcpu_hotplug(int type, uint32_t apic_id)
{
	schedule_work(&xen_pcpu_work);

	return 0;
}
EXPORT_SYMBOL(xen_pcpu_hotplug);

static irqreturn_t xen_pcpu_interrupt(int irq, void *dev_id)
{
	schedule_work(&xen_pcpu_work);
	return IRQ_HANDLED;
}

static int __init xen_pcpu_init(void)
{
	int err;

	if (!xen_initial_domain())
		return 0;

	err = sysdev_class_register(&xen_pcpu_sysdev_class);
	if (err) {
		printk(KERN_WARNING
			"xen_pcpu_init: register xen_pcpu sysdev Failed!\n");
		return err;
	}

	INIT_LIST_HEAD(&xen_pcpus.list);
	xen_pcpus.present = 0;

	xen_sync_pcpus();
	if (xen_pcpus.present > 0)
		err = bind_virq_to_irqhandler(VIRQ_PCPU_STATE,
			0, xen_pcpu_interrupt, 0, "pcpu", NULL);
	if (err < 0)
		printk(KERN_WARNING "xen_pcpu_init: "
			"Failed to bind pcpu_state virq\n"
			"You will lost latest information! \n");
	return err;
}

arch_initcall(xen_pcpu_init);
