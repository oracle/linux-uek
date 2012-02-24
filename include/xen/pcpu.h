#ifndef _XEN_PCPU_H
#define _XEN_PCPU_H

#include <xen/interface/platform.h>
#include <linux/sysdev.h>

extern int xen_pcpu_hotplug(int type, uint32_t apic_id);
#define XEN_PCPU_ONLINE     0x01
#define XEN_PCPU_OFFLINE    0x02
#define XEN_PCPU_ADD        0x04
#define XEN_PCPU_REMOVE     0x08

struct pcpu {
	struct list_head pcpu_list;
	struct sys_device sysdev;
	uint32_t xen_id;
	uint32_t apic_id;
	uint32_t acpi_id;
	uint32_t flags;
};

static inline int xen_pcpu_online(uint32_t flags)
{
	return !!(flags & XEN_PCPU_FLAGS_ONLINE);
}

extern int register_xen_pcpu_notifier(struct notifier_block *nb);

extern void unregister_xen_pcpu_notifier(struct notifier_block *nb);

extern int xen_pcpu_index(uint32_t acpi_id, int is_acpiid);
#endif
