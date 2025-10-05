/*
 * Assignment of PCI 64-bit prefetchable memory resources
 *
 * Copyright 2015, Arista Networks, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */

#include <linux/string.h>
#include <linux/init.h>
#include <linux/pci.h>
#include <linux/export.h>

#define ONE_MB (1024ULL*1024)
#define ONE_GB (ONE_MB*1024)

#define DEBUG_ON
#ifdef DEBUG_ON
#define DEBUG(...) do { printk(KERN_DEBUG __VA_ARGS__); } while (0)
#else
#define DEBUG(...)
#endif

struct prefmem_setting {
	int depth;  /* -1 for wildcard */
	int vendor;
	int device; /* -1 for wildcard */
	resource_size_t size;  /* 0 for end-of-list */
};

struct platform_hotplug {
	const char *name;
	const struct prefmem_setting *settings;
};
static const struct platform_hotplug *prefmem_hotplug_info = NULL;

static const struct prefmem_setting yosemite[] = {
	{3,  PCI_VENDOR_ID_PLX,        0x8725, ONE_GB},
	{3,  PCI_VENDOR_ID_PLX,        0x8749, ONE_GB},
	{5,  PCI_VENDOR_ID_PLX,        -1,     64*ONE_MB},
	{},
};

static const struct prefmem_setting denali[] = {
	{3,  PCI_VENDOR_ID_PMC_Sierra, 0x8533, 8*ONE_GB},
	{3,  PCI_VENDOR_ID_PMC_Sierra, 0x8534, 8*ONE_GB},
	{5,  PCI_VENDOR_ID_PLX,        -1,     64*ONE_MB},
	{},
};

static const struct prefmem_setting tundra[] = {
	{3,  PCI_VENDOR_ID_PMC_Sierra, 0x8532, ONE_GB},
	{5,  PCI_VENDOR_ID_PLX,        -1,     64*ONE_MB},
	{},
};

static const struct prefmem_setting oak[] = {
	{3,  PCI_VENDOR_ID_PLX,        0x8725, ONE_GB},
	{3,  PCI_VENDOR_ID_PLX,        0x8749, ONE_GB},
	{5,  PCI_VENDOR_ID_PLX,        -1,     32*ONE_MB},
	{},
};

static const struct prefmem_setting crow[] = {
	{3,  PCI_VENDOR_ID_PLX,        0x8609, 512*ONE_MB},
	{},
};

static const struct prefmem_setting magpie[] = {
	{3,  PCI_VENDOR_ID_PLX,        0x8609, 512*ONE_MB},
	{},
};

static const struct prefmem_setting blackbird[] = {
	{3,  PCI_VENDOR_ID_PLX,        0x8717, 32*ONE_MB},
	{},
};

static const struct prefmem_setting rook[] = {
	{3,  PCI_VENDOR_ID_PLX,        0x8717, 64*ONE_MB},
	{5,  PCI_VENDOR_ID_PLX,        0x8717, 64*ONE_MB},
	{-1, PCI_VENDOR_ID_INTEL,      0x8c10, 64*ONE_MB},
	{-1, PCI_VENDOR_ID_INTEL,      0x8c12, 64*ONE_MB},
	{-1, PCI_VENDOR_ID_INTEL,      0x8c14, 64*ONE_MB},
	{-1, PCI_VENDOR_ID_INTEL,      0x8c16, 64*ONE_MB},
	{-1, PCI_VENDOR_ID_INTEL,      0x8c18, 64*ONE_MB},
	{-1, PCI_VENDOR_ID_INTEL,      0x8c1a, 64*ONE_MB},
	{-1, PCI_VENDOR_ID_INTEL,      0x8c1c, 64*ONE_MB},
	{-1, PCI_VENDOR_ID_INTEL,      0x8c1e, 64*ONE_MB},
	{},
};

static const struct prefmem_setting woodpecker[] = {
	{-1, PCI_VENDOR_ID_AMD,        0x157c, 64*ONE_MB},
	{},
};

static const struct prefmem_setting lorikeet[] = {
	{-1, PCI_VENDOR_ID_AMD,        0x1453, 128*ONE_MB},
	{3,  PCI_VENDOR_ID_PLX,        -1, ONE_GB},
	{},
};

static const struct platform_hotplug platform_list[] = {
	{ "eaglepeak", yosemite },
	{ "oldfaithful", yosemite },
	{ "greatfountain", yosemite },
	{ "oak", oak },
	{ "crow", crow },
	{ "magpie", magpie },
	{ "blackbird", blackbird },
	{ "rook", rook },
	{ "montara", rook },
	{ "sprucefish", denali },
	{ "hedgehog", lorikeet },
	{ "dawson", rook },
	{ "woodpecker", woodpecker },
	{ "belvedere", woodpecker },
	{ "narwhal", tundra },
	{ "penguin", tundra },
	{ "lorikeet", lorikeet },
};

static resource_size_t power2(resource_size_t sz)
{
	return (sz)? roundup_pow_of_two(sz) : 0;
}

static resource_size_t pci_bus_prefmem_sz_child(struct pci_bus *bus)
{
	struct pci_dev *dev;
	struct resource *res;
	resource_size_t child_sz = 0;
	unsigned long prefmask = IORESOURCE_MEM | IORESOURCE_PREFETCH;

	list_for_each_entry(dev, &bus->devices, bus_list) {
		int i;
		resource_size_t devsz = 0;

		for (i = 0; i < PCI_NUM_RESOURCES; i++) {
			res = &dev->resource[i];

			if ((res->flags & prefmask) == prefmask)
				devsz += resource_size(res);
		}

		if ((dev->class >> 8) != PCI_CLASS_BRIDGE_PCI)
			devsz = power2(devsz);

		child_sz += devsz;
	}

	return child_sz;
}

static int pci_dev_depth(struct pci_dev *dev)
{
	int depth = 0;
	struct pci_bus *bus;

	bus = dev->bus;
	while (bus) {
		depth++;
		bus = bus->parent;
	}

	return depth;
}

static resource_size_t pci_bus_prefmem_sz(struct pci_bus *bus)
{
	resource_size_t sz_hotplug = 0;
	resource_size_t sz_child = pci_bus_prefmem_sz_child(bus);
	struct pci_dev *dev = bus->self;
	int pci_depth = pci_dev_depth(dev);
	const struct prefmem_setting *setting;
	int i;

	if (!prefmem_hotplug_info)
		goto out;

	for(i = 0; prefmem_hotplug_info->settings[i].size != 0; i++) {
		setting = &prefmem_hotplug_info->settings[i];

		if (setting->depth != -1 && setting->depth != pci_depth)
			continue;
		if (setting->vendor != dev->vendor)
			continue;
		if (setting->device != -1 && setting->device != dev->device)
			continue;

		sz_hotplug = setting->size;
		break;
	}

out:
	DEBUG("%s: %s hotplug=0x%llx child=0x%llx\n",
	      __FUNCTION__, bus->name, sz_hotplug, sz_child);

	return max(sz_child, sz_hotplug);
}

static void pbus_resize_prefmem(struct pci_bus *bus, bool release)
{
	struct resource *res;
	int resno = PCI_BRIDGE_RESOURCES + 2;
	resource_size_t sz_new;
	unsigned long prefmask = IORESOURCE_MEM | IORESOURCE_PREFETCH;

	res = &bus->self->resource[resno];

	if (res->flags && res->parent) {
		if (!release) {
			DEBUG("%s resource %d %pR kept as is\n",
			      bus->name, resno, res);
			return;
		}
		/* first release */
		release_child_resources(res);
		if (!release_resource(res)) {
			printk(KERN_INFO "%s resource %d %pR released\n",
			       bus->name, resno, res);
			/* keep the old size */
			res->end = resource_size(res) - 1;
			res->start = 0;
			res->flags = 0;
		}
	}

	/* reassign its size */
	sz_new = pci_bus_prefmem_sz(bus);
	if (sz_new > resource_size(res)) {
		res->start = 0;
		res->end = sz_new - 1;
	}
	if (res->end) {
		res->flags = prefmask | IORESOURCE_MEM_64 | IORESOURCE_SIZEALIGN;
	}

	DEBUG("%s: resource %d %pR new_size: 0x%llx\n",
	      bus->name, resno, res, sz_new);
}

static void _pci_bus_resize_prefmem(struct pci_bus *bus, bool release)
{
	struct pci_dev *dev;

	list_for_each_entry(dev, &bus->devices, bus_list) {
		struct pci_bus *child_bus = dev->subordinate;
		if (!child_bus ||
		    ((child_bus->self->class >> 8) != PCI_CLASS_BRIDGE_PCI))
			continue;

		_pci_bus_resize_prefmem(child_bus, release);
	}

	if (pci_is_root_bus(bus))
		return;

	if ((bus->self->class >> 8) == PCI_CLASS_BRIDGE_PCI)
		pbus_resize_prefmem(bus, release);

}

static int __init platform_hotplug_info_setup(char *str)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(platform_list); i++)
		if (!strcmp(platform_list[i].name, str)) {
			prefmem_hotplug_info = &platform_list[i];
			break;
		}
	return 0;
}
__setup("platform=", platform_hotplug_info_setup);

static u8 reassign_prefmem = 0;
static int __init reassign_prefmem_setup(char *p)
{
	reassign_prefmem = 1;
	return 0;
}
early_param("reassign_prefmem", reassign_prefmem_setup);

int pci_bus_resize_prefmem(struct pci_bus *bus)
{
	if (!reassign_prefmem)
		return 0;

	if (!prefmem_hotplug_info)
		return 0;

	_pci_bus_resize_prefmem(bus, false);
	return 1;
}
EXPORT_SYMBOL(pci_bus_resize_prefmem);

void pci_reassign_prefmem_res(void)
{
	struct pci_bus *bus;

	if (!reassign_prefmem)
		return;

	list_for_each_entry(bus, &pci_root_buses, node) {
		_pci_bus_resize_prefmem(bus, true);
		pci_bus_assign_resources(bus);
	}
}
EXPORT_SYMBOL(pci_reassign_prefmem_res);
