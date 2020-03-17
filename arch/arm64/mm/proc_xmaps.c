// SPDX-License-Identifier: GPL-2.0
#include <linux/mm.h>
#include <linux/seq_file.h>
#include <linux/pagemap.h>

void proc_xmaps_show_vma_header_prefix(struct seq_file *m,
				   unsigned long start, unsigned long end,
				   vm_flags_t flags, unsigned long long pgoff,
				   dev_t dev, unsigned long ino, pgprot_t prot)
{
	static const char *shnams[] = {
		"NonSh", "Rsvd", "Outer", "Inner"
	};
	static const char *names[] = {
		"Device_nGnRnE", "Device_nGnRE", "Device_GRE",
		"Normal_NC", "Normal", "Normal_WT", "ATTR(6)",
		"ATTR(7)"
	};

	seq_setwidth(m, 25 + sizeof(void *) * 6 - 1);
	seq_printf(m, "%09lx-%09lx %c%c%c%c %09llx %02x:%02x %5lu %016llx %-5s %-13s ",
		start,
		end,
		flags & VM_READ ? 'r' : '-',
		flags & VM_WRITE ? 'w' : '-',
		flags & VM_EXEC ? 'x' : '-',
		flags & VM_MAYSHARE ? 's' : 'p',
		pgoff,
		MAJOR(dev), MINOR(dev), ino,
		pgprot_val(prot),
		shnams[(pgprot_val(prot) >> 8) & 0x3],
		names[(pgprot_val(prot) >> 2) & 0x7]);
}
