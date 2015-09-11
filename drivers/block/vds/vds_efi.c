/*
 * vds_vtoc.c: LDOM Virtual Disk Server.
 *
 * Copyright (C) 2014 Oracle. All rights reserved.
 */

#include "vds.h"
#include "vds_io.h"
#include <../block/partitions/check.h>
#include <../block/partitions/efi.h>
#include <linux/byteorder/generic.h>
#include <linux/crc32.h>

#define	VDS_EFI_GPE_LEN(port, nparts) \
	roundup((sizeof(gpt_entry) * (nparts)), (port)->vdisk_bsize)

/*
 * Return a 32-bit CRC of the contents of the buffer.
 *
 * The seed is 0xffffffff and the result is XORed with 0xffffffff
 * because this is what the Itanium firmware expects.
 */
static unsigned int vds_efi_crc32(const unsigned char *s, unsigned int len)
{
	return crc32(~0L, (void *)s, len) ^ ~0L;

}

/*
 * vds_efi_crc_check
 *
 * Compute the CRC on the range of memory specified by (addr, len)
 * and return whether that CRC value matches the value stored at
 * the location referenced by crc_field.
 */
static int vds_efi_crc_check(u32 *crc_field, unsigned char *addr, u32 len)
{
	u32		crc_stored;
	u32		crc_computed;
	int		rv = 0;

	crc_stored = *crc_field;
	*crc_field = cpu_to_le32(0);
	crc_computed = vds_efi_crc32(addr, len);
	*crc_field = crc_stored;

	if (le32_to_cpu(crc_stored) != crc_computed) {
		vdsmsg(warn,
		       "Bad EFI CRC: (stored, computed): (0x%x, 0x%x)\n",
		       crc_stored, crc_computed);
		rv = -EINVAL;
	}

	return rv;
}

/*
 * Check that an EFI GPT is valid. This function should be called with a raw
 * EFI GPT i.e. GPT data should be in little endian format as indicated in the
 * EFI specification and they should not have been swapped to match with the
 * system endianness.
 */
static int vds_efi_check_gpt(struct vio_driver_state *vio,
			     gpt_header *gpt, size_t block_size)
{
	if (gpt->signature != cpu_to_le64(GPT_HEADER_SIGNATURE)) {
		vdsdbg(IOC, "Bad EFI signature: 0x%llx != 0x%llx\n",
		    (long long)gpt->signature,
		    (long long)cpu_to_le64(GPT_HEADER_SIGNATURE));
		return -EINVAL;
	}

	/*
	 * check CRC of the header; the size of the header should
	 * never be larger than one block
	 */
	if (le32_to_cpu(gpt->header_size) > block_size) {
		vdsmsg(warn, "Header (%u bytes) larger than one block (%u)\n",
		       le32_to_cpu(gpt->header_size),
		       (unsigned int)block_size);
		return -EINVAL;
	}

	return vds_efi_crc_check(&gpt->header_crc32,
	    (unsigned char *)gpt, le32_to_cpu(gpt->header_size));
}

static void vds_efi_update_part(struct vds_port *port, gpt_entry *gpe)
{
	int i;
	u64 start, end;

	vds_label_clear_part(port);

	for (i = 0; i < port->npart; i++) {

		start = le64_to_cpu(gpe[i].starting_lba);
		end = le64_to_cpu(gpe[i].ending_lba);

		if (start && end) {
			port->part[i].start = start;
			port->part[i].size = end - start + 1;
		}
	}
}

static int vds_efi_update(struct vds_port *port, gpt_header *gpt)
{
	int rv;
	u32 nparts;
	size_t gpe_len;
	sector_t lba;
	gpt_entry *gpe = NULL;
	struct vio_driver_state *vio = &port->vio;

	/*
	 * Validate GPT and update partition info.
	 */
	rv = vds_efi_check_gpt(vio, gpt, port->vdisk_bsize);
	if (rv) {
		vdsdbg(IOC, "bad EFI GPT\n");
		return rv;
	}

	lba = le64_to_cpu(gpt->partition_entry_lba);
	nparts = le32_to_cpu(gpt->num_partition_entries);

	/*
	 * If the number of partitions represented in the GPT
	 * Header is larger than what is created by convention
	 * force the vdisk subsystem to use the conventional value.
	 *
	 * Note that we do not force a fatal error.  The vdisk
	 * client will not be able to access partitions beyond
	 * the specified value, but the vdisk client will also
	 * not fail on operations that access an EFI disk having
	 * a large number of unused partitions.
	 */
	nparts = min_t(u32, nparts, VDS_MAXPART);
	port->npart = nparts;

	gpe_len = VDS_EFI_GPE_LEN(port, nparts);
	if (gpe_len) {
		gpe = kzalloc(gpe_len, GFP_KERNEL);

		rv = vds_read(port, (void *)gpe, lba, gpe_len);
		if (rv) {
			kfree(gpe);
			port->npart = 0;
			return rv;
		}

		vds_efi_update_part(port, gpe);
		kfree(gpe);
	}

	port->label_type = VDS_LABEL_EFI;

	return 0;
}

/*
 * Get the EFI GPT or GPE from the disk backend. The on-disk GPT and GPE
 * are stored in little endian format and this function converts selected
 * fields using the endianness of the system for it's internal use but the
 * client data is returned unmodified.
 *
 * The number of partitions in an EFI GPT can be larger than what the vdisk
 * subsystem supports.  Return the smaller of what is in the label and what
 * the vdisk subsystem supports.
 */
int vds_efi_validate(struct vds_port *port)
{
	int rv;
	struct vio_driver_state *vio = &port->vio;

	rv = vds_read(port, port->label, VDS_EFI_GPT, DK_LABEL_SIZE);

	if (!rv)
		rv = vds_efi_update(port, (gpt_header *)port->label);

	if (rv)
		vdsdbg(IOC, "failed: rv=%d\n", rv);

	return rv;
}

inline int vds_efi_get(struct vds_port *port, sector_t lba, size_t len,
		       void *data)
{
	return vds_read(port, data, lba, len);
}

int vds_efi_set(struct vds_port *port, sector_t lba, size_t len, void *data)
{
	int rv, err;
	struct vio_driver_state *vio = &port->vio;

	vdsdbg(IOC, "data=%p lba=%lu len=%lu\n", data, lba, len);

	err = vds_write(port, data, lba, len);

	if (err) {
		vdsmsg(err, "write EFI label failed: rv=%d\n", err);
	} else if (lba == VDS_EFI_GPT) {
		rv = vds_efi_validate(port);
		if (rv)
			/*
			 * To convert from EFI to VTOC, Solaris format(1M)
			 * clears the EFI signature, issues a GETGEOM command
			 * and puts the EFI signature back on the disk, so
			 * ignore invalid signature errors here just in case.
			 */
			vdsdbg(IOC, "read EFI label failed: rv=%d\n", rv);
	}

	return err;
}

int vds_efi_clear(struct vds_port *port)
{
	int rv;
	struct vio_driver_state *vio = &port->vio;

	/*
	 * Clear primary and backup GPT.
	 */
	rv = vds_clear(port, VDS_EFI_GPT, port->vdisk_bsize);
	if (rv)
		return rv;

	rv = vds_clear(port, port->vdisk_size - 1, port->vdisk_bsize);
	if (rv)
		vdsdbg(IOC, "Clearing backup GPT failed rv=%d\n", rv);

	vds_label_reset(port);

	return 0;
}
