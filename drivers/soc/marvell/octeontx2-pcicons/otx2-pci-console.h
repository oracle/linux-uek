/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2019 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Supports the PCI Console when OcteonTX2 is running as an Endpoint.
 *
 */

#ifndef __OTX2_PCI_CONSOLE_H__
#define __OTX2_PCI_CONSOLE_H__

/** CONSOLE! converted to little-endian */
#define OCTEONTX_PCIE_CONSOLE_MAGIC             0x21454C4F534E4F43

/** CONDSCR! converted to little-endian */
#define OCTEONTX_PCIE_CONSOLE_NEXUS_MAGIC       0x21524353444E4F43

#define OCTEONTX_PCIE_CONSOLE_MAJOR             1
#define OCTEONTX_PCIE_CONSOLE_MINOR             0

#define OCTEONTX_PCIE_MAX_CONSOLES              8

#define OCTEONTX_PCIE_CONSOLE_NAME_LEN          16

#define PCI_CONS_HOST_WAIT_TIMEOUT_USECS        1000
#define PCI_CONS_HOST_WAIT_LOOP_USECS           10

#define PCI_CONS_TTY_POLL_INTERVAL_JIFFIES      1
/**
 * NOTE: this must match structure in U-Boot console driver.
 *
 * This is the main container structure that contains all the information
 * about all PCI consoles.  The address of this structure is passed to
 * various routines that operation on PCI consoles.
 *
 * @param magic         console descriptor magic number
 * @param major_version major version of console data structure
 * @param minor_version minor version of console data structure
 * @param flags         flags applied to all consoles
 * @param num_consoles  number of console data structures available
 * @param excl_lock     lock between cores for this data structure
 * @param in_use        Set if the console is claimed by anyone (shared or not)
 * @param exclusive     bitmap of consoles exclusively used
 * @param pad           padding for header for future versions
 * @param console_addr  array of addresses for each console, 0 if unavailable.
 */
struct octeontx_pcie_console_nexus {
	__le64                magic;
	u8                    major_version;
	u8                    minor_version;
	u8                    flags;
	u8                    num_consoles;
	spinlock_t            excl_lock;
	__le32 /* volatile */ in_use;
	__le32 /* volatile */ exclusive;
	u64                   pad[13];
	/* Starts at offset 128 */
	__le64                console_addr[OCTEONTX_PCIE_MAX_CONSOLES];
} __packed;

/**
 * NOTE: this must match structure in U-Boot console driver.
 *
 * Structure that defines a single console.
 *
 * Note: when read_index == write_index, the buffer is empty.
 * The actual usable size  of each console is console_buf_size -1;
 *
 * There are two different types of locks.  pcie_lock is for locking
 * between the host and target.  excl_lock should always be acquired
 * before pcie_lock is acquired and released after pcie_lock is released.
 *
 * excl_lock is a spinlock held between different tasks, such as u-boot
 * and atf or the atf and the Linux kernel.  It should be held whenever
 * any of the indices are changed or when the pcie_lock is held.
 *
 * @param magic                 console magic number OCTEONTX_PCIE_CONSOLE_MAGIC
 * @param name                  name assigned to the console ("ATF", "U-Boot")
 * @param flags                 flags associated with console, see
 *                                 OCTEONTX_PCIE_CONSOLE_FLAG_...
 * @param owner_id              owning task id of last user, 0 if unused.
 * @param input_buf_size        Input buffer size in bytes
 * @param output_buf_size       Output buffer size in bytes
 * @param input_base_addr       Base address of input buffer
 * @param input_read_index      index target begins reading data from
 * @param input_write_index     index host starts writing from
 * @param output_base_addr      Base address of output buffer
 * @param host_console_connected   non-zero if host console is connected
 * @param output_read_index     index host reads from
 * @param output_write_index    index target writes to
 * @param pcie_lock             lock held whenever the indices are updated
 *                              using Peterson's algorithm.  Use
 *                              octeontx_pcie_target_lock() and
 *                              octeontx_pcie_target_unlock() to lock and
 *                              unlock this data structure.
 * @param user                  User-defined pointer
 *                              (octeontx_pcie_console_priv *) for U-Boot
 * @param excl_lock             cpu core lock.  This lock should be held
 *                              whenever this data structure is updated by
 *                              the target since it can be shared by multiple
 *                              targets.
 * @param pad                   pads header to 128 bytes
 *
 * Typically the input and output buffers immediately follow this data
 * structure, however, this is not a requirement.
 *
 * Note that the host_console_connected and output_read_index MUST be
 * next to each other and should be 64-bit aligned. This is due to the
 * fact that if the output buffer fills up and no host is connected that
 * the read pointer must be modified atomically in case the host should
 * connect within that window.
 */
struct octeontx_pcie_console {
	__le64                     magic;
	char                       name[OCTEONTX_PCIE_CONSOLE_NAME_LEN];
	__le32 /* volatile */      flags;
	__le32 /* volatile */      owner_id;
	__le32                     input_buf_size;
	__le32                     output_buf_size;
	__le64                     input_base_addr;
	__le32                     input_read_index;
	__le32 /* volatile */      input_write_index;
	__le64                     output_base_addr;
	__le32 /* volatile */      host_console_connected;
	__le32 /* volatile */      output_read_index;
	__le32                     output_write_index;
	union {
		__le32             unused_excl_lock;
		__le32             cons_idx; /* host console index */
	} host;
	void                       *user;
	u32 /* i.e. struct octeontx_pcie_lock */ pcie_lock;
	u32                        pad[8];
} __packed;

/**
 * struct pci_console_nexus: Console nexus driver state
 *
 * @of_node:                 associated device tree node
 * @of_base:                 device tree nexus address
 * @of_size:                 device tree nexus size
 * @nexus:                   [mapped] pointer to nexus state structure
 */
struct pci_console_nexus {
	struct device_node                         *of_node;
	struct octeontx_pcie_console_nexus __iomem *desc;
};

/**
 * struct pci_console:        Console driver state
 *
 * @device:                   Linux device
 * @cons:                     Linux console
 * @of_node:                  associated device tree node
 * @ring_descr:               [mapped] pointer to console memory ring descriptor
 * @input_ring:               [mapped] pointer to console input ring
 * @output_ring:              [mapped] pointer to console output ring
 * @nexus_desc:               [mapped] nexus descriptor
 * @octeontx_console_acquired indicates if console was acquired (and therefore,
 *                            needs to be release during de-init)
 * @tty.drv:                  Linux TTY driver
 * @tty.port:                 Linux TTY port
 * @tty.poll_timer:           Linux timer used to poll for available data
 * @tty.open_count:           reference count for TTY driver
 */
struct pci_console {
	struct device                        *device;
	struct console                       cons;
	struct device_node                   *of_node;
	struct octeontx_pcie_console __iomem *ring_descr;
	u8                           __iomem *input_ring;
	u8                           __iomem *output_ring;
	struct octeontx_pcie_console_nexus __iomem *nexus_desc;
	spinlock_t                        excl_lock[OCTEONTX_PCIE_MAX_CONSOLES];
	bool                                 octeontx_console_acquired;
	struct {
		struct tty_driver            *drv;
		struct tty_port              port;
		struct timer_list            poll_timer;
		u32                          open_count;
		struct {
			u32                  poll_count;
			u32                  dropped_count;
			u32                  pushed_count;
		} stats;
	} tty;
};

#endif // __OTX2_PCI_CONSOLE_H__

