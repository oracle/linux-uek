/* Broadcom NetXtreme-C/E network driver.
 *  *
 *   * Copyright (c) 2016-2017 Broadcom Limited
 *    *
 *     * This program is free software; you can redistribute it and/or modify
 *      * it under the terms of the GNU General Public License as published by
 *       * the Free Software Foundation.
 *        */
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/pci.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/if_vlan.h>
#include <linux/bpf.h>
#include <linux/bpf_trace.h>
#include <linux/filter.h>
#include "bnxt_compat.h"


bool xdp_rxq_info_is_reg(struct xdp_rxq_info *xdp_rxq)
{
	return (xdp_rxq->reg_state == REG_STATE_REGISTERED);
}


#define  PCI_EXP_LNKCAP2_SLS_16_0GB	0x00000010 /* Supported Speed 16GT/s */
#define  PCI_EXP_LNKCAP_SLS_16_0GB 0x00000004 /* LNKCAP2 SLS Vector bit 3 */

const unsigned char pcie_link_speed[] = {
	PCI_SPEED_UNKNOWN,		/* 0 */
	PCIE_SPEED_2_5GT,		/* 1 */
	PCIE_SPEED_5_0GT,		/* 2 */
	PCIE_SPEED_8_0GT,		/* 3 */
	PCI_SPEED_UNKNOWN,		/* 4 */
	PCI_SPEED_UNKNOWN,		/* 5 */
	PCI_SPEED_UNKNOWN,		/* 6 */
	PCI_SPEED_UNKNOWN,		/* 7 */
	PCI_SPEED_UNKNOWN,		/* 8 */
	PCI_SPEED_UNKNOWN,		/* 9 */
	PCI_SPEED_UNKNOWN,		/* A */
	PCI_SPEED_UNKNOWN,		/* B */
	PCI_SPEED_UNKNOWN,		/* C */
	PCI_SPEED_UNKNOWN,		/* D */
	PCI_SPEED_UNKNOWN,		/* E */
	PCI_SPEED_UNKNOWN		/* F */
};

/* PCIe link information */
#define PCIE_SPEED2STR(speed) \
	((speed) == PCIE_SPEED_8_0GT ? "8 GT/s" : \
	 (speed) == PCIE_SPEED_5_0GT ? "5 GT/s" : \
	 (speed) == PCIE_SPEED_2_5GT ? "2.5 GT/s" : \
	 "Unknown speed")

/* PCIe speed to Mb/s reduced by encoding overhead */
#define PCIE_SPEED2MBS_ENC(speed) \
	((speed) == PCIE_SPEED_8_0GT  ?  8000*128/130 : \
	 (speed) == PCIE_SPEED_5_0GT  ?  5000*8/10 : \
	 (speed) == PCIE_SPEED_2_5GT  ?  2500*8/10 : \
	 0)

/**
 * pcie_get_width_cap - query for the PCI device's link width capability
 * @dev: PCI device to query
 *
 * Query the PCI device width capability.  Return the maximum link width
 * supported by the device.
 */
enum pcie_link_width pcie_get_width_cap(struct pci_dev *dev)
{
	u32 lnkcap;

	pcie_capability_read_dword(dev, PCI_EXP_LNKCAP, &lnkcap);
	if (lnkcap)
		return (lnkcap & PCI_EXP_LNKCAP_MLW) >> 4;

	return PCIE_LNK_WIDTH_UNKNOWN;
}

/**
 * pcie_get_speed_cap - query for the PCI device's link speed capability
 * @dev: PCI device to query
 *
 * Query the PCI device speed capability.  Return the maximum link speed
 * supported by the device.
 */
enum pci_bus_speed pcie_get_speed_cap(struct pci_dev *dev)
{
	u32 lnkcap2, lnkcap;

	/*
	 * PCIe r4.0 sec 7.5.3.18 recommends using the Supported Link
	 * Speeds Vector in Link Capabilities 2 when supported, falling
	 * back to Max Link Speed in Link Capabilities otherwise.
	 */
	pcie_capability_read_dword(dev, PCI_EXP_LNKCAP2, &lnkcap2);
	if (lnkcap2) { /* PCIe r3.0-compliant */
		if (lnkcap2 & PCI_EXP_LNKCAP2_SLS_8_0GB)
			return PCIE_SPEED_8_0GT;
		else if (lnkcap2 & PCI_EXP_LNKCAP2_SLS_5_0GB)
			return PCIE_SPEED_5_0GT;
		else if (lnkcap2 & PCI_EXP_LNKCAP2_SLS_2_5GB)
			return PCIE_SPEED_2_5GT;
		return PCI_SPEED_UNKNOWN;
	}

	pcie_capability_read_dword(dev, PCI_EXP_LNKCAP, &lnkcap);
	if (lnkcap) { 
		if (lnkcap & PCI_EXP_LNKCAP_SLS_8_0GB)
			return PCIE_SPEED_8_0GT;
		else if (lnkcap & PCI_EXP_LNKCAP_SLS_5_0GB)
			return PCIE_SPEED_5_0GT;
		else if (lnkcap & PCI_EXP_LNKCAP_SLS_2_5GB)
			return PCIE_SPEED_2_5GT;
	}

	return PCI_SPEED_UNKNOWN;
}


/**
 * pcie_bandwidth_capable - calculate a PCI device's link bandwidth capability
 * @dev: PCI device
 * @speed: storage for link speed
 * @width: storage for link width
 *
 * Calculate a PCI device's link bandwidth by querying for its link speed
 * and width, multiplying them, and applying encoding overhead.  The result
 * is in Mb/s, i.e., megabits/second of raw bandwidth.
 */
u32 pcie_bandwidth_capable(struct pci_dev *dev, enum pci_bus_speed *speed,
			   enum pcie_link_width *width)
{
	*speed = pcie_get_speed_cap(dev);
	*width = pcie_get_width_cap(dev);

	if (*speed == PCI_SPEED_UNKNOWN || *width == PCIE_LNK_WIDTH_UNKNOWN)
		return 0;

	return *width * PCIE_SPEED2MBS_ENC(*speed);
}

/**
 * pcie_bandwidth_available - determine minimum link settings of a PCIe
 *			      device and its bandwidth limitation
 * @dev: PCI device to query
 * @limiting_dev: storage for device causing the bandwidth limitation
 * @speed: storage for speed of limiting device
 * @width: storage for width of limiting device
 *
 * Walk up the PCI device chain and find the point where the minimum
 * bandwidth is available.  Return the bandwidth available there and (if
 * limiting_dev, speed, and width pointers are supplied) information about
 * that point.  The bandwidth returned is in Mb/s, i.e., megabits/second of
 * raw bandwidth.
 */
u32 pcie_bandwidth_available(struct pci_dev *dev, struct pci_dev **limiting_dev,
			     enum pci_bus_speed *speed,
			     enum pcie_link_width *width)
{
	u16 lnksta;
	enum pci_bus_speed next_speed;
	enum pcie_link_width next_width;
	u32 bw, next_bw;

	if (speed)
		*speed = PCI_SPEED_UNKNOWN;
	if (width)
		*width = PCIE_LNK_WIDTH_UNKNOWN;

	bw = 0;

	while (dev) {
		pcie_capability_read_word(dev, PCI_EXP_LNKSTA, &lnksta);

		next_speed = pcie_link_speed[lnksta & PCI_EXP_LNKSTA_CLS];
		next_width = (lnksta & PCI_EXP_LNKSTA_NLW) >>
			PCI_EXP_LNKSTA_NLW_SHIFT;

		next_bw = next_width * PCIE_SPEED2MBS_ENC(next_speed);

		/* Check if current device limits the total bandwidth */
		if (!bw || next_bw <= bw) {
			bw = next_bw;

			if (limiting_dev)
				*limiting_dev = dev;
			if (speed)
				*speed = next_speed;
			if (width)
				*width = next_width;
		}

		dev = pci_upstream_bridge(dev);
	}

	return bw;
}

/**
 * __pcie_print_link_status - Report the PCI device's link speed and width
 * @dev: PCI device to query
 * @verbose: Print info even when enough bandwidth is available
 *
 * If the available bandwidth at the device is less than the device is
 * capable of, report the device's maximum possible bandwidth and the
 * upstream link that limits its performance.  If @verbose, always print
 * the available bandwidth, even if the device isn't constrained.
 */
void __pcie_print_link_status(struct pci_dev *dev, bool verbose)
{
	enum pcie_link_width width, width_cap;
	enum pci_bus_speed speed, speed_cap;
	struct pci_dev *limiting_dev = NULL;
	u32 bw_avail, bw_cap;

	bw_cap = pcie_bandwidth_capable(dev, &speed_cap, &width_cap);
	bw_avail = pcie_bandwidth_available(dev, &limiting_dev, &speed, &width);

	if (bw_avail >= bw_cap && verbose)
		pci_info(dev, "%u.%03u Gb/s available PCIe bandwidth (%s x%d link)\n",
			 bw_cap / 1000, bw_cap % 1000,
			 PCIE_SPEED2STR(speed_cap), width_cap);
	else if (bw_avail < bw_cap)
		pci_info(dev, "%u.%03u Gb/s available PCIe bandwidth, limited by %s x%d link at %s (capable of %u.%03u Gb/s with %s x%d link)\n",
			 bw_avail / 1000, bw_avail % 1000,
			 PCIE_SPEED2STR(speed), width,
			 limiting_dev ? pci_name(limiting_dev) : "<unknown>",
			 bw_cap / 1000, bw_cap % 1000,
			 PCIE_SPEED2STR(speed_cap), width_cap);
}

/**
 * pcie_print_link_status - Report the PCI device's link speed and width
 * @dev: PCI device to query
 *
 * Report the available bandwidth at the device.
 */
void pcie_print_link_status(struct pci_dev *dev)
{
	__pcie_print_link_status(dev, true);
}

