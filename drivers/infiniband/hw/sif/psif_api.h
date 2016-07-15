/*
 * Copyright (c) 2015, 2016, Oracle and/or its affiliates. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 *
 * Driver for Oracle Scalable Infiniband Fabric (SIF) Host Channel Adapters
 */

#ifndef	_PSIF_API_H
#define	_PSIF_API_H


#if defined(__arm__)
#include <stdint.h>
#define u8 uint8_t
#define u16 uint16_t
#define u32 uint32_t
#define u64 uint64_t
typedef uint64_t __be64;
#endif /* __arm__ */

#define PSIF_RELEASE_STR "PSIF.ARCH.05.68 revB"
#define PSIF_MAJOR_VERSION  5
#define PSIF_MINOR_VERSION 68
#define PSIF_CHIP_VERSION  2
#define PSIF_VERSION ((PSIF_MAJOR_VERSION<<16)+PSIF_MINOR_VERSION)
#define PSIF_API_VERSION(x, y) ((x<<16)+y)

#define PSIF_REV2

#define PSIF1V0 (0x00D4206D)
#define PSIF2V0 (0x10D4206D)
#define PSIF2V1 (0x30D4206D)

/*
 * Update if protocol changes in a backward incompatible way
 */
#define EPSC_MAJOR_VERSION 2

/*
 * Update when new operations are added or otherwise
 * backward compatible changes are made
 */
#define EPSC_MINOR_VERSION 6

/*
 * Macros for EPSC API #if checking in code
 */
#define EPSC_VERSION ((EPSC_MAJOR_VERSION<<16)+EPSC_MINOR_VERSION)
#define EPSC_API_VERSION(x, y) ((x<<16)+y)

/*
 * Macro to conver 16 bit sequence number to 64 bit wire format
 */
#define EPSC_STATUS_16_to_64(s) ((((u64)(s)) <<  0) | (((u64)(s)) << 16) | \
                                (((u64)(s)) << 32) | ((((u64)s)) << 48))
/*
 * Macros to force layout to match HW implementation
 */
#define PSIF_PACKED           __packed
#define PSIF_PACKED_ALIGNED   __aligned(8) __packed
#define PSIF_PACKED_ALIGNED32 __aligned(32) __packed
#define PSIF_ALIGNED          __aligned(8)
#define PSIF_ALIGNED8         __aligned(8)
#define PSIF_ALIGNED32        __aligned(32)

#define PSIF_PF PSIF_VF0

/* IPVer is a constant 6 */
#define IB_GRH_IPVER 0x6

/* No raw packets are supported so set nxthdr to 0x1B */
#define IB_GRH_NXTHDR 0x1b

/* ICRC - 4 bytes */
#define IB_ICRC_WIDTH 32

/* AUTOMATICALLY GENERATED from address_group. Width of the CSR data bus. */
#define CSR_DATA_WIDTH 64

/* Number of universal functions. */
#define NUM_UF 34

/* Number of vSwitch ports. */
#define NUM_VSWITCH_PORTS 35

/* Number of vHCAs. */
#define NUM_VHCA 33

/* Number of host ports. */
#define NUM_HOST_PORTS 1

/* Number of IB ports */
#define NUM_IB_PORTS 2

/* Number of GIDs per physical IB port (2*NUM_VHCA+1) */
#define NUM_GIDS_PER_PORT 67

#define NUM_SQ_EPS_CB 256

/* Number of SQ scheduler lists */
#define NUM_SQS_LIST 68

/* Number of scatter elements. */
#define NUM_SCATTER_ELEM 16

/* XXX Based on what? */
#define NUM_TVL 128

/*
 * Invalid UF number. Used in multicast handling for indicating end of
 * multicast request from EPS.
 */
#define INVALID_UF_NUM 255

/* Gid Inedxes per UF. */
#define NUM_GID_INDEXES 2

/* Number of physical collect buffers. */
#define CBU_NUM_PCB 1024

/* Number of virtual collect buffers. */
#define CBU_NUM_VCB 16384

/* Index to the error QP. */
#define QPS_ERROR_INDEX 0

/** \brief Bit definition for degraded mode reporting
 *  \hideinitializer
 *  \details
 *  In the response structure for the mailbox online request from the driver
 *  this bit is set in the `info` member if the PSIF firmware is already in
 *  degraded mode. That means that the driver should refrain from doing more
 *  than just the bare minimum needed to allow updating of the firmware.
 */
#define PSIF_INFO_FLAG_DEGRADED (1 << 16)

/** Request value for mailbox register to restart */
#define MAILBOX_RESTART ((u64)0)

/** Response value for mailbox register on error */
#define MAILBOX_IN_ERROR 0x0000ffffffff0000ULL

/** Mailbox (response) value for unused VFs */
#define MAILBOX_NOT_IN_USE 0x0000ffeeeeff0000ULL

/** Mailbox response value for busy UFs (QP cleanup ongoing) */
#define MAILBOX_NOT_READY 0x0000ffddddff0000ULL

/** Mailbox response value that the doorbell needs to be rung again */
#define MAILBOX_AGAIN 0x0000ffeddeff0000ULL

/** Highes non-online mailbox sequence number - applied directly after reset */
#define MAILBOX_SEQ_SET_PROTOCOL ((u16)0x7fff)

/** MSB of mailbox sequence number */
#define MAILBOX_SEQ_ONLINE_MASK ((u16)0x8000)

/* Images will always be aligned on 32k boundaries */
#define PSIF_IMAGE_ALIGNMENT 0x008000

/* */
#define PSIF_IMAGE_HEADER_OFFSET 0x800




#endif	/* _PSIF_API_H */
