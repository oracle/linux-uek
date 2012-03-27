/*****************************************************************************
* DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS HEADER.
*
* Copyright 2009, 2011 Oracle America, Inc. All rights reserved.
*
* This program is free software; you can redistribute it and/or modify it under
* the terms of the GNU General Public License version 2 only, as published by
* the Free Software Foundation.
*
* This program is distributed in the hope that it will be useful, but WITHOUT
* ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
* FOR A PARTICULAR PURPOSE.  See the GNU General Public License version 2 for
* more details (a copy is included in the LICENSE file that accompanied this
* code).
*
* You should have received a copy of the GNU General Public License version 2
* along with this program; If not,
* see http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt
*
* Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 or
* visit www.oracle.com if you need additional information or have any
* questions.
*
******************************************************************************/

#ifndef	_HXGE_HXGE_DEFS_H
#define	_HXGE_HXGE_DEFS_H

#include <linux/delay.h>
#include <asm/io.h>

typedef enum {
    FALSE = 0,
    TRUE = 1
} boolean_t;


#define         NO_DEBUG        0x0000000000000000ULL
#define         RX_CTL          0x0000000000000002ULL
#define         TX_CTL          0x0000000000000004ULL
#define         OBP_CTL         0x0000000000000008ULL

#define         VPD_CTL         0x0000000000000010ULL
#define         DDI_CTL         0x0000000000000020ULL
#define         MEM_CTL         0x0000000000000040ULL

#define         IOC_CTL         0x0000000000000100ULL
#define         MOD_CTL         0x0000000000000200ULL
#define         DMA_CTL         0x0000000000000400ULL
#define         STR_CTL         0x0000000000000800ULL

#define         INT_CTL         0x0000000000001000ULL
#define         SYSERR_CTL      0x0000000000002000ULL
#define         KST_CTL         0x0000000000004000ULL

#define         FCRAM_CTL       0x0000000000040000ULL
#define         MAC_CTL         0x0000000000080000ULL

#define         DMA2_CTL        0x0000000000200000ULL
#define         RX2_CTL         0x0000000000400000ULL
#define         TX2_CTL         0x0000000000800000ULL

#define         MEM2_CTL        0x0000000001000000ULL
#define         MEM3_CTL        0x0000000002000000ULL
#define         NEMO_CTL        0x0000000004000000ULL
#define         NDD_CTL         0x0000000008000000ULL
#define         NDD2_CTL        0x0000000010000000ULL

#define         TCAM_CTL        0x0000000020000000ULL
#define         CFG_CTL         0x0000000040000000ULL
#define         CFG2_CTL        0x0000000080000000ULL

#define         PFC_CTL         TCAM_CTL

#define         VIR_CTL         0x0000000100000000ULL
#define         VIR2_CTL        0x0000000200000000ULL

#define         HXGE_NOTE       0x0000001000000000ULL
#define         HXGE_ERR_CTL    0x0000002000000000ULL

#define         DUMP_ALWAYS     0x2000000000000000ULL


/************************************************************************
 * Special Hydra handling for 32-bit access architecture
 *
 * Hydra CR xxxxxxxx
 *
 * If on a 32-bit architecture (e.g., i686 vs x86_64), we must perform
 * two consecutive 32-bit PIOs to gain access to any 64-bit Hydra
 * register. The Hydra PEU (PCI Execution Unit) will internally "buffer"
 * the two separate 32-bit reads, do a SINGLE 64-bit (atomic) register
 * read, and then return the two 32-bit values.  The Hydra read does
 * ***NOT*** occur until the second 32-bit PIO read arrives (the first
 * 32-bit read is simply "held" or buffered pending arrival of the
 * "other half of the read" operation).  Similarly for write operations,
 * the Hydra buffers and then coalesces two distinct 32-bit write PIOs
 * into a single (atomic) 64-bit internal register write.
 *
 * Now, this is cool (gives us 64-bit "atomic/coherent") register access
 * on a 32-bit machine.
 *
 * The Issue (there is debate over this being a "bug" or a "feature") is
 * that ABSOLUTELY NO INTERVENING PCI PIO access can occur between the
 * two consecutive 32-bit PIO accesses for a 64-bit register.  If a
 * PIO access comes in that is NOT consecutive (e.g., is NOT for address
 * and address+4), the held/buffered PIO is discarded, and an entirely
 * new register access is started, either a 32-bit register access that
 * will run normally to completion, or a NEW 64-bit access, for which 
 * this is the "first half", and which will be held until the "second half"
 * (address+4) arrives, triggering completion of the 64-bit access.
 *
 * As such, *ALL* Hydra PCI PIO read/writes must be locked with exclusive
 * PCI bus access (guaranteed consecutive & sequential).    Actually, the
 * only thing we MUST guarantee is that the PIO *requests* are consecutive
 * and sequential delivered to the Hydra; for reads we really don't care
 * in which order Hydra sends the upper/lower halves back to us...
 *
 * Bear in mind we can have a dozen different CPUs concurrently executing
 * Hydra driver code all trying to execute 64-bit PIO register access!
 *
 */

#if BITS_PER_LONG == 32		/* Special Hydra handling for 32bit arch */

struct hxge_adapter;

extern spinlock_t hxge_lock;

static inline u64 __hxge_readq(void __iomem *addr)
{
//	/* Use 'MMX' 64-bit mov available on i386/i686 architecture */
//
// Unfortunately, needs to save FPU status, not just %%mm0
// Deferred for future investigation...should be faster than spin_lock!
//
//	u64 var = 0, tmp = 0;
//	__asm__ __volatile__ (
//		"movq %%mm0, %[t]\n\t"
//		"movl %[a], %%eax\n\t"
//		"movq (%%eax), %%mm0\n\t"
//		"movq %%mm0, %[r]\n\t"
//		"movq %[t], %%mm0\n\t"
//		:[r] "=m"(var), [t]"+m"(tmp)
//		:[a] "r"(addr)
//		:"%eax"
//	);
//	smp_rmb();
//	return var;

	uint64_t val;

	unsigned long flags;

	spin_lock_irqsave (&hxge_lock, flags);

#if defined(__BIG_ENDIAN)
	val = (uint64_t)(readl(addr)) << 32;
	val |= (uint64_t)(readl(addr+4) & 0xFFFFFFFF);
#else
	val = (uint64_t)(readl(addr) & 0xFFFFFFFF);
	val |= (uint64_t)(readl(addr+4)) << 32;
#endif

	spin_unlock_irqrestore (&hxge_lock, flags);

	return val;
}

static inline void __hxge_writeq(uint64_t val, void *addr)
{
//	/* Use 'MMX' 64-bit mov available on i386/i686 architecture */
//
// Unfortunately, needs to save FPU status, not just %%mm0
// Deferred for future investigation...should be faster than spin_lock!
//
//	u64 tmp = 0;
//	__asm__ __volatile__ (
//		"movq %%mm0, %[t]\n\t"
//		"movq %[d], %%mm0\n\t"
//		"movl %[a], %%eax\n\t"
//		"movq %%mm0, (%%eax)\n\t"
//		"movq %[t], %%mm0\n\t"
//		:[t] "+m"(tmp)
//		:[a] "r"(addr), [d] "m"(val)
//		:"%eax"
//	);
//	smp_wmb();
//	return;

	unsigned long flags;

	spin_lock_irqsave (&hxge_lock, flags);

#if defined(__BIG_ENDIAN)
 	writel ((uint32_t)(val >> 32), addr);
 	writel ((uint32_t)(val), addr+4);
#else
 	writel ((uint32_t)(val), addr);
 	writel ((uint32_t)(val >> 32), addr+4);
#endif /* defined (__BIG_ENDIAN) */

	spin_unlock_irqrestore (&hxge_lock, flags);

	return;
}

static inline u32 __hxge_readl(void __iomem *addr)
{
	uint32_t val;
	unsigned long flags;

	spin_lock_irqsave (&hxge_lock, flags);

	val = readl(addr);

	spin_unlock_irqrestore (&hxge_lock, flags);

	return val;
}

static inline void __hxge_writel(u32 val, void *addr)
{
	unsigned long flags;

	spin_lock_irqsave (&hxge_lock, flags);

	writel (val, addr);

	spin_unlock_irqrestore (&hxge_lock, flags);

	return;
}

#define hxge_readq(addr)\
({\
	u64 v; v = __hxge_readq(addr); v;\
})

#define hxge_writeq(v, addr)\
do{\
	__hxge_writeq(v, addr);\
} while(0)

#define hxge_readl(addr)\
({\
	u32 v; v = __hxge_readl(addr); v;\
})

#define hxge_writel(v, addr)\
do{\
	__hxge_writel(v, addr);\
} while(0)

#else	/* 64-bit BITS_PER_LONG -- the normal, easy case */

#define hxge_readq(addr)		readq(addr)
#define hxge_writeq(val, addr)		writeq(val, addr)

#define hxge_readl(addr)	readl(addr)
#define hxge_writel(val, addr)	writel(val, addr)

#endif	/* BITS_PER_LONG */


/* HXGE specific definitions (uses the above ones) */
#define HXGE_REG_RD64(handle, offset, val_p)\
do{\
        *(val_p) = hxge_readq((handle + offset));\
} while (0)

#define HXGE_REG_RD32(handle, offset, val_p)\
do{\
        *(val_p) = hxge_readl((handle + offset));\
} while (0)

#define HXGE_REG_WR64(handle, offset, val)\
do{\
        hxge_writeq( (val), (handle + (offset)));\
} while (0)

#define HXGE_REG_WR32(handle, offset, val)\
do{\
        hxge_writel((val), (handle +(offset)));\
} while (0)

#define HXGE_MEM_PIO_READ64(handle)\
({\
	u64 v;\
	v = hxge_readq(handle);\
	v;\
})

#define HXGE_MEM_PIO_WRITE32(handle, data)\
do{\
	hxge_writel((val), handle);\
} while (0)

#define HXGE_MEM_PIO_WRITE64(handle, data)\
do{\
	hxge_writeq((data), handle);\
} while (0)


/* RDC/TDC CSR size */
#define	DMA_CSR_SIZE		2048

/*
 * Define the Default RBR, RCR
 */
#define	RBR_DEFAULT_MAX_BLKS	4096	/* each entry (16 blockaddr/64B) */
#define	RBR_NBLK_PER_LINE	16	/* 16 block addresses per 64 B line */
#define	RBR_DEFAULT_MAX_LEN	65472	/* 2^16 - 64 */
#define	RBR_DEFAULT_MIN_LEN	64	/* multiple of 64 */

#define	SW_OFFSET_NO_OFFSET	0
#define	SW_OFFSET_64		1	/* 64 bytes */
#define	SW_OFFSET_128		2	/* 128 bytes */
#define	SW_OFFSET_INVALID	3

/*
 * RBR block descriptor is 32 bits (bits [43:12]
 */
#define	RBR_BKADDR_SHIFT	12
#define	RCR_DEFAULT_MAX_BLKS	4096	/* each entry (8 blockaddr/64B) */
#define	RCR_NBLK_PER_LINE	8	/* 8 block addresses per 64 B line */
#define	RCR_DEFAULT_MAX_LEN	(RCR_DEFAULT_MAX_BLKS)
#define	RCR_DEFAULT_MIN_LEN	32

/*  DMA Channels.  */
#define	HXGE_MAX_DMCS		(HXGE_MAX_RDCS + HXGE_MAX_TDCS)
#define HXGE_MIN_RDCS		1
#define	HXGE_MAX_RDCS		4
#define HXGE_MIN_TDCS		1
#define	HXGE_MAX_TDCS		4

#define	VLAN_ETHERTYPE			(0x8100)

/* 256 total, each blade gets 42 */
#define	TCAM_HXGE_TCAM_MAX_ENTRY	42

/*
 * Locate the DMA channel start offset (PIO_VADDR)
 * (DMA virtual address space of the PIO block)
 */
/* TX_RNG_CFIG is not used since we are not using VADDR. */
#define	TX_RNG_CFIG			0x1000000
#define	TDMC_PIOVADDR_OFFSET(channel)	(2 * DMA_CSR_SIZE * channel)
#define	RDMC_PIOVADDR_OFFSET(channel)	(TDMC_OFFSET(channel) + DMA_CSR_SIZE)

/*
 * PIO access using the DMC block directly (DMC)
 */
#define	DMC_OFFSET(channel)		(DMA_CSR_SIZE * channel)
#define	TDMC_OFFSET(channel)		(TX_RNG_CFIG + DMA_CSR_SIZE * channel)

/*
 * The following macros expect unsigned input values.
 */
#define	TXDMA_CHANNEL_VALID(cn)		(cn < HXGE_MAX_TDCS)

/*
 * Logical device definitions.
 */
#define	HXGE_INT_MAX_LD		32
#define	HXGE_INT_MAX_LDG	32

#define	HXGE_RDMA_LD_START	0	/* 0 - 3 with 4 - 7 reserved */
#define	HXGE_TDMA_LD_START	8	/* 8 - 11 with 12 - 15 reserved */
#define	HXGE_VMAC_LD		16
#define	HXGE_PFC_LD		17
#define	HXGE_NMAC_LD		18
#define	HXGE_MBOX_LD_START	20	/* 20 - 23  for SW Mbox */
#define	HXGE_SYS_ERROR_LD	31

#define	LDG_VALID(n)		(n < HXGE_INT_MAX_LDG)
#define	LD_VALID(n)		(n < HXGE_INT_MAX_LD)
#define	LD_RXDMA_LD_VALID(n)	(n < HXGE_MAX_RDCS)
#define	LD_TXDMA_LD_VALID(n)	(n >= HXGE_MAX_RDCS && \
					((n - HXGE_MAX_RDCS) < HXGE_MAX_TDCS)))

#define	LD_TIMER_MAX		0x3f
#define	LD_INTTIMER_VALID(n)	(n <= LD_TIMER_MAX)

/* System Interrupt Data */
#define	SID_VECTOR_MAX		0x1f
#define	SID_VECTOR_VALID(n)	(n <= SID_VECTOR_MAX)

#define	LD_IM_MASK		0x00000003ULL
#define	LDGTITMRES_RES_MASK	0x000FFFFFULL

#define	STD_FRAME_SIZE		1522		/* 1518 + 4 = 5EE + 4 */

#define HXGE_DMA_START  B_TRUE
#define HXGE_DMA_STOP   B_FALSE

/* The timer resolution is 4 microsec per tick (250MHz clock). So, we set it 
   to be 8 microsecs */
#define HXGE_TIMER_RESO 8
/* Number of ticks to count down before timer goes off. It is set to be 
   16 microsecs */
#define HXGE_TIMER_LDG  8

/*
 * Receive and Transmit DMA definitions
 */
#ifdef  _DMA_USES_VIRTADDR
#define HXGE_DMA_BLOCK          1
#else
#define HXGE_DMA_BLOCK          (64 * 64)
#endif

#define HXGE_RBR_RBB_MIN        (64)
#define HXGE_RBR_RBB_MAX        (65536-64)
#define HXGE_RBR_RBB_DEFAULT    (2048) /* CR 6779304 */
#define HXGE_RBR_SPARE          0
#define HXGE_RCR_MIN            (HXGE_RBR_RBB_MIN * 2)
#define HXGE_RCR_MAX            (32768) /* 2^15 (CR 6779304) */

#define HXGE_RCR_CLK_RESO	25000
#define HXGE_RCR_TIMEOUT        1
#define HXGE_RCR_TIMEOUT_MIN	0 /* 0 => disable timeout */
#define HXGE_RCR_TIMEOUT_MAX	63

#define HXGE_RCR_THRESHOLD	1
#define HXGE_RCR_THRESHOLD_MIN	0
#define HXGE_RCR_THRESHOLD_MAX	65535

#define HXGE_MAX_RX_PKTS_MIN	10
#define HXGE_MAX_RX_PKTS_MAX	65535
/* Maximum number of Rx packets that can be processed before the interrupt
   handler lets go and handles the rest later. The limit is imposed by the
   quota and budget in the NAPI case but in the non-NAPI case, this is the 
   only way to limit processing at one time */
#define HXGE_MAX_RX_PKTS	512

/* Assume the smallest buffer size of 256B. So, we can have
 * 16 256B packets in a 4K page
 */
#define HXGE_RCR_DEFAULT        (HXGE_RBR_RBB_DEFAULT * 16)

#define HXGE_TX_RING_DEFAULT    (1024)
#define HXGE_TX_RING_MAX        (64 * 128 - 1)

#define RBR_BKSIZE_4K                   0
#define RBR_BKSIZE_8K                   1
#define RBR_BKSIZE_4K_BYTES             (4 * 1024)

#define RBR_BUFSZ2_2K                   0
#define RBR_BUFSZ2_4K                   1
#define RBR_BUFSZ2_2K_BYTES             (2 * 1024)
#define RBR_BUFSZ2_4K_BYTES             (4 * 1024)

#define RBR_BUFSZ1_1K                   0
#define RBR_BUFSZ1_2K                   1
#define RBR_BUFSZ1_1K_BYTES             1024
#define RBR_BUFSZ1_2K_BYTES             (2 * 1024)

#define RBR_BUFSZ0_256B                 0
#define RBR_BUFSZ0_512B                 1
#define RBR_BUFSZ0_1K                   2
#define RBR_BUFSZ0_256_BYTES            256
#define RBR_BUFSZ0_512B_BYTES           512
#define RBR_BUFSZ0_1K_BYTES             (1024)

#define HXGE_MAX_MAC_ADDRS		16

/* HPI Debug and Error defines */
#define         HPI_RDC_CTL     0x0000000000000001ULL
#define         HPI_TDC_CTL     0x0000000000000002ULL

#define         HPI_XPCS_CTL    0x0000000000000010ULL
#define         HPI_PCS_CTL     0x0000000000000020ULL
#define         HPI_ESR_CTL     0x0000000000000040ULL
#define         HPI_BMAC_CTL    0x0000000000000080ULL
#define         HPI_XMAC_CTL    0x0000000000000100ULL
#define         HPI_MAC_CTL     HPI_BMAC_CTL | HPI_XMAC_CTL

#define         HPI_TCAM_CTL    0x0000000000000400ULL
#define         HPI_FCRAM_CTL   0x0000000000000800ULL
#define         HPI_FFLP_CTL    HPI_TCAM_CTL | HPI_FCRAM_CTL

#define         HPI_VIR_CTL     0x0000000000001000ULL
#define         HPI_PIO_CTL     0x0000000000002000ULL
#define         HPI_VIO_CTL     0x0000000000004000ULL

#define         HPI_REG_CTL     0x0000000040000000ULL
#define         HPI_CTL         0x0000000080000000ULL
#define         HPI_ERR_CTL     0x0000000080000000ULL

#define HXGE_DELAY(microseconds)   (udelay(microseconds))

/* The sizes (in bytes) of a ethernet packet */
#define ENET_HEADER_SIZE             14
#define MAXIMUM_ETHERNET_FRAME_SIZE  1518 /* With checksum */
#define MINIMUM_ETHERNET_FRAME_SIZE  64   /* With checksum */
#define ETHERNET_CSUM_SIZE            4 
#define MAXIMUM_ETHERNET_PACKET_SIZE \
    (MAXIMUM_ETHERNET_FRAME_SIZE - ETHERNET_CSUM_SIZE)
#define MINIMUM_ETHERNET_PACKET_SIZE \
    (MINIMUM_ETHERNET_FRAME_SIZE - ETHERNET_CSUM_SIZE)
#define CRC_LENGTH                   ETHERNET_CSUM_SIZE
#define MAX_JUMBO_FRAME_SIZE         9216 /* Standard Jumbo frame */
#define MAXIMUM_ETHERNET_VLAN_SIZE   MAXIMUM_ETHERNET_FRAME_SIZE+4 /* VLAN tagging included */

#define HASH_TABLE_SIZE 1024

typedef enum {			/* Represents bit numbers */
        RING_INIT = 1,
        RING_ENABLED,
        RING_RESET,
	RING_RECLAIM
} ring_state_t;


#endif	/* _HXGE_HXGE_DEFS_H */
