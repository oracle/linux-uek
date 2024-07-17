/***********************license start***************
 * Copyright (c) 2003-2010  Cavium Inc. (support@cavium.com). All rights
 * reserved.
 *
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *   * Redistributions in binary form must reproduce the above
 *     copyright notice, this list of conditions and the following
 *     disclaimer in the documentation and/or other materials provided
 *     with the distribution.

 *   * Neither the name of Cavium Inc. nor the names of
 *     its contributors may be used to endorse or promote products
 *     derived from this software without specific prior written
 *     permission.

 * This Software, including technical data, may be subject to U.S. export  control
 * laws, including the U.S. Export Administration Act and its  associated
 * regulations, and may be subject to export or import  regulations in other
 * countries.

 * TO THE MAXIMUM EXTENT PERMITTED BY LAW, THE SOFTWARE IS PROVIDED "AS IS"
 * AND WITH ALL FAULTS AND CAVIUM INC. MAKES NO PROMISES, REPRESENTATIONS OR
 * WARRANTIES, EITHER EXPRESS, IMPLIED, STATUTORY, OR OTHERWISE, WITH RESPECT TO
 * THE SOFTWARE, INCLUDING ITS CONDITION, ITS CONFORMITY TO ANY REPRESENTATION OR
 * DESCRIPTION, OR THE EXISTENCE OF ANY LATENT OR PATENT DEFECTS, AND CAVIUM
 * SPECIFICALLY DISCLAIMS ALL IMPLIED (IF ANY) WARRANTIES OF TITLE,
 * MERCHANTABILITY, NONINFRINGEMENT, FITNESS FOR A PARTICULAR PURPOSE, LACK OF
 * VIRUSES, ACCURACY OR COMPLETENESS, QUIET ENJOYMENT, QUIET POSSESSION OR
 * CORRESPONDENCE TO DESCRIPTION. THE ENTIRE  RISK ARISING OUT OF USE OR
 * PERFORMANCE OF THE SOFTWARE LIES WITH YOU.
 ***********************license end**************************************/

/**
 * @file
 *
 * Interface to the hardware Packet Output unit.
 *
 * Starting with SDK 1.7.0, the PKO output functions now support
 * two types of locking. CVMX_PKO_LOCK_ATOMIC_TAG continues to
 * function similarly to previous SDKs by using POW atomic tags
 * to preserve ordering and exclusivity. As a new option, you
 * can now pass CVMX_PKO_LOCK_CMD_QUEUE which uses a ll/sc
 * memory based locking instead. This locking has the advantage
 * of not affecting the tag state but doesn't preserve packet
 * ordering. CVMX_PKO_LOCK_CMD_QUEUE is appropriate in most
 * generic code while CVMX_PKO_LOCK_CMD_QUEUE should be used
 * with hand tuned fast path code.
 *
 * Some of other SDK differences visible to the command command
 * queuing:
 * - PKO indexes are no longer stored in the FAU. A large
 *   percentage of the FAU register block used to be tied up
 *   maintaining PKO queue pointers. These are now stored in a
 *   global named block.
 * - The PKO <b>use_locking</b> parameter can now have a global
 *   effect. Since all application use the same named block,
 *   queue locking correctly applies across all operating
 *   systems when using CVMX_PKO_LOCK_CMD_QUEUE.
 * - PKO 3 word commands are now supported. Use
 *   cvmx_pko_send_packet_finish3().
 *
 */

#ifndef __CVMX_HWPKO_H__
#define __CVMX_HWPKO_H__

#ifdef CVMX_BUILD_FOR_LINUX_KERNEL
#include "cvmx-pko-defs.h"
#include <asm/octeon/cvmx-hwfau.h>
#include <asm/octeon/cvmx-fpa.h>
#include <asm/octeon/cvmx-pow.h>
#include <asm/octeon/cvmx-cmd-queue.h>
#include <asm/octeon/cvmx-helper.h>
#include <asm/octeon/cvmx-helper-cfg.h>
#include <asm/octeon/cvmx-helper-pko.h>
#else
#include "cvmx-hwfau.h"
#include "cvmx-fpa.h"
#include "cvmx-pow.h"
#include "cvmx-pko3.h"	/* for back-comp */
#include "cvmx-cmd-queue.h"
#include "cvmx-helper.h"
#include "cvmx-helper-util.h"
#include "cvmx-helper-cfg.h"
#include "cvmx-helper-pko.h"
#endif

#ifdef	__cplusplus
/* *INDENT-OFF* */
extern "C" {
/* *INDENT-ON* */
#endif

/* Adjust the command buffer size by 1 word so that in the case of using only
** two word PKO commands no command words stradle buffers.  The useful values
** for this are 0 and 1. */
#define CVMX_PKO_COMMAND_BUFFER_SIZE_ADJUST (1)


#define CVMX_PKO_MAX_OUTPUT_QUEUES_STATIC 256
#define CVMX_PKO_MAX_OUTPUT_QUEUES      ((OCTEON_IS_MODEL(OCTEON_CN31XX) || \
					  OCTEON_IS_MODEL(OCTEON_CN3010) || \
					  OCTEON_IS_MODEL(OCTEON_CN3005) || \
					  OCTEON_IS_MODEL(OCTEON_CN50XX)) ? \
					  32 :				    \
					 (OCTEON_IS_MODEL(OCTEON_CN58XX) || \
					  OCTEON_IS_MODEL(OCTEON_CN56XX) || \
					  OCTEON_IS_MODEL(OCTEON_CN52XX) || \
					  OCTEON_IS_OCTEON2() || \
					  OCTEON_IS_MODEL(OCTEON_CN70XX)) ? \
					  256 : 128)
#define CVMX_PKO_NUM_OUTPUT_PORTS       ((OCTEON_IS_MODEL(OCTEON_CN63XX)) ? 44 : (OCTEON_IS_MODEL(OCTEON_CN66XX) ? 48 : 40))
#define CVMX_PKO_MEM_QUEUE_PTRS_ILLEGAL_PID 63	/* use this for queues that are not used */
#define CVMX_PKO_QUEUE_STATIC_PRIORITY  9
#define CVMX_PKO_ILLEGAL_QUEUE  0xFFFF
#define CVMX_PKO_MAX_QUEUE_DEPTH 0

typedef enum {
	CVMX_PKO_SUCCESS,
	CVMX_PKO_INVALID_PORT,
	CVMX_PKO_INVALID_QUEUE,
	CVMX_PKO_INVALID_PRIORITY,
	CVMX_PKO_NO_MEMORY,
	CVMX_PKO_PORT_ALREADY_SETUP,
	CVMX_PKO_CMD_QUEUE_INIT_ERROR
} cvmx_pko_return_value_t;

/**
 * This enumeration represents the differnet locking modes supported by PKO.
 */
typedef enum {
	CVMX_PKO_LOCK_NONE = 0,
				    /**< PKO doesn't do any locking. It is the responsibility
                                        of the application to make sure that no other core is
                                        accessing the same queue at the same time */
	CVMX_PKO_LOCK_ATOMIC_TAG = 1,
				    /**< PKO performs an atomic tagswitch to insure exclusive
                                        access to the output queue. This will maintain
                                        packet ordering on output */
	CVMX_PKO_LOCK_CMD_QUEUE = 2,
				    /**< PKO uses the common command queue locks to insure
                                        exclusive access to the output queue. This is a memory
                                        based ll/sc. This is the most portable locking
                                        mechanism */
} cvmx_pko_lock_t;

typedef struct cvmx_pko_port_status {
	uint32_t packets;
	uint64_t octets;
	uint64_t doorbell;
} cvmx_pko_port_status_t;

/**
 * This structure defines the address to use on a packet enqueue
 */
typedef union {
	uint64_t u64;
	struct {
#ifdef __BIG_ENDIAN_BITFIELD
		cvmx_mips_space_t mem_space:2;
						/**< Must CVMX_IO_SEG */
		uint64_t reserved:13;		/**< Must be zero */
		uint64_t is_io:1;		/**< Must be one */
		uint64_t did:8;			/**< The ID of the device on the non-coherent bus */
		uint64_t reserved2:4;		/**< Must be zero */
		uint64_t reserved3:15;		/**< Must be zero */
		uint64_t port:9;		/**< The hardware must have the output port in addition to the output queue */
		uint64_t queue:9;		/**< The output queue to send the packet to (0-127 are legal) */
		uint64_t reserved4:3;		/**< Must be zero */
#else
		uint64_t reserved4:3;
		uint64_t queue:9;
		uint64_t port:9;
		uint64_t reserved3:15;
		uint64_t reserved2:4;
		uint64_t did:8;
		uint64_t is_io:1;
		uint64_t reserved:13;
		cvmx_mips_space_t mem_space:2;
#endif
	} s;
} cvmx_pko_doorbell_address_t;

/**
 * Structure of the first packet output command word.
 */
typedef union {
	uint64_t u64;
	struct {
#ifdef __BIG_ENDIAN_BITFIELD
		cvmx_fau_op_size_t size1:2;
					     /**< The size of the reg1 operation - could be 8, 16, 32, or 64 bits */
		cvmx_fau_op_size_t size0:2;
					     /**< The size of the reg0 operation - could be 8, 16, 32, or 64 bits */
		uint64_t subone1:1;	     /**< If set, subtract 1, if clear, subtract packet size */
		uint64_t reg1:11;	     /**< The register, subtract will be done if reg1 is non-zero */
		uint64_t subone0:1;	     /**< If set, subtract 1, if clear, subtract packet size */
		uint64_t reg0:11;	     /**< The register, subtract will be done if reg0 is non-zero */
		uint64_t le:1;		     /**< When set, interpret segment pointer and segment bytes in little endian order */
		uint64_t n2:1;		     /**< When set, packet data not allocated in L2 cache by PKO */
		uint64_t wqp:1;		     /**< If set and rsp is set, word3 contains a pointer to a work queue entry */
		uint64_t rsp:1;		     /**< If set, the hardware will send a response when done */
		uint64_t gather:1;	     /**< If set, the supplied pkt_ptr is really a pointer to a list of pkt_ptr's */
		uint64_t ipoffp1:7;	     /**< If ipoffp1 is non zero, (ipoffp1-1) is the number of bytes to IP header,
                                                and the hardware will calculate and insert the  UDP/TCP checksum */
		uint64_t ignore_i:1;	     /**< If set, ignore the I bit (force to zero) from all pointer structures */
		uint64_t dontfree:1;	     /**< If clear, the hardware will attempt to free the buffers containing the packet */
		uint64_t segs:6;	     /**< The total number of segs in the packet, if gather set, also gather list length */
		uint64_t total_bytes:16;
					     /**< Including L2, but no trailing CRC */
#else
		uint64_t total_bytes:16;
		uint64_t segs:6;
		uint64_t dontfree:1;
		uint64_t ignore_i:1;
		uint64_t ipoffp1:7;
		uint64_t gather:1;
		uint64_t rsp:1;
		uint64_t wqp:1;
		uint64_t n2:1;
		uint64_t le:1;
		uint64_t reg0:11;
		uint64_t subone0:1;
		uint64_t reg1:11;
		uint64_t subone1:1;
		cvmx_fau_op_size_t size0:2;
		cvmx_fau_op_size_t size1:2;
#endif
	} s;
} cvmx_pko_command_word0_t;

/**
 * Call before any other calls to initialize the packet
 * output system.
 */
/* extern void cvmx_pko_initialize_global(void); */
/* extern int cvmx_pko_initialize_local(void); */

extern void cvmx_pko_hw_init(uint8_t pool, unsigned bufsize);

/**
 * Enables the packet output hardware. It must already be
 * configured.
 */
extern void cvmx_pko_enable(void);

/**
 * Disables the packet output. Does not affect any configuration.
 */
extern void cvmx_pko_disable(void);

/**
 * Shutdown and free resources required by packet output.
 */

extern void cvmx_pko_shutdown(void);

/**
 * Configure a output port and the associated queues for use.
 *
 * @param port       Port to configure.
 * @param base_queue First queue number to associate with this port.
 * @param num_queues Number of queues t oassociate with this port
 * @param priority   Array of priority levels for each queue. Values are
 *                   allowed to be 1-8. A value of 8 get 8 times the traffic
 *                   of a value of 1. There must be num_queues elements in the
 *                   array.
 */
extern cvmx_pko_return_value_t cvmx_pko_config_port(int port, int base_queue, int num_queues, const uint8_t priority[]);

/**
 * Ring the packet output doorbell. This tells the packet
 * output hardware that "len" command words have been added
 * to its pending list.  This command includes the required
 * CVMX_SYNCWS before the doorbell ring.
 *
 * WARNING: This function may have to look up the proper PKO port in
 * the IPD port to PKO port map, and is thus slower than calling
 * cvmx_pko_doorbell_pkoid() directly if the PKO port identifier is
 * known.
 *
 * @param ipd_port   The IPD port corresponding the to pko port the packet is for
 * @param queue  Queue the packet is for
 * @param len    Length of the command in 64 bit words
 */
static inline void cvmx_pko_doorbell(uint64_t ipd_port, uint64_t queue, uint64_t len)
{
	cvmx_pko_doorbell_address_t ptr;
	uint64_t pko_port;

	pko_port = ipd_port;
	if (octeon_has_feature(OCTEON_FEATURE_PKND))
		pko_port = cvmx_helper_cfg_ipd2pko_port_base(ipd_port);

	ptr.u64 = 0;
	ptr.s.mem_space = CVMX_IO_SEG;
	ptr.s.did = CVMX_OCT_DID_PKT_SEND;
	ptr.s.is_io = 1;
	ptr.s.port = pko_port;
	ptr.s.queue = queue;
	CVMX_SYNCWS;		/* Need to make sure output queue data is in DRAM before doorbell write */
	cvmx_write_io(ptr.u64, len);
}

/**
 * Prepare to send a packet.  This may initiate a tag switch to
 * get exclusive access to the output queue structure, and
 * performs other prep work for the packet send operation.
 *
 * cvmx_pko_send_packet_finish() MUST be called after this function is called,
 * and must be called with the same port/queue/use_locking arguments.
 *
 * The use_locking parameter allows the caller to use three
 * possible locking modes.
 * - CVMX_PKO_LOCK_NONE
 *      - PKO doesn't do any locking. It is the responsibility
 *          of the application to make sure that no other core
 *          is accessing the same queue at the same time.
 * - CVMX_PKO_LOCK_ATOMIC_TAG
 *      - PKO performs an atomic tagswitch to insure exclusive
 *          access to the output queue. This will maintain
 *          packet ordering on output.
 * - CVMX_PKO_LOCK_CMD_QUEUE
 *      - PKO uses the common command queue locks to insure
 *          exclusive access to the output queue. This is a
 *          memory based ll/sc. This is the most portable
 *          locking mechanism.
 *
 * NOTE: If atomic locking is used, the POW entry CANNOT be
 * descheduled, as it does not contain a valid WQE pointer.
 *
 * @param port   Port to send it on, this can be either IPD port or PKO
 * 		 port.
 * @param queue  Queue to use
 * @param use_locking
 *               CVMX_PKO_LOCK_NONE, CVMX_PKO_LOCK_ATOMIC_TAG, or CVMX_PKO_LOCK_CMD_QUEUE
 */
static inline void cvmx_pko_send_packet_prepare(uint64_t port __attribute__ ((unused)), uint64_t queue, cvmx_pko_lock_t use_locking)
{
	if (use_locking == CVMX_PKO_LOCK_ATOMIC_TAG) {
		/* Must do a full switch here to handle all cases.  We use a fake WQE pointer, as the POW does
		 ** not access this memory.  The WQE pointer and group are only used if this work is descheduled,
		 ** which is not supported by the cvmx_pko_send_packet_prepare/cvmx_pko_send_packet_finish combination.
		 ** Note that this is a special case in which these fake values can be used - this is not a general technique.
		 */
		uint32_t tag = CVMX_TAG_SW_BITS_INTERNAL << CVMX_TAG_SW_SHIFT | CVMX_TAG_SUBGROUP_PKO << CVMX_TAG_SUBGROUP_SHIFT | (CVMX_TAG_SUBGROUP_MASK & queue);
		cvmx_pow_tag_sw_full((cvmx_wqe_t *) cvmx_phys_to_ptr(0x80), tag, CVMX_POW_TAG_TYPE_ATOMIC, 0);
	}
}

#define cvmx_pko_send_packet_prepare_pkoid	cvmx_pko_send_packet_prepare

/**
 * Complete packet output. cvmx_pko_send_packet_prepare() must be called exactly once before this,
 * and the same parameters must be passed to both cvmx_pko_send_packet_prepare() and
 * cvmx_pko_send_packet_finish().
 *
 * WARNING: This function may have to look up the proper PKO port in
 * the IPD port to PKO port map, and is thus slower than calling
 * cvmx_pko_send_packet_finish_pkoid() directly if the PKO port
 * identifier is known.
 *
 * @param ipd_port   The IPD port corresponding the to pko port the packet is for
 * @param queue  Queue to use
 * @param pko_command
 *               PKO HW command word
 * @param packet Packet to send
 * @param use_locking
 *               CVMX_PKO_LOCK_NONE, CVMX_PKO_LOCK_ATOMIC_TAG, or CVMX_PKO_LOCK_CMD_QUEUE
 *
 * @return returns CVMX_PKO_SUCCESS on success, or error code on failure of output
 */
static inline cvmx_pko_return_value_t cvmx_hwpko_send_packet_finish(uint64_t ipd_port, uint64_t queue,
								    cvmx_pko_command_word0_t pko_command, cvmx_buf_ptr_t packet, cvmx_pko_lock_t use_locking)
{
	cvmx_cmd_queue_result_t result;

	if (use_locking == CVMX_PKO_LOCK_ATOMIC_TAG)
		cvmx_pow_tag_sw_wait();

	result = cvmx_cmd_queue_write2(CVMX_CMD_QUEUE_PKO(queue), (use_locking == CVMX_PKO_LOCK_CMD_QUEUE), pko_command.u64, packet.u64);
	if (cvmx_likely(result == CVMX_CMD_QUEUE_SUCCESS)) {
		cvmx_pko_doorbell(ipd_port, queue, 2);
		return CVMX_PKO_SUCCESS;
	} else if ((result == CVMX_CMD_QUEUE_NO_MEMORY) || (result == CVMX_CMD_QUEUE_FULL)) {
		return CVMX_PKO_NO_MEMORY;
	} else {
		return CVMX_PKO_INVALID_QUEUE;
	}
}

/**
 * Complete packet output. cvmx_pko_send_packet_prepare() must be called exactly once before this,
 * and the same parameters must be passed to both cvmx_pko_send_packet_prepare() and
 * cvmx_pko_send_packet_finish().
 *
 * WARNING: This function may have to look up the proper PKO port in
 * the IPD port to PKO port map, and is thus slower than calling
 * cvmx_pko_send_packet_finish3_pkoid() directly if the PKO port
 * identifier is known.
 *
 * @param ipd_port   The IPD port corresponding the to pko port the packet is for
 * @param queue  Queue to use
 * @param pko_command
 *               PKO HW command word
 * @param packet Packet to send
 * @param addr   Plysical address of a work queue entry or physical address to zero on complete.
 * @param use_locking
 *               CVMX_PKO_LOCK_NONE, CVMX_PKO_LOCK_ATOMIC_TAG, or CVMX_PKO_LOCK_CMD_QUEUE
 *
 * @return returns CVMX_PKO_SUCCESS on success, or error code on failure of output
 */
static inline cvmx_pko_return_value_t cvmx_hwpko_send_packet_finish3(uint64_t ipd_port, uint64_t queue,
							     cvmx_pko_command_word0_t pko_command, cvmx_buf_ptr_t packet, uint64_t addr, cvmx_pko_lock_t use_locking)
{
	cvmx_cmd_queue_result_t result;
	if (use_locking == CVMX_PKO_LOCK_ATOMIC_TAG)
		cvmx_pow_tag_sw_wait();

	result = cvmx_cmd_queue_write3(CVMX_CMD_QUEUE_PKO(queue), (use_locking == CVMX_PKO_LOCK_CMD_QUEUE), pko_command.u64, packet.u64, addr);
	if (cvmx_likely(result == CVMX_CMD_QUEUE_SUCCESS)) {
		cvmx_pko_doorbell(ipd_port, queue, 3);
		return CVMX_PKO_SUCCESS;
	} else if ((result == CVMX_CMD_QUEUE_NO_MEMORY) || (result == CVMX_CMD_QUEUE_FULL)) {
		return CVMX_PKO_NO_MEMORY;
	} else {
		return CVMX_PKO_INVALID_QUEUE;
	}
}

/**
 * Get the first pko_port for the (interface, index)
 *
 * @param interface
 * @param index
 */
extern int cvmx_pko_get_base_pko_port(int interface, int index);

/**
 * Get the number of pko_ports for the (interface, index)
 *
 * @param interface
 * @param index
 */
extern int cvmx_pko_get_num_pko_ports(int interface, int index);

/**
 * For a given port number, return the base pko output queue
 * for the port.
 *
 * @param port   IPD port number
 * @return Base output queue
 */
extern int cvmx_pko_get_base_queue(int port);

/**
 * For a given port number, return the number of pko output queues.
 *
 * @param port   IPD port number
 * @return Number of output queues
 */
extern int cvmx_pko_get_num_queues(int port);

/**
 * Sets the internal FPA pool data structure for PKO comamnd queue.
 * @param pool	fpa pool number yo use
 * @param buffer_size	buffer size of pool
 * @param buffer_count	number of buufers to allocate to pool
 *
 * @note the caller is responsable for setting up the pool with
 * an appropriate buffer size and sufficient buffer count.
 */
void cvmx_pko_set_cmd_que_pool_config(int64_t pool, uint64_t buffer_size,
					   uint64_t buffer_count);

/**
 * Get the status counters for a port.
 *
 * @param ipd_port Port number (ipd_port) to get statistics for.
 * @param clear    Set to 1 to clear the counters after they are read
 * @param status   Where to put the results.
 *
 * Note:
 *     - Only the doorbell for the base queue of the ipd_port is
 *       collected.
 *     - Retrieving the stats involves writing the index through
 *       CVMX_PKO_REG_READ_IDX and reading the stat CSRs, in that
 *       order. It is not MP-safe and caller should guarantee
 *       atomicity.
 */
void cvmx_pko_get_port_status(uint64_t ipd_port, uint64_t clear, cvmx_pko_port_status_t * status);

/**
 * Rate limit a PKO port to a max packets/sec. This function is only
 * supported on CN57XX, CN56XX, CN55XX, and CN54XX.
 *
 * @param port      Port to rate limit
 * @param packets_s Maximum packet/sec
 * @param burst     Maximum number of packets to burst in a row before rate
 *                  limiting cuts in.
 *
 * @return Zero on success, negative on failure
 */
extern int cvmx_pko_rate_limit_packets(int port, int packets_s, int burst);

/**
 * Rate limit a PKO port to a max bits/sec. This function is only
 * supported on CN57XX, CN56XX, CN55XX, and CN54XX.
 *
 * @param port   Port to rate limit
 * @param bits_s PKO rate limit in bits/sec
 * @param burst  Maximum number of bits to burst before rate
 *               limiting cuts in.
 *
 * @return Zero on success, negative on failure
 */
extern int cvmx_pko_rate_limit_bits(int port, uint64_t bits_s, int burst);

/**
 * @INTERNAL
 *
 * Retrieve the PKO pipe number for a port
 *
 * @param interface
 * @param index
 *
 * @return negative on error.
 *
 * This applies only to the non-loopback interfaces.
 *
 */
extern int __cvmx_pko_get_pipe(int interface, int index);

/**
 * For a given PKO port number, return the base output queue
 * for the port.
 *
 * @param pko_port   PKO port number
 * @return           Base output queue
 */
extern int cvmx_pko_get_base_queue_pkoid(int pko_port);

/**
 * For a given PKO port number, return the number of output queues
 * for the port.
 *
 * @param pko_port	PKO port number
 * @return		the number of output queues
 */
extern int cvmx_pko_get_num_queues_pkoid(int pko_port);

/**
 * Ring the packet output doorbell. This tells the packet
 * output hardware that "len" command words have been added
 * to its pending list.  This command includes the required
 * CVMX_SYNCWS before the doorbell ring.
 *
 * @param pko_port   Port the packet is for
 * @param queue  Queue the packet is for
 * @param len    Length of the command in 64 bit words
 */
static inline void cvmx_pko_doorbell_pkoid(uint64_t pko_port, uint64_t queue, uint64_t len)
{
	cvmx_pko_doorbell_address_t ptr;

	ptr.u64 = 0;
	ptr.s.mem_space = CVMX_IO_SEG;
	ptr.s.did = CVMX_OCT_DID_PKT_SEND;
	ptr.s.is_io = 1;
	ptr.s.port = pko_port;
	ptr.s.queue = queue;
	CVMX_SYNCWS;		/* Need to make sure output queue data is in DRAM before doorbell write */
	cvmx_write_io(ptr.u64, len);
}

/**
 * Complete packet output. cvmx_pko_send_packet_prepare() must be called exactly once before this,
 * and the same parameters must be passed to both cvmx_pko_send_packet_prepare() and
 * cvmx_pko_send_packet_finish_pkoid().
 *
 * @param pko_port   Port to send it on
 * @param queue  Queue to use
 * @param pko_command
 *               PKO HW command word
 * @param packet Packet to send
 * @param use_locking
 *               CVMX_PKO_LOCK_NONE, CVMX_PKO_LOCK_ATOMIC_TAG, or CVMX_PKO_LOCK_CMD_QUEUE
 *
 * @return returns CVMX_PKO_SUCCESS on success, or error code on failure of output
 */
static inline cvmx_pko_return_value_t cvmx_hwpko_send_packet_finish_pkoid(int pko_port, uint64_t queue,
								  cvmx_pko_command_word0_t pko_command, cvmx_buf_ptr_t packet, cvmx_pko_lock_t use_locking)
{
	cvmx_cmd_queue_result_t result;
	if (use_locking == CVMX_PKO_LOCK_ATOMIC_TAG)
		cvmx_pow_tag_sw_wait();

	result = cvmx_cmd_queue_write2(CVMX_CMD_QUEUE_PKO(queue), (use_locking == CVMX_PKO_LOCK_CMD_QUEUE), pko_command.u64, packet.u64);
	if (cvmx_likely(result == CVMX_CMD_QUEUE_SUCCESS)) {
		cvmx_pko_doorbell_pkoid(pko_port, queue, 2);
		return CVMX_PKO_SUCCESS;
	} else if ((result == CVMX_CMD_QUEUE_NO_MEMORY) || (result == CVMX_CMD_QUEUE_FULL)) {
		return CVMX_PKO_NO_MEMORY;
	} else {
		return CVMX_PKO_INVALID_QUEUE;
	}
}

/**
 * Complete packet output. cvmx_pko_send_packet_prepare() must be called exactly once before this,
 * and the same parameters must be passed to both cvmx_pko_send_packet_prepare() and
 * cvmx_pko_send_packet_finish_pkoid().
 *
 * @param pko_port   The PKO port the packet is for
 * @param queue  Queue to use
 * @param pko_command
 *               PKO HW command word
 * @param packet Packet to send
 * @param addr   Plysical address of a work queue entry or physical address to zero on complete.
 * @param use_locking
 *               CVMX_PKO_LOCK_NONE, CVMX_PKO_LOCK_ATOMIC_TAG, or CVMX_PKO_LOCK_CMD_QUEUE
 *
 * @return returns CVMX_PKO_SUCCESS on success, or error code on failure of output
 */
static inline cvmx_pko_return_value_t cvmx_hwpko_send_packet_finish3_pkoid(uint64_t pko_port, uint64_t queue,
								   cvmx_pko_command_word0_t pko_command, cvmx_buf_ptr_t packet, uint64_t addr, cvmx_pko_lock_t use_locking)
{
	cvmx_cmd_queue_result_t result;
	if (use_locking == CVMX_PKO_LOCK_ATOMIC_TAG)
		cvmx_pow_tag_sw_wait();

	result = cvmx_cmd_queue_write3(CVMX_CMD_QUEUE_PKO(queue), (use_locking == CVMX_PKO_LOCK_CMD_QUEUE), pko_command.u64, packet.u64, addr);
	if (cvmx_likely(result == CVMX_CMD_QUEUE_SUCCESS)) {
		cvmx_pko_doorbell_pkoid(pko_port, queue, 3);
		return CVMX_PKO_SUCCESS;
	} else if ((result == CVMX_CMD_QUEUE_NO_MEMORY) || (result == CVMX_CMD_QUEUE_FULL)) {
		return CVMX_PKO_NO_MEMORY;
	} else {
		return CVMX_PKO_INVALID_QUEUE;
	}
}

/*
 * Obtain the number of PKO commands pending in a queue
 *
 * @param queue is the queue identifier to be queried
 * @return the number of commands pending transmission or -1 on error
 */
int cvmx_pko_queue_pend_count( cvmx_cmd_queue_id_t queue);

void cvmx_pko_set_cmd_queue_pool_buffer_count(uint64_t buffer_count);

#ifdef	__cplusplus
/* *INDENT-OFF* */
}
/* *INDENT-ON* */
#endif

#endif /* __CVMX_HWPKO_H__ */
