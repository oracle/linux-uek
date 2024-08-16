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
 * Functions for XAUI initialization, configuration,
 * and monitoring.
 *
 * <hr>$Revision$<hr>
 */
#ifndef __CVMX_HELPER_XAUI_H__
#define __CVMX_HELPER_XAUI_H__

/**
 * @INTERNAL
 * Probe a XAUI interface and determine the number of ports
 * connected to it. The XAUI interface should still be down
 * after this call.
 *
 * @param xiface Interface to probe
 *
 * @return Number of ports on the interface. Zero to disable.
 */
extern int __cvmx_helper_xaui_probe(int xiface);
extern int __cvmx_helper_xaui_enumerate(int xiface);

/**
 * @INTERNAL
 * Bringup and enable a XAUI interface. After this call packet
 * I/O should be fully functional. This is called with IPD
 * enabled but PKO disabled.
 *
 * @param xiface Interface to bring up
 *
 * @return Zero on success, negative on failure
 */
extern int __cvmx_helper_xaui_enable(int xiface);

/**
 * Retrain XAUI interface.
 *
 * GMX is disabled as part of retraining.
 * While GMX is disabled, new recieved packets are dropped.
 * If GMX was in the middle of recieving a packet when disabled,
 * that packet will be recieved before GMX idles.
 * Transmitted packets are buffered normally, but not sent.
 * If GMX was in the middle of transmitting a packet when disabled,
 * that packet will be transmitted before GMX idles.
 *
 * @param interface Interface to retrain
 *
 * @return Zero on success, negative on failure
 */
extern int cvmx_helper_xaui_link_retrain(int interface);

/**
 * Reinitialize XAUI interface.  Does a probe without changing the hardware
 * state.
 *
 * @param interface	Interface to reinitialize
 *
 * @return	0 on success, negative on failure
 */
extern int cvmx_helper_xaui_link_reinit(int interface);

/**
 * @INTERNAL
 * Return the link state of an IPD/PKO port as returned by
 * auto negotiation. The result of this function may not match
 * Octeon's link config if auto negotiation has changed since
 * the last call to cvmx_helper_link_set().
 *
 * @param ipd_port IPD/PKO port to query
 *
 * @return Link state
 */
extern union cvmx_helper_link_info __cvmx_helper_xaui_link_get(int ipd_port);

/**
 * @INTERNAL
 * Configure an IPD/PKO port for the specified link state. This
 * function does not influence auto negotiation at the PHY level.
 * The passed link state must always match the link state returned
 * by cvmx_helper_link_get(). It is normally best to use
 * cvmx_helper_link_autoconf() instead.
 *
 * @param ipd_port  IPD/PKO port to configure
 * @param link_info The new link state
 *
 * @return Zero on success, negative on failure
 */
extern int __cvmx_helper_xaui_link_set(int ipd_port, cvmx_helper_link_info_t link_info);

/**
 * @INTERNAL
 * Configure a port for internal and/or external loopback. Internal loopback
 * causes packets sent by the port to be received by Octeon. External loopback
 * causes packets received from the wire to sent out again.
 *
 * @param ipd_port IPD/PKO port to loopback.
 * @param enable_internal
 *                 Non zero if you want internal loopback
 * @param enable_external
 *                 Non zero if you want external loopback
 *
 * @return Zero on success, negative on failure.
 */
extern int __cvmx_helper_xaui_configure_loopback(int ipd_port, int enable_internal, int enable_external);

#endif
