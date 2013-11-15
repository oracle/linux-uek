/*
 * Copyright (c) 2006-2012 Xsigo Systems Inc.  All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 */

#ifndef __XSMP_COMMON_H__
#define __XSMP_COMMON_H__

/*
 *	Node ID: A 96-bit identifier of the initiating node
 *	The lower part is the 'guid'
 */
struct xsmp_node_id {
	u32 node_id_aux;
	u64 node_id_primary;
} __attribute__((packed));

/*
 *	The XSMP message header
 *
 *	The message header precedes all XSMP messages from either
 *	the XCM or the server.
 *	'message_type' identifies the class of the message.
 *	'seq_number' is a serially incrementing count (different
 *	for each direction) used to track the order of messages.
 *
 *	This is followed by a series of message objects (of the same
 *	class) adding up to the 'length' field of the header.
 */
struct xsmp_message_header {
	u8 type;
	u8 code;
	u16 length;
	u32 seq_number;
	struct xsmp_node_id source_id;
	struct xsmp_node_id dest_id;
} __attribute__((packed));

#define XSMP_MESSAGE_TYPE_SESSION	1
#define XSMP_MESSAGE_TYPE_VNIC		2
#define XSMP_MESSAGE_TYPE_VHBA		3
#define XSMP_MESSAGE_TYPE_VSSL		4
#define XSMP_MESSAGE_TYPE_USPACE	5
#define XSMP_MESSAGE_TYPE_XVE		6

#define XSMP_MESSAGE_TYPE_MAX		8

enum xscore_cap_flags {
	RESOURCE_FLAG_INDEX_VNIC = 0,
	RESOURCE_FLAG_INDEX_VHBA = 1,
	RESOURCE_FLAG_INDEX_VSSL = 2,
	RESOURCE_FLAG_INDEX_USPACE = 3,
	RESOURCE_FLAG_INDEX_NO_HA = 4,
	RESOURCE_FLAG_INDEX_XVE = 6,
	RESOURCE_FLAG_INDEX_MAX
};

#define RESOURCE_VNIC	(1 << RESOURCE_FLAG_INDEX_VNIC)
#define RESOURCE_VHBA	(1 << RESOURCE_FLAG_INDEX_VHBA)
#define RESOURCE_VSSL	(1 << RESOURCE_FLAG_INDEX_VSSL)
#define RESOURCE_USPACE	(1 << RESOURCE_FLAG_INDEX_USPACE)
#define RESOURCE_NO_HA (1 << RESOURCE_FLAG_INDEX_NO_HA)

#endif /* __XSMP_COMMON_H__ */
