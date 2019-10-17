/* SPDX-License-Identifier: GPL-2.0
 * Marvell OcteonTX and OcteonTX2 ZIP Virtual Function driver
 *
 * Copyright (C) 2019 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef __ZIP_OCTEONTX_H__
#define __ZIP_OCTEONTX_H__

#include <linux/ioctl.h>
#include <linux/types.h>

/* RAWPIPE */
#define RAW_FORMAT       0

/* ZPIPE */
#define ZLIB_FORMAT      1

/* GZPIPE */
#define GZIP_FORMAT      2

/* LZSPIPE */
#define LZS_FORMAT       3

/* Maximum number of ZIP VF devices supported */
#define ZIP_MAX_VFS             8

/* Hash sha1 size is 20 */
#define ZIP_HASH_SHA1_SIZE      20

/* Hash sha256 size is 32*/
#define ZIP_HASH_SHA256_SIZE    32

/**
 * The common data structure between user and kernel space.
 * Maintains the required meta data between user and kernel space
 * communication
 */
struct zip_operation {
	/* State of zip operation */
	__u64   state;

	/* Next input byte is read from here */
	__u64   input;

	/* Next output byte written here */
	__u64   output;

	/* Inflate context buffer address */
	__u64   ctx_addr;

	/* Pointer to the history buffer */
	__u64   history;

	/* Number of bytes available at next_in */
	__u32   input_len;

	/* Total number of input bytes read so far */
	__u32   input_total_len;

	/* Remaining free space at next_out */
	__u32   output_len;

	/* Total number of bytes output so far */
	__u32   output_total_len;

	/**
	 * Checksum (depends on stream's adler32) value of the uncompressed
	 * data
	 */
	__u32   csum;

	/* Flush flag */
	__u32   flush;

	/* Format (depends on stream's wrap). 0-raw, 1-zlib, 2-gzip */
	__u32   format;

	/* Speed depends on stream's level. */
	__u32   speed;

	/* Compression code ( depends on the stream's strategy) */
	__u32   ccode;

	/* Beginning of file indication for inflate */
	__u32   begin_file;

	/* Size of the history data */
	__u32   history_len;

	/* Ending of the file indication for inflate */
	__u32   end_file;

	/* Completion status of the ZIP invocation */
	__u32   compcode;

	/* Input bytes read by zip engine in current instruction */
	__u32   bytes_read;

	/* Total bits processed by the engine for entire file */
	__u32   bits_processed;

	/* Flag for ALG, 0:DEFLATE, 1:LZS */
	__u32   alg_type;

	/* Hash type */
	__u32   htype;

	/* Pointer to hash state structure */
	__u64   hstate_ptr;

	/* Stores hash result, max 32 bytees for sha256 */
	__u8    hresult[32];

	/* To distinguish between ILP32 and LP64 */
	__u32   sizeofptr;

	/* Optional just for padding */
	__u32   sizeofzops;
};

/* ZIP invocation result completion status codes */
#define NOTDONE      0x0

/* Successful completion */
#define SUCCESS      0x1

/* Output truncated */
#define DTRUNC       0x2

/* Dynamic Stop */
#define DYNAMIC_STOP 0x3

/* Uncompress ran out of input data when IWORD0[EF] was set */
#define ITRUNC       0x4

/* Uncompress found the reserved block type 3 */
#define RBLOCK       0x5

/* Uncompress found LEN != NLEN in an uncompressed block in the input */
#define NLEN         0x6

/* Uncompress found a bad code in the main Huffman codes */
#define BADCODE      0x7

/*
 * Uncompress found a bad code in the 19 Huffman codes used to encode
 * lengths.
 */
#define BADCODE2     0x8

/* Compress found a zero-length input */
#define ZERO_LEN     0x9

/* The compress or decompress encountered an internal parity error */
#define PARITY       0xA

/*
 * Uncompress found a string identifier that precedes the uncompressed
 * data and decompression history
 */
#define FATAL        0xB

/* ZIP Engine specific ioctl base command */
#define CVM_ZIP_DRV_IOCTL_BASE      0xbb

/* Deflate specific IOCTL command */
#define CVM_ZIP_DRV_IOCTL_DEFLATE   _IOWR(CVM_ZIP_DRV_IOCTL_BASE, 0, \
					struct zip_operation)

/* ZIP Driver cleanup specific IOCTL command */
#define CVM_ZIP_DRV_IOCTL_CLEANUP   _IOWR(CVM_ZIP_DRV_IOCTL_BASE, 4, \
					struct zip_operation)

#endif /* __ZIP_OCTEONTX_H__ */
