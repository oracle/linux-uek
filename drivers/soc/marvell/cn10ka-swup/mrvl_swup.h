/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2021 Marvell
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef __MRVL_SWUP_H__
#define __MRVL_SWUP_H__

#define PLAT_CN10K_VERIFY_FIRMWARE		0xc2000b0c

#define VER_MAX_NAME_LENGTH	32
#define SMC_MAX_OBJECTS		32
#define SMC_MAX_VERSION_ENTRIES 32
#define VERSION_STRING_LENGTH   32
#define HASH_SIZE               64
#define VERIFY_LOG_SIZE		1024

#define MARLIN_CHECK_PREDEFINED_OBJ (1<<0)
#define MARLIN_PRINT_CONSOLE_LOGS   (1<<15)

#define VERSION_FLAG_BACKUP	                BIT(0)
#define VERSION_FLAG_EMMC	                BIT(1)
#define SMC_VERSION_CHECK_SPECIFIC_OBJECTS	BIT(2)
#define SMC_VERSION_CHECK_VALIDATE_HASH		BIT(3)

#define VERSION_MAGIC		0x4e535256	/** VRSN */
#define VERSION_INFO_VERSION	0x0100	/** 1.0.0.0 */

struct tim_opaque_data_version_info {
	uint8_t     major_version;  /** Major version number */
	uint8_t     minor_version;  /** Minor version number */
	uint8_t     revision_number;/** Revision number */
	uint8_t     revision_type;  /** Revision type (TBD) */
	uint16_t    year;           /** GIT Year */
	uint8_t     month;          /** GIT Month */
	uint8_t     day;            /** GIT Day */
	uint8_t     hour;           /** GIT Hour */
	uint8_t     minute;         /** GIT Minute */
	uint16_t    flags;          /** Flags (TBD) */
	uint32_t    customer_version;/** Customer defined version number */
	uint8_t     version_string[VERSION_STRING_LENGTH];
} __packed4;

/** Return code for version info */
enum smc_version_ret {
	VERSION_OK,
	FIRMWARE_LAYOUT_CHANGED,
	TOO_MANY_OBJECTS,
	INVALID_DEVICE_TREE,
	VERSION_NOT_SUPPORTED,
};

/** This is used for each object (version entry) */
enum smc_version_entry_retcode {
	RET_OK = 0,
	RET_NOT_FOUND = 1,
	RET_TIM_INVALID = 2,
	RET_BAD_HASH = 3,
	RET_NOT_ENOUGH_MEMORY = 4,
	RET_NAME_MISMATCH = 5,
	RET_TIM_NO_VERSION = 6,
	RET_TIM_NO_HASH = 7,
	RET_HASH_ENGINE_ERROR = 8,
	RET_HASH_NO_MATCH = 9,
	RET_IMAGE_TOO_BIG = 10,
	RET_DEVICE_TREE_ENTRY_ERROR = 11,
};

struct smc_version_info_entry {
	char name[VER_MAX_NAME_LENGTH];
	struct tim_opaque_data_version_info version;
	uint8_t tim_hash[HASH_SIZE];	/** Hash value stored in the TIM */
	uint8_t obj_hash[HASH_SIZE];	/** Calculated hash value */
	uint64_t tim_address;		/** Address of TIM in flash */
	uint64_t max_size;		/** Maximum space for object and TIM */
	uint64_t object_size;		/** Size of flash object in bytes */
	uint64_t object_address;	/** Address of object in flash */
	uint16_t hash_size;		/** Size of hash in bytes */
	uint16_t flags;			/** Flags for this object */
	enum smc_version_entry_retcode retcode;	/** Return code if error */
	uint64_t reserved[8];		/** Reserved for future growth */
	uint8_t log[VERIFY_LOG_SIZE];	/** Log for object */
};

struct smc_version_info {
	uint32_t	magic_number;	/** VRSN */
	uint16_t	version;	/** Version of descriptor */
	uint16_t	version_flags;	/** Flags passed to version process */
	uint32_t	bus;		/** SPI BUS number */
	uint32_t	cs;		/** SPI chip select number */
	uintptr_t	work_buffer_addr;/** Used to decompress objects */
	uint64_t	work_buffer_size;/** Size of decompression buffer */
	enum smc_version_ret	retcode;
	uint32_t	num_objects;
	uint32_t	timeout;	/** Timeout in ms */
	uint32_t	pad32;		/** Pad to 64 bits */
	uint64_t	reserved[5];	/** Reserved for future growth */
	struct smc_version_info_entry objects[SMC_MAX_VERSION_ENTRIES];
};

/* IOCTL interface
 * Use same data structure for:
 * get_version
 * verify_hash
 */

struct marlin_bootflash_get_versions {
	uint32_t  bus;              /** SPI BUS number */
	uint32_t  cs;               /** SPI chip select number */
	uintptr_t log_addr;         /** Pointer to a buffer where to store log */
	size_t    log_size;         /** Size of the log buffer */
	uint16_t  version_flags;    /** Flags to specify options */
	uint32_t  selected_objects; /** Mask of a selection of TIMs (32 max) */
	uint64_t  reserved[5];	    /** Reserved for future growth */
	enum smc_version_ret	retcode;
	struct smc_version_info_entry desc[SMC_MAX_VERSION_ENTRIES];
};

#define GET_VERSION _IOWR('a', 'a', struct marlin_bootflash_get_versions*)
#define VERIFY_HASH _IOWR('a', 'b', struct marlin_bootflash_get_versions*)

#endif	/* __TIM_UPDATE_H__ */
