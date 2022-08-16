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

#define PLAT_OCTEONTX_SPI_SECURE_UPDATE         0xc2000b05
#define PLAT_CN10K_VERIFY_FIRMWARE		0xc2000b0c
#define PLAT_CN10K_ASYNC_STATUS			0xc2000b0e
#define PLAT_CN10K_SPI_READ_FLASH		0xc2000b11


#define VER_MAX_NAME_LENGTH	32
#define SMC_MAX_OBJECTS		32
#define SMC_MAX_VERSION_ENTRIES 32
#define VERSION_STRING_LENGTH   32
#define HASH_SIZE               64
#define VERIFY_LOG_SIZE		1024

#define MARLIN_CHECK_PREDEFINED_OBJ (1<<0)
#define MARLIN_FORCE_ASYNC          (1<<13)
#define MARLIN_FORCE_CLONE	    (1<<14)
#define MARLIN_PRINT_CONSOLE_LOGS   (1<<15)


#define VERSION_FLAG_BACKUP	                BIT(0)
#define VERSION_FLAG_EMMC	                BIT(1)
#define SMC_VERSION_CHECK_SPECIFIC_OBJECTS	BIT(2)
#define SMC_VERSION_CHECK_VALIDATE_HASH		BIT(3)

/**
 * Set this to copy objects to the backup flash after verification.
 * Do not set this and SCM_VERSION_COPY_TO_BACKUP_EMMC.
 */
#define SMC_VERSION_COPY_TO_BACKUP_FLASH	BIT(4)

/**
 * Set this to copy objects to the backup eMMC after verification.
 * Do not set this and SCM_VERSION_COPY_TO_BACKUP_FLASH.
 */
#define SMC_VERSION_COPY_TO_BACKUP_EMMC		BIT(5)

/**
 * Set this to copy objects to the backup flash offset after verification.
 */
#define SMC_VERSION_COPY_TO_BACKUP_OFFSET	BIT(6)

/**
 * Set this to force copy all objects into backup storage
 */
#define SMC_VERSION_FORCE_COPY_OBJECTS		BIT(7)

#define SMC_VERSION_ASYNC_HASH		BIT(8)

#define VERSION_MAGIC		0x4e535256	/** VRSN */
#define VERSION_INFO_VERSION	0x0102	       /** 1.0.0.0 */

struct memory_desc {
	void	   *virt;
	dma_addr_t phys;
	uint64_t   size;
	char	   pool_name[32];
};

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
} __packed;

/* VERSION INFO
 * HASH VERIFICATION
 */

/** Return code for version info */
enum smc_version_ret {
	VERSION_OK,
	FIRMWARE_LAYOUT_CHANGED,
	TOO_MANY_OBJECTS,
	INVALID_DEVICE_TREE,
	VERSION_NOT_SUPPORTED,
		/** SMC_VERSION_CHECK_VALIDATE_HASH must be set */
	BACKUP_SRC_NOT_VALIDATED,
	/** An object failed the verification stage */
	BACKUP_SRC_FAILED_VALIDATION,
	/** Both the source and destination are the same */
	BACKUP_SRC_AND_DEST_ARE_SAME,
	/** An I/O error with the source occurred copying an object */
	BACKUP_IO_SRC_ERROR,
	/** An I/O error with the destination occurred writing an object */
	BACKUP_IO_DST_ERROR,
	/** An I/O error with the destination occurred erasing the media */
	BACKUP_IO_ERASE_ERROR,
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
	uint64_t tim_size;		/** Size of TIM in bytes */
	uint64_t max_size;		/** Maximum space for object and TIM */
	uint64_t object_size;		/** Size of flash object in bytes */
	uint64_t object_address;	/** Address of object in flash */
	uint16_t hash_size;		/** Size of hash in bytes */
	uint16_t flags;			/** Flags for this object */
	enum smc_version_entry_retcode retcode;	/** Return code if error */
	uint64_t perform_clone;         /** run clone operation on that image */
	uint64_t reserved[6];		/** Reserved for future growth */
	uint8_t log[VERIFY_LOG_SIZE];	/** Log for object */
};

struct smc_version_info {
	uint32_t	magic_number;	/** VRSN */
	uint16_t	version;	/** Version of descriptor */
	uint16_t	version_flags;	/** Flags passed to version process */
	uint32_t	bus;		/** SPI BUS number */
	uint32_t	cs;		/** SPI chip select number */
	uint32_t	target_bus;	/** Target bus used for copying */
	uint32_t	target_cs;	/** Target CS used for copying */
	uintptr_t	work_buffer_addr;/** Used to decompress objects */
	uint64_t	work_buffer_size;/** Size of decompression buffer */
	enum smc_version_ret	retcode;
	uint32_t	num_objects;
	uint32_t	timeout;	/** Timeout in ms */
	uint32_t	reserved32;		/** Pad to 64 bits */
	uint64_t	reserved[4];	/** Reserved for future growth */
	struct smc_version_info_entry objects[SMC_MAX_VERSION_ENTRIES];
};

/* UPDATE
 */

enum update_ret {
	/** No errors */
	UPDATE_OK = 0,
	/** Error with the CPIO image */
	UPDATE_CPIO_ERROR = -1,
	/** Invalid TIM found in update */
	UPDATE_TIM_ERROR = -2,
	/** One or more files failed hash check */
	UPDATE_HASH_ERROR = -3,
	/** Update authentication error */
	UPDATE_AUTH_ERROR = -4,
	/** I/O error reading or writing to the flash */
	UPDATE_IO_ERROR = -5,
	/**
	 * Error found that requires all objects to be updated,
	 * i.e. a corrupt object found in the existing flash
	 */
	UPDATE_REQUIRE_FULL = -6,
	/** Out of resources, too many files, etc. */
	UPDATE_NO_MEM = -7,
	/** Problem found with device tree firmware-update section */
	UPDATE_DT_ERROR = -8,
	/** Incomplete file grouping found */
	UPDATE_GROUP_ERROR = -9,
	/** Location or size of an object invalid */
	UPDATE_LOCATION_ERROR = -10,
	/** Unsupported media */
	UPDATE_INVALID_MEDIA = -11,
	/** Invalid alignment of update file */
	UPDATE_BAD_ALIGNMENT = -12,
	/** TIM is missing in an object */
	UPDATE_MISSING_TIM = -13,
	/** File is missing in an object */
	UPDATE_MISSING_FILE = -14,
	/** TIM is missing in flash */
	UPDATE_TIM_MISSING = -15,
	/** I/O issue with eHSM component */
	UPDATE_EHSM_ERROR = -16,
	/** Update rejected due to version check */
	UPDATE_VERSION_CHECK_FAIL = -17,
	/** Bad magic number in update descriptor */
	UPDATE_BAD_DESC_MAGIC = -18,
	/** Unsupported version in update descriptor */
	UPDATE_BAD_DESC_VERSION = -19,
	/** Error mapping update to secure memory */
	UPDATE_MMAP_ERROR = -20,

	UPDATE_WORK_BUFFER_TOO_SMALL = -21,
	/** Unknown error */
	UPDATE_UNKNOWN_ERROR = -1000,
};

struct smc_update_obj_info {

};

#define UPDATE_MAGIC		0x55504454	/* UPDT */
/** Current smc_update_descriptor version */
#define UPDATE_VERSION		0x0100
#define UPDATE_VERSION_PREV         0x0001

#define UPDATE_FLAG_BACKUP	   0x0001	/** Set to update secondary location */
#define UPDATE_FLAG_EMMC	   0x0002	/** Set to update eMMC instead of SPI */
#define UPDATE_FLAG_ERASE_PART	   0x0004	/** Erase eMMC partition data */
#define UPDATE_FLAG_IGNORE_VERSION 0x0008 /** Don't perform version check */
#define UPDATE_FLAG_FORCE_WRITE		BIT(4)
/** Erase configuration data after update */
#define UPDATE_FLAG_ERASE_CONFIG	BIT(5)
/** Log update progress */
#define UPDATE_FLAG_LOG_PROGRESS	BIT(6)
/** Set when user parameters are passed */
#define UPDATE_FLAG_USER_PARMS	0x8000

/** Offset from the beginning of the flash where the backup image is located */
#define BACKUP_IMAGE_OFFSET	0x2000000
/**
 * This descriptor is passed by U-Boot or other software performing an update
 */
struct smc_update_descriptor {
	uint32_t	magic;		/** UPDATE_MAGIC */
	uint16_t	version;	/** Version of descriptor */
	uint16_t	update_flags;	/** Flags passed to update process */
	uint64_t	image_addr;	/** Address of image (CPIO file) */
	uint64_t	image_size;	/** Size of image (CPIO file) */
	uint32_t	bus;		/** SPI BUS number */
	uint32_t	cs;		/** SPI chip select number */
	uint32_t	async_spi;      /** Async SPI operations */
	uint32_t	retcode;	/** Retcode for async operations */
	uint64_t	user_addr;	/** Passed to customer function */
	uint64_t	user_size;	/** Passed to customer function */
	uint64_t	user_flags;	/** Passed to customer function */
	uintptr_t	work_buffer;	/** Used for compressed objects */
	uint64_t	work_buffer_size;/** Size of work buffer */
	uintptr_t	output_console;	/** Text output console for update info */
	uint32_t	output_console_size;/** Console buffer size in bytes */
	uint32_t	output_console_end;/** Not used yet */
	uint64_t	reserved2[8];
	struct smc_update_obj_info object_retinfo[SMC_MAX_OBJECTS];
};


struct smc_update_descriptor_prev {
	uint32_t	magic;		/** UPDATE_MAGIC */
	uint16_t	version;	/** Version of descriptor */
	uint16_t	update_flags;	/** Flags passed to update process */
	uint64_t	image_addr;	/** Address of image (CPIO file) */
	uint64_t	image_size;	/** Size of image (CPIO file) */
	uint32_t	bus;		/** SPI BUS number */
	uint32_t	cs;		/** SPI chip select number */
	uint32_t	async_spi;      /** Async SPI operations */
	uint32_t	reserved;	/** Space to add stuff */
	uint64_t	user_addr;	/** Passed to customer function */
	uint64_t	user_size;	/** Passed to customer function */
	uint64_t	user_flags;	/** Passed to customer function */
	uintptr_t	work_buffer;	/** Used for compressed objects */
	uint64_t	work_buffer_size;/** Size of work buffer */
	struct smc_update_obj_info object_retinfo[SMC_MAX_OBJECTS];
};

/* READ FLASH */

enum read_flash_ret {
	/** No errors */
	READ_FL_OK = 0,
	/** I/O error reading or writing to the flash */
	READ_FL_IO_ERROR = -1,
	/** Out of resources, too many files, etc. */
	READ_FL_NO_MEM = -2,
	/** Error mapping update to secure memory */
	READ_FL_MMAP_ERROR = -3,

	/** Unknown error */
	READ_FL_UNKNOWN_ERROR = -1000,
};

/**
 * This descriptor is used to read data from flash
 */
struct smc_read_flash_descriptor {
	uint64_t	addr;		/** Physical buffer address */
	uint64_t	offset;		/** Offset in flash */
	uint64_t	length;		/** Length to read */
	uint32_t	bus;		/** SPI BUS number */
	uint32_t	cs;		/** SPI chip select number */
	uint32_t	async_spi;	/** Async SPI operations */
	uint32_t	reserved;	/** Space to add stuff */
};

enum marlin_bootflash_clone_op {
	CLONE_SPI = 0,
	CLONE_MMC = 1,
	CLONE_OFFSET = 2,
};


/* IOCTL interface
 * Use same data structure for:
 * get_version
 * verify_hash
 */
struct mrvl_get_versions {
	uint32_t  bus;              /** SPI BUS number */
	uint32_t  cs;               /** SPI chip select number */
	uintptr_t log_addr;         /** Pointer to a buffer where to store log */
	size_t    log_size;         /** Size of the log buffer */
	uint16_t  version_flags;    /** Flags to specify options */
	uint32_t  selected_objects; /** Mask of a selection of TIMs (32 max) */
	uint64_t  timeout;
	uint64_t  reserved[4];	    /** Reserved for future growth */
	enum smc_version_ret	retcode;
	struct smc_version_info_entry desc[SMC_MAX_VERSION_ENTRIES];
} __packed;

struct mrvl_clone_fw {
	uint32_t bus;              /** SPI BUS number */
	uint32_t cs;               /** SPI chip select number */
	uint32_t target_bus;	   /** Target SPI BUS number */
	uint32_t target_cs;	   /** Target SPI chip select number */
	enum marlin_bootflash_clone_op	clone_op; /** Clone configuration */
	uint16_t  version_flags;    /** Flags to specify options */
	uint32_t  selected_objects; /** Mask of a selection of TIMs (32 max) */
	uint64_t reserved[5];	   /** Reserved for future growth */
	enum smc_version_ret	retcode;
	struct smc_version_info_entry desc[SMC_MAX_VERSION_ENTRIES];
} __packed;

struct mrvl_phys_buffer {
	uint64_t cpio_buf;
	uint64_t cpio_buf_size;
	uint64_t sign_buf;
	uint64_t sign_buf_size;
	uint64_t log_buf;
	uint64_t log_buf_size;
	uint64_t read_buf;
	uint64_t read_buf_size;
} __packed;

struct mrvl_update {
	uint32_t bus;
	uint32_t cs;
	uint64_t image_size;
	uint64_t flags;
	uint64_t user_flags;
	uint64_t user_size;
	uint16_t timeout;
	enum update_ret ret;
} __packed;

struct mrvl_read_flash {
	uint32_t bus;
	uint32_t cs;
	uint64_t offset;
	uint64_t len;
	enum read_flash_ret ret;
} __packed;

#define GET_VERSION _IOWR('a', 'a', struct mrvl_get_versions*)
#define VERIFY_HASH _IOWR('a', 'b', struct mrvl_get_versions*)
#define GET_MEMBUF  _IOWR('a', 'c', struct mrvl_phys_buffer*)
#define RUN_UPDATE  _IOWR('a', 'd', struct mrvl_update*)
#define CLONE_FW    _IOWR('a', 'e', struct mrvl_clone_fw*)
#define READ_FLASH  _IOWR('a', 'f', struct mrvl_read_flash*)
#define FREE_RD_BUF _IOWR('a', 'g', struct mrvl_phys_buffer*)

#endif	/* __MRVL_SWUP_H__ */
