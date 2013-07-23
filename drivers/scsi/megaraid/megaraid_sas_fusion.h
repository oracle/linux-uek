/*
 *  Linux MegaRAID driver for SAS based RAID controllers
 *
 *  Copyright (c) 2009-2012  LSI Corporation.
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License
 *  as published by the Free Software Foundation; either version 2
 *  of the License, or (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 *
 *  FILE: megaraid_sas_fusion.h
 *
 *  Authors: LSI Corporation
 *           Manoj Jose
 *           Sumant Patro
 *
 *  Send feedback to: <megaraidlinux@lsi.com>
 *
 *  Mail to: LSI Corporation, 1621 Barber Lane, Milpitas, CA 95035
 *     ATTN: Linuxraid
 */

#ifndef _MEGARAID_SAS_FUSION_H_
#define _MEGARAID_SAS_FUSION_H_

/* Fusion defines */
#define MEGASAS_MAX_SZ_CHAIN_FRAME 1024
#define MFI_FUSION_ENABLE_INTERRUPT_MASK (0x00000009)
#define MEGA_MPI2_RAID_DEFAULT_IO_FRAME_SIZE 256
#define MEGASAS_MPI2_FUNCTION_PASSTHRU_IO_REQUEST   0xF0
#define MEGASAS_MPI2_FUNCTION_LD_IO_REQUEST         0xF1
#define MEGASAS_LOAD_BALANCE_FLAG		    0x1
#define MEGASAS_DCMD_MBOX_PEND_FLAG		    0x1
#define HOST_DIAG_WRITE_ENABLE			    0x80
#define HOST_DIAG_RESET_ADAPTER			    0x4
#define MEGASAS_FUSION_MAX_RESET_TRIES		    3
#define MAX_MSIX_QUEUES_FUSION			    128

/* Invader defines */
#define MPI2_TYPE_CUDA				    0x2
#define MPI25_SAS_DEVICE0_FLAGS_ENABLED_FAST_PATH   0x4000
#define	MR_RL_FLAGS_GRANT_DESTINATION_CPU0	    0x00
#define	MR_RL_FLAGS_GRANT_DESTINATION_CPU1	    0x10
#define	MR_RL_FLAGS_GRANT_DESTINATION_CUDA	    0x80
#define MR_RL_FLAGS_SEQ_NUM_ENABLE		    0x8

/* T10 PI defines */
#define MR_PROT_INFO_TYPE_CONTROLLER                0x8
#define MEGASAS_SCSI_VARIABLE_LENGTH_CMD            0x7f
#define MEGASAS_SCSI_SERVICE_ACTION_READ32          0x9
#define MEGASAS_SCSI_SERVICE_ACTION_WRITE32         0xB
#define MEGASAS_SCSI_ADDL_CDB_LEN                   0x18
#define MEGASAS_RD_WR_PROTECT_CHECK_ALL		    0x20
#define MEGASAS_RD_WR_PROTECT_CHECK_NONE	    0x60

#define MPI2_SUP_REPLY_POST_HOST_INDEX_OFFSET   (0x0000030C)
#define MPI2_REPLY_POST_HOST_INDEX_OFFSET	(0x0000006C)

/*
 * Raid context flags
 */

#define MR_RAID_CTX_RAID_FLAGS_IO_SUB_TYPE_SHIFT   0x4
#define MR_RAID_CTX_RAID_FLAGS_IO_SUB_TYPE_MASK    0x30
typedef enum MR_RAID_FLAGS_IO_SUB_TYPE {
	MR_RAID_FLAGS_IO_SUB_TYPE_NONE = 0,
	MR_RAID_FLAGS_IO_SUB_TYPE_SYSTEM_PD = 1,
} MR_RAID_FLAGS_IO_SUB_TYPE;

/*
 * Request descriptor types
 */
#define MEGASAS_REQ_DESCRIPT_FLAGS_LD_IO           0x7
#define MEGASAS_REQ_DESCRIPT_FLAGS_MFA             0x1
#define MEGASAS_REQ_DESCRIPT_FLAGS_NO_LOCK	   0x2
#define MEGASAS_REQ_DESCRIPT_FLAGS_TYPE_SHIFT      1

#define MEGASAS_FP_CMD_LEN	16
#define MEGASAS_FUSION_IN_RESET 0

/*
 * Raid Context structure which describes MegaRAID specific IO Paramenters
 * This resides at offset 0x60 where the SGL normally starts in MPT IO Frames
 */

typedef struct _RAID_CONTEXT {
	u8	Type:4;		    // 0x00
	u8	nseg:4;		    // 0x00
	u8	resvd0;		    // 0x01
	u16     timeoutValue;       // 0x02 -0x03

	u8      regLockFlags;       // 0x04
	u8      resvd1;             // 0x05
	u16     VirtualDiskTgtId;   // 0x06 -0x07

	u64     regLockRowLBA;      // 0x08 - 0x0F

	u32     regLockLength;      // 0x10 - 0x13

	u16     nextLMId;           // 0x14 - 0x15
	u8      exStatus;           // 0x16
	u8      status;             // 0x17 status

	u8      RAIDFlags;          // 0x18 resvd[7:6], ioSubType[5:4], resvd[3:1], preferredCpu[0] */
	u8      numSGE;             // 0x19 numSge; not including chain entries */
	u16	    configSeqNum;       // 0x1A -0x1B
	u8      spanArm;            // 0x1C span[7:5], arm[4:0] */
	u8	    resvd2[3];		// 0x1D-0x1f */
} RAID_CONTEXT;

#define RAID_CTX_SPANARM_ARM_SHIFT	(0)
#define RAID_CTX_SPANARM_ARM_MASK	(0x1f)

#define RAID_CTX_SPANARM_SPAN_SHIFT	(5)
#define RAID_CTX_SPANARM_SPAN_MASK	(0xE0)

/*
 * define region lock types
 */
typedef enum    _REGION_TYPE {
	REGION_TYPE_UNUSED       = 0,    // lock is currently not active
	REGION_TYPE_SHARED_READ  = 1,    // shared lock (for reads)
	REGION_TYPE_SHARED_WRITE = 2,
	REGION_TYPE_EXCLUSIVE    = 3,    // exclusive lock (for writes)
} REGION_TYPE;

/* MPI2 defines */
#define MPI2_FUNCTION_IOC_INIT                      (0x02) /* IOC Init */
#define MPI2_WHOINIT_HOST_DRIVER                (0x04)
#define MPI2_VERSION_MAJOR                  (0x02)
#define MPI2_VERSION_MINOR                  (0x00)
#define MPI2_VERSION_MAJOR_MASK             (0xFF00)
#define MPI2_VERSION_MAJOR_SHIFT            (8)
#define MPI2_VERSION_MINOR_MASK             (0x00FF)
#define MPI2_VERSION_MINOR_SHIFT            (0)
#define MPI2_VERSION ((MPI2_VERSION_MAJOR << MPI2_VERSION_MAJOR_SHIFT) | \
		      MPI2_VERSION_MINOR)
#define MPI2_HEADER_VERSION_UNIT            (0x10)
#define MPI2_HEADER_VERSION_DEV             (0x00)
#define MPI2_HEADER_VERSION_UNIT_MASK       (0xFF00)
#define MPI2_HEADER_VERSION_UNIT_SHIFT      (8)
#define MPI2_HEADER_VERSION_DEV_MASK        (0x00FF)
#define MPI2_HEADER_VERSION_DEV_SHIFT       (0)
#define MPI2_HEADER_VERSION ((MPI2_HEADER_VERSION_UNIT << 8) | MPI2_HEADER_VERSION_DEV)
#define MPI2_IEEE_SGE_FLAGS_IOCPLBNTA_ADDR      (0x03)
#define MPI2_SCSIIO_EEDPFLAGS_INC_PRI_REFTAG        (0x8000)
#define MPI2_SCSIIO_EEDPFLAGS_CHECK_REFTAG          (0x0400)
#define MPI2_SCSIIO_EEDPFLAGS_CHECK_REMOVE_OP       (0x0003)
#define MPI2_SCSIIO_EEDPFLAGS_CHECK_APPTAG          (0x0200)
#define MPI2_SCSIIO_EEDPFLAGS_CHECK_GUARD           (0x0100)
#define MPI2_SCSIIO_EEDPFLAGS_INSERT_OP             (0x0004)
#define MPI2_FUNCTION_SCSI_IO_REQUEST               (0x00) /* SCSI IO */
#define MPI2_REQ_DESCRIPT_FLAGS_HIGH_PRIORITY           (0x06)
#define MPI2_REQ_DESCRIPT_FLAGS_SCSI_IO                 (0x00)
#define MPI2_SGE_FLAGS_64_BIT_ADDRESSING        (0x02)
#define MPI2_SCSIIO_CONTROL_WRITE               (0x01000000)
#define MPI2_SCSIIO_CONTROL_READ                (0x02000000)
#define MPI2_REQ_DESCRIPT_FLAGS_TYPE_MASK               (0x0E)
#define MPI2_RPY_DESCRIPT_FLAGS_UNUSED                      (0x0F)
#define MPI2_RPY_DESCRIPT_FLAGS_SCSI_IO_SUCCESS             (0x00)
#define MPI2_RPY_DESCRIPT_FLAGS_TYPE_MASK                   (0x0F)
#define MPI2_WRSEQ_FLUSH_KEY_VALUE              (0x0)
#define MPI2_WRITE_SEQUENCE_OFFSET              (0x00000004)
#define MPI2_WRSEQ_1ST_KEY_VALUE                (0xF)
#define MPI2_WRSEQ_2ND_KEY_VALUE                (0x4)
#define MPI2_WRSEQ_3RD_KEY_VALUE                (0xB)
#define MPI2_WRSEQ_4TH_KEY_VALUE                (0x2)
#define MPI2_WRSEQ_5TH_KEY_VALUE                (0x7)
#define MPI2_WRSEQ_6TH_KEY_VALUE                (0xD)

#ifndef MPI2_POINTER
#define MPI2_POINTER     *
#endif

typedef struct _MPI25_IEEE_SGE_CHAIN64
{
	u64                     Address;
	u32                     Length;
	u16                     Reserved1;
	u8                      NextChainOffset;
	u8                      Flags;
} MPI25_IEEE_SGE_CHAIN64, MPI2_POINTER PTR_MPI25_IEEE_SGE_CHAIN64,
	Mpi25IeeeSgeChain64_t, MPI2_POINTER pMpi25IeeeSgeChain64_t;

typedef struct _MPI2_SGE_SIMPLE_UNION
{
	u32                     FlagsLength;
	union
	{
		u32                 Address32;
		u64                 Address64;
	} u;
} MPI2_SGE_SIMPLE_UNION, MPI2_POINTER PTR_MPI2_SGE_SIMPLE_UNION,
	Mpi2SGESimpleUnion_t, MPI2_POINTER pMpi2SGESimpleUnion_t;

typedef struct
{
	u8                      CDB[20];                    /* 0x00 */
	u32                     PrimaryReferenceTag;        /* 0x14 */
	u16                     PrimaryApplicationTag;      /* 0x18 */
	u16                     PrimaryApplicationTagMask;  /* 0x1A */
	u32                     TransferLength;             /* 0x1C */
} MPI2_SCSI_IO_CDB_EEDP32, MPI2_POINTER PTR_MPI2_SCSI_IO_CDB_EEDP32,
	Mpi2ScsiIoCdbEedp32_t, MPI2_POINTER pMpi2ScsiIoCdbEedp32_t;

typedef struct _MPI2_SGE_CHAIN_UNION
{
	u16                     Length;
	u8                      NextChainOffset;
	u8                      Flags;
	union
	{
		u32                 Address32;
		u64                 Address64;
	} u;
} MPI2_SGE_CHAIN_UNION, MPI2_POINTER PTR_MPI2_SGE_CHAIN_UNION,
	Mpi2SGEChainUnion_t, MPI2_POINTER pMpi2SGEChainUnion_t;

typedef struct _MPI2_IEEE_SGE_SIMPLE32
{
	u32                     Address;
	u32                     FlagsLength;
} MPI2_IEEE_SGE_SIMPLE32, MPI2_POINTER PTR_MPI2_IEEE_SGE_SIMPLE32,
	Mpi2IeeeSgeSimple32_t, MPI2_POINTER pMpi2IeeeSgeSimple32_t;

typedef struct _MPI2_IEEE_SGE_SIMPLE64
{
	u64                     Address;
	u32                     Length;
	u16                     Reserved1;
	u8                      Reserved2;
	u8                      Flags;
} MPI2_IEEE_SGE_SIMPLE64, MPI2_POINTER PTR_MPI2_IEEE_SGE_SIMPLE64,
	Mpi2IeeeSgeSimple64_t, MPI2_POINTER pMpi2IeeeSgeSimple64_t;

typedef union _MPI2_IEEE_SGE_SIMPLE_UNION
{
	MPI2_IEEE_SGE_SIMPLE32  Simple32;
	MPI2_IEEE_SGE_SIMPLE64  Simple64;
} MPI2_IEEE_SGE_SIMPLE_UNION, MPI2_POINTER PTR_MPI2_IEEE_SGE_SIMPLE_UNION,
	Mpi2IeeeSgeSimpleUnion_t, MPI2_POINTER pMpi2IeeeSgeSimpleUnion_t;

typedef MPI2_IEEE_SGE_SIMPLE32  MPI2_IEEE_SGE_CHAIN32;
typedef MPI2_IEEE_SGE_SIMPLE64  MPI2_IEEE_SGE_CHAIN64;

typedef union _MPI2_IEEE_SGE_CHAIN_UNION
{
	MPI2_IEEE_SGE_CHAIN32   Chain32;
	MPI2_IEEE_SGE_CHAIN64   Chain64;
} MPI2_IEEE_SGE_CHAIN_UNION, MPI2_POINTER PTR_MPI2_IEEE_SGE_CHAIN_UNION,
	Mpi2IeeeSgeChainUnion_t, MPI2_POINTER pMpi2IeeeSgeChainUnion_t;

typedef union _MPI2_SGE_IO_UNION
{
	MPI2_SGE_SIMPLE_UNION       MpiSimple;
	MPI2_SGE_CHAIN_UNION        MpiChain;
	MPI2_IEEE_SGE_SIMPLE_UNION  IeeeSimple;
	MPI2_IEEE_SGE_CHAIN_UNION   IeeeChain;
} MPI2_SGE_IO_UNION, MPI2_POINTER PTR_MPI2_SGE_IO_UNION,
	Mpi2SGEIOUnion_t, MPI2_POINTER pMpi2SGEIOUnion_t;

typedef union
{
	u8                      CDB32[32];
	MPI2_SCSI_IO_CDB_EEDP32 EEDP32;
	MPI2_SGE_SIMPLE_UNION   SGE;
} MPI2_SCSI_IO_CDB_UNION, MPI2_POINTER PTR_MPI2_SCSI_IO_CDB_UNION,
	Mpi2ScsiIoCdb_t, MPI2_POINTER pMpi2ScsiIoCdb_t;

/*
 * RAID SCSI IO Request Message
 * Total SGE count will be one less than  _MPI2_SCSI_IO_REQUEST
 */
typedef struct _MPI2_RAID_SCSI_IO_REQUEST
{
	u16                     DevHandle;                      /* 0x00 */
	u8                      ChainOffset;                    /* 0x02 */
	u8                      Function;                       /* 0x03 */
	u16                     Reserved1;                      /* 0x04 */
	u8                      Reserved2;                      /* 0x06 */
	u8                      MsgFlags;                       /* 0x07 */
	u8                      VP_ID;                          /* 0x08 */
	u8                      VF_ID;                          /* 0x09 */
	u16                     Reserved3;                      /* 0x0A */
	u32                     SenseBufferLowAddress;          /* 0x0C */
	u16                     SGLFlags;                       /* 0x10 */
	u8                      SenseBufferLength;              /* 0x12 */
	u8                      Reserved4;                      /* 0x13 */
	u8                      SGLOffset0;                     /* 0x14 */
	u8                      SGLOffset1;                     /* 0x15 */
	u8                      SGLOffset2;                     /* 0x16 */
	u8                      SGLOffset3;                     /* 0x17 */
	u32                     SkipCount;                      /* 0x18 */
	u32                     DataLength;                     /* 0x1C */
	u32                     BidirectionalDataLength;        /* 0x20 */
	u16                     IoFlags;                        /* 0x24 */
	u16                     EEDPFlags;                      /* 0x26 */
	u32                     EEDPBlockSize;                  /* 0x28 */
	u32                     SecondaryReferenceTag;          /* 0x2C */
	u16                     SecondaryApplicationTag;        /* 0x30 */
	u16                     ApplicationTagTranslationMask;  /* 0x32 */
	u8                      LUN[8];                         /* 0x34 */
	u32                     Control;                        /* 0x3C */
	MPI2_SCSI_IO_CDB_UNION  CDB;                            /* 0x40 */
	RAID_CONTEXT            RaidContext;                    /* 0x60 */
	MPI2_SGE_IO_UNION       SGL;                            /* 0x80 */
} MEGASAS_RAID_SCSI_IO_REQUEST, MPI2_POINTER PTR_MEGASAS_RAID_SCSI_IO_REQUEST,
	MEGASASRaidSCSIIORequest_t, MPI2_POINTER pMEGASASRaidSCSIIORequest_t;

/*
 * MPT RAID MFA IO Descriptor.
 */
typedef struct _MEGASAS_RAID_MFA_IO_DESCRIPTOR {
	u32     RequestFlags    : 8;
	u32     MessageAddress1 : 24; /* bits 31:8*/
	u32     MessageAddress2;      /* bits 61:32 */
} MEGASAS_RAID_MFA_IO_REQUEST_DESCRIPTOR,*PMEGASAS_RAID_MFA_IO_REQUEST_DESCRIPTOR;

/* Default Request Descriptor */
typedef struct _MPI2_DEFAULT_REQUEST_DESCRIPTOR
{
	u8              RequestFlags;               /* 0x00 */
	u8              MSIxIndex;                  /* 0x01 */
	u16             SMID;                       /* 0x02 */
	u16             LMID;                       /* 0x04 */
	u16             DescriptorTypeDependent;    /* 0x06 */
} MPI2_DEFAULT_REQUEST_DESCRIPTOR,
	MPI2_POINTER PTR_MPI2_DEFAULT_REQUEST_DESCRIPTOR,
	Mpi2DefaultRequestDescriptor_t, MPI2_POINTER pMpi2DefaultRequestDescriptor_t;

/* High Priority Request Descriptor */
typedef struct _MPI2_HIGH_PRIORITY_REQUEST_DESCRIPTOR
{
	u8              RequestFlags;               /* 0x00 */
	u8              MSIxIndex;                  /* 0x01 */
	u16             SMID;                       /* 0x02 */
	u16             LMID;                       /* 0x04 */
	u16             Reserved1;                  /* 0x06 */
} MPI2_HIGH_PRIORITY_REQUEST_DESCRIPTOR,
	MPI2_POINTER PTR_MPI2_HIGH_PRIORITY_REQUEST_DESCRIPTOR,
	Mpi2HighPriorityRequestDescriptor_t,
	MPI2_POINTER pMpi2HighPriorityRequestDescriptor_t;

/* SCSI IO Request Descriptor */
typedef struct _MPI2_SCSI_IO_REQUEST_DESCRIPTOR
{
	u8              RequestFlags;               /* 0x00 */
	u8              MSIxIndex;                  /* 0x01 */
	u16             SMID;                       /* 0x02 */
	u16             LMID;                       /* 0x04 */
	u16             DevHandle;                  /* 0x06 */
} MPI2_SCSI_IO_REQUEST_DESCRIPTOR,
	MPI2_POINTER PTR_MPI2_SCSI_IO_REQUEST_DESCRIPTOR,
	Mpi2SCSIIORequestDescriptor_t, MPI2_POINTER pMpi2SCSIIORequestDescriptor_t;

/* SCSI Target Request Descriptor */
typedef struct _MPI2_SCSI_TARGET_REQUEST_DESCRIPTOR
{
	u8              RequestFlags;               /* 0x00 */
	u8              MSIxIndex;                  /* 0x01 */
	u16             SMID;                       /* 0x02 */
	u16             LMID;                       /* 0x04 */
	u16             IoIndex;                    /* 0x06 */
} MPI2_SCSI_TARGET_REQUEST_DESCRIPTOR,
	MPI2_POINTER PTR_MPI2_SCSI_TARGET_REQUEST_DESCRIPTOR,
	Mpi2SCSITargetRequestDescriptor_t,
	MPI2_POINTER pMpi2SCSITargetRequestDescriptor_t;

/* RAID Accelerator Request Descriptor */
typedef struct _MPI2_RAID_ACCEL_REQUEST_DESCRIPTOR
{
	u8              RequestFlags;               /* 0x00 */
	u8              MSIxIndex;                  /* 0x01 */
	u16             SMID;                       /* 0x02 */
	u16             LMID;                       /* 0x04 */
	u16             Reserved;                   /* 0x06 */
} MPI2_RAID_ACCEL_REQUEST_DESCRIPTOR,
	MPI2_POINTER PTR_MPI2_RAID_ACCEL_REQUEST_DESCRIPTOR,
	Mpi2RAIDAcceleratorRequestDescriptor_t,
	MPI2_POINTER pMpi2RAIDAcceleratorRequestDescriptor_t;

/* union of Request Descriptors */
typedef union _MEGASAS_REQUEST_DESCRIPTOR_UNION
{
	MPI2_DEFAULT_REQUEST_DESCRIPTOR             Default;
	MPI2_HIGH_PRIORITY_REQUEST_DESCRIPTOR       HighPriority;
	MPI2_SCSI_IO_REQUEST_DESCRIPTOR             SCSIIO;
	MPI2_SCSI_TARGET_REQUEST_DESCRIPTOR         SCSITarget;
	MPI2_RAID_ACCEL_REQUEST_DESCRIPTOR          RAIDAccelerator;
	MEGASAS_RAID_MFA_IO_REQUEST_DESCRIPTOR          MFAIo;
	union {
		struct {
			u32 low;
			u32 high;
		} u;
		u64 Words;
	};
} MEGASAS_REQUEST_DESCRIPTOR_UNION;

/* Default Reply Descriptor */
typedef struct _MPI2_DEFAULT_REPLY_DESCRIPTOR
{
	u8              ReplyFlags;                 /* 0x00 */
	u8              MSIxIndex;                  /* 0x01 */
	u16             DescriptorTypeDependent1;   /* 0x02 */
	u32             DescriptorTypeDependent2;   /* 0x04 */
} MPI2_DEFAULT_REPLY_DESCRIPTOR, MPI2_POINTER PTR_MPI2_DEFAULT_REPLY_DESCRIPTOR,
	Mpi2DefaultReplyDescriptor_t, MPI2_POINTER pMpi2DefaultReplyDescriptor_t;

/* Address Reply Descriptor */
typedef struct _MPI2_ADDRESS_REPLY_DESCRIPTOR
{
	u8              ReplyFlags;                 /* 0x00 */
	u8              MSIxIndex;                  /* 0x01 */
	u16             SMID;                       /* 0x02 */
	u32             ReplyFrameAddress;          /* 0x04 */
} MPI2_ADDRESS_REPLY_DESCRIPTOR, MPI2_POINTER PTR_MPI2_ADDRESS_REPLY_DESCRIPTOR,
	Mpi2AddressReplyDescriptor_t, MPI2_POINTER pMpi2AddressReplyDescriptor_t;

/* SCSI IO Success Reply Descriptor */
typedef struct _MPI2_SCSI_IO_SUCCESS_REPLY_DESCRIPTOR
{
	u8              ReplyFlags;                 /* 0x00 */
	u8              MSIxIndex;                  /* 0x01 */
	u16             SMID;                       /* 0x02 */
	u16             TaskTag;                    /* 0x04 */
	u16             Reserved1;                  /* 0x06 */
} MPI2_SCSI_IO_SUCCESS_REPLY_DESCRIPTOR,
	MPI2_POINTER PTR_MPI2_SCSI_IO_SUCCESS_REPLY_DESCRIPTOR,
	Mpi2SCSIIOSuccessReplyDescriptor_t,
	MPI2_POINTER pMpi2SCSIIOSuccessReplyDescriptor_t;

/* TargetAssist Success Reply Descriptor */
typedef struct _MPI2_TARGETASSIST_SUCCESS_REPLY_DESCRIPTOR
{
	u8              ReplyFlags;                 /* 0x00 */
	u8              MSIxIndex;                  /* 0x01 */
	u16             SMID;                       /* 0x02 */
	u8              SequenceNumber;             /* 0x04 */
	u8              Reserved1;                  /* 0x05 */
	u16             IoIndex;                    /* 0x06 */
} MPI2_TARGETASSIST_SUCCESS_REPLY_DESCRIPTOR,
	MPI2_POINTER PTR_MPI2_TARGETASSIST_SUCCESS_REPLY_DESCRIPTOR,
	Mpi2TargetAssistSuccessReplyDescriptor_t,
	MPI2_POINTER pMpi2TargetAssistSuccessReplyDescriptor_t;

/* Target Command Buffer Reply Descriptor */
typedef struct _MPI2_TARGET_COMMAND_BUFFER_REPLY_DESCRIPTOR
{
	u8              ReplyFlags;                 /* 0x00 */
	u8              MSIxIndex;                  /* 0x01 */
	u8              VP_ID;                      /* 0x02 */
	u8              Flags;                      /* 0x03 */
	u16             InitiatorDevHandle;         /* 0x04 */
	u16             IoIndex;                    /* 0x06 */
} MPI2_TARGET_COMMAND_BUFFER_REPLY_DESCRIPTOR,
	MPI2_POINTER PTR_MPI2_TARGET_COMMAND_BUFFER_REPLY_DESCRIPTOR,
	Mpi2TargetCommandBufferReplyDescriptor_t,
	MPI2_POINTER pMpi2TargetCommandBufferReplyDescriptor_t;

/* RAID Accelerator Success Reply Descriptor */
typedef struct _MPI2_RAID_ACCELERATOR_SUCCESS_REPLY_DESCRIPTOR
{
	u8              ReplyFlags;                 /* 0x00 */
	u8              MSIxIndex;                  /* 0x01 */
	u16             SMID;                       /* 0x02 */
	u32             Reserved;                   /* 0x04 */
} MPI2_RAID_ACCELERATOR_SUCCESS_REPLY_DESCRIPTOR,
	MPI2_POINTER PTR_MPI2_RAID_ACCELERATOR_SUCCESS_REPLY_DESCRIPTOR,
	Mpi2RAIDAcceleratorSuccessReplyDescriptor_t,
	MPI2_POINTER pMpi2RAIDAcceleratorSuccessReplyDescriptor_t;

/* union of Reply Descriptors */
typedef union _MPI2_REPLY_DESCRIPTORS_UNION
{
	MPI2_DEFAULT_REPLY_DESCRIPTOR                   Default;
	MPI2_ADDRESS_REPLY_DESCRIPTOR                   AddressReply;
	MPI2_SCSI_IO_SUCCESS_REPLY_DESCRIPTOR           SCSIIOSuccess;
	MPI2_TARGETASSIST_SUCCESS_REPLY_DESCRIPTOR      TargetAssistSuccess;
	MPI2_TARGET_COMMAND_BUFFER_REPLY_DESCRIPTOR     TargetCommandBuffer;
	MPI2_RAID_ACCELERATOR_SUCCESS_REPLY_DESCRIPTOR  RAIDAcceleratorSuccess;
	u64                                             Words;
} MPI2_REPLY_DESCRIPTORS_UNION, MPI2_POINTER PTR_MPI2_REPLY_DESCRIPTORS_UNION,
	Mpi2ReplyDescriptorsUnion_t, MPI2_POINTER pMpi2ReplyDescriptorsUnion_t;

/* IOCInit Request message */
typedef struct _MPI2_IOC_INIT_REQUEST
{
	u8                      WhoInit;                        /* 0x00 */
	u8                      Reserved1;                      /* 0x01 */
	u8                      ChainOffset;                    /* 0x02 */
	u8                      Function;                       /* 0x03 */
	u16                     Reserved2;                      /* 0x04 */
	u8                      Reserved3;                      /* 0x06 */
	u8                      MsgFlags;                       /* 0x07 */
	u8                      VP_ID;                          /* 0x08 */
	u8                      VF_ID;                          /* 0x09 */
	u16                     Reserved4;                      /* 0x0A */
	u16                     MsgVersion;                     /* 0x0C */
	u16                     HeaderVersion;                  /* 0x0E */
	u32                     Reserved5;                      /* 0x10 */
	u16                     Reserved6;                      /* 0x14 */
	u8                      Reserved7;                      /* 0x16 */
	u8                      HostMSIxVectors;                /* 0x17 */
	u16                     Reserved8;                      /* 0x18 */
	u16                     SystemRequestFrameSize;         /* 0x1A */
	u16                     ReplyDescriptorPostQueueDepth;  /* 0x1C */
	u16                     ReplyFreeQueueDepth;            /* 0x1E */
	u32                     SenseBufferAddressHigh;         /* 0x20 */
	u32                     SystemReplyAddressHigh;         /* 0x24 */
	u64                     SystemRequestFrameBaseAddress;  /* 0x28 */
	u64                     ReplyDescriptorPostQueueAddress;/* 0x30 */
	u64                     ReplyFreeQueueAddress;          /* 0x38 */
	u64                     TimeStamp;                      /* 0x40 */
} MPI2_IOC_INIT_REQUEST, MPI2_POINTER PTR_MPI2_IOC_INIT_REQUEST,
	Mpi2IOCInitRequest_t, MPI2_POINTER pMpi2IOCInitRequest_t;

/* mrpriv defines */
#define MR_PD_INVALID 0xFFFF
#define MAX_SPAN_DEPTH 8
#define MAX_QUAD_DEPTH	MAX_SPAN_DEPTH
#define MAX_RAIDMAP_SPAN_DEPTH (MAX_SPAN_DEPTH)
#define MAX_ROW_SIZE 32
#define MAX_RAIDMAP_ROW_SIZE (MAX_ROW_SIZE)
#define MAX_LOGICAL_DRIVES 64
#define MAX_RAIDMAP_LOGICAL_DRIVES (MAX_LOGICAL_DRIVES)
#define MAX_RAIDMAP_VIEWS (MAX_LOGICAL_DRIVES)
#define MAX_ARRAYS 128
#define MAX_RAIDMAP_ARRAYS (MAX_ARRAYS)
#define MAX_PHYSICAL_DEVICES 256
#define MAX_RAIDMAP_PHYSICAL_DEVICES (MAX_PHYSICAL_DEVICES)
#define MR_DCMD_LD_MAP_GET_INFO             0x0300e101   // get the mapping information of this LD

typedef enum _MR_CTRL_IO_METRICS_CMD_TYPE {
        MR_CTRL_IO_METRICS_CMD_START            = 0,     // Start (or restart) Full IO metrics collection
        MR_CTRL_IO_METRICS_CMD_STOP             = 1,     // Stop  IO metrics collection
        MR_CTRL_IO_METRICS_CMD_START_BASIC      = 2,     // Start collection of only basic IO metrics
        MR_CTRL_IO_METRICS_CMD_SEND_IDLE_FP     = 3,     // Send bitmap of LDs that are idle with respect to FP
} MR_CTRL_IO_METRICS_CMD_TYPE;

typedef struct _MR_DEV_HANDLE_INFO {
	u16     curDevHdl;                  // the device handle currently used by fw to issue the command.
	u8      validHandles;               // bitmap of valid device handles.
	u8      reserved;
	u16     devHandle[2];               // 0x04 dev handles for all the paths.
} MR_DEV_HANDLE_INFO;                   // 0x08, Total Size

typedef struct _MR_ARRAY_INFO {
	u16      pd[MAX_RAIDMAP_ROW_SIZE];
} MR_ARRAY_INFO;                       // 0x40, Total Size

typedef struct _MR_QUAD_ELEMENT {
	u64     logStart;                   // 0x00
	u64     logEnd;                     // 0x08
	u64     offsetInSpan;               // 0x10
	u32     diff;                       // 0x18
	u32     reserved1;                  // 0x1C
} MR_QUAD_ELEMENT;                      // 0x20, Total size

typedef struct _MR_SPAN_INFO {
	u32             noElements;             // 0x00
	u32             reserved1;              // 0x04
	MR_QUAD_ELEMENT quad[MAX_RAIDMAP_SPAN_DEPTH];   // 0x08
} MR_SPAN_INFO;                             // 0x108, Total size

typedef struct _MR_LD_SPAN_ {           // SPAN structure
	u64      startBlk;                  // 0x00, starting block number in array
	u64      numBlks;                   // 0x08, number of blocks
	u16      arrayRef;                  // 0x10, array reference
	u8       spanRowSize;               // 0x11, span row size
	u8       spanRowDataSize;           // 0x12, span row data size
	u8       reserved[4];               // 0x13, reserved
} MR_LD_SPAN;                           // 0x18, Total Size

typedef struct _MR_SPAN_BLOCK_INFO {
	u64          num_rows;             // number of rows/span
	MR_LD_SPAN   span;                 // 0x08
	MR_SPAN_INFO block_span_info;      // 0x20
} MR_SPAN_BLOCK_INFO;                  // 0x128, Total Size

typedef struct _MR_LD_RAID {
	struct {
		u32     fpCapable           :1;
		u32     reserved5           :3;
		u32     ldPiMode            :4;
		u32     pdPiMode            :4; // Every Pd has to be same.
		u32     encryptionType      :8; // FDE or controller encryption (MR_LD_ENCRYPTION_TYPE)
		u32     fpWriteCapable      :1;
		u32     fpReadCapable       :1;
		u32     fpWriteAcrossStripe :1;
		u32     fpReadAcrossStripe  :1;
		u32     reserved4           :8;
	} capability;                   // 0x00
	u32     reserved6;
	u64     size;                   // 0x08, LD size in blocks

	u8      spanDepth;              // 0x10, Total Number of Spans
	u8      level;                  // 0x11, RAID level
	u8      stripeShift;            // 0x12, shift-count to get stripe size (0=512, 1=1K, 7=64K, etc.)
	u8      rowSize;                // 0x13, number of disks in a row

	u8      rowDataSize;            // 0x14, number of data disks in a row
	u8      writeMode;              // 0x15, WRITE_THROUGH or WRITE_BACK
	u8      PRL;                    // 0x16, To differentiate between RAID1 and RAID1E
	u8      SRL;                    // 0x17

	u16     targetId;               // 0x18, ld Target Id.
	u8      ldState;                // 0x1a, state of ld, state corresponds to MR_LD_STATE
	u8      regTypeReqOnWrite;      // 0x1b, Pre calculate region type requests based on MFC etc..
	u8      modFactor;              // 0x1c, same as rowSize,
	u8	regTypeReqOnRead;	// 0x1d, region lock type used for read, valid only if regTypeOnReadIsValid=1
	u16     seqNum;                 // 0x1e, LD sequence number

	struct {
		u32 ldSyncRequired:1;       // This LD requires sync command before completing
		u32 reserved:31;
	} flags;                        // 0x20

	u8      reserved3[0x5C];        // 0x24
} MR_LD_RAID;                       // 0x80, Total Size

typedef struct _MR_LD_SPAN_MAP {
	MR_LD_RAID          ldRaid;                             // 0x00
	u8                  dataArmMap[MAX_RAIDMAP_ROW_SIZE];   // 0x80, needed for GET_ARM() - R0/1/5 only.
	MR_SPAN_BLOCK_INFO  spanBlock[MAX_RAIDMAP_SPAN_DEPTH];  // 0xA0
} MR_LD_SPAN_MAP;                // 0x9E0

typedef struct _MR_FW_RAID_MAP {
	u32                 totalSize;              // total size of this structure, including this field.

	union {
		struct {                                // Simple method of version checking variables
			u32         maxLd;
			u32         maxSpanDepth;
			u32         maxRowSize;
			u32         maxPdCount;
			u32         maxArrays;
		} validationInfo;
		u32             version[5];
		u32             reserved1[5];
	};

	u32                 ldCount;                                // count of lds.
	u32                 Reserved1;                              //
	u8                  ldTgtIdToLd[MAX_RAIDMAP_LOGICAL_DRIVES+MAX_RAIDMAP_VIEWS];        // 0x20. This doesn't correspond to
	// FW Ld Tgt Id to LD, but will purge. For example: if tgt Id is 4
	// and FW LD is 2, and there is only one LD, FW will populate the
	// array like this. [0xFF, 0xFF, 0xFF, 0xFF, 0x0,.....]. This is to
	// help reduce the entire strcture size if there are few LDs or
	// driver is looking info for 1 LD only.
	u8                  fpPdIoTimeoutSec;                       // timeout value used by driver in FP IOs
	u8                  reserved2[7];
	MR_ARRAY_INFO       arMapInfo[MAX_RAIDMAP_ARRAYS];              // 0x00a8
	MR_DEV_HANDLE_INFO  devHndlInfo[MAX_RAIDMAP_PHYSICAL_DEVICES];  // 0x20a8
	MR_LD_SPAN_MAP      ldSpanMap[1];                               // 0x28a8 - [0 - MAX_RAIDMAP_LOGICAL_DRIVES + MAX_RAIDMAP_VIEWS + 1];

} MR_FW_RAID_MAP;                            // 0x3288, Total Size

struct IO_REQUEST_INFO {
	u64 ldStartBlock;
	u32 numBlocks;
	u16 ldTgtId;
	u8 isRead;
	u16 devHandle;
	u64 pdBlock;
	u8 fpOkForIo;
	u8 IoforUnevenSpan;
	u8 start_span;
	u8 reserved;
	u64 start_row;
};

typedef struct _MR_LD_TARGET_SYNC {
	u8  targetId;
	u8  reserved;
	u16 seqNum;
} MR_LD_TARGET_SYNC;

#define IEEE_SGE_FLAGS_ADDR_MASK            (0x03)
#define IEEE_SGE_FLAGS_SYSTEM_ADDR          (0x00)
#define IEEE_SGE_FLAGS_IOCDDR_ADDR          (0x01)
#define IEEE_SGE_FLAGS_IOCPLB_ADDR          (0x02)
#define IEEE_SGE_FLAGS_IOCPLBNTA_ADDR       (0x03)
#define IEEE_SGE_FLAGS_CHAIN_ELEMENT        (0x80)
#define IEEE_SGE_FLAGS_END_OF_LIST          (0x40)

struct megasas_register_set;
struct megasas_instance;

union desc_word {
	u64 word;
	struct {
		u32 low;
		u32 high;
	} u;
};

struct megasas_cmd_fusion {
	MEGASAS_RAID_SCSI_IO_REQUEST	*io_request;
	dma_addr_t			io_request_phys_addr;

	MPI2_SGE_IO_UNION	*sg_frame;
	dma_addr_t			sg_frame_phys_addr;

	u8 *sense;
	dma_addr_t sense_phys_addr;

	struct list_head list;
	struct scsi_cmnd *scmd;
	struct megasas_instance *instance;

	u8 retry_for_fw_reset;
	MEGASAS_REQUEST_DESCRIPTOR_UNION  *request_desc;

	/*
	 * Context for a MFI frame.
	 * Used to get the mfi cmd from list when a MFI cmd is completed
	 */
	u32 sync_cmd_idx;
	u32 index;
	u8 flags;
};

typedef struct _LD_LOAD_BALANCE_INFO
{
	u8	loadBalanceFlag;
	u8	reserved1;
	u16     raid1DevHandle[2];
	atomic_t     scsi_pending_cmds[2];
	u64     last_accessed_block[2];
} LD_LOAD_BALANCE_INFO, *PLD_LOAD_BALANCE_INFO;

/* SPAN_SET is info caclulated from span info from Raid map per ld */
typedef struct _LD_SPAN_SET {
    u64  log_start_lba;
    u64  log_end_lba;
    u64  span_row_start;
    u64  span_row_end;
    u64  data_strip_start;
    u64  data_strip_end;
    u64  data_row_start;
    u64  data_row_end;
    u8   strip_offset[MAX_SPAN_DEPTH];
    u32    span_row_data_width;
    u32    diff;
    u32    reserved[2];
}LD_SPAN_SET, *PLD_SPAN_SET;

typedef struct LOG_BLOCK_SPAN_INFO {
    LD_SPAN_SET  span_set[MAX_SPAN_DEPTH];
}LD_SPAN_INFO, *PLD_SPAN_INFO;


typedef struct _MR_FW_RAID_MAP_ALL {

	MR_FW_RAID_MAP raidMap;
	MR_LD_SPAN_MAP ldSpanMap[MAX_LOGICAL_DRIVES - 1];
}  __attribute__ ((packed))  MR_FW_RAID_MAP_ALL;

struct fusion_context
{
	struct megasas_cmd_fusion **cmd_list;
	struct list_head cmd_pool;

	spinlock_t cmd_pool_lock;

	dma_addr_t req_frames_desc_phys;
	u8 *req_frames_desc;

	struct dma_pool *io_request_frames_pool;
	dma_addr_t io_request_frames_phys;
	u8 *io_request_frames;

	struct dma_pool *sg_dma_pool;
	struct dma_pool *sense_dma_pool;

	dma_addr_t reply_frames_desc_phys;
	Mpi2ReplyDescriptorsUnion_t *reply_frames_desc;
	struct dma_pool *reply_frames_desc_pool;

	u16 last_reply_idx[MAX_MSIX_QUEUES_FUSION];

	u32 reply_q_depth;
	u32 request_alloc_sz;
	u32 reply_alloc_sz;
	u32 io_frames_alloc_sz;

	u16	max_sge_in_main_msg;
	u16	max_sge_in_chain;

	u8	chain_offset_io_request;
	u8	chain_offset_mfi_pthru;

	MR_FW_RAID_MAP_ALL *ld_map[2];
	dma_addr_t ld_map_phys[2];

	u32 map_sz;
	u8 fast_path_io;
	LD_LOAD_BALANCE_INFO load_balance_info[MAX_LOGICAL_DRIVES];
	LD_SPAN_INFO log_to_span[MAX_LOGICAL_DRIVES];
};

union desc_value {
	u64 word;
	struct {
		u32 low;
		u32 high;
	} u;
};

#endif //_MEGARAID_SAS_FUSION_H_
