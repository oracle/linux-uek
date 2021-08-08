.. SPDX-License-Identifier: GPL-2.0
.. Copyright © 2019-2024 Daniel P. Smith <dpsmith@apertussolutions.com>

===================================
Secure Launch Config and Interfaces
===================================

:Author: Daniel P. Smith
:Date: August 2024

Configuration
=============

The settings to enable Secure Launch using Kconfig are under::

  "Processor type and features" --> "Secure Launch support"

A kernel with this option enabled can still be booted using other supported
methods.

To reduce the Trusted Computing Base (TCB) of the MLE [1]_, the build
configuration should be pared down as narrowly as one's use case allows.
Fewer drivers (less active hardware) and features reduce the attack surface.
As an example in the extreme, the MLE could only have local disk access with no
other hardware supports except optional network access for remote attestation.

It is also desirable, if possible, to embed the initrd used with the MLE kernel
image to reduce complexity.

The following are important configuration necessities to always consider:

KASLR Configuration
-------------------

Due to Secure Launch hardware implementation details and how KASLR functions,
Secure Launch is not able to interoperate with KASLR at this time. Attempts to
enable KASLR in a kernel started using Secure Launch may result in crashes and
other instabilities at boot. Even in cases where Secure Launch and KASLR work
together, it is still recommended that KASLR be disabled to avoid introducing
security concerns with unprotected kernel memory.

If possible, a kernel being used as an MLE should be built with KASLR disabled::

  "Processor type and features" -->
      "Build a relocatable kernel" -->
          "Randomize the address of the kernel image (KASLR) [ ]"

This action unsets the Kconfig value CONFIG_RANDOMIZE_BASE.

If it is not possible to disable at build time, then it is recommended to force
KASLR to be disabled using the kernel command line when doing a Secure Launch.
The kernel parameter is as follows::

  nokaslr

.. note::
    Should KASLR be made capable of reading/using only the protected page
    regions set up by the memory protection mechanisms used by the hardware
    DRTM capability, it would then become possible to use KASLR with Secure
    Launch.

IOMMU Configuration
-------------------

When doing a Secure Launch, the IOMMU should always be enabled and the drivers
loaded. However, IOMMU passthrough mode should never be used. This leaves the
MLE completely exposed to DMA after the PMRs [2]_ are disabled. The current
default mode is to use IOMMU in lazy translated mode, but strict translated
mode is the preferred IOMMU mode and this should be selected in the build
configuration::

  "Device Drivers" -->
      "IOMMU Hardware Support" -->
          "IOMMU default domain type" -->
              "(X) Translated - Strict"

In addition, the Intel IOMMU should be on by default. The following sets this as the
default in the build configuration::

  "Device Drivers" -->
      "IOMMU Hardware Support" -->
          "Support for Intel IOMMU using DMA Remapping Devices [*]"

and::

  "Device Drivers" -->
      "IOMMU Hardware Support" -->
          "Support for Intel IOMMU using DMA Remapping Devices [*]" -->
              "Enable Intel DMA Remapping Devices by default  [*]"

It is recommended that no other command line options should be set to override
the defaults above. If there is a desire to run an alternate configuration,
then that configuration should be evaluated for what benefits might
be gained against the risks for DMA attacks to which the kernel is likely
going to be exposed.

Secure Launch Resource Table
============================

The Secure Launch Resource Table (SLRT) is a platform-agnostic, standard format
for providing information for the pre-launch environment and to pass
information to the post-launch environment. The table is populated by one or
more bootloaders in the boot chain and used by Secure Launch on how to set up
the environment during post-launch. The details for the SLRT are documented
in the TrenchBoot Secure Launch Specification [3]_.

Intel TXT Interface
===================

The primary interfaces between the various components in TXT are the TXT MMIO
registers and the TXT heap. The MMIO register banks are described in Appendix B
of the TXT MLE [1]_ Development Guide.

The TXT heap is described in Appendix C of the TXT MLE [1]_ Development
Guide. Most of the TXT heap is predefined in the specification. The heap is
initialized by firmware and the pre-launch environment and is subsequently used
by the SINIT ACM. One section, called the OS to MLE Data Table, is reserved for
software to define. This table is set up per the recommendation detailed in
Appendix B of the TrenchBoot Secure Launch Specification::

        /*
         * Secure Launch defined OS/MLE TXT Heap table
         */
        struct txt_os_mle_data {
                u32 version;
                u32 reserved;
                u64 boot_params_addr;
                u64 slrt;
                u64 txt_info;
                u32 ap_wake_block;
                u32 ap_wake_block_size;
                u8 mle_scratch[64];
        } __packed;

Description of structure:

=====================  ========================================================================
Field                  Use
=====================  ========================================================================
version                Structure version, current value 1
boot_params_addr       Physical base address of the Linux boot parameters
slrt                   Physical address of the Secure Launch Resource Table
txt_info               Pointer into the SLRT for easily locating TXT specific table
ap_wake_block          Physical address of the block of memory for parking APs after a launch
ap_wake_block_size     Size of the AP wake block
mle_scratch            Scratch area used post-launch by the MLE kernel. Fields:
 
                        - SL_SCRATCH_AP_EBX area to share %ebx base pointer among CPUs
                        - SL_SCRATCH_AP_JMP_OFFSET offset to abs. ljmp fixup location for APs
=====================  ========================================================================

Error Codes
-----------

The TXT specification defines the layout for TXT 32 bit error code values.
The bit encodings indicate where the error originated (e.g. with the CPU,
in the SINIT ACM, in software). The error is written to a sticky TXT
register that persists across resets called TXT.ERRORCODE (see the TXT
MLE Development Guide). The errors defined by the Secure Launch feature are
those generated in the MLE software. They have the format::

  0xc0008XXX

The low 12 bits are free for defining the following Secure Launch specific
error codes.

======  ================
Name:   SL_ERROR_GENERIC
Value:  0xc0008001
======  ================

Description:

Generic catch all error. Currently unused.

======  =================
Name:   SL_ERROR_TPM_INIT
Value:  0xc0008002
======  =================

Description:

The Secure Launch code failed to get access to the TPM hardware interface.
This is most likely due to misconfigured hardware or kernel. Ensure the TPM
chip is enabled, and the kernel TPM support is built in (it should not be built
as a module).

======  ==========================
Name:   SL_ERROR_TPM_INVALID_LOG20
Value:  0xc0008003
======  ==========================

Description:

Either the Secure Launch code failed to find a valid event log descriptor for a
version 2.0 TPM, or the event log descriptor is malformed. Usually this
indicates incompatible versions of the pre-launch environment and the
MLE kernel. The pre-launch environment and the kernel share a structure in the
TXT heap and if this structure (the OS-MLE table) is mismatched, this error is
common. This TXT heap area is set up by the pre-launch environment, so the
issue may originate there. It could also be the sign of an attempted attack.

======  ===========================
Name:   SL_ERROR_TPM_LOGGING_FAILED
Value:  0xc0008004
======  ===========================

Description:

There was a failed attempt to write a TPM event to the event log early in the
Secure Launch process. This is likely the result of a malformed TPM event log
buffer. Formatting of the event log buffer information is done by the
pre-launch environment, so the issue most likely originates there.

======  ============================
Name:   SL_ERROR_REGION_STRADDLE_4GB
Value:  0xc0008005
======  ============================

Description:

During early validation, a buffer or region was found to straddle the 4GB
boundary. Because of the way TXT provides DMA memory protection, this is an unsafe
configuration and is flagged as an error. This is most likely a configuration
issue in the pre-launch environment. It could also be the sign of an attempted
attack.

======  ===================
Name:   SL_ERROR_TPM_EXTEND
Value:  0xc0008006
======  ===================

Description:

There was a failed attempt to extend a TPM PCR in the Secure Launch platform
module. This is most likely to due to misconfigured hardware or kernel. Ensure
the TPM chip is enabled, and the kernel TPM support is built in (it should not
be built as a module).

======  ======================
Name:   SL_ERROR_MTRR_INV_VCNT
Value:  0xc0008007
======  ======================

Description:

During early Secure Launch validation, an invalid variable MTRR count was
found. The pre-launch environment passes a number of MSR values to the MLE to
restore including the MTRRs. The values are restored by the Secure Launch early
entry point code. After measuring the values supplied by the pre-launch
environment, a discrepancy was found, validating the values. It could be the
sign of an attempted attack.

======  ==========================
Name:   SL_ERROR_MTRR_INV_DEF_TYPE
Value:  0xc0008008
======  ==========================

Description:

During early Secure Launch validation, an invalid default MTRR type was found.
See SL_ERROR_MTRR_INV_VCNT for more details.

======  ======================
Name:   SL_ERROR_MTRR_INV_BASE
Value:  0xc0008009
======  ======================

Description:

During early Secure Launch validation, an invalid variable MTRR base value was
found. See SL_ERROR_MTRR_INV_VCNT for more details.

======  ======================
Name:   SL_ERROR_MTRR_INV_MASK
Value:  0xc000800a
======  ======================

Description:

During early Secure Launch validation, an invalid variable MTRR mask value was
found. See SL_ERROR_MTRR_INV_VCNT for more details.

======  ========================
Name:   SL_ERROR_MSR_INV_MISC_EN
Value:  0xc000800b
======  ========================

Description:

During early Secure Launch validation, an invalid miscellaneous enable MSR
value was found. See SL_ERROR_MTRR_INV_VCNT for more details.

======  =========================
Name:   SL_ERROR_INV_AP_INTERRUPT
Value:  0xc000800c
======  =========================

Description:

The application processors (APs) wait to be woken up by the SMP initialization
code. The only interrupt that they expect is an NMI; all other interrupts
should be masked. If an AP gets an interrupt other than an NMI, it will
cause this error. This error is very unlikely to occur.

======  =========================
Name:   SL_ERROR_INTEGER_OVERFLOW
Value:  0xc000800d
======  =========================

Description:

A buffer base and size passed to the MLE caused an integer overflow when
added together. This is most likely a configuration issue in the pre-launch
environment. It could also be the sign of an attempted attack.

======  ==================
Name:   SL_ERROR_HEAP_WALK
Value:  0xc000800e
======  ==================

Description:

An error occurred in TXT heap walking code. The underlying issue is a failure to
early_memremap() portions of the heap, most likely due to a resource shortage.

======  =================
Name:   SL_ERROR_HEAP_MAP
Value:  0xc000800f
======  =================

Description:

This error is essentially the same as SL_ERROR_HEAP_WALK, but occurred during the
actual early_memremap() operation.

======  =========================
Name:   SL_ERROR_REGION_ABOVE_4GB
Value:  0xc0008010
======  =========================

Description:

A memory region used by the MLE is above 4GB. In general this is not a problem
because memory > 4Gb can be protected from DMA. There are certain buffers that
should never be above 4Gb, and one of these caused the violation. This is most
likely a configuration issue in the pre-launch environment. It could also be
the sign of an attempted attack.

======  ==========================
Name:   SL_ERROR_HEAP_INVALID_DMAR
Value:  0xc0008011
======  ==========================

Description:

The backup copy of the ACPI DMAR table which is supposed to be located in the
TXT heap could not be found. This is due to a bug in the platform's ACM module
or in firmware.

======  =======================
Name:   SL_ERROR_HEAP_DMAR_SIZE
Value:  0xc0008012
======  =======================

Description:

The backup copy of the ACPI DMAR table in the TXT heap is to large to be stored
for later usage. This error is very unlikely to occur since the area reserved
for the copy is far larger than the DMAR should be.

======  ======================
Name:   SL_ERROR_HEAP_DMAR_MAP
Value:  0xc0008013
======  ======================

Description:

The backup copy of the ACPI DMAR table in the TXT heap could not be mapped. The
underlying issue is a failure to early_memremap() the DMAR table, most likely
due to a resource shortage.

======  ====================
Name:   SL_ERROR_HI_PMR_BASE
Value:  0xc0008014
======  ====================

Description:

On a system with more than 4G of RAM, the high PMR [2]_ base address should be
set to 4G. This error is due to that not being the case. This PMR value is set
by the pre-launch environment, so the issue most likely originates there. It
could also be the sign of an attempted attack.

======  ====================
Name:   SL_ERROR_HI_PMR_SIZE
Value:  0xc0008015
======  ====================

Description:

On a system with more than 4G of RAM, the high PMR [2]_ size should be set to
cover all RAM > 4G. This error is due to that not being the case. This PMR
value is set by the pre-launch environment, so the issue most likely originates
there. It could also be the sign of an attempted attack.

======  ====================
Name:   SL_ERROR_LO_PMR_BASE
Value:  0xc0008016
======  ====================

Description:

The low PMR [2]_ base should always be set to address zero. This error is due
to that not being the case. This PMR value is set by the pre-launch environment
so the issue most likely originates there. It could also be the sign of an
attempted attack.

======  ====================
Name:   SL_ERROR_LO_PMR_MLE
Value:  0xc0008017
======  ====================

Description:

This error indicates the MLE image is not covered by the low PMR [2]_ range.
The PMR values are set by the pre-launch environment, so the issue most likely
originates there. It could also be the sign of an attempted attack.

======  =======================
Name:   SL_ERROR_INITRD_TOO_BIG
Value:  0xc0008018
======  =======================

Description:

The external initrd provided is larger than 4Gb. This is not a valid
configuration for a Secure Launch due to managing DMA protection.

======  =========================
Name:   SL_ERROR_HEAP_ZERO_OFFSET
Value:  0xc0008019
======  =========================

Description:

During a TXT heap walk, an invalid/zero next table offset value was found. This
indicates the TXT heap is malformed. The TXT heap is initialized by the
pre-launch environment, so the issue most likely originates there. It could
also be a sign of an attempted attack. In addition, ACM is also responsible for
manipulating parts of the TXT heap, so the issue could be due to a bug in the
platform's ACM module.

======  =============================
Name:   SL_ERROR_WAKE_BLOCK_TOO_SMALL
Value:  0xc000801a
======  =============================

Description:

The AP wake block buffer passed to the MLE via the OS-MLE TXT heap table is not
large enough. This value is set by the pre-launch environment, so the issue
most likely originates there. It also could be the sign of an attempted attack.

======  ===========================
Name:   SL_ERROR_MLE_BUFFER_OVERLAP
Value:  0xc000801b
======  ===========================

Description:

One of the buffers passed to the MLE via the OS-MLE TXT heap table overlaps
with the MLE image in memory. This value is set by the pre-launch environment
so the issue most likely originates there. It could also be the sign of an
attempted attack.

======  ==========================
Name:   SL_ERROR_BUFFER_BEYOND_PMR
Value:  0xc000801c
======  ==========================

Description:

One of the buffers passed to the MLE via the OS-MLE TXT heap table is not
protected by a PMR. This value is set by the pre-launch environment, so the
issue most likely originates there. It could also be the sign of an attempted
attack.

======  =============================
Name:   SL_ERROR_OS_SINIT_BAD_VERSION
Value:  0xc000801d
======  =============================

Description:

The version of the OS-SINIT TXT heap table is bad. It must be 6 or greater.
This value is set by the pre-launch environment, so the issue most likely
originates there. It could also be the sign of an attempted attack. It is also
possible though very unlikely that the platform is so old that the ACM being
used requires an unsupported version.

======  =====================
Name:   SL_ERROR_EVENTLOG_MAP
Value:  0xc000801e
======  =====================

Description:

An error occurred in the Secure Launch module while mapping the TPM event log.
The underlying issue is memremap() failure, most likely due to a resource
shortage.

======  ========================
Name:   SL_ERROR_TPM_NUMBER_ALGS
Value:  0xc000801f
======  ========================

Description:

The TPM 2.0 event log reports an unsupported number of hashing algorithms.
Secure launch currently only supports a maximum of two: SHA1 and SHA256.

======  ===========================
Name:   SL_ERROR_TPM_UNKNOWN_DIGEST
Value:  0xc0008020
======  ===========================

Description:

The TPM 2.0 event log reports an unsupported hashing algorithm. Secure launch
currently only supports two algorithms: SHA1 and SHA256.

======  ==========================
Name:   SL_ERROR_TPM_INVALID_EVENT
Value:  0xc0008021
======  ==========================

Description:

An invalid/malformed event was found in the TPM event log while reading it.
Since only trusted entities are supposed to be writing the event log, this
would indicate either a bug or a possible attack.

======  =====================
Name:   SL_ERROR_INVALID_SLRT
Value:  0xc0008022
======  =====================

Description:

The Secure Launch Resource Table is invalid or malformed and is unusable. This
implies the pre-launch code did not properly set up the SLRT.

======  ===========================
Name:   SL_ERROR_SLRT_MISSING_ENTRY
Value:  0xc0008023
======  ===========================

Description:

The Secure Launch Resource Table is missing a required entry within it. This
implies the pre-launch code did not properly set up the SLRT.

======  =================
Name:   SL_ERROR_SLRT_MAP
Value:  0xc0008024
======  =================

Description:

An error occurred in the Secure Launch module while mapping the Secure Launch
Resource table. The underlying issue is memremap() failure, most likely due to
a resource shortage.

.. [1]
    MLE: Measured Launch Environment is the binary runtime that is measured and
    then run by the TXT SINIT ACM. The TXT MLE Development Guide describes the
    requirements for the MLE in detail.

.. [2]
    PMR: Intel VTd has a feature in the IOMMU called Protected Memory Registers.
    There are two of these registers and they allow all DMA to be blocked
    to large areas of memory. The low PMR can cover all memory below 4Gb on 2Mb
    boundaries. The high PMR can cover all RAM on the system, again on 2Mb
    boundaries. This feature is used during a Secure Launch by TXT.

.. [3]
    Secure Launch Specification: https://trenchboot.org/specifications/Secure_Launch/
