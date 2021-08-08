.. SPDX-License-Identifier: GPL-2.0
.. Copyright © 2019-2024 Daniel P. Smith <dpsmith@apertussolutions.com>

======================
Secure Launch Overview
======================

:Author: Daniel P. Smith
:Date: August 2024

Overview
========

Prior to the start of the TrenchBoot project, the only active Open Source
project supporting dynamic launch was Intel's tboot project to support their
implementation of dynamic launch known as Intel Trusted eXecution Technology
(TXT). The approach taken by tboot was to provide an exokernel that could
handle the launch protocol implemented by the Intel provided loader, the SINIT
Authenticated Code Module (ACM [2]_), and remained in memory to manage the SMX
CPU mode that a dynamic launch would put a system. While it is not precluded
from being used for a late launch, tboot's primary use case was to be
used as an early launch solution. As a result, the TrenchBoot project started
the development of Secure Launch kernel feature to provide a more generalized
approach. The focus of the effort is twofold: first, to make the Linux
kernel directly aware of the launch protocol used by Intel, AMD/Hygon, Arm, and
potentially OpenPOWER; second, to make the Linux kernel able to
initiate a dynamic launch. It is through this approach that the Secure Launch
kernel feature creates a basis for the Linux kernel to be used in a variety of
dynamic launch use cases.

.. note::
    A quick note on terminology. The larger open source project itself is
    called TrenchBoot, which is hosted on GitHub (links below). The kernel
    feature enabling the use of the x86 technology is referred to as "Secure
    Launch" within the kernel code.

Goals
=====

The first use case that the TrenchBoot project focused on was the ability for
the Linux kernel to be started by a dynamic launch, in particular as part of an
early launch sequence. In this case, the dynamic launch will be initiated by
any bootloader with associated support added to it. For example, the first
targeted bootloader in this case was GRUB2. An integral part of establishing a
measurement-based launch integrity involves measuring everything that is
intended to be executed (kernel image, initrd, etc.) and everything that will
configure that kernel to execute (command line, boot params, etc.), then
storing those measurements in a protected manner. Both the Intel and AMD
dynamic launch implementations leverage the Trusted Platform Module (TPM) to
store those measurements. The TPM itself has been designed such that a dynamic
launch unlocks a specific set of Platform Configuration Registers (PCR) for
holding measurement taken during the dynamic launch. These are referred to as
the DRTM PCRs, PCRs 17-22. Further details on this process can be found in the
documentation for the GETSEC instruction provided by Intel's TXT and the SKINIT
instruction provided by AMD's AMD-V. The documentation on these technologies
can be readily found online; see the `Resources`_ section below for references.

.. note::
    Currently, only Intel TXT is supported in this first release of the Secure
    Launch feature. AMD/Hygon SKINIT and Arm support will be added in a
    subsequent release.

To enable the kernel to be launched by GETSEC a stub, the Secure Launch stub
must be built into the setup section of the compressed kernel to handle the
specific state that the dynamic launch process leaves the BSP. Also, the Secure
Launch stub must measure everything that is going to be used as early as
possible. This stub code and subsequent code must also deal with the specific
state that the dynamic launch leaves the APs as well.

Design Decisions
================

A number of design decisions were made during the development of the Secure
Launch feature. The two primary guiding decisions were:

 - Keeping the Secure Launch code as separate from the rest of the kernel
   as possible.
 - Modifying the existing boot path of the kernel as little as possible.

The following illustrate how the implementation followed these design
decisions:

 - All the entry point code necessary to properly configure the system post
   launch is found in st_stub.S in the compressed kernel image. This code
   validates the state of the system, restores necessary system operating
   configurations and properly handles post launch CPU states.
 - After the sl_stub.S is complete, it jumps directly to the unmodified
   startup_32 kernel entry point.
 - A single call is made to a function sl_main() prior to the main kernel
   decompression step. This code performs further validation and takes the
   needed DRTM measurements.
 - After the call to sl_main(), the main kernel is decompressed and boots as
   it normally would.
 - Final setup for the Secure Launch kernel is done in a separate Secure
   Launch module that is loaded via a late initcall. This code is responsible
   for extending the measurements taken earlier into the TPM DRTM PCRs and
   setting up the securityfs interface to allow access to the TPM event log and
   public TXT registers.
 - On the reboot and kexec paths, calls are made to a function to finalize the
   state of the Secure Launch kernel.

The one place where Secure Launch code is mixed directly in with kernel code is
in the SMP boot code. This is due to the unique state that the dynamic launch
leaves the APs in. On Intel, this involves using a method other than the
standard INIT-SIPI sequence.

A final note is that originally the extending of the PCRs was completed in the
Secure Launch stub when the measurements were taken. An alternative solution
had to be implemented due to the TPM maintainers objecting to the PCR
extensions being done with a minimal interface to the TPM that was an
independent implementation of the mainline kernel driver. Since the mainline
driver relies heavily on kernel interfaces not available in the compressed
kernel, it was not possible to reuse the mainline TPM driver. This resulted in
the decision to move the extension operations to the Secure Launch module in
the mainline kernel, where the TPM driver would be available.

Basic Boot Flow
===============

Outlined here is a summary of the boot flow for Secure Launch. A more detailed
review of Secure Launch process can be found in the Secure Launch
Specification (a link is located in the `Resources`_ section).

Pre-launch: *Phase where the environment is prepared and configured to initiate
the secure launch by the boot chain.*

 - The SLRT is initialized and dl_stub is placed in memory.
 - Load the kernel, initrd and ACM [2]_ into memory.
 - Set up the TXT heap and page tables describing the MLE [1]_ per the
   specification.
 - If non-UEFI platform, dl_stub is called.
 - If UEFI platforms, SLRT registered with UEFI and efi-stub called.
 - Upon completion, efi-stub will call EBS followed by dl_stub.
 - The dl_stub will prepare the CPU and the TPM for the launch.
 - The secure launch is then initiated with the GETSET[SENTER] instruction.

Post-launch: *Phase where control is passed from the ACM to the MLE and the secure
kernel begins execution.*

 - Entry from the dynamic launch jumps to the SL stub.
 - SL stub fixes up the world on the BSP.
 - For TXT, SL stub wakes the APs, fixes up their worlds.
 - For TXT, APs are left halted using MONITOR/MWAIT intructions.
 - SL stub jumps to startup_32.
 - SL main does validation of buffers and memory locations. It sets
   the boot parameter loadflag value SLAUNCH_FLAG to inform the main
   kernel that a Secure Launch was done.
 - SL main locates the TPM event log and writes the measurements of
   configuration and module information into it.
 - Kernel boot proceeds normally from this point.
 - During early setup, slaunch_setup() runs to finish validation
   and setup tasks.
 - The SMP bring up code is modified to wake the waiting APs via the monitor
   address.
 - APs vector to rmpiggy and start up normally from that point.
 - SL platform module is registered as a late initcall module. It reads
   the TPM event log and extends the measurements taken into the TPM PCRs.
 - SL platform module initializes the securityfs interface to allow
   access to the TPM event log and TXT public registers.
 - Kernel boot finishes booting normally.
 - SEXIT support to leave SMX mode is present on the kexec path and
   the various reboot paths (poweroff, reset, halt).

PCR Usage
=========

The TCG DRTM architecture there are three PCRs defined for usage, PCR.Details
(PCR17), PCR.Authorities (PCR18), and PCR.DLME_Authority (PCR19). For a deeper
understanding of Detail and Authorities it is recommended to review the TCG
DRTM architecture.

To determine PCR usage, Linux Secure Launch follows the TrenchBoot Secure
Launch Specification of using a measurement policy stored in the SLRT. The
policy details what should be measured and the PCR in which to store the
measurement. The measurement policy provides the ability to select the
PCR.DLME_Detail (PCR20) PCR as the location for the DRTM components measured by
the kernel, e.g. external initrd image. This can then be combined with storing
the user authority in the PCR.DLME_Authority PCR to seal/attest to different
variations of platform details/authorities and user details/authorities. An
example of how this can be achieved was presented in the FOSDEM - 2021 talk
"Secure Upgrades with DRTM".

SHA-1 Usage
-----------

Secure Launch is written to be compliant with the Intel TXT Measured Launch
Developer's Guide. The MLE Guide dictates that the system can be configured to
use both the SHA-1 and SHA-2 hashing algorithms. The choice is dictated by what
hash algorithm banks firmware enabled at system start time.

Regardless of the preference towards SHA-2, if the firmware elected to start
with the SHA-1 and SHA-2 banks active and the dynamic launch was configured to
include SHA-1, Secure Launch is obligated to record measurements for all
algorithms requested in the launch configuration. If SHA-1 can be disabled in
the firmware setup, then TXT and Secure Launch will only use the SHA-2 banks
while establishing the launch environment.

Ultimately, the security of an RTM solution is how and what measurements are
used to assess the health of a system. If SHA-1 measurements are made but not
used, i.e. the attestation enforcement only uses SHA-2, then it has zero impact
on the security of the system.

Finally, there are older systems with TPM 1.2 chips that only support SHA-1. If
the system integrator (whether that be the OEM, employer, distro maintainer,
system administrator, or end user) chooses to use older hardware that only has
a TPM 1.2 chip, then they are accepting the risk it creates in their solution.

Resources
=========

The TrenchBoot project:

https://trenchboot.org

Secure Launch Specification:

https://trenchboot.org/specifications/Secure_Launch/

Trusted Computing Group's D-RTM Architecture:

https://trustedcomputinggroup.org/wp-content/uploads/TCG_D-RTM_Architecture_v1-0_Published_06172013.pdf

TXT documentation in the Intel TXT MLE Development Guide:

https://www.intel.com/content/dam/www/public/us/en/documents/guides/intel-txt-software-development-guide.pdf

TXT instructions documentation in the Intel SDM Instruction Set volume:

https://software.intel.com/en-us/articles/intel-sdm

AMD SKINIT documentation in the System Programming manual:

https://www.amd.com/system/files/TechDocs/24593.pdf

GRUB Secure Launch support:

https://github.com/TrenchBoot/grub/tree/grub-sl-fc-38-dlstub

FOSDEM 2021: Secure Upgrades with DRTM

https://archive.fosdem.org/2021/schedule/event/firmware_suwd/

.. [1]
    MLE: Measured Launch Environment is the binary runtime that is measured and
    then run by the TXT SINIT ACM. The TXT MLE Development Guide describes the
    requirements for the MLE in detail.

.. [2]
    ACM: Intel's Authenticated Code Module. This is the 32b bit binary blob that
    is run securely by the GETSEC[SENTER] during a measured launch. It is described
    in the Intel documentation on TXT and versions for various chipsets are
    signed and distributed by Intel.
