.. SPDX-License-Identifier: GPL-2.0

==================================================
Userspace Memory Failure Recovery Policy via memfd
==================================================

:Author:
    Jiaqi Yan <jiaqiyan@google.com>


Motivation
==========

When a userspace process is able to recover from memory failures (MF)
caused by uncorrected memory error (UE) in the DIMM, especially when it is
able to avoid consuming known UEs, keeping the memory page mapped and
accessible is benifical to the owning process for a couple of reasons:

- The memory pages affected by UE have a large smallest granularity, for
  example 1G hugepage, but the actual corrupted amount of the page is only
  several cachlines. Losing the entire hugepage of data is unacceptable to
  the application.

- In addition to keeping the data accessible, the application still wants
  to access with a large page size for the fastest virtual-to-physical
  translations.

Memory failure recovery for 1G HugeTLB is a good example. With memfd
userspace process can control whether the kernel hard offlines its
hugepages that backs the in-RAM file created by memfd.


User API
========

``int memfd_create(const char *name, unsigned int flags)``

``MFD_MF_KEEP_UE_MAPPED``

	When ``MFD_MF_KEEP_UE_MAPPED`` bit is set in ``flags``, MF recovery
	in the kernel does not hard offline memory due to UE until the
	returned ``memfd`` is released. IOW, the HWPoison-ed memory remains
	accessible via the returned ``memfd`` or the memory mapping created
	with the returned ``memfd``. Note the affected memory will be
	immediately isolated and prevented from future use once the memfd
	is closed. By default ``MFD_MF_KEEP_UE_MAPPED`` is not set, and
	kernel hard offlines memory having UEs.

Notes about the behavior and limitations

- Even if the page affected by UE is kept, a portion of the (huge)page is
  already lost due to hardware corruption, and the size of the portion
  is the smallest page size that kernel uses to manages memory on the
  architecture, i.e. PAGESIZE. Accessing a virtual address within any of
  these parts results in a SIGBUS; accessing virtual address outside these
  parts are good until it is corrupted by new memory error.

- ``MFD_MF_KEEP_UE_MAPPED`` currently only works for HugeTLB, so
  ``MFD_HUGETLB`` must also be set when setting ``MFD_MF_KEEP_UE_MAPPED``.
  Otherwise ``memfd_create`` returns EINVAL.

- UEK8 currently looses the entire UE impacted hugepage once the memfd is
  closed.
