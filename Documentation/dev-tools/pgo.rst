.. SPDX-License-Identifier: GPL-2.0

===============================
Using PGO with the Linux kernel
===============================

Clang's profiling kernel support (PGO_) enables profiling of the Linux kernel
when building with Clang. The profiling data is exported via the ``pgo``
debugfs directory.

.. _PGO: https://clang.llvm.org/docs/UsersManual.html#profile-guided-optimization


Preparation
===========

Configure the kernel with:

.. code-block:: make

   CONFIG_DEBUG_FS=y
   CONFIG_PGO_CLANG=y

Note that kernels compiled with profiling flags will be significantly larger
and run slower.

Profiling data will only become accessible once debugfs has been mounted:

.. code-block:: sh

   mount -t debugfs none /sys/kernel/debug


Customization
=============

You can enable or disable profiling for individual file and directories by
adding a line similar to the following to the respective kernel Makefile:

- For a single file (e.g. main.o)

  .. code-block:: make

     PGO_PROFILE_main.o := y

- For all files in one directory

  .. code-block:: make

     PGO_PROFILE := y

To exclude files from being profiled use

  .. code-block:: make

     PGO_PROFILE_main.o := n

and

  .. code-block:: make

     PGO_PROFILE := n

Only files which are linked to the main kernel image or are compiled as kernel
modules are supported by this mechanism.


Files
=====

The PGO kernel support creates the following files in debugfs:

``/sys/kernel/debug/pgo``
	Parent directory for all PGO-related files.

``/sys/kernel/debug/pgo/reset``
	Global reset file: resets all coverage data to zero when written to.

``/sys/kernel/debug/pgo/vmlinux.profraw``
	The raw PGO data that must be processed with ``llvm_profdata``.


Workflow
========

The PGO kernel can be run on the host or test machines. The data though should
be analyzed with Clang's tools from the same Clang version as the kernel was
compiled. Clang's tolerant of version skew, but it's easier to use the same
Clang version.

The profiling data is useful for optimizing the kernel, analyzing coverage,
etc. Clang offers tools to perform these tasks.

Here is an example workflow for profiling an instrumented kernel with PGO and
using the result to optimize the kernel:

1) Install the kernel on the TEST machine.

2) Reset the data counters right before running the load tests

   .. code-block:: sh

      $ echo 1 > /sys/kernel/debug/pgo/reset

3) Run the load tests.

4) Collect the raw profile data

   .. code-block:: sh

      $ cp -a /sys/kernel/debug/pgo/vmlinux.profraw /tmp/vmlinux.profraw

5) (Optional) Download the raw profile data to the HOST machine.

6) Process the raw profile data

   .. code-block:: sh

      $ llvm-profdata merge --output=vmlinux.profdata vmlinux.profraw

   Note that multiple raw profile data files can be merged during this step.

7) Rebuild the kernel using the processed profile data (PGO disabled)

   .. code-block:: sh

      $ make LLVM=1 KCFLAGS=-fprofile-use=vmlinux.profdata ...
