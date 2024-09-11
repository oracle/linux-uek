UEK-next: Oracle's Next Unbreakable Enterprise Kernel Development Release
=========================================================================

The Next Unbreakable Enterprise Kernel Developer Release (UEK-next) is the
next generation of the UEK kernel based upon the upstream Linux `v6.10` tag.

The UEK-next developer release allows Oracle Linux users to try out the latest
developments from upstream Linux combined with Oracle UEK-specific features.

To read more about Linux kernel development at Oracle, see:

- https://blogs.oracle.com/linuxkernel

The original README for the Linux kernel along with a other useful documentation
can be found at Documentation/admin-guide/README.rst

## Support

UEK-next is not supported for production use, however we will provide limited
test and development support for these kernels to help validate applications and
workloads.

## How it is formed

The UEK-next release is built by applying UEK specific fixes on top of the
latest Linux mainline release tag.

UEK-next developer releases are upstream Linux kernels with Oracle Linux patches
for use to evaluate new features in upstream Linux and enable developers to
experiment with the latest hardware support, and to validate application
compatibility with the latest kernels.

Every UEK-next release will be based on a major upstream release(e.g.: 6.10
based, 6.11 based, etc.)

## Noteworthy Changes

- Updated package naming

  To make it easier to identify a UEK-next kernel we have updated the RPM and
  the effective `uname -r` output to use the OS release of `ol9ueknext`, for
  example:

  ```
  $ uname -r
  6.10.0-2.el9ueknext.x86_64
  ```

  Similarly, the RPM name now includes this too:

  ```
  kernel-ueknext-6.10.0-2.el9ueknext.x86_64.rpm
  kernel-ueknext-core-6.10.0-2.el9ueknext.x86_64.rpm
  kernel-ueknext-modules-6.10.0-2.el9ueknext.x86_64.rpm
  kernel-ueknext-modules-core-6.10.0-2.el9ueknext.x86_64.rpm
  kernel-ueknext-modules-extra-6.10.0-2.el9ueknext.x86_64.rpm
  ```

## Known Problems

- Continued to bring in the upstream extensible scheduler class "sched_ext"

  This new scheduler provides a means to write additional CPU schedulers using
  BPF, meaning that it can be introduced or updated on a live system. The
  upstream changes were brought in to enable developers using UEK to try it
  out.

  The changes used for UEK-next v6.10 were based on those targeting v6.11 at:

  - https://lore.kernel.org/all/ZpWjbCQPtuUcvo8r@slm.duckdns.org/

  but it was later found that this did not include the changes for cgroups
  which were removed.

- There is an issue when using OCFS2 in a single node configuration

  Using an OCFS2 filesystem has exhibited issues based on changes in the
  upstream v6.10 code-base, and may be seen as a lack of inodes and a
  resulting "No space left on device" message.

- Due to a bug in `v6.8`, a `dnf upgrade` of kernel-ueknext `v6.8` to `v6.10` may
  be seen as an upgrade rather than a parallel installation due to a bug in
  the `v6.8` RPMs where they were not correctly identified as install-only,
  with an error similar to:

  ```
  Problem 1: cannot install both kernel-ueknext-6.10.0-2.el9ueknext.x86_64 from 
             @commandline and kernel-ueknext-6.8.0-2.el9uek.x86_64 from @System
   - conflicting requests
   - problem with installed package kernel-ueknext-6.8.0-2.el9uek.x86_64
  ```

  A workaround is to temporarily add the following to `/etc/dnf/dnf.conf`:

  ```ini
  installonlypkgs = kernel-ueknext, kernel-ueknext-core, kernel-ueknext-modules, kernel-ueknext-modules-core, kernel-ueknext-modules-extra 
  ```

- Some NVME devices exhibit what appears to be a corruption of the metadata

  Due to inconsistencies between the firmware and the kernel, the kernel
  believes that the device supports WRITE ZEROES, when it does not.

  This can be resolved by ensuring that the NVME firmware is updated to the
  latest version.

# Reporting Issues

Issues found while using this release that are not present in upstream Linux may
be reported using Github Issues at:

- https://github.com/oracle/linux-uek/issues

If you have kernel patches, please contribute to upstream Linux first! Patches
accepted by upstream will be part of the next UEK-next build a few weeks after
that kernel is released.

# Recent Blog posts

- https://blogs.oracle.com/linux/post/uek-next

- https://blogs.oracle.com/linux/post/exploring-ueknexts-kernel-configuration

- https://blogs.oracle.com/linux/post/virtioblk-using-iothread-vq-mapping
