UEK-next: Oracle's Next Unbreakable Enterprise Kernel Development Release
=========================================================================

The Next Unbreakable Enterprise Kernel Developer Release (UEK-next) is the
next generation of the UEK kernel based upon the upstream Linux `v6.15` tag.

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

UEK-next does not have a Secure Boot signature and as a result cannot be used on
systems where Secure Boot is enabled.

## How it is formed

The UEK-next release is built by applying UEK specific fixes on top of the
latest Linux mainline release tag.

UEK-next developer releases are upstream Linux kernels with Oracle Linux patches
for use to evaluate new features in upstream Linux and enable developers to
experiment with the latest hardware support, and to validate application
compatibility with the latest kernels.

Every UEK-next release is based on a major upstream release (e.g.: 6.13 based,
6.14 based, etc.)

## Noteworthy Changes

- UEK-next is also now available for installation on Oracle Linux 10

## Known Problems

- Several selftest issues identified with BPF which are also present on the
  mainline kernel

- Running selinux in target or enforcing mode results in syslog messages being
  generated

# Reporting Issues

Issues found while using this release that are not present in upstream Linux may
be reported using Github Issues at:

- https://github.com/oracle/linux-uek/issues

If you have kernel patches, please contribute to upstream Linux first! Patches
accepted by upstream will be part of the next UEK-next build a few weeks after
that kernel is released.

# Recent Blog posts

- https://blogs.oracle.com/linux/post/uek8-packaging

- https://elufasys.com/investigating-the-kernel-configuration-of-uek-next/

- https://blogs.oracle.com/linux/post/uek-next

- https://blogs.oracle.com/linux/post/exploring-ueknexts-kernel-configuration

- https://blogs.oracle.com/linux/post/virtioblk-using-iothread-vq-mapping
