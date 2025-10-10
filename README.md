# Oracle Linux: Unbreakable Enterprise Kernel (UEK)

## Introducing UEK

The Unbreakable Enterprise Kernel (UEK) is a Linux kernel built by Oracle and supported via Oracle Linux Support. Its focus is performance, stability, and minimal backports by tracking the mainline source code as closely as is practical. UEK is well-tested and used to run Oracle's Engineered Systems, Oracle Cloud Infrastructure, and large-scale enterprise deployments for Oracle Linux customers.

Oracle is a long-time contributor to Linux and we have always had a strong emphasis on upstreaming and open-sourcing our changes to the kernel. Keeping our changes open source allows us to integrate with upstream Linux kernels quickly, which also means we have state-of-the-art drivers and filesystems, hardware support, and security fixes from the community...in addition to the work we have contributed ourselves. [Read more on the Oracle Linux Kernel Blog.](https://blogs.oracle.com/linuxkernel)

This repository contains the source for the Unbreakable Enterprise Kernel 
including a small number of Oracle additions which have not yet been accepted into the main 
Linux kernel source tree. You can preview those changes, which are continually merged into
the upstream Linux tree, in the `ueknext/latest` branch.
[Binary RPMs for UEK-next are also available publicly.](https://blogs.oracle.com/linux/post/uek-next)

The full Oracle Linux distribution, both sources and binaries, can be found at [yum.oracle.com](https://yum.oracle.com).

## Current Branches

This repository hosts source code for UEK versions which are in development and in production, as well as archived releases. 

| UEK Release and Tag | Linux Kernel version | Release Status | Target Arch | Target Userspace Distribution(s) |
|--------------------|-----------------------------|----------------------|-----------------|--------------------------------------------|
| [`ueknext/latest`](https://github.com/oracle/linux-uek/tree/ueknext/latest) | latest | Production | `x86_64`, `aarch64` | Oracle Linux 9, Oracle Linux 10 |
| [`uek8/u1`](https://github.com/oracle/linux-uek/tree/uek8/u1)<br/>[`v6.12.0-105.49.4`](https://github.com/oracle/linux-uek/tree/v6.12.0-105.49.4) | v6.12 | Production | `x86_64`, `aarch64` | Oracle Linux 9, Oracle Linux 10 |
| [`uek7/u3`](https://github.com/oracle/linux-uek/tree/uek7/u3)<br/>[`v5.15.0-314.193.4`](https://github.com/oracle/linux-uek/tree/v5.15.0-314.193.4) | v5.15 | Production | `x86_64`, `aarch64` | Oracle Linux 8, Oracle Linux 9 |
| [`uek6/u3`](https://github.com/oracle/linux-uek/tree/uek6/u3)<br/>[`v5.4.17-2136.349.2`](https://github.com/oracle/linux-uek/tree/v5.4.17-2136.349.2) | v5.4 | Production | `x86_64`, `aarch64` | Oracle Linux 7, Oracle Linux 8 |

Building from this repository requires [libdtrace-ctf](https://github.com/oracle/libdtrace-ctf/) in addition to standard kernel build tools.

## Refresh Schedule

This repository will be refreshed weekly as new development versions are available.

## Linux Development at Oracle

Oracle's Linux team is a top ten contributor in each upstream kernel release. Our mission is to improve Linux, which means higher performance, better security, and more advanced diagnosability. We also focus on the fundamentals of the OS, improving the scheduler and core memory allocation routines. The Oracle Linux team participates in the development and upstream maintainership for key areas of the kernel, including scsi, xfs, btrfs, RDS, hugetlbfs, nfs and nfsd, and more. Since 2007, Oracle has contributed more than 400,000 lines of code to Linux, and been ranked in the top 15 all-time contributors to Linux. 

The source for UEK was previously available at [oss.oracle.com](https://oss.oracle.com) and has always been available publicly as a git repository with full git history. By posting the UEK source here on [github.com](https://github.com/oracle/linux-uek/) we hope to increase the visibility for our work and to make it even easier for people to access the source for UEK. We also use this repository for working with developers at partner companies and in the Linux community.

[And, we're hiring](https://www.oracle.com/corporate/careers/index.html)!

## Issues, Pull Requests and Support

The UEK source is published here without support. For compiled binaries and a supported
enterprise distribution, Oracle Linux is free to download, distribute and use and can be obtained from [linux.oracle.com](https://linux.oracle.com) and via our yum server at [yum.oracle.com](https://yum.oracle.com). 

We cannot accept pull requests for linux-uek via GitHub.

## Additional Resources

* [Oracle Linux documentation](http://docs.oracle.com/en/operating-systems/linux.html)
* [Oracle Linux blog](https://blogs.oracle.com/linux/) | [Oracle Linux kernel blog](https://blogs.oracle.com/linuxkernel)
* [Twitter](https://twitter.com/oraclelinux) 
* [Facebook](https://www.facebook.com/OracleLinux/)
* [YouTube](https://www.youtube.com/user/OracleLinuxChannel/)
