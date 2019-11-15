# Oracle Linux: Unbreakable Enterprise Kernel (UEK)

## Introducing UEK

The Unbreakable Enterprise Kernel (UEK) is a Linux kernel built by Oracle and supported via Oracle Linux support. Its focus is performance, stability, and minimal backports by tracking the mainline source code as closely as is practical. UEK is well-tested and used to run Oracle's Engineered Systems, Oracle Cloud Infrastructure, and large enterprise deployments for Oracle customers.

The source for UEK has always been available at [oss.oracle.com](https://oss.oracle.com/git/gitweb.cgi?p=linux-uek.git;a=summary), as a git repository with full git history. By posting the UEK source here on [github.com](https://github.com/oracle/linux-uek/) we hope to increase the visibility for our work and to make it even easier for people to access the source for UEK. We will also use this repository for working with developers at partner companies and in the Linux community.

## Current Branches

This repository hosts source code for UEK versions which are in development and in production. 

| UEK Release and Tag | Linux Kernel version | Release Status | Target Arch | Target Userspace Distribution(s) |
|--------------------|-----------------------------|----------------------|-----------------|--------------------------------------------|
| [`uek5/master`](https://github.com/oracle/linux-uek/tree/uek5/master)<br/>[`v4.14.35-1945`](https://github.com/oracle/linux-uek/tree/v4.14.35-1945) | v4.14 | Production | `x86_64`, `aarch64` | Oracle Linux 7 |
| [`uek5/u2`](https://github.com/oracle/linux-uek/tree/uek5/u2)<br/>[`v4.14.35-1902.8.0.1.sn`](https://github.com/oracle/linux-uek/tree/v4.14.35-1902.8.0.1.sn) | v4.14 | Production | `x86_64`, `aarch64` | Oracle Linux 7 |
| [`uek5/u1`](https://github.com/oracle/linux-uek/tree/uek5/u1)<br/>[`v4.14.35-1844.6.5`](https://github.com/oracle/linux-uek/tree/v4.14.35-1844.6.5) | v4.14 | Production | `x86_64`, `aarch64` | Oracle Linux 7 |
| [`uek5/ga`](https://github.com/oracle/linux-uek/tree/uek5/ga)<br/>[`v4.14.35-1818.5.14`](https://github.com/oracle/linux-uek/tree/v4.14.35-1818.5.14) | v4.14 | Production | `x86_64`, `aarch64` | Oracle Linux 7 |
| [`uek4/qu7`](https://github.com/oracle/linux-uek/tree/uek4/qu7)<br/>[`v4.1.12-124.33.2`](https://github.com/oracle/linux-uek/tree/v4.1.12-124.33.2) | v4.1 | Production | `x86_64`, `SPARC` | Oracle Linux 6, Oracle Linux 7 |
| [`uek3/master`](https://github.com/oracle/linux-uek/tree/uek3/master)<br/>[`v3.8.13-118.40.1`](https://github.com/oracle/linux-uek/tree/v3.8.13-118.40.1) | v3.8 | Production | `x86_64` | Oracle Linux 6, Oracle Linux 7 |
| [`uek2/master`](https://github.com/oracle/linux-uek/tree/uek2/master)<br/>[`v2.6.39-400.315.1`](https://github.com/oracle/linux-uek/tree/v2.6.39-400.315.1) | v3.0 | Production | `x86_64`, `SPARC` | Oracle Linux 5, Oracle Linux 6 |


This repository contains the source for the Unbreakable Enterprise Kernel 
including a small number of Oracle additions which have not yet been accepted into the mainline 
Linux kernel source tree.

Building from this repository requires [libdtrace-ctf](https://github.com/oracle/libdtrace-ctf/) in addition to standard kernel build tools.

## Refresh Schedule

This repository will be refreshed weekly as new development versions are available.

## Linux Development at Oracle

Oracle is a long-time contributor to Linux and we have always had a strong emphasis on upstreaming and open-sourcing our changes to the kernel. Keeping our changes open source allows us to integrate with upstream Linux kernels quickly, which also means we have state-of-the-art drivers and filesystems, hardware support, and security fixes from the community...in addition to the work we have contributed ourselves. [Read more on the Oracle Linux Kernel Blog.](https://blogs.oracle.com/linuxkernel)

Since 2007, Oracle has contributed more than 400,000 lines of code to Linux, and been ranked in the top 15 all-time contributors to Linux with more than 7,500 changesets. For example, Btrfs OCFS2, and RDS were originally written and submitted at Oracle. Also XFS —whose maintainer works at Oracle— and NFS have seen significant contributions.

Oracle's Linux team is a top ten contributor in each upstream kernel release. Our mission is to improve Linux, which means higher performance, better security, and more advanced diagnosability. We also focus on the fundamentals of the OS, improving the scheduler and core memory allocation routines. 

[And, we're hiring](https://www.oracle.com/corporate/careers/index.html)!

## Issues, Pull Requests and Support

Please ask questions, report issues or provide suggestions in the
[Oracle Linux and UEK Preview](https://community.oracle.com/community/server_&_storage_systems/linux/oracle_linux_and_uek_preview)
space in the Oracle Developer Community. We will not accept pull requests via GitHub, but pointers to upstream commits are welcomed.

The UEK source is published here without support. For compiled binaries and a supported
enterprise distribution, Oracle Linux is free to download, distribute and use and can be obtained from http://www.oracle.com/technetwork/server-storage/linux/downloads/index.html.  Individual packages and updates are available on the [Oracle Linux yum server](https://yum.oracle.com/)

SPARC64 is not a supported platform for Oracle Linux.


## Additional Resources

* [Oracle Linux documentation](http://docs.oracle.com/en/operating-systems/linux.html)
* [Oracle Linux blog](https://blogs.oracle.com/linux/) | [Oracle Linux kernel blog](https://blogs.oracle.com/linuxkernel)
* [Twitter](https://twitter.com/oraclelinux) 
* [Facebook](https://www.facebook.com/OracleLinux/)
* [YouTube](https://www.youtube.com/user/OracleLinuxChannel/)


