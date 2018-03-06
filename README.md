# Oracle Linux: Unbreakable Enterprise Kernel (UEK)

## Introducing UEK

The Unbreakable Enterprise Kernel (UEK) is a Linux kernel built by Oracle and supported via Oracle Linux support. Its focus is performance, stability, and minimal backports by tracking the mainline source code as closely as is practical. UEK is well tested and is used to run Oracle's Engineered Systems, Oracle Cloud Infrastructure, and large enterprise deployments for Oracle customers.

## Current Branches

This repository hosts source code for UEK versions which are in development and in production. 

| UEK Release | Linux Kernel version | Release Status | Target Arch | Target Userspace Distribution(s) |
|--------------------|-----------------------------|----------------------|-----------------|--------------------------------------------|
| [`uek5/master`](https://github.com/oracle/linux-uek/tree/uek5/master) | v4.14 | Development | `x86_64`, `aarch64` | Oracle Linux 7 |

This repository contains the source for the Unbreakable Enterprise Kernel 
including Oracle additions which have not yet been accepted into the mainline 
Linux kernel source tree.

Building from this repository requires additional dependencies which are available here, in addition to standard kernel build tools.
    [libdtrace-ctf](http://oss.oracle.com/git/gitweb.cgi?p=libdtrace-ctf.git;a=summary) and [dtrace-utils](http://oss.oracle.com/git/gitweb.cgi?p=dtrace-utils.git;a=summary)


## Refresh Schedule

This repository will be refreshed weekly as new development versions are available.

## Linux Development at Oracle

Oracle is a long-time contributor to Linux and we have always had a strong emphasis on upstreaming and open-sourcing our changes to the kernel. Keeping our changes open source allows us to integrate with upstream Linux kernels quickly, which also means we have state-of-the-art drivers and filesystems, hardware support, and security fixes from the community...in addition to the work we have contributed ourselves.  [Read more on the Oracle Linux Kernel Blog.](https://blogs.oracle.com/linuxkernel)

Since 2007, Oracle has contributed more than 400,000 lines of code to Linux, and been ranked in the top 15 all-time contributors to Linux through more than 7,500 changesets. If you're using a filesystem other than ext4, chances are it was written at Oracle or contains significant improvements from Oracle: whether it's NFS, where we've been significant contributors for years; btrfs, which was originally written and submitted at Oracle; or xfs, where the upstream kernel maintainer works at Oracle. It's not just OCFS2 and RDS, though those subsystems continue to have their niche use cases. 

Oracle's Linux team is a top ten contributor in each upstream kernel release. Our mission is to improve Linux, which means better performance, better security, and better diagnosability. We also focus on the fundamentals of the OS, improving the scheduler and core memory allocation routines. 

[And, we're hiring](https://www.oracle.com/corporate/careers/index.html)!

## Issues, Pull Requests and Support

Please ask questions, report issues or provide suggestions in the
[Oracle Linux and UEK Preview](https://community.oracle.com/community/server_&_storage_systems/linux/oracle_linux_and_uek_preview)
space on the OTN Developer Community site. We will not accept pull requests via github, but pointers to upstream commits are welcomed.

The UEK source is published here without support. For compiled binaries and a supported
enterprise distribution, Oracle Linux is free to download, distribute and use and can be obtained from http://www.oracle.com/technetwork/server-storage/linux/downloads/index.html.

## Additional Resources

* [Oracle Linux documentation](http://docs.oracle.com/en/operating-systems/linux.html)
* [Oracle Linux blog](https://blogs.oracle.com/linux/)
* [Oracle Linux kernel blog](https://blogs.oracle.com/linuxkernel)
* [Twitter](https://twitter.com/oraclelinux) 
* [Facebook](https://www.facebook.com/OracleLinux/)
* [YouTube](https://www.youtube.com/user/OracleLinuxChannel/)
