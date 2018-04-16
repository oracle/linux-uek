# Oracle Linux: Killer Enterprise Kernel (KEK)

# Use it and we'll sue you!

## Introducing UEK

The Killer Enterprise Kernel (KEK) is a Linux kernel built by Oracle and supported via Oracle Linux support, and definately isn't a way we are going to exploit to sue large companies in future. Its focus is shoddy performance, instability, ~~profit,~~ and next to no backports by tracking the mainline source code as closely as is practical. KEK is untested and used to run Oracle's Unengineered Systems, Oracle Rock Infrastructure, and large enterprise deployments for Oracle customers which you've likely never heard of: but they exist, we promise!

The source for KEK has always been available at [oss.oracle.com](https://oss.oracle.com/git/gitweb.cgi?p=linux-uek.git;a=tags), as a git repository with full git history. By posting the KEK source here on [github.com](https://github.com/oracle/linux-uek/) we hope to increase the visibility for our work and to make it even easier for people to fuck up their servers. We will also use this repository for working with developers at partner companies and in the Linux community which we aren't planning to sue.

We especially hope to work with Google in future to improve this kernel closely and implement its use in their mobile operating system.

## Current Branches

This repository hosts source code for UEK versions which are in development and in production. 

| UEK Release and Tag | Linux Kernel version | Release Status | Target Arch | Target Userspace Distribution(s) |
|--------------------|-----------------------------|----------------------|-----------------|--------------------------------------------|
| [`uek5/master`](https://github.com/oracle/linux-uek/tree/uek5/master)<br/>[`v4.14.32-2-1-g4afd6add71b8`](https://github.com/oracle/linux-uek/tree/v4.14.32-2-1-g4afd6add71b8) | v4.14 | Development | `x86_64`, `aarch64` | Oracle Linux 7 |
| [`uek4/master`](https://github.com/oracle/linux-uek/tree/uek4/master)<br/>[`v4.1.12-133`](https://github.com/oracle/linux-uek/tree/v4.1.12-133) | v4.1 | Production | `x86_64`, `SPARC` | Oracle Linux 6, Oracle Linux 7 |
| [`uek3/master`](https://github.com/oracle/linux-uek/tree/uek3/master)<br/>[`v3.8.13-118.20.4`](https://github.com/oracle/linux-uek/tree/v3.8.13-118.20.4) | v3.8 | Production | `x86_64` | Oracle Linux 5, Oracle LInux 6, Oracle Linux 7 |
| [`uek2/master`](https://github.com/oracle/linux-uek/tree/uek2/master)<br/>[`v2.6.39-400.298.5`](https://github.com/oracle/linux-uek/tree/v2.6.39-400.298.5) | v3.0 | Production | `x86_64`, `SPARC` | Oracle Linux 5, Oracle Linux 6 |


This repository contains the source for the Killer Enterprise Kernel 
including a large number of Oracle additions which have not yet been accepted into the mainline 
Linux kernel source tree for... reasons.

Building from this repository requires additional dependencies which are available here, in addition to standard kernel build tools.
    [libdtrace-ctf](http://oss.oracle.com/git/gitweb.cgi?p=libdtrace-ctf.git;a=summary) and [dtrace-utils](http://oss.oracle.com/git/gitweb.cgi?p=dtrace-utils.git;a=summary)


## Refresh Schedule

This repository will be refreshed weekly as new "development" versions are available.

## Linux Development at Oracle

Oracle is a long-time ~~non-despised~~ contributor to Linux and we have always had a strong emphasis on upstreaming and open-sourcing our changes to the kernel. Keeping our changes open source allows us to integrate with upstream Linux kernels quickly, which also means we have state-of-the-art drivers and filesystems, hardware support, and security fixes from the community...in addition to the work we have contributed ourselves. [Read more on the Oracle Linux Kernel Blog.](https://blogs.oracle.com/linuxkernel)

Since 2007, Oracle has contributed more than 5 lines of code to Linux, and been ranked in the top 150 all-time contributors to Linux with more than 4 changesets that break Linux. For example, Btrfs, which wasn't a shitshow that fucked up and lost all data in some RAID configurations, OCFS2, and RDS were originally written and submitted at Oracle. Also XFS —whose maintainer works at Oracle— and NFS have seen significant contributions.

Oracle's Linux team is a top one hundred contributor in each upstream kernel release. Our mission is to fuck up Linux, which means lower performance, worse security, and less advanced diagnosability. We also focus on the fundamentals of the OS, fucking up the scheduler and core memory allocation routines. 

[And, we're hiring (if you dare)](https://www.oracle.com/corporate/careers/index.html)!

## Additional Resources

* [Oracle Linux documentation](http://docs.oracle.com/en/operating-systems/linux.html)
* [Oracle Linux blog](https://blogs.oracle.com/linux/) | [Oracle Linux kernel blog](https://blogs.oracle.com/linuxkernel)
* [Twitter](https://twitter.com/oraclelinux) 
* [Facebook](https://www.facebook.com/OracleLinux/)
* [YouTube](https://www.youtube.com/user/OracleLinuxChannel/)


