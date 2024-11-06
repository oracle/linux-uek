# Building UEK-next

The following steps can be used to build UEK-next from source code present on Github.

## Ensure that you have Git installed

```
$ sudo dnf install -y git
```

## Clone the repository and checkout to the tag

```
$ git clone https://github.com/oracle/linux-uek.git --depth=1 --branch ueknext/latest --single-branch
$ cd linux-uek
```

## Install the packages required to build the kernel

```
$ sudo dnf build-dep --enablerepo="ol9_codeready_builder" uek-rpm/ol9/kernel-uek.spec
$ sudo dnf install -y perl
```

## Set the gcc version to 13, that we just installed.

```
$ source /opt/rh/gcc-toolset-13/enable
$ gcc --version
gcc (GCC) 13.1.1 20230614 (Red Hat 13.1.1-4)
Copyright (C) 2023 Free Software Foundation, Inc.
This is free software; see the source for copying conditions.  There is NO
warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
```


## Use the correct UEK-next configuration

```
$ cp uek-rpm/ol9/config-$(uname -p) .config
$ make olddefconfig
```

## Build RPMs

At this point there are 2 possibilities for generating the RPMs, it is possible to:

- Create UEK-next specification RPMs, recommended if intending to report any issues

- Create an all-in-one RPM, using the Linux kernel's own mechanism

It should be noted that builds can take quite some time, depending on the build system's configuration.


### Build UEK-next RPMs

```
$ mkdir -p rpmbuild/SOURCES
$ cp uek-rpm/ol9/* rpmbuild/SOURCES/
$ cp uek-rpm/tools/* rpmbuild/SOURCES
$ KERNEL_VERSION=$(make kernelversion)
$ git archive --format=tar --prefix="linux-${KERNEL_VERSION}/" -o "rpmbuild/SOURCES/linux-${KERNEL_VERSION}.tar"  HEAD
$ bzip2 -v "rpmbuild/SOURCES/linux-${KERNEL_VERSION}.tar"
$ rpmbuild --define "_topdir ${PWD}/rpmbuild" -bb uek-rpm/ol9/kernel-uek.spec
```

Further instructions on installing the generated RPMs in `rpmbuild/RPMS` can be found in [INSTALL.md](INSTALL.md)

### Build RPMs based on the Linux kernel mechanism

```
$ make -j$(nproc) binrpm-pkg
Wrote: /home/opc/linux-uek/rpmbuild/RPMS/x86_64/kernel-headers-6.11.0+-1.x86_64.rpm
Wrote: /home/opc/linux-uek/rpmbuild/RPMS/x86_64/kernel-devel-6.11.0+-1.x86_64.rpm
Wrote: /home/opc/linux-uek/rpmbuild/RPMS/x86_64/kernel-6.11.0+-1.x86_64.rpm
Executing(%clean): /bin/sh -e /var/tmp/rpm-tmp.0J6zal
+ umask 022
+ cd /home/opc/linux-uek
+ rm -rf /home/opc/linux-uek/rpmbuild/BUILDROOT/kernel-6.11.0+-1.x86_64
+ RPM_EC=0
++ jobs -p
+ exit 0
```

The generated RPM can be installed from `rpmbuild/RPMS/$(arch -p)` using the path generated,

```
$ sudo dnf install -y /home/opc/linux-uek/rpmbuild/RPMS/x86_64/kernel-6.11.0+-1.x86_64.rpm
$ sudo grubby --set-default /boot/vmlinuz-6.11.0+
The default is /boot/loader/entries/e3b44b41fd25421f99d3ff3416d9d237-6.11.0+.conf with index 3 and kernel /boot/vmlinuz-6.11.0+
$ sudo reboot
```
