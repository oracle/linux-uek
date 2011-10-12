Summary: The Linux kernel


# For a stable, released kernel, released_kernel should be 1. For rawhide
# and/or a kernel built from an rc or git snapshot, released_kernel should
# be 0.
%define released_kernel 1

# Versions of various parts

# Polite request for people who spin their own kernel rpms:
# please modify the "buildid" define in a way that identifies
# that the kernel isn't the stock distribution kernel, for example,
# by setting the define to ".local" or ".bz123456"
#
# % define buildid .local

%define rhel 1
%if %{rhel}
%define distro_build 100
%define signmodules 1
%else

# fedora_build defines which build revision of this kernel version we're
# building. Rather than incrementing forever, as with the prior versioning
# setup, we set fedora_cvs_origin to the current cvs revision s/1.// of the
# kernel spec when the kernel is rebased, so fedora_build automatically
# works out to the offset from the rebase, so it doesn't get too ginormous.
#
# If you're building on a branch, the RCS revision will be something like
# 1.1205.1.1.  In this case we drop the initial 1, subtract fedora_cvs_origin
# from the second number, and then append the rest of the RCS string as is.
# Don't stare at the awk too long, you'll go blind.
%define fedora_cvs_origin   1462
%define fedora_cvs_revision() %2
%global fedora_build %(echo %{fedora_cvs_origin}.%{fedora_cvs_revision $Revision: 1.1504 $} | awk -F . '{ OFS = "."; ORS = ""; print $3 - $1 ; i = 4 ; OFS = ""; while (i <= NF) { print ".", $i ; i++} }')
%define distro_build %{fedora_build}
%define signmodules 0
%endif

# base_sublevel is the kernel version we're starting with and patching
# on top of -- for example, 2.6.22-rc7-git1 starts with a 2.6.21 base,
# which yields a base_sublevel of 21.
%define base_sublevel 39

## If this is a released kernel ##
%if 0%{?released_kernel}

# Do we have a -stable update to apply?
%define stable_update 0
# Is it a -stable RC?
%define stable_rc 0
# Set rpm version accordingly
%if 0%{?stable_update}
%define stablerev .%{stable_update}
%define stable_base %{stable_update}
%if 0%{?stable_rc}
# stable RCs are incremental patches, so we need the previous stable patch
%define stable_base %(echo $((%{stable_update} - 1)))
%endif
%endif
%define rpmversion 2.6.%{base_sublevel}%{?stablerev}

## The not-released-kernel case ##
%else
# The next upstream release sublevel (base_sublevel+1)
%define upstream_sublevel %(echo $((%{base_sublevel} + 1)))
# The rc snapshot level
%define rcrev 0
# The git snapshot level
%define gitrev 0
# Set rpm version accordingly
%define rpmversion 2.6.%{upstream_sublevel}
%endif
# Nb: The above rcrev and gitrev values automagically define Patch00 and Patch01 below.

# What parts do we want to build?  We must build at least one kernel.
# These are the kernels that are built IF the architecture allows it.
# All should default to 1 (enabled) and be flipped to 0 (disabled)
# by later arch-specific checks.

# The following build options are enabled by default.
# Use either --without <opt> in your rpmbuild command or force values
# to 0 in here to disable them.
#
# standard kernel
%define with_up        1
# kernel-smp (only valid for ppc 32-bit, sparc64)
%define with_smp       1
# kernel-kdump
%define with_kdump     0
# kernel-debug
%define with_debug     1
%define with_paravirt  1
%define with_paravirt_debug  1
# kernel-doc
%define with_doc       1
# kernel-headers
%define with_headers   1
# kernel-firmware
%define with_firmware  0
# kernel-debuginfo
%define with_debuginfo %{?_without_debuginfo: 0} %{?!_without_debuginfo: 1}
# kernel-bootwrapper (for creating zImages from kernel + initrd)
%define with_bootwrapper %{?_without_bootwrapper: 0} %{?!_without_bootwrapper: 1}
# Want to build a the vsdo directories installed
%define with_vdso_install %{?_without_vdso_install: 0} %{?!_without_vdso_install: 1}
# Control whether we perform a compat. check against published ABI.
%define with_kabichk	0

# Build the kernel-doc package, but don't fail the build if it botches.
# Here "true" means "continue" and "false" means "fail the build".
%if 0%{?released_kernel}
%define doc_build_fail false
%else
%define doc_build_fail true
%endif

# Additional options for user-friendly one-off kernel building:
#
# Only build the base kernel (--with baseonly):
%define with_baseonly  %{?_with_baseonly:     1} %{?!_with_baseonly:     0}
# Only build the smp kernel (--with smponly):
%define with_smponly   %{?_with_smponly:      1} %{?!_with_smponly:      0}

# should we do C=1 builds with sparse
%define with_sparse	%{?_with_sparse:      1} %{?!_with_sparse:      0}

# Set debugbuildsenabled to 1 for production (build separate debug kernels)
#  and 0 for rawhide (all kernels are debug kernels).
# See also 'make debug' and 'make release'.
%define debugbuildsenabled 1

# Want to build a vanilla kernel build without any non-upstream patches?
# (well, almost none, we need nonintconfig for build purposes). Default to 0 (off).
%define with_vanilla %{?_with_vanilla: 1} %{?!_with_vanilla: 0}

# pkg_release is what we'll fill in for the rpm Release: field
%if 0%{?released_kernel}

%if 0%{?stable_rc}
%define stable_rctag .rc%{stable_rc}
%endif
%define pkg_release %{distro_build}%{?stable_rctag}%{?dist}%{?buildid}

%else

# non-released_kernel
%if 0%{?rcrev}
%define rctag .rc%rcrev
%else
%define rctag .rc0
%endif
%if 0%{?gitrev}
%define gittag .git%gitrev
%else
%define gittag .git0
%endif
%define pkg_release 0.%{distro_build}%{?rctag}%{?gittag}%{?dist}%{?buildid}

%endif

# The kernel tarball/base version
%define kversion 2.6.%{base_sublevel}

%define make_target bzImage

%define hdrarch %_target_cpu
%define asmarch %_target_cpu

%if 0%{!?nopatches:1}
%define nopatches 0
%endif

%if %{with_vanilla}
%define nopatches 1
%endif

%if %{nopatches}
%define with_bootwrapper 0
%define variant -vanilla
%else
%define variant_fedora -fedora
%endif

%define using_upstream_branch 0
%if 0%{?upstream_branch:1}
%define stable_update 0
%define using_upstream_branch 1
%define variant -%{upstream_branch}%{?variant_fedora}
%define pkg_release 0.%{distro_build}%{upstream_branch_tag}%{?dist}%{?buildid}
%endif

%if %{rhel}
%define pkg_release %{distro_build}.0.14%{?dist}uek%{?buildid}
%endif
%define KVERREL %{rpmversion}-%{pkg_release}

%if !%{debugbuildsenabled}
%define with_debug 0
%endif

%if !%{with_debuginfo}
%define _enable_debug_packages 0
%endif
%define debuginfodir /usr/lib/debug

# We only build -PAE for 686 as of Fedora 11.
%ifarch i686
%define with_up 1
%define with_pae 0
%else
%define with_pae 0
%endif

# if requested, only build base kernel
%if %{with_baseonly}
%define with_smp 0
%define with_kdump 0
%define with_debug 0
%endif

# if requested, only build smp kernel
%if %{with_smponly}
%define with_up 0
%define with_kdump 0
%define with_debug 0
%endif

%define all_x86 i386 i686

%if %{with_vdso_install}
# These arches install vdso/ directories.
%define vdso_arches %{all_x86} x86_64 ppc ppc64
%endif

# Overrides for generic default options

# only ppc and sparc64 need separate smp kernels
%ifnarch ppc sparc64 alphaev56
%define with_smp 0
%endif

# only build kernel-kdump on ppc64
# (no relocatable kernel support upstream yet)
#FIXME: Temporarily disabled to speed up builds.
#ifnarch ppc64
%define with_kdump 0
#endif

# don't do debug builds on anything but i686 and x86_64
%ifnarch i686 x86_64
%define with_debug 0
%endif

# only package docs noarch
%ifnarch noarch
%define with_doc 0
%endif

# no need to build headers again for these arches,
# they can just use i586 and ppc64 headers
%ifarch ppc64iseries
%define with_headers 0
%endif

# don't build noarch kernels or headers (duh)
%ifarch noarch
%define with_up 0
%define with_headers 0
%define with_paravirt 0
%define with_paravirt_debug 0
%define all_arch_configs kernel-%{version}-*.config
%define with_firmware  %{?_without_firmware:  0} %{?!_without_firmware:  1}
%endif

# bootwrapper is only on ppc
%ifnarch ppc ppc64
%define with_bootwrapper 0
%endif

# sparse blows up on ppc64 alpha and sparc64
%ifarch ppc64 ppc alpha sparc64
%define with_sparse 0
%endif

# Per-arch tweaks

%ifarch %{all_x86}
%define asmarch x86
%define hdrarch i386
%define all_arch_configs kernel-%{version}-i?86*.config
%define image_install_path boot
%define kernel_image arch/x86/boot/bzImage
%endif

%ifarch x86_64
%define asmarch x86
%define all_arch_configs kernel-%{version}-x86_64*.config
%define image_install_path boot
%define kernel_image arch/x86/boot/bzImage
%endif

%ifarch ppc64
%define asmarch powerpc
%define hdrarch powerpc
%define all_arch_configs kernel-%{version}-ppc64*.config
%define image_install_path boot
%define make_target vmlinux
%define kernel_image vmlinux
%define kernel_image_elf 1
%endif

%ifarch s390x
%define asmarch s390
%define hdrarch s390
%define all_arch_configs kernel-%{version}-s390x.config
%define image_install_path boot
%define make_target image
%define kernel_image arch/s390/boot/image
%endif

%ifarch sparc
# We only build sparc headers since we dont support sparc32 hardware
%endif

%ifarch sparc64
%define asmarch sparc
%define all_arch_configs kernel-%{version}-sparc64*.config
%define make_target image
%define kernel_image arch/sparc/boot/image
%define image_install_path boot
%endif

%ifarch ppc
%define asmarch powerpc
%define hdrarch powerpc
%define all_arch_configs kernel-%{version}-ppc{-,.}*config
%define image_install_path boot
%define make_target vmlinux
%define kernel_image vmlinux
%define kernel_image_elf 1
%endif

%ifarch ia64
%define all_arch_configs kernel-%{version}-ia64*.config
%define image_install_path boot/efi/EFI/redhat
%define make_target compressed
%define kernel_image vmlinux.gz
%endif

%ifarch alpha alphaev56
%define all_arch_configs kernel-%{version}-alpha*.config
%define image_install_path boot
%define make_target vmlinux
%define kernel_image vmlinux
%endif

%ifarch %{arm}
%define all_arch_configs kernel-%{version}-arm*.config
%define image_install_path boot
%define hdrarch arm
%define make_target vmlinux
%define kernel_image vmlinux
%endif

%if %{nopatches}
# XXX temporary until last vdso patches are upstream
%define vdso_arches ppc ppc64
%endif

%define oldconfig_target oldnoconfig

# To temporarily exclude an architecture from being built, add it to
# %nobuildarches. Do _NOT_ use the ExclusiveArch: line, because if we
# don't build kernel-headers then the new build system will no longer let
# us use the previous build of that package -- it'll just be completely AWOL.
# Which is a BadThing(tm).

# We don't build a kernel on i386; we only do kernel-headers there,
# and we no longer build for 31bit S390. Same for 32bit sparc and arm.
##%define nobuildarches i386 s390 sparc %{arm}
%define nobuildarches s390 sparc %{arm}

%ifarch %nobuildarches
%define with_up 0
%define with_smp 0
%define with_pae 0
%define with_paravirt 0
%define with_paravirt_debug 0
%define with_kdump 0
%define with_debuginfo 0
%define _enable_debug_packages 0
%define with_paravirt 0
%define with_paravirt_debug 0
%endif

%define with_pae_debug 0
%if %{with_pae}
%define with_pae_debug %{with_debug}
%endif

#
# Three sets of minimum package version requirements in the form of Conflicts:
# to versions below the minimum
#

#
# First the general kernel 2.6 required versions as per
# Documentation/Changes
#
%define kernel_dot_org_conflicts  ppp < 2.4.3-3, isdn4k-utils < 3.2-32, nfs-utils < 1.0.7-12, e2fsprogs < 1.37-4, util-linux < 2.12, jfsutils < 1.1.7-2, reiserfs-utils < 3.6.19-2, xfsprogs < 2.6.13-4, procps < 3.2.5-6.3, oprofile < 0.9.1-2

#
# Then a series of requirements that are distribution specific, either
# because we add patches for something, or the older versions have
# problems with the newer kernel or lack certain things that make
# integration in the distro harder than needed.
#
##%define package_conflicts initscripts < 7.23, udev < 063-6, iptables < 1.3.2-1, ipw2200-firmware < 2.4, iwl4965-firmware < 228.57.2, selinux-policy-targeted < 1.25.3-14, squashfs-tools < 4.0, wireless-tools < 29-3
%define package_conflicts initscripts < 7.23, udev < 063-6, iptables < 1.3.2-1, ipw2200-firmware < 2.4, selinux-policy-targeted < 1.25.3-14

#
# The ld.so.conf.d file we install uses syntax older ldconfig's don't grok.
#
%define kernel_xen_conflicts glibc < 2.3.5-1, xen < 3.0.1

# upto and including kernel 2.4.9 rpms, the 4Gb+ kernel was called kernel-enterprise
# now that the smp kernel offers this capability, obsolete the old kernel
%define kernel_smp_obsoletes kernel-enterprise < 2.4.10
%define kernel_PAE_obsoletes kernel-smp < 2.6.17
%define kernel_PAE_provides kernel-xen = %{rpmversion}-%{pkg_release}

%ifarch x86_64
%define kernel_provides kernel%{?variant}-xen = %{rpmversion}-%{pkg_release}
%endif

# We moved the drm include files into kernel-headers, make sure there's
# a recent enough libdrm-devel on the system that doesn't have those.
%define kernel_headers_conflicts libdrm-devel < 2.4.0-0.15

#
# Packages that need to be installed before the kernel is, because the %post
# scripts use them.
#
##%define kernel_prereq  fileutils, module-init-tools, initscripts >= 8.11.1-1, mkinitrd >= 6.0.61-1, kernel-firmware >= %{rpmversion}-%{pkg_release}, /sbin/new-kernel-pkg
%define kernel_prereq  fileutils, module-init-tools, initscripts >= 8.11.1-1, kernel-firmware >= %{rpmversion}-%{pkg_release}, /sbin/new-kernel-pkg, mkinitrd >= 5.1.19.6-61.0.2, kexec-tools >= 1.102pre-96.1.1.el5_5.2, device-mapper-multipath >= 0.4.9-23.0.1.el5, ql2xxx-firmware, oraclelinux-release

#
# This macro does requires, provides, conflicts, obsoletes for a kernel package.
#	%%kernel_reqprovconf <subpackage>
# It uses any kernel_<subpackage>_conflicts and kernel_<subpackage>_obsoletes
# macros defined above.
#
%define kernel_reqprovconf \
Provides: kernel%{?variant} = %{rpmversion}-%{pkg_release}\
Provides: kernel%{?variant}-%{_target_cpu} = %{rpmversion}-%{pkg_release}%{?1:.%{1}}\
Provides: kernel%{?variant}-drm = 4.3.0\
Provides: kernel%{?variant}-drm-nouveau = 12\
Provides: kernel%{?variant}-modeset = 1\
Provides: kernel%{?variant}-uname-r = %{KVERREL}%{?1:.%{1}}\
Provides: oracleasm = 2.0.5\
Provides: perf = %{KVERREL}%{?1:.%{1}}\
Provides: libperf.a = %{KVERREL}%{?1:.%{1}}\
Requires(pre): %{kernel_prereq}\
Conflicts: %{kernel_dot_org_conflicts}\
Conflicts: %{package_conflicts}\
%{expand:%%{?kernel%{?1:_%{1}}_conflicts:Conflicts: %%{kernel%{?1:_%{1}}_conflicts}}}\
#%{expand:%%{?kernel%{?1:_%{1}}_obsoletes:Obsoletes: %%{kernel%{?1:_%{1}}_obsoletes}}}\
%{expand:%%{?kernel%{?1:_%{1}}_provides:Provides: %%{kernel%{?1:_%{1}}_provides}}}\
# We can't let RPM do the dependencies automatic because it'll then pick up\
# a correct but undesirable perl dependency from the module headers which\
# isn't required for the kernel proper to function\
AutoReq: no\
AutoProv: yes\
%{nil}

%define variant -uek
Name: kernel%{?variant}
Group: System Environment/Kernel
License: GPLv2
URL: http://www.kernel.org/
Version: %{rpmversion}
Release: %{pkg_release}
# DO NOT CHANGE THE 'ExclusiveArch' LINE TO TEMPORARILY EXCLUDE AN ARCHITECTURE BUILD.
# SET %%nobuildarches (ABOVE) INSTEAD
ExclusiveArch: noarch %{all_x86} x86_64 ppc ppc64 ia64 sparc sparc64 s390x alpha alphaev56 %{arm}
ExclusiveOS: Linux

%kernel_reqprovconf
%ifarch x86_64
Obsoletes: kernel-smp
%endif


#
# List the packages used during the kernel build
#
BuildRequires: module-init-tools, patch >= 2.5.4, bash >= 2.03, sh-utils, tar
BuildRequires: bzip2, findutils, gzip, m4, perl, make >= 3.78, diffutils, gawk
BuildRequires: gcc >= 3.4.2, binutils >= 2.12
BuildRequires: net-tools
BuildRequires: elfutils-libelf-devel
%if %{with_doc}
BuildRequires: xmlto
%endif
%if %{with_sparse}
BuildRequires: sparse >= 0.4.1
%endif
%if %{signmodules}
BuildRequires: gnupg
%endif
BuildConflicts: rhbuildsys(DiskFree) < 500Mb

Source0: ftp://ftp.kernel.org/pub/linux/kernel/v2.6/linux-%{kversion}.tar.bz2

Source11: genkey
Source14: find-provides
Source15: merge.pl
Source16: perf
Source17: kabitool
Source18: check-kabi
Source19: extrakeys.pub

Source20: Makefile.config
Source21: config-debug
Source22: config-nodebug
Source23: config-generic
Source24: config-rhel-generic
Source25: Module.kabi_i686
Source28: Module.kabi_x86_64
Source29: config-generic-paravirt

Source30: config-x86-generic
##Source31: config-i586
Source32: config-i686

Source40: config-x86_64-generic

Source50: config-powerpc-generic
Source51: config-powerpc32-generic
Source52: config-powerpc32-smp
Source53: config-powerpc64
##Source54: config-powerpc64-kdump

Source60: config-ia64-generic

Source70: config-s390x

Source90: config-sparc64-generic
##Source91: config-sparc64-smp

Source100: config-arm

Source101: kabi_whitelist_i686
Source102: kabi_whitelist_x86_64

# Here should be only the patches up to the upstream canonical Linus tree.

# For a stable release kernel
%if 0%{?stable_update}
%if 0%{?stable_base}
%define    stable_patch_00  patch-2.6.%{base_sublevel}.%{stable_base}.bz2
Patch00: %{stable_patch_00}
%endif
%if 0%{?stable_rc}
%define    stable_patch_01  patch-2.6.%{base_sublevel}.%{stable_update}-rc%{stable_rc}.bz2
Patch01: %{stable_patch_01}
%endif

# non-released_kernel case
# These are automagically defined by the rcrev and gitrev values set up
# near the top of this spec file.
%else
%if 0%{?rcrev}
Patch00: patch-2.6.%{upstream_sublevel}-rc%{rcrev}.bz2
%if 0%{?gitrev}
Patch01: patch-2.6.%{upstream_sublevel}-rc%{rcrev}-git%{gitrev}.bz2
%endif
%else
# pre-{base_sublevel+1}-rc1 case
%if 0%{?gitrev}
Patch00: patch-2.6.%{base_sublevel}-git%{gitrev}.bz2
%endif
%endif
%endif

%if %{using_upstream_branch}
### BRANCH PATCH ###
%endif

%if !%{nopatches}
# revert upstream patches we get via other methods
%endif

BuildRoot: %{_tmppath}/kernel-%{KVERREL}-root

# Override find_provides to use a script that provides "kernel(symbol) = hash".
# Pass path of the RPM temp dir containing kabideps to find-provides script.
%global _use_internal_dependency_generator 0
%define __find_provides %_sourcedir/find-provides %{_tmppath}
%define __find_requires /usr/lib/rpm/redhat/find-requires kernel


%description
The kernel package contains the Linux kernel (vmlinuz), the core of any
Linux operating system.  The kernel handles the basic functions
of the operating system: memory allocation, process allocation, device
input and output, etc.


%package doc
Summary: Various documentation bits found in the kernel source
Group: Documentation
%description doc
This package contains documentation files from the kernel
source. Various bits of information about the Linux kernel and the
device drivers shipped with it are documented in these files.

You'll want to install this package if you need a reference to the
options that can be passed to Linux kernel modules at load time.


%package headers
Summary: Header files for the Linux kernel for use by glibc
Group: Development/System
Obsoletes: glibc-kernheaders
Provides: glibc-kernheaders = 3.0-46
Obsoletes: kernel-headers
Provides: kernel-headers
%description headers
Kernel-headers includes the C header files that specify the interface
between the Linux kernel and userspace libraries and programs.  The
header files define structures and constants that are needed for
building most standard programs and are also needed for rebuilding the
glibc package.

%package firmware
Summary: Firmware files used by the Linux kernel
Group: Development/System
Obsoletes: kernel-firmware
Obsoletes: kernel-uek-firmware < 2.6.39
# This is... complicated.
# Look at the WHENCE file.
License: GPL+ and GPLv2+ and MIT and Redistributable, no modification permitted
%if "x%{?variant}" != "x"
Provides: kernel-firmware = %{rpmversion}-%{pkg_release}
%endif
%description firmware
Kernel-firmware includes firmware files required for some devices to
operate.

%package bootwrapper
Summary: Boot wrapper files for generating combined kernel + initrd images
Group: Development/System
Requires: gzip
%description bootwrapper
Kernel-bootwrapper contains the wrapper code which makes bootable "zImage"
files combining both kernel and initial ramdisk.

%package debuginfo-common
Summary: Kernel source files used by %{name}-debuginfo packages
Group: Development/Debug
Provides: %{name}-debuginfo-common-%{_target_cpu} = %{version}-%{release}
%description debuginfo-common
This package is required by %{name}-debuginfo subpackages.
It provides the kernel source files common to all builds.


#
# This macro creates a kernel-<subpackage>-debuginfo package.
#	%%kernel_debuginfo_package <subpackage>
#
%define kernel_debuginfo_package() \
%package %{?1:%{1}-}debuginfo\
Summary: Debug information for package %{name}%{?1:-%{1}}\
Group: Development/Debug\
Requires: %{name}-debuginfo-common-%{_target_cpu} = %{version}-%{release}\
Provides: %{name}%{?1:-%{1}}-debuginfo-%{_target_cpu} = %{version}-%{release}\
AutoReqProv: no\
%description -n %{name}%{?1:-%{1}}-debuginfo\
This package provides debug information for package %{name}%{?1:-%{1}}.\
This is required to use SystemTap with %{name}%{?1:-%{1}}-%{KVERREL}.\
%{expand:%%global debuginfo_args %{?debuginfo_args} -p '/.*/%%{KVERREL}%{?1:\.%{1}}/.*|/.*%%{KVERREL}%{?1:\.%{1}}(\.debug)?' -o debuginfo%{?1}.list}\
%{nil}

#
# This macro creates a kernel-<subpackage>-devel package.
#	%%kernel_devel_package <subpackage> <pretty-name>
#
%define kernel_devel_package() \
%package %{?1:%{1}-}devel\
Summary: Development package for building kernel modules to match the %{?2:%{2} }kernel\
Group: System Environment/Kernel\
Provides: kernel%{?variant}%{?1:-%{1}}-devel-%{_target_cpu} = %{version}-%{release}\
Provides: kernel%{?variant}-xen-devel = %{version}-%{release}%{?1:.%{1}}\
Provides: kernel%{?variant}-devel-%{_target_cpu} = %{version}-%{release}%{?1:.%{1}}\
Provides: kernel%{?variant}-devel = %{version}-%{release}%{?1:.%{1}}\
Provides: kernel%{?variant}-devel-uname-r = %{KVERREL}%{?1:.%{1}}\
AutoReqProv: no\
Requires(pre): /usr/bin/find\
%description -n kernel%{?variant}%{?1:-%{1}}-devel\
This package provides kernel headers and makefiles sufficient to build modules\
against the %{?2:%{2} }kernel package.\
%{nil}

#
# This macro creates a kernel-<subpackage> and its -devel and -debuginfo too.
#	%%define variant_summary The Linux kernel compiled for <configuration>
#	%%kernel_variant_package [-n <pretty-name>] <subpackage>
#
%define kernel_variant_package(n:) \
%package %1\
Summary: %{variant_summary}\
Group: System Environment/Kernel\
%kernel_reqprovconf\
%{expand:%%kernel_devel_package %1 %{!?-n:%1}%{?-n:%{-n*}}}\
%{expand:%%kernel_debuginfo_package %1}\
%{nil}


# First the auxiliary packages of the main kernel package.
%kernel_devel_package
%kernel_debuginfo_package


# Now, each variant package.

%define variant_summary The Linux kernel compiled for SMP machines
%kernel_variant_package -n SMP smp
%description smp
This package includes a SMP version of the Linux kernel. It is
required only on machines with two or more CPUs as well as machines with
hyperthreading technology.

Install the kernel-smp package if your machine uses two or more CPUs.


%define variant_summary The Linux kernel compiled for PAE capable machines
%kernel_variant_package PAE
%description PAE
This package includes a version of the Linux kernel with support for up to
64GB of high memory. It requires a CPU with Physical Address Extensions (PAE).
The non-PAE kernel can only address up to 4GB of memory.
Install the kernel-PAE package if your machine has more than 4GB of memory.


%define variant_summary The Linux kernel compiled with extra debugging enabled for PAE capable machines
%kernel_variant_package PAEdebug
Obsoletes: kernel-PAE-debug
%description PAEdebug
This package includes a version of the Linux kernel with support for up to
64GB of high memory. It requires a CPU with Physical Address Extensions (PAE).
The non-PAE kernel can only address up to 4GB of memory.
Install the kernel-PAE package if your machine has more than 4GB of memory.

This variant of the kernel has numerous debugging options enabled.
It should only be installed when trying to gather additional information
on kernel bugs, as some of these options impact performance noticably.


%define variant_summary The Linux kernel compiled with extra debugging enabled
%kernel_variant_package debug
%description debug
The kernel package contains the Linux kernel (vmlinuz), the core of any
Linux operating system.  The kernel handles the basic functions
of the operating system:  memory allocation, process allocation, device
input and output, etc.

This variant of the kernel has numerous debugging options enabled.
It should only be installed when trying to gather additional information
on kernel bugs, as some of these options impact performance noticably.


%define variant_summary A minimal Linux kernel compiled for crash dumps
%kernel_variant_package kdump
%description kdump
This package includes a kdump version of the Linux kernel. It is
required only on machines which will use the kexec-based kernel crash dump
mechanism.

%define variant_summary Paravitrualized kernel
%kernel_variant_package paravirt
%description paravirt
This package includes a paravirt version of the Linux kernel.
CONFIG_PARAVIRT_SPINLOCKS=y

%define variant_summary Paravitrualized debug kernel
%kernel_variant_package paravirt_debug
%description paravirt_debug
This package includes a paravirt version of the Linux kernel with debug info.
CONFIG_PARAVIRT_SPINLOCKS=y


%prep
# do a few sanity-checks for --with *only builds
%if %{with_baseonly}
%if !%{with_up}%{with_pae}
echo "Cannot build --with baseonly, up build is disabled"
exit 1
%endif
%endif

%if %{with_smponly}
%if !%{with_smp}
echo "Cannot build --with smponly, smp build is disabled"
exit 1
%endif
%endif

patch_command='patch -p1 -F1 -s'
ApplyPatch()
{
  local patch=$1
  shift
  if [ ! -f $RPM_SOURCE_DIR/$patch ]; then
    exit 1;
  fi
  if ! egrep "^Patch[0-9]+: $patch\$" %{_specdir}/%{name}.spec ; then
    [ "${patch:0:10}" != "patch-2.6." ] && echo "Patch $patch not listed in specfile" && exit 1;
  fi
  case "$patch" in
  *.bz2) bunzip2 < "$RPM_SOURCE_DIR/$patch" | $patch_command ${1+"$@"} ;;
  *.gz) gunzip < "$RPM_SOURCE_DIR/$patch" | $patch_command ${1+"$@"} ;;
  *) $patch_command ${1+"$@"} < "$RPM_SOURCE_DIR/$patch" ;;
  esac
}

test_config_file()
{
  TestConfig=$1
  Arch=`head -1 .config | cut -b 3-`
  if [ `make ARCH=$Arch listnewconfig 2>/dev/null | grep -c CONFIG`  -ne 0 ]; then 
	echo "Following config options are unconfigured"
	make ARCH=$Arch listnewconfig 2> /dev/null
	echo "WARNING: Kernel version and config file missmatch"
	echo "WARNING: This options will be unset by default in config file"
  fi
}

# First we unpack the kernel tarball.
# If this isn't the first make prep, we use links to the existing clean tarball
# which speeds things up quite a bit.

# Update to latest upstream.
%if 0%{?released_kernel}
%define vanillaversion 2.6.%{base_sublevel}
# non-released_kernel case
%else
%if 0%{?rcrev}
%define vanillaversion 2.6.%{upstream_sublevel}-rc%{rcrev}
%if 0%{?gitrev}
%define vanillaversion 2.6.%{upstream_sublevel}-rc%{rcrev}-git%{gitrev}
%endif
%else
# pre-{base_sublevel+1}-rc1 case
%if 0%{?gitrev}
%define vanillaversion 2.6.%{base_sublevel}-git%{gitrev}
%endif
%endif
%endif

# We can share hardlinked source trees by putting a list of
# directory names of the CVS checkouts that we want to share
# with in .shared-srctree. (Full pathnames are required.)
[ -f .shared-srctree ] && sharedirs=$(cat .shared-srctree)

if [ ! -d kernel-%{kversion}/vanilla-%{vanillaversion} ]; then

  if [ -d kernel-%{kversion}/vanilla-%{kversion} ]; then

    cd kernel-%{kversion}

    # Any vanilla-* directories other than the base one are stale.
    for dir in vanilla-*; do
      [ "$dir" = vanilla-%{kversion} ] || rm -rf $dir &
    done

  else

    # Ok, first time we do a make prep.
    rm -f pax_global_header
    for sharedir in $sharedirs ; do
      if [[ ! -z $sharedir  &&  -d $sharedir/kernel-%{kversion}/vanilla-%{kversion} ]] ; then
        break
      fi
    done
    if [[ ! -z $sharedir  &&  -d $sharedir/kernel-%{kversion}/vanilla-%{kversion} ]] ; then
%setup -q -n kernel-%{kversion} -c -T
      cp -rl $sharedir/kernel-%{kversion}/vanilla-%{kversion} .
    else
%setup -q -n kernel-%{kversion} -c
      mv linux-%{kversion} vanilla-%{kversion}
    fi

  fi

%if "%{kversion}" != "%{vanillaversion}"

  for sharedir in $sharedirs ; do
    if [[ ! -z $sharedir  &&  -d $sharedir/kernel-%{kversion}/vanilla-%{vanillaversion} ]] ; then
      break
    fi
  done
  if [[ ! -z $sharedir  &&  -d $sharedir/kernel-%{kversion}/vanilla-%{vanillaversion} ]] ; then

    cp -rl $sharedir/kernel-%{kversion}/vanilla-%{vanillaversion} .

  else

    cp -rl vanilla-%{kversion} vanilla-%{vanillaversion}
    cd vanilla-%{vanillaversion}

# Update vanilla to the latest upstream.
# (non-released_kernel case only)
%if 0%{?rcrev}
    ApplyPatch patch-2.6.%{upstream_sublevel}-rc%{rcrev}.bz2
%if 0%{?gitrev}
    ApplyPatch patch-2.6.%{upstream_sublevel}-rc%{rcrev}-git%{gitrev}.bz2
%endif
%else
# pre-{base_sublevel+1}-rc1 case
%if 0%{?gitrev}
    ApplyPatch patch-2.6.%{base_sublevel}-git%{gitrev}.bz2
%endif
%endif

    cd ..

  fi

%endif

else
  # We already have a vanilla dir.
  cd kernel-%{kversion}
fi

if [ -d linux-%{kversion}.%{_target_cpu} ]; then
  # Just in case we ctrl-c'd a prep already
  rm -rf deleteme.%{_target_cpu}
  # Move away the stale away, and delete in background.
  mv linux-%{kversion}.%{_target_cpu} deleteme.%{_target_cpu}
  rm -rf deleteme.%{_target_cpu} &
fi

cp -rl vanilla-%{vanillaversion} linux-%{kversion}.%{_target_cpu}

cd linux-%{kversion}.%{_target_cpu}

# released_kernel with possible stable updates
%if 0%{?stable_base}
ApplyPatch %{stable_patch_00}
%endif
%if 0%{?stable_rc}
ApplyPatch %{stable_patch_01}
%endif

%if %{using_upstream_branch}
### BRANCH APPLY ###
%endif

# Drop some necessary files from the source dir into the buildroot
cp $RPM_SOURCE_DIR/config-* .
cp %{SOURCE15} .

# Dynamically generate kernel .config files from config-* files
make -f %{SOURCE20} VERSION=%{version} configs

#if a rhel kernel, apply the rhel config options
%if 0%{?rhel}
  for i in %{all_arch_configs}
  do
    mv $i $i.tmp
    ./merge.pl config-rhel-generic $i.tmp > $i
    rm $i.tmp
  done
%endif

%if !%{nopatches}
# revert patches from upstream that conflict or that we get via other means
%endif

# Any further pre-build tree manipulations happen here.

chmod +x scripts/checkpatch.pl

# only deal with configs if we are going to build for the arch
%ifnarch %nobuildarches

mkdir configs

# Remove configs not for the buildarch
for cfg in kernel-%{version}-*.config; do
  if [ `echo %{all_arch_configs} | grep -c $cfg` -eq 0 ]; then
    rm -f $cfg
  fi
done

%if !%{debugbuildsenabled}
rm -f kernel-%{version}-*debug.config
%endif

# now run oldconfig over all the config files
for i in *.config
do
  mv $i .config
  test_config_file $i
  Arch=`head -1 .config | cut -b 3-`
  make ARCH=$Arch %{oldconfig_target} > /dev/null
  echo "# $Arch" > configs/$i
  cat .config >> configs/$i
done
# end of kernel config
%endif

# get rid of unwanted files resulting from patch fuzz
find . \( -name "*.orig" -o -name "*~" \) -exec rm -f {} \; >/dev/null
%if %{signmodules}
  cp %{SOURCE19} .
  pwd
  rm -rf ./gpg_gen
  mkdir ./gpg_gen
  chmod 700 ./gpg_gen
  gpg --homedir ./gpg_gen --batch --gen-key %{SOURCE11}
# if there're external keys to be included
  if [ -s %{SOURCE19} ]; then
      gpg --homedir . --no-default-keyring --keyring kernel.pub --import %{SOURCE19}
  fi
  gpg --homedir . --export --keyring ./kernel.pub Oracle > ./gpg_gen/extract.pub
  gcc -o scripts/bin2c scripts/bin2c.c
  scripts/bin2c ksign_def_public_key __initdata <./gpg_gen/extract.pub >crypto/signature/key.h
%endif
 	  	 

cd ..

###
### build
###
%build

%if %{with_sparse}
%define sparse_mflags	C=1
%endif

cp_vmlinux()
{
  eu-strip --remove-comment -o "$2" "$1"
}

BuildKernel() {
    MakeTarget=$1
    KernelImage=$2
    Flavour=$3
    InstallName=${4:-vmlinuz}

    # Pick the right config file for the kernel we're building
    Config=kernel-%{version}-%{_target_cpu}${Flavour:+-${Flavour}}.config
    DevelDir=/usr/src/kernels/%{KVERREL}${Flavour:+.${Flavour}}

    # When the bootable image is just the ELF kernel, strip it.
    # We already copy the unstripped file into the debuginfo package.
    if [ "$KernelImage" = vmlinux ]; then
      CopyKernel=cp_vmlinux
    else
      CopyKernel=cp
    fi

    KernelVer=%{version}-%{release}${Flavour:+.${Flavour}}
    echo BUILDING A KERNEL FOR ${Flavour} %{_target_cpu}...

    # make sure EXTRAVERSION says what we want it to say
    perl -p -i -e "s/^EXTRAVERSION.*/EXTRAVERSION = %{?stablerev}-%{release}${Flavour:+.${Flavour}}/" Makefile

    # if pre-rc1 devel kernel, must fix up SUBLEVEL for our versioning scheme
    %if !0%{?rcrev}
    %if 0%{?gitrev}
    perl -p -i -e 's/^SUBLEVEL.*/SUBLEVEL = %{upstream_sublevel}/' Makefile
    %endif
    %endif

    # and now to start the build process

    make -s mrproper
    cp configs/$Config .config

    Arch=`head -1 .config | cut -b 3-`
    echo USING ARCH=$Arch

    make -s ARCH=$Arch %{oldconfig_target} > /dev/null
    make -s ARCH=$Arch V=1 %{?_smp_mflags} $MakeTarget %{?sparse_mflags}
    make -s ARCH=$Arch V=1 %{?_smp_mflags} modules %{?sparse_mflags} || exit 1

    # Start installing the results
%if %{with_debuginfo}
    mkdir -p $RPM_BUILD_ROOT%{debuginfodir}/boot
    mkdir -p $RPM_BUILD_ROOT%{debuginfodir}/%{image_install_path}
%endif
    mkdir -p $RPM_BUILD_ROOT/%{image_install_path}
    install -m 644 .config $RPM_BUILD_ROOT/boot/config-$KernelVer
    install -m 644 System.map $RPM_BUILD_ROOT/boot/System.map-$KernelVer
    touch $RPM_BUILD_ROOT/boot/initrd-$KernelVer.img
    if [ -f arch/$Arch/boot/zImage.stub ]; then
      cp arch/$Arch/boot/zImage.stub $RPM_BUILD_ROOT/%{image_install_path}/zImage.stub-$KernelVer || :
    fi
    $CopyKernel $KernelImage \
    		$RPM_BUILD_ROOT/%{image_install_path}/$InstallName-$KernelVer
    chmod 755 $RPM_BUILD_ROOT/%{image_install_path}/$InstallName-$KernelVer

    mkdir -p $RPM_BUILD_ROOT/lib/modules/$KernelVer
    # Override $(mod-fw) because we don't want it to install any firmware
    # We'll do that ourselves with 'make firmware_install'
    make -s ARCH=$Arch INSTALL_MOD_PATH=$RPM_BUILD_ROOT modules_install KERNELRELEASE=$KernelVer mod-fw=
    # check if the modules are being signed
%if %{signmodules}
      if [ -z "$(readelf -n $(find fs/ -name \*.ko | head -n 1) | grep module.sig)" ]; then
        echo "ERROR: modules are NOT signed" >&2;
	    exit 1;
      fi
%endif

	%ifarch %{vdso_arches}
    make -s ARCH=$Arch INSTALL_MOD_PATH=$RPM_BUILD_ROOT vdso_install KERNELRELEASE=$KernelVer
    if grep '^CONFIG_XEN=y$' .config >/dev/null; then
      echo > ldconfig-kernel.conf "\
# This directive teaches ldconfig to search in nosegneg subdirectories
# and cache the DSOs there with extra bit 0 set in their hwcap match
# fields.  In Xen guest kernels, the vDSO tells the dynamic linker to
# search in nosegneg subdirectories and to match this extra hwcap bit
# in the ld.so.cache file.
hwcap 0 nosegneg"
    fi
    if [ ! -s ldconfig-kernel.conf ]; then
      echo > ldconfig-kernel.conf "\
# Placeholder file, no vDSO hwcap entries used in this kernel."
    fi
    %{__install} -D -m 444 ldconfig-kernel.conf \
        $RPM_BUILD_ROOT/etc/ld.so.conf.d/kernel-$KernelVer.conf
%ifnarch noarch
# build tools/perf:
    if [ -d tools/perf ]; then
	cd tools/perf
	make all
# and install it:
	mkdir -p $RPM_BUILD_ROOT/usr/bin/$KernelVer/
	install -m 755 perf $RPM_BUILD_ROOT/usr/bin/$KernelVer/perf
	#install -m 755 libperf.a $RPM_BUILD_ROOT/lib/modules/$KernelVer/bin/%{_target_cpu}/libperf.a
	cd ../..
    fi
%endif
%endif

    # And save the headers/makefiles etc for building modules against
    #
    # This all looks scary, but the end result is supposed to be:
    # * all arch relevant include/ files
    # * all Makefile/Kconfig files
    # * all script/ files

    rm -f $RPM_BUILD_ROOT/lib/modules/$KernelVer/build
    rm -f $RPM_BUILD_ROOT/lib/modules/$KernelVer/source
    mkdir -p $RPM_BUILD_ROOT/lib/modules/$KernelVer/build
    (cd $RPM_BUILD_ROOT/lib/modules/$KernelVer ; ln -s build source)
    # dirs for additional modules per module-init-tools, kbuild/modules.txt
    mkdir -p $RPM_BUILD_ROOT/lib/modules/$KernelVer/extra
    mkdir -p $RPM_BUILD_ROOT/lib/modules/$KernelVer/updates
    mkdir -p $RPM_BUILD_ROOT/lib/modules/$KernelVer/weak-updates
    # first copy everything
    cp --parents `find  -type f -name "Makefile*" -o -name "Kconfig*"` $RPM_BUILD_ROOT/lib/modules/$KernelVer/build
    cp Module.symvers $RPM_BUILD_ROOT/lib/modules/$KernelVer/build
    cp System.map $RPM_BUILD_ROOT/lib/modules/$KernelVer/build
    if [ -s Module.markers ]; then
      cp Module.markers $RPM_BUILD_ROOT/lib/modules/$KernelVer/build
    fi

    # create the kABI metadata for use in packaging
    echo "**** GENERATING kernel ABI metadata ****"
    gzip -c9 < Module.symvers > $RPM_BUILD_ROOT/boot/symvers-$KernelVer.gz
    chmod 0755 %_sourcedir/kabitool
    if [ -e $RPM_SOURCE_DIR/kabi_whitelist_%{_target_cpu}$Flavour ]; then
      cp $RPM_SOURCE_DIR/kabi_whitelist_%{_target_cpu}$Flavour $RPM_BUILD_ROOT/lib/modules/$KernelVer/build/kabi_whitelist 
    fi 
    rm -f %{_tmppath}/kernel-$KernelVer-kabideps
    %_sourcedir/kabitool -s Module.symvers -o %{_tmppath}/kernel-$KernelVer-kabideps

%if %{with_kabichk}
    echo "**** kABI checking is enabled in kernel SPEC file. ****"
    chmod 0755 $RPM_SOURCE_DIR/check-kabi
    if [ -e $RPM_SOURCE_DIR/Module.kabi_%{_target_cpu}$Flavour ]; then
        cp $RPM_SOURCE_DIR/Module.kabi_%{_target_cpu}$Flavour $RPM_BUILD_ROOT/Module.kabi
        $RPM_SOURCE_DIR/check-kabi -k $RPM_BUILD_ROOT/Module.kabi -s Module.symvers || exit 1
        rm $RPM_BUILD_ROOT/Module.kabi # for now, don't keep it around.
    else
        echo "**** NOTE: Cannot find reference Module.kabi file. ****"
    fi
%endif

    # then drop all but the needed Makefiles/Kconfig files
    rm -rf $RPM_BUILD_ROOT/lib/modules/$KernelVer/build/Documentation
    rm -rf $RPM_BUILD_ROOT/lib/modules/$KernelVer/build/scripts
    rm -rf $RPM_BUILD_ROOT/lib/modules/$KernelVer/build/include
    cp .config $RPM_BUILD_ROOT/lib/modules/$KernelVer/build
    cp -a scripts $RPM_BUILD_ROOT/lib/modules/$KernelVer/build
    if [ -d arch/$Arch/scripts ]; then
      cp -a arch/$Arch/scripts $RPM_BUILD_ROOT/lib/modules/$KernelVer/build/arch/%{_arch} || :
    fi
    if [ -f arch/$Arch/*lds ]; then
      cp -a arch/$Arch/*lds $RPM_BUILD_ROOT/lib/modules/$KernelVer/build/arch/%{_arch}/ || :
    fi
    rm -f $RPM_BUILD_ROOT/lib/modules/$KernelVer/build/scripts/*.o
    rm -f $RPM_BUILD_ROOT/lib/modules/$KernelVer/build/scripts/*/*.o
%ifarch ppc
    cp -a --parents arch/powerpc/lib/crtsavres.[So] $RPM_BUILD_ROOT/lib/modules/$KernelVer/build/
%endif
    if [ -d arch/%{asmarch}/include ]; then
      cp -a --parents arch/%{asmarch}/include $RPM_BUILD_ROOT/lib/modules/$KernelVer/build/
    fi
    cp -a --parents Kbuild $RPM_BUILD_ROOT/lib/modules/$KernelVer/build/
    cp -a --parents kernel/bounds.c $RPM_BUILD_ROOT/lib/modules/$KernelVer/build/
    cp -a --parents arch/%{asmarch}/kernel/asm-offsets.c $RPM_BUILD_ROOT/lib/modules/$KernelVer/build/
    cp -a --parents arch/%{asmarch}/kernel/asm-offsets_64.c $RPM_BUILD_ROOT/lib/modules/$KernelVer/build/
    cp -a --parents security/selinux/include $RPM_BUILD_ROOT/lib/modules/$KernelVer/build/ 
    
    mkdir -p $RPM_BUILD_ROOT/lib/modules/$KernelVer/build/include
    cd include
    cp -a acpi config generated crypto keys linux math-emu media mtd net pcmcia rdma rxrpc scsi sound trace video asm-generic xen $RPM_BUILD_ROOT/lib/modules/$KernelVer/build/include
    asmdir=../arch/%{asmarch}/include/asm
    cp -a $asmdir $RPM_BUILD_ROOT/lib/modules/$KernelVer/build/include/
    pushd $RPM_BUILD_ROOT/lib/modules/$KernelVer/build/include
    ln -s $asmdir asm
    popd
    # Make sure the Makefile and version.h have a matching timestamp so that
    # external modules can be built
    touch -r $RPM_BUILD_ROOT/lib/modules/$KernelVer/build/Makefile $RPM_BUILD_ROOT/lib/modules/$KernelVer/build/include/linux/version.h
    touch -r $RPM_BUILD_ROOT/lib/modules/$KernelVer/build/.config $RPM_BUILD_ROOT/lib/modules/$KernelVer/build/include/linux/autoconf.h
    # Copy .config to include/config/auto.conf so "make prepare" is unnecessary.
    cp $RPM_BUILD_ROOT/lib/modules/$KernelVer/build/.config $RPM_BUILD_ROOT/lib/modules/$KernelVer/build/include/config/auto.conf
    cd ..

    #
    # save the vmlinux file for kernel debugging into the kernel-debuginfo rpm
    #
%if %{with_debuginfo}
    mkdir -p $RPM_BUILD_ROOT%{debuginfodir}/lib/modules/$KernelVer
    cp vmlinux $RPM_BUILD_ROOT%{debuginfodir}/lib/modules/$KernelVer
%endif

    find $RPM_BUILD_ROOT/lib/modules/$KernelVer -name "*.ko" -type f >modnames

    # mark modules executable so that strip-to-file can strip them
    xargs --no-run-if-empty chmod u+x < modnames

    # Generate a list of modules for block and networking.

    fgrep /drivers/ modnames | xargs --no-run-if-empty nm -upA |
    sed -n 's,^.*/\([^/]*\.ko\):  *U \(.*\)$,\1 \2,p' > drivers.undef

    collect_modules_list()
    {
      sed -r -n -e "s/^([^ ]+) \\.?($2)\$/\\1/p" drivers.undef |
      LC_ALL=C sort -u > $RPM_BUILD_ROOT/lib/modules/$KernelVer/modules.$1
    }

    collect_modules_list networking \
    			 'register_netdev|ieee80211_register_hw|usbnet_probe'
    collect_modules_list block \
    			 'ata_scsi_ioctl|scsi_add_host|blk_init_queue|register_mtd_blktrans|scsi_esp_register'
    collect_modules_list drm \
    			 'drm_open|drm_init'
    collect_modules_list modesetting \
    			 'drm_crtc_init'

    # detect missing or incorrect license tags
    rm -f modinfo
    while read i
    do
      echo -n "${i#$RPM_BUILD_ROOT/lib/modules/$KernelVer/} " >> modinfo
      /sbin/modinfo -l $i >> modinfo
    done < modnames

    egrep -v \
    	  'GPL( v2)?$|Dual BSD/GPL$|Dual MPL/GPL$|GPL and additional rights$' \
	  modinfo && exit 1

    rm -f modinfo modnames

    # remove files that will be auto generated by depmod at rpm -i time
    for i in alias ccwmap dep ieee1394map inputmap isapnpmap ofmap pcimap seriomap symbols usbmap
    do
      rm -f $RPM_BUILD_ROOT/lib/modules/$KernelVer/modules.$i
    done

    # Move the devel headers out of the root file system
    mkdir -p $RPM_BUILD_ROOT/usr/src/kernels
    mv $RPM_BUILD_ROOT/lib/modules/$KernelVer/build $RPM_BUILD_ROOT/$DevelDir
    ln -sf ../../..$DevelDir $RPM_BUILD_ROOT/lib/modules/$KernelVer/build
}

###
# DO it...
###

# prepare directories
rm -rf $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT/boot

cd linux-%{kversion}.%{_target_cpu}

%if %{with_paravirt}
BuildKernel %make_target %kernel_image paravirt 
%endif

%if %{with_paravirt_debug}
BuildKernel %make_target %kernel_image paravirt_debug 
%endif

%if %{with_debug}
%if %{with_up}
BuildKernel %make_target %kernel_image debug
%endif
%if %{with_pae}
BuildKernel %make_target %kernel_image PAEdebug
%endif
%endif

%if %{with_pae}
BuildKernel %make_target %kernel_image PAE
%endif

%if %{with_up}
BuildKernel %make_target %kernel_image
%endif

%if %{with_smp}
BuildKernel %make_target %kernel_image smp
%endif

%if %{with_kdump}
BuildKernel vmlinux vmlinux kdump vmlinux
%endif

%if %{with_doc}
# Make the HTML and man pages.
make -j1  htmldocs mandocs || %{doc_build_fail}

# sometimes non-world-readable files sneak into the kernel source tree
chmod -R a=rX Documentation
find Documentation -type d | xargs chmod u+w
%endif

###
### Special hacks for debuginfo subpackages.
###

# This macro is used by %%install, so we must redefine it before that.
%define debug_package %{nil}

%if %{with_debuginfo}
%ifnarch noarch
%global __debug_package 1
%files debuginfo-common
%defattr(-,root,root)
/usr/src/debug/kernel-%{version}/linux-%{kversion}.%{_target_cpu}
%dir /usr/src/debug
%dir %{debuginfodir}
%dir %{debuginfodir}/%{image_install_path}
%dir %{debuginfodir}/lib
%dir %{debuginfodir}/lib/modules
%dir %{debuginfodir}/usr/src/kernels
%endif
%endif

###
### install
###

%install

cd linux-%{kversion}.%{_target_cpu}

%if %{with_doc}
docdir=$RPM_BUILD_ROOT%{_datadir}/doc/kernel-doc-%{rpmversion}
man9dir=$RPM_BUILD_ROOT%{_datadir}/man/man9

# copy the source over
mkdir -p $docdir
tar -f - --exclude=man --exclude='.*' -c Documentation | tar xf - -C $docdir

# Install man pages for the kernel API.
mkdir -p $man9dir
find Documentation/DocBook/man -name '*.9.gz' -print0 |
xargs -0 --no-run-if-empty %{__install} -m 444 -t $man9dir $m
ls $man9dir | grep -q '' || > $man9dir/BROKEN
%endif

%ifnarch noarch
# perf shell wrapper
mkdir -p $RPM_BUILD_ROOT/usr/sbin/
cp $RPM_SOURCE_DIR/perf $RPM_BUILD_ROOT/usr/sbin/perf
chmod 0755 $RPM_BUILD_ROOT/usr/sbin/perf
%endif

%if %{with_headers}
# Install kernel headers
make ARCH=%{hdrarch} INSTALL_HDR_PATH=$RPM_BUILD_ROOT/usr headers_install

# Do headers_check but don't die if it fails.
make ARCH=%{hdrarch} INSTALL_HDR_PATH=$RPM_BUILD_ROOT/usr headers_check \
     > hdrwarnings.txt || :
if grep -q exist hdrwarnings.txt; then
   sed s:^$RPM_BUILD_ROOT/usr/include/:: hdrwarnings.txt
   # Temporarily cause a build failure if header inconsistencies.
   # exit 1
fi

find $RPM_BUILD_ROOT/usr/include \
     \( -name .install -o -name .check -o \
     	-name ..install.cmd -o -name ..check.cmd \) | xargs rm -f

# glibc provides scsi headers for itself, for now
rm -rf $RPM_BUILD_ROOT/usr/include/scsi
rm -f $RPM_BUILD_ROOT/usr/include/asm*/atomic.h
rm -f $RPM_BUILD_ROOT/usr/include/asm*/io.h
rm -f $RPM_BUILD_ROOT/usr/include/asm*/irq.h

# these are provided by drm-devel
rm -rf $RPM_BUILD_ROOT/usr/include/drm
%endif

%if %{with_firmware}
mkdir -p $RPM_BUILD_ROOT/lib/firmware
Arch=`head -n 3 .config |grep -e "Linux.*Kernel" |cut -d '/' -f 2 | cut -d ' ' -f 1`
make ARCH=$Arch INSTALL_FW_PATH=$RPM_BUILD_ROOT/lib/firmware firmware_install
%endif

%if %{with_bootwrapper}
Arch=`head -n 3 .config |grep -e "Linux.*Kernel" |cut -d '/' -f 2 | cut -d ' ' -f 1`
make ARCH=$Arch DESTDIR=$RPM_BUILD_ROOT bootwrapper_install WRAPPER_OBJDIR=%{_libdir}/kernel-wrapper WRAPPER_DTSDIR=%{_libdir}/kernel-wrapper/dts
%endif

###
### clean
###

%clean
rm -rf $RPM_BUILD_ROOT

###
### scripts
###

#
# This macro defines a %%post script for a kernel*-devel package.
#	%%kernel_devel_post [<subpackage>]
#
%define kernel_devel_post() \
%{expand:%%post %{?1:%{1}-}devel}\
if [ -f /etc/sysconfig/kernel ]\
then\
    . /etc/sysconfig/kernel || exit $?\
fi\
if [ "$HARDLINK" != "no" -a -x /usr/sbin/hardlink ]\
then\
    (cd /usr/src/kernels/%{KVERREL}%{?1:.%{1}} &&\
     /usr/bin/find . -type f | while read f; do\
       hardlink -c /usr/src/kernels/*.fc*.*/$f $f\
     done)\
fi\
%{nil}

# This macro defines a %%posttrans script for a kernel package.
#	%%kernel_variant_posttrans [<subpackage>]
# More text can follow to go at the end of this variant's %%post.
#
###%define kernel_variant_posttrans() \
###%{expand:%%posttrans %{?1}}\
###/sbin/new-kernel-pkg --package kernel%{?1:-%{1}} --rpmposttrans %{KVERREL}%{?1:.%{1}} || exit $?\
###%{nil}

#
# This macro defines a %%post script for a kernel package and its devel package.
#	%%kernel_variant_post [-v <subpackage>] [-r <replace>]
# More text can follow to go at the end of this variant's %%post.
#
%define kernel_variant_post(uv:r:) \
%{expand:%%kernel_devel_post %{!-u:%{?-v*}}}\
%{expand:%%kernel_variant_posttrans %{!-u:%{?-v*}}}\
%{expand:%%post %{!-u:%{?-v*}}}\
%{-r:\
if [ `uname -i` == "x86_64" -o `uname -i` == "i386" ] &&\
   [ -f /etc/sysconfig/kernel ]; then\
  /bin/sed -r -i -e 's/^DEFAULTKERNEL=%{-r*}$/DEFAULTKERNEL=kernel%{?-v:-%{-v*}}/' /etc/sysconfig/kernel || exit $?\
fi}\
/sbin/new-kernel-pkg --package kernel%{?-v:-%{-v*}} --mkinitrd --depmod --install %{KVERREL}%{!-u:%{?-v:.%{-v*}}} || exit $?\
if [ -x /sbin/weak-modules ]\
then\
    /sbin/weak-modules --add-kernel %{KVERREL}%{!-u:%{?-v:.%{-v*}}} || exit $?\
fi\
%{nil}

#
# This macro defines a %%preun script for a kernel package.
#	%%kernel_variant_preun <subpackage>
#
%define kernel_variant_preun() \
%{expand:%%preun %{?1}}\
/sbin/new-kernel-pkg --rminitrd --rmmoddep --remove %{KVERREL}%{?1:.%{1}} || exit $?\
if [ -x /sbin/weak-modules ]\
then\
    /sbin/weak-modules --remove-kernel %{KVERREL}%{?1:.%{1}} || exit $?\
fi\
%{nil}

#
# This macro defines a %%pre script for a kernel package.
#	%%kernel_variant_pre <subpackage>
#
%define kernel_variant_pre() \
%{expand:%%pre %{?1}}\
message="Change references of /dev/hd in /etc/fstab to disk label"\
if [ -f /etc/fstab ]\
then\
awk '($2=="/boot")&&/^\\/dev\\/hd/{print $1}' /etc/fstab | egrep -q "^/dev/hd"\
bdretval=$?\
awk '($2=="/")&&/^\\/dev\\/hd/{print $1}' /etc/fstab | egrep -q "^/dev/hd"\
rdretval=$?\
awk '($2=="/boot")&&/^LABEL=/{print $1}' /etc/fstab | egrep -q "^LABEL="\
blretval=$?\
awk '($2=="/")&&/^LABEL=/{print $1}' /etc/fstab | egrep -q "^LABEL="\
rlretval=$?\
if [ $bdretval == 0 ] || [ $rdretval == 0 ]\
then\
echo -e $message\
exit 1\
elif [ $blretval == 0 ] && [ $rlretval == 0 ]\
then\
grep -v "^#" /etc/fstab | egrep -q "/dev/hd"\
if [ $? == 0 ]\
then\
echo -e $message\
fi\
elif [ $blretval == 0 ] && [ $rdretval != 0 ]\
then\
grep -v "^#" /etc/fstab | egrep -q "/dev/hd"\
if [ $? == 0 ]\
then\
echo -e $message\
fi\
elif [ $bdretval != 0 ] && [ $rlretval == 0 ]\
then\
grep -v "^#" /etc/fstab | egrep -q "/dev/hd"\
if [ $? == 0 ]\
then\
echo -e $message\
fi\
elif [ $bdretval != 0 ] && [ $rdretval != 0 ]\
then\
grep -v "^#" /etc/fstab | egrep -q "/dev/hd"\
if [ $? == 0 ]\
then\
echo -e $message\
fi\
fi\
fi\
%{nil}

%kernel_variant_pre
%kernel_variant_preun
%ifarch x86_64
%kernel_variant_post -u -v uek -r (kernel|kernel-smp|kernel-xen)
%else
%kernel_variant_post -u -v uek -r (kernel|kernel-smp|kernel-PAE|kernel-xen)
%endif

%kernel_variant_pre smp
%kernel_variant_preun smp
%kernel_variant_post -v smp

%kernel_variant_pre PAE
%kernel_variant_preun PAE
%kernel_variant_post -v PAE -r (kernel|kernel-smp|kernel-xen)

%kernel_variant_pre debug
%kernel_variant_preun debug
%kernel_variant_post -v debug

%kernel_variant_post -v PAEdebug -r (kernel|kernel-smp|kernel-xen)
%kernel_variant_preun PAEdebug
%kernel_variant_pre PAEdebug

%kernel_variant_post -v paravirt -r (kernel-smp|kernel-xen|kernel-uek)
%kernel_variant_preun paravirt
%kernel_variant_pre paravirt

%kernel_variant_post -v paravirt_debug -r (kernel-smp|kernel-xen|kernel-uek)
%kernel_variant_preun paravirt_debug
%kernel_variant_pre paravirt_debug


if [ -x /sbin/ldconfig ]
then
    /sbin/ldconfig -X || exit $?
fi

###
### file lists
###

%if %{with_headers}
%files headers
%defattr(-,root,root)
/usr/include/*
%endif

%if %{with_firmware}
%files firmware
%defattr(-,root,root)
/lib/firmware/*
%doc linux-%{kversion}.%{_target_cpu}/firmware/WHENCE
%endif

%if %{with_bootwrapper}
%files bootwrapper
%defattr(-,root,root)
/usr/sbin/*
%{_libdir}/kernel-wrapper
%endif

# only some architecture builds need kernel-doc
%if %{with_doc}
%files doc
%defattr(-,root,root)
%{_datadir}/doc/kernel-doc-%{rpmversion}/Documentation/*
%dir %{_datadir}/doc/kernel-doc-%{rpmversion}/Documentation
%dir %{_datadir}/doc/kernel-doc-%{rpmversion}
%{_datadir}/man/man9/*
%endif

# This is %{image_install_path} on an arch where that includes ELF files,
# or empty otherwise.
%define elf_image_install_path %{?kernel_image_elf:%{image_install_path}}

#
# This macro defines the %%files sections for a kernel package
# and its devel and debuginfo packages.
#	%%kernel_variant_files [-k vmlinux] <condition> <subpackage>
#
%define kernel_variant_files(k:) \
%if %{1}\
%{expand:%%files %{?2}}\
%defattr(-,root,root)\
/%{image_install_path}/%{?-k:%{-k*}}%{!?-k:vmlinuz}-%{KVERREL}%{?2:.%{2}}\
/boot/System.map-%{KVERREL}%{?2:.%{2}}\
/boot/symvers-%{KVERREL}%{?2:.%{2}}.gz\
/boot/config-%{KVERREL}%{?2:.%{2}}\
%dir /lib/modules/%{KVERREL}%{?2:.%{2}}\
/lib/modules/%{KVERREL}%{?2:.%{2}}/kernel\
/lib/modules/%{KVERREL}%{?2:.%{2}}/build\
/lib/modules/%{KVERREL}%{?2:.%{2}}/source\
/lib/modules/%{KVERREL}%{?2:.%{2}}/extra\
/lib/modules/%{KVERREL}%{?2:.%{2}}/updates\
/lib/modules/%{KVERREL}%{?2:.%{2}}/weak-updates\
%ifarch %{vdso_arches}\
/lib/modules/%{KVERREL}%{?2:.%{2}}/vdso\
/etc/ld.so.conf.d/kernel-%{KVERREL}%{?2:.%{2}}.conf\
%endif\
/lib/modules/%{KVERREL}%{?2:.%{2}}/modules.*\
/usr/bin/%{KVERREL}%{?2:.%{2}}/perf\
/usr/sbin/perf\
%ghost /boot/initrd-%{KVERREL}%{?2:.%{2}}.img\
%{expand:%%files %{?2:%{2}-}devel}\
%defattr(-,root,root)\
%dir /usr/src/kernels\
%verify(not mtime) /usr/src/kernels/%{KVERREL}%{?2:.%{2}}\
/usr/src/kernels/%{KVERREL}%{?2:.%{2}}\
%if %{with_debuginfo}\
%ifnarch noarch\
%{expand:%%files %{?2:%{2}-}debuginfo}\
%defattr(-,root,root)\
%{debuginfodir}/lib/modules/%{KVERREL}%{?2:.%{2}}\
%{debuginfodir}/usr/src/kernels/%{KVERREL}%{?2:.%{2}}\
%{debuginfodir}/usr/bin/%{KVERREL}%{?2:.%{2}}\
%endif\
%endif\
%endif\
%{nil}


%kernel_variant_files %{with_paravirt} paravirt
%kernel_variant_files %{with_paravirt_debug} paravirt_debug
%kernel_variant_files %{with_up}
%kernel_variant_files %{with_smp} smp
%if %{with_up}
%kernel_variant_files %{with_debug} debug
%endif
%kernel_variant_files %{with_pae} PAE
%kernel_variant_files %{with_pae_debug} PAEdebug
%kernel_variant_files -k vmlinux %{with_kdump} kdump

%changelog
* Wed Oct 12 2011 Guru Anbalagane <guru.anbalagane@oracle.com> [2.6.39-100.0.14.el5uek]
- Apply signature checking to modules on module load (David Howells)
- Don't include .note.gnu.build-id in the digest (David Howells)
- config: turn on module sign (Maxim Uvarov)
- fix modpost port bug for module signatures  (Maxim Uvarov)
- xen: Fix selfballooning and ensure it doesn't go too far (Dan Magenheimer)
- config: disable XEN_BALLOON_MEMORY_HOTPLUG
- apic, i386/bigsmp: Fix false warnings regarding logical APIC ID mismatches (Jan Beulich)

* Mon Oct 10 2011 Maxim Uvarov <maxim.uvarov@oracle.com> [2.6.39-100.0.13.el5uek]
- fix btrfs compilation for 32 bit
- ext4 turn on CONFIG_LBDAF for 32bit kernel [orabug 12965485]
- exec: do not call request_module() twice from search_binary_handler()
- merge 3.0.6 patches

* Thu Sep 29 2011 Guru Anbalagane <guru.anbalagane@oracle.com> [2.6.39-100.0.12.el5uek]
- audit: dynamically allocate audit_names when not enough spaceis in the names array [orabug 13038425]
- update btrfs 3.0

* Wed Sep 28 2011 Guru Anbalagane <guru.anbalagane@oracle.com> [2.6.39-100.0.11.el5uek]
- xen:  Add  bootmem.h in xen-selfballoon.c

* Wed Sep 28 2011 Guru Anbalagane <guru.anbalagane@oracle.com> [2.6.39-100.0.10.el5uek]
- mpt2sas: Add a module parameter that permits overriding protection capabilities
- mpt2sas: Return the correct sense key for DIF errors
- mpt2sas: Do not check DIF for unwritten blocks
- Revert "xen/e820: if there is no dom0_mem=, don't tweak extra_pages."
- Revert "[AUDIT/workaround] Increase AUDIT_NAMES array len" [orabug 13034299]
- block: Rate-limit failed I/O error message  [orabug 13007648]
- config: disable panic on hardlockup [orabug 13007648]
- ocfs2: update ocfs2 version [orabug 13017352]
- x86/paravirt: PTE updates in k(un)map_atomic need to be synchronous, regardless of lazy_mmu mode
- bnx2x: prevent flooded warnning kernel info [orabug 12687487]
- tg3: Dont dump DMA error when interface not ready [orabug 12981473]
- xen: Fix selfballooning and ensure it doesn't go too far
- ocfs2: Add datavolume mount option [orabug 13017352]

* Thu Sep 22 2011 Guru Anbalagane <guru.anbalagane@oracle.com> [2.6.39-100.0.9
.el5uek]
- generate -paravirt configs more accurate [orabug 13002151]
- radeon: add missed firmwares [orabug 12981553]
- ksplice: Clear garbage data on the kernel stack when handling signals
- Add devel headers [orabug 13000607]

* Wed Sep 21 2011 Kevin Lyons [2.6.39-100.0.8.el5uek]
- Add -u parameter to kernel_variant_post to make it work
  properly for uek [orabug 12965870]

* Tue Sep 20 2011 Guru Anbalagane <guru.anbalagane@oracle.com> [2.6.39-100.0.7.el5uek]
- fix --noarch build
- CONFIG: Add support for Large files - 32bit orabug 12984979

* Mon Sep 19 2011 Guru Anbalagane <guru.anbalagane@oracle.com> [2.6.39-100.0.6.el5uek]
- rebase to 3.0.4
- Build paravirt and paravirt-debug kernels
- Remove commented out patches from spec
- Specfile: build OCFS2
- make XEN_MAX_DOMAIN_MEMORY selectable
- config-debug: enable LOCKDEP and more debug options
- Turn on CONFIG_CRYPTO_FIPS (Maxim Uvarov)
- CONFIG: enable sysfs(el5) and xen memory hotplug
- scsi: bump up SD_MAX_DISKS (Dave Kleikamp)
- x86, acpi: Handle xapic/x2apic entries in MADT at same time (Yinghai Lu)

* Tue Sep 13 2011 Guru Anbalagane <guru.anbalagane@oracle.com> [2.6.39-100.0.5.el5uek]
- xen: allow enable use of VGA console on dom0
- xen: prepare tmem shim to handle frontswap
- xen: Add __attribute__((format(printf... where appropriate
- xen: Populate xenbus device attributes
- xen: Add module alias to autoload backend drivers
- xen: tmem: self-ballooning and frontswap-selfshrinking
- xen/pci: Shuffle code around.
- xen/pci: Update comments and fix empty spaces.
- xen/pci: Provide #ifdef CONFIG_ACPI to easy code squashing.
- xen/pci: In xen_register_pirq bind the GSI to the IRQ after the hypercall.
- xen/pci: Use the xen_register_pirq for HVM and initial domain users
- xen/pci: Squash pci_xen_initial_domain and xen_setup_pirqs together.
- xen/pci: Move the allocation of IRQs when there are no IOAPIC's to the end
- xen/pci: Retire unnecessary #ifdef CONFIG_ACPI
- xen/pci: Remove 'xen_allocate_pirq_gsi'.
- xen/pci: Use 'acpi_gsi_to_irq' value unconditionally.
- xen/pciback: xen pci backend driver.
- xen/pciback: Cleanup the driver based on checkpatch warnings and errors.
- xen/pciback: Register the owner (domain) of the PCI device.
- xen/pciback: guest SR-IOV support for PV guest
- xen/pciback: Disable MSI/MSI-X when reseting a device
- xen/pciback: Allocate IRQ handler for device that is shared with guest.
- xen/pciback: Fine-grain the spinlocks and fix BUG: scheduling while atomic cases.
- xen: rename pciback module to xen-pciback.
- xen/pciback: Don't setup an fake IRQ handler for SR-IOV devices.
- xen/pciback: Print out the MSI/MSI-X (PIRQ) values
- xen/pciback: Drop two backends, squash and cleanup some code.
- xen/pciback: Remove the DEBUG option.
- xen/pciback: Have 'passthrough' option instead of XEN_PCIDEV_BACKEND_PASS and XEN_PCIDEV_BACKEND_VPCI
- mm: frontswap: swap data structure changes
- mm: frontswap: core code
- mm: frontswap: add swap hooks and extend try_to_unuse
- mm: frontswap: config and doc files
- xen:pvhvm: Modpost section mismatch fix
- xen/pciback: remove duplicated #include
- trace/xen: add skeleton for Xen trace events
- xen/multicalls: remove debugfs stats
- xen/trace: set up tracepoint skeleton
- xen/trace: add multicall tracing
- xen/trace: add mmu tracepoints
- xen/trace: add ptpage alloc/release tracepoints
- xen/trace: add xen_pgd_(un)pin tracepoints
- xen/trace: add segment desc tracing
- xen/trace: add tlb flush tracepoints
- xen/mmu: use extend_args for more mmuext updates
- xen/mmu: tune pgtable alloc/release
- xen/multicalls: disable MC_DEBUG
- xen/multicalls: add unlikely around slowpath in __xen_mc_entry()
- xen/multicall: special-case singleton hypercalls
- xen/multicall: move *idx fields to start of mc_buffer
- xen/trace: convert mmu events to use DECLARE_EVENT_CLASS()/DEFINE_EVENT()
- xen/trace: use class for multicall trace
- xen/tracing: fix compile errors when tracing is disabled.
- xen/tracing: it looks like we wanted CONFIG_FTRACE
- xen/trace: Fix compile error when CONFIG_XEN_PRIVILEGED_GUEST is not set
- xen/tracing: Fix tracing config option properly
- Input: xen-kbdfront - enable driver for HVM guests
- xen/balloon: memory hotplug support for Xen balloon driver
- mm: extend memory hotplug API to allow memory hotplug in virtual machines
- xen/blkback: Add module alias for autoloading
- xen/blkback: Don't let in-flight requests defer pending ones.
- xen/netback: Add module alias for autoloading
- xen: convert to 64 bit stats interface
- xen/balloon: Fix compile errors - missing header files.
- xen/self-balloon: Add dependency on tmem.
- xen: xen-selfballoon.c needs more header files
- xen/grant: Fix compile warning.
- xen: Fix printk() format in xen/setup.c
- xen: Fix misleading WARN message at xen_release_chunk
- xen/x86: replace order-based range checking of M2P table by linear one
- xen: Do not enable PV IPIs when vector callback not present
- xen-blkfront: Fix one off warning about name clash
- xen-blkfront: Drop name and minor adjustments for emulated scsi devices
- xen/blkback: Make description more obvious.
- xen-blkback: fixed indentation and comments
- SCSI: Fix oops dereferencing queue
- xen: use maximum reservation to limit amount of usable RAM
- xen: x86_32: do not enable iterrupts when returning from exception in interrupt context
- xen/smp: Warn user why they keel over - nosmp or noapic and what to use instead.
- xen: disable PV spinlocks on HVM
- xen/e820: if there is no dom0_mem=, don't tweak extra_pages.
- config: from 6.1 and review
- Revert "IPC reduce lock contention in semctl"
- Revert "IPC lock reduction corners"
- Revert "use rwlocks for ipc"
- Revert "ipc semaphores: order wakeups based on waiter CPU"
- Revert "ipc semaphores: reduce ipc_lock contention in semtimedop

* Thu Aug 25 2011 Guru Anbalagane <guru.anbalagane@oracle.com> [2.6.39-100.0.4.el5uek]
- revert makefile to 2.6.39

* Wed  Aug 24 2011 Guru Anbalagane <guru.anbalagane@oracle.com> [2.6.39-100.0.3.el5uek]
- Rebase to linux-3.0.3

* Thu  Aug 11 2011 Guru Anbalagane <guru.anbalagane@oracle.com> [2.6.39-100.0.2.el5uek]
- [AUDIT/workaround] Increase AUDIT_NAMES array len (Maxim Uvarov)
- Increase kernel log buffer to 1MB (SHIFT=20)
- export list of msi irqs into sysfs (Chris Mason)
- memcg: mark init_section_page_cgroup() properly (Namhyung Kim)
- memcg: fix init_page_cgroup nid with sparsemem (KAMEZAWA Hiroyuki)

* Thu Jul 29 2011 Guru Anbalagane <guru.anbalagane@oracle.com> [2.6.39-100.0.1.el5uek]
- Linux 2.6.39.3
- ipc semaphores: reduce ipc_lock contention in semtimedop
- ipc semaphores: order wakeups based on waiter CPU
- use rwlocks for ipc
- IPC lock reduction corners
- IPC reduce lock contention in semctl
- Batched wakeups from ipc
