%global __spec_install_pre %{___build_pre}

%undefine __brp_mangle_shebangs

# Errors in specfile are causing builds to fail. Adding workarounds.
%define _unpackaged_files_terminate_build       0
%define _missing_doc_files_terminate_build      0
%define _wrong_version_format_terminate_build   0

Summary: Oracle Unbreakable Enterprise Kernel Release 8

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

# define _kernel_cc to allow overrides to kernel make invocations.
# Example:
# % define _kernel_cc CC=gcc7

%define distro_build 0

# Sign modules on x86 and aarch64.  Make sure the config files match this setting if more
# architectures are added.
%ifarch x86_64 aarch64
%global signkernel 1
%else
%global signkernel 0
%endif

# Sign modules on all arches
%global signmodules 1

# base_sublevel is the kernel version we're starting with and patching
# on top of -- for example, 2.6.22-rc7-git1 starts with a 2.6.21 base,
# which yields a base_sublevel of 21.
%define base_sublevel 0

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
%define rpmversion 6.12.%{base_sublevel}%{?stablerev}

## The not-released-kernel case ##
%else
# The next upstream release sublevel (base_sublevel+1)
%define upstream_sublevel %(echo $((%{base_sublevel} + 1)))
# The rc snapshot level
%define rcrev 0
# The git snapshot level
%define gitrev 0
# Set rpm version accordingly
%define rpmversion 6.12.%{upstream_sublevel}
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
# kernel-container
%define with_container 1
# kernel-debug
%define with_debug     1
# kernel-doc
%define with_doc       0
# kernel-headers
%define with_headers   1
# bpftools
%define with_bpftool   1
# tools
%define with_tools     %{?_without_tools:     0} %{?!_without_tools:     1}
# kernel-debuginfo
%define with_debuginfo %{?_without_debuginfo: 0} %{?!_without_debuginfo: 1}
# Want to build a the vsdo directories installed
%define with_vdso_install %{?_without_vdso_install: 0} %{?!_without_vdso_install: 1}
# module compression
%define with_compression 1
#build kernel with 4k & 64k page size for aarch64
%define with_64k_ps %{?_with_64k_ps: %{_with_64k_ps}} %{?!_with_64k_ps: 0}
%define with_64k_ps_debug %{?_with_64k_ps_debug: %{_with_64k_ps_debug}} %{?!_with_64k_ps_debug: 0}
# build embedded/bluefield3 kernel
%define with_embedded %{?_without_embedded: 0} %{?!_without_embedded: 1}
%define with_embedded_debug 0
%if %{with_embedded}
%define with_embedded_debug %{with_debug}
%endif

# verbose build, i.e. no silent rules and V=1
%define with_verbose %{?_with_verbose:        1} %{?!_with_verbose:      0}

%if %{with_verbose}
%define make_opts V=1
%else
%define make_opts -s
%endif

# Build the kernel-doc package, but don't fail the build if it botches.
# Here "true" means "continue" and "false" means "fail the build".
%if 0%{?released_kernel}
%define doc_build_fail false
%else
%define doc_build_fail true
%endif

# This is used to enable/disable kABI checking.
%define with_kabichk 0

# .BTF section must stay in modules
%define _find_debuginfo_opt_btf --keep-section .BTF
%define _find_debuginfo_opts %{_find_debuginfo_opt_btf}

# Additional options for user-friendly one-off kernel building:
#
# Only build the base kernel (--with baseonly):
%define with_baseonly  %{?_with_baseonly:     1} %{?!_with_baseonly:     0}

# Only build the 64k page size kernel (--with 64konly):
%define with_64konly    %{?_with_64konly:       1} %{?!_with_64konly:       0}

# Only build the embedded kernel (--with embeddedonly)
%define with_embeddedonly %{?_with_embeddedonly: 1} %{?!_with_embeddedonly: 0}

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
%define pkg_release 1%{?dist}uek%{?buildid}

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
%define pkg_release 1%{?dist}uek%{?buildid}

%endif

# The kernel tarball/base version
%define kversion 6.12.%{base_sublevel}

%define make_target bzImage

%define hdrarch %_target_cpu
%define asmarch %_target_cpu

%if 0%{!?nopatches:1}
%define nopatches 0
%endif

%if %{with_vanilla}
%define nopatches 1
%endif

%define pkg_release 1%{?dist}uek%{?buildid}

%define KVERREL %{rpmversion}-%{pkg_release}.%{_target_cpu}

%if !%{debugbuildsenabled}
%define with_debug 0
%endif

%if !%{with_debuginfo}
%define _enable_debug_packages 0
%endif
%define debuginfodir /usr/lib/debug

# Needed because we override almost everything involving build-ids
# and debuginfo generation. Currently we rely on the old alldebug setting.
# From the rpm documentation:
# - alldebug
#     build_id links are generated only when the __debug_package global is
#     defined. This will generate build_id links in the -debuginfo package
#     for both the main file as /usr/lib/debug/.build-id/xx/yyy and for
#     the .debug file as /usr/lib/debug/.build-id/xx/yyy.debug.
#     This is the old style build_id links as generated by the original
#     find-debuginfo.sh script.
%global _build_id_links alldebug

# if requested, only build base kernel
%if %{with_baseonly}
%define with_debug 0
%define with_64k_ps 0
%define with_64k_ps_debug 0
%define with_embedded 0
%define with_embedded_debug 0
%endif

%define all_x86 i386 i686

%if %{with_vdso_install}
# These arches install vdso/ directories.
%define vdso_arches %{all_x86} x86_64 aarch64
%endif

# Overrides for generic default options

# don't do debug builds on anything but i686, x86_64, and aarch64
%ifnarch i686 x86_64 aarch64
%define with_debug 0
%endif

# don't do 4k/64k page size or embedded kernels for arch except aarch64
%ifnarch aarch64
%define with_64k_ps       0
%define with_64k_ps_debug 0
%define with_embedded 0
%define with_embedded_debug 0
%endif

# only package docs noarch
%ifnarch noarch
%define with_doc 0
%endif

# don't build noarch kernels or headers (duh)
%ifarch noarch
%define with_up 0
%define with_container 0
%define with_compression 0
%define with_headers 0
%define with_bpftool 0
%define with_tools 0
%endif

# Enable bpftool
%ifarch x86_64 aarch64
%define with_bpftool 1
%endif

# Per-arch tweaks

%ifarch %{all_x86}
%define asmarch x86
%define hdrarch i386
%define image_install_path boot
%define kernel_image arch/x86/boot/bzImage
%endif

%ifarch x86_64
%define asmarch x86
%define image_install_path boot
%define kernel_image arch/x86/boot/bzImage
%if %{with_container}
#
# With binutils >= 2.36 the PVH ELF Note does not function as expected
# due to new .note.gnu.property ELF sections being added by default by
# the assembler.  These .notes are not needed for the kernel so add
# the -mx86-used-note=no switch for the assembler to turn them off
# so that the PVH .note section is created in the location expected
# by the bootloader.
#
%define container_cflags	EXTRA_CFLAGS="-Wa,-mx86-used-note=no"
%endif
%endif

%ifarch %{arm}
%define image_install_path boot
%define hdrarch arm
%define make_target vmlinux
%define kernel_image vmlinux
%endif

%ifarch aarch64
%define image_install_path boot
%define asmarch arm64
%define hdrarch arm64
%define make_target Image
%define kernel_image arch/arm64/boot/Image
%if %{with_64konly}
%define with_64k_ps 1
%define with_up 0
%define with_container 0
%define with_debug 0
%define with_embedded 0
%define with_embedded_debug 0
%define with_headers 0
%define with_bpftool 0
%define with_tools 0
%else
%if %{with_embeddedonly}
%define with_embedded 1
%define with_up 0
%define with_container 0
%define with_64k_ps 0
%define with_debug 0
%define with_headers 0
%define with_bpftool 0
%define with_tools 0
%else
%define with_headers   1
%define with_bpftool   1
%endif
%endif
%endif

# To temporarily exclude an architecture from being built, add it to
# %nobuildarches. Do _NOT_ use the ExclusiveArch: line, because if we
# don't build kernel-headers then the new build system will no longer let
# us use the previous build of that package -- it'll just be completely AWOL.
# Which is a BadThing(tm).

# We don't build a kernel on i386; we only do kernel-headers there,
# and we no longer build for 31bit S390. Same for 32bit sparc and arm.
%define nobuildarches s390 sparc %{arm}

%ifarch %nobuildarches
%define with_up 0
%define with_debuginfo 0
%define _enable_debug_packages 0
%define with_bpftool 0
%define with_tools 0
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
%define package_conflicts initscripts < 7.23, udev < 063-6, iptables < 1.3.2-1, ipw2200-firmware < 2.4, selinux-policy-targeted < 1.25.3-14, device-mapper-multipath < 0.4.9-64, dracut < 004-303.0.3

#
# Packages that need to be installed before the kernel is, because the %post
# scripts use them.
#
%define kernel_prereq  coreutils, systemd >= 203-2, /usr/bin/kernel-install
%define initrd_prereq  dracut >= 027

%define variant %{?build_variant:%{build_variant}}%{!?build_variant:-luci}

%define installonly_variant_name kernel-uek

Name: kernel%{?variant}
Group: System Environment/Kernel
License: GPLv2
URL: http://www.kernel.org/
Version: %{rpmversion}
Release: %{pkg_release}
# DO NOT CHANGE THE 'ExclusiveArch' LINE TO TEMPORARILY EXCLUDE AN ARCHITECTURE BUILD.
# SET %%nobuildarches (ABOVE) INSTEAD
ExclusiveArch: noarch %{all_x86} x86_64 %{arm} aarch64
ExclusiveOS: Linux
%ifnarch %{nobuildarches}
Requires: %{name}-core-uname-r = %{KVERREL}
Requires: %{name}-modules-uname-r = %{KVERREL}
Requires: %{name}-modules-core-uname-r = %{KVERREL}
%endif

#
# List the packages used during the kernel build
#
BuildRequires: kmod, patch >= 2.5.4, bash >= 2.03, sh-utils, tar, git
BuildRequires: bzip2, xz, findutils, gzip, m4, perl-interpreter, perl-Carp, perl-devel, perl-generators, make >= 3.78, diffutils, gawk
BuildRequires: gcc-toolset-13-annobin-plugin-gcc
BuildRequires: gcc-toolset-13-binutils
BuildRequires: gcc-toolset-13-gcc
BuildRequires: gcc-toolset-13-gcc-c++
BuildRequires: gcc-toolset-13-runtime
BuildRequires: gcc-toolset-13-gcc-plugin-annobin
BuildRequires: gcc-toolset-13-binutils-devel
BuildRequires: redhat-rpm-config >= 130-1, hmaccalc, python3-devel
BuildRequires: net-tools, hostname
BuildRequires: elfutils-libelf-devel
BuildRequires: python3, python3-devel
BuildRequires: flex >= 2.5.19, bison >= 2.3
BuildRequires: pkgconfig
BuildRequires: glib2-devel
BuildRequires: elfutils-devel
BuildRequires: bc
BuildRequires: hostname
BuildRequires: openssl, openssl-devel
BuildRequires: rsync
BuildRequires: numactl-devel
BuildRequires: dwarves >= 1.25
BuildRequires: slang-devel
%if %{with_sparse}
BuildRequires: sparse >= 0.4.1
%endif

%ifarch x86_64
BuildRequires: libcap-devel
%endif
%if %{signkernel}%{signmodules}
BuildRequires: openssl openssl-devel
%if %{signkernel}
BuildRequires: nss-tools
BuildRequires: pesign >= 0.10-4
%endif
%endif

%if %{with_doc}
BuildRequires: python3-sphinx >= 1.7.9, python3-pyyaml
BuildRequires: fontconfig >= 2.13.0
%endif

%if %{with_bpftool}
BuildRequires: python3-docutils
BuildRequires: zlib-devel
%endif
BuildConflicts: rhbuildsys(DiskFree) < 500Mb

%if %{with_debuginfo}
BuildRequires: rpm-build
BuildRequires: elfutils
BuildConflicts: rpm < 4.13.0.1-19

## See /usr/lib/rpm/macros on OL8 for macro descriptions.
%undefine _include_minidebuginfo
%undefine _find_debuginfo_dwz_opts
%undefine _unique_build_ids
%undefine _unique_debug_names
%undefine _unique_debug_srcs
%undefine _debugsource_packages
%undefine _debuginfo_subpackages

# Terminate the build if the ELF file processed by find-debuginfo.sh has no build ID
%global _missing_build_ids_terminate_build 1

# Do not recompute build-ids but keep whatever is in the ELF file already.
%global _no_recompute_build_ids 1

%endif

Source0: linux-%{kversion}.tar.bz2

%if %{signkernel}%{signmodules}
Source10: x509.genkey
%endif

Source11: mod-denylist.sh
Source12: mod-extra.list
Source13: mod-sign.sh
%define modsign_cmd %{SOURCE13}

Source14: find-provides
Source16: perf
Source17: kabitool
Source18: check-kabi
Source20: x86_energy_perf_policy
Source21: securebootca.cer
Source22: secureboot.cer
Source23: turbostat
source24: secureboot_aarch64.cer
Source43: generate_bls_conf.sh
Source44: modules-core-x86_64.list
Source45: modules-core-aarch64.list
Source46: filter-modules.sh
Source47: core-emb3-aarch64.list

Source1000: config-x86_64
Source1001: config-x86_64-debug
Source1002: config-x86_64-container
Source1007: config-aarch64
Source1008: config-aarch64-debug
Source1009: config-aarch64-container
Source1010: config-aarch64-emb3
Source1011: config-aarch64-emb3-debug

Source25: Module.kabi_x86_64debug
Source26: Module.kabi_x86_64
Source27: Module.kabi_aarch64debug
Source28: Module.kabi_aarch64
Source29: Symtypes.kabi_x86_64debug
Source30: Symtypes.kabi_x86_64
Source31: Symtypes.kabi_aarch64debug
Source32: Symtypes.kabi_aarch64
Source33: kabi

Source200: kabi_lockedlist_x86_64debug
Source201: kabi_lockedlist_x86_64
Source202: kabi_lockedlist_aarch64debug
Source203: kabi_lockedlist_aarch64

%if "kernel%{?variant}" != "%{installonly_variant_name}"
Provides: %{installonly_variant_name}
%endif

%ifarch x86_64
%define sb_cer %{SOURCE22}
%endif

%ifarch aarch64
%define sb_cer %{SOURCE24}
%endif

BuildRoot: %{_tmppath}/kernel-%{KVERREL}-root

%ifnarch aarch64 x86_64
# Override find_provides to use a script that provides "kernel(symbol) = hash".
# Pass path of the RPM temp dir containing kabideps to find-provides script.
%global _use_internal_dependency_generator 0
%define __find_provides %_sourcedir/find-provides %{_tmppath}
%define __find_requires /usr/lib/rpm/redhat/find-requires kernel
%endif

# END OF PATCH DEFINITIONS

%description
It is a kernel%{?variant} meta package.

%package doc
Summary: Various documentation bits found in the kernel source
Group: Documentation
Obsoletes: kernel-doc
Provides: kernel-doc
AutoReq: no
%description doc
This package contains documentation files from the kernel
source. Various bits of information about the Linux kernel and the
device drivers shipped with it are documented in these files.

You'll want to install this package if you need a reference to the
options that can be passed to Linux kernel modules at load time.


%if %{with_container}
%package -n kernel%{variant}-container
Summary: The Linux kernel optimized for running inside a container
Group: Development/System
%description  -n kernel%{variant}-container
Container kernel

%package -n kernel%{variant}-container-debug
Summary: Debug conmponents for the UEK container kernel
Group: Development/System
AutoReq: no
%description  -n kernel%{variant}-container-debug
Container kernel config file and System.map
%endif

%if %{with_headers}
%package headers
Summary: Header files for the Linux kernel for use by glibc
Group: Development/System
Conflicts: glibc-kernheaders
Conflicts: kernel-headers
Provides: kernel-headers
Provides: glibc-kernheaders = 3.0-46
AutoReq: no
%description headers
Kernel-headers includes the C header files that specify the interface
between the Linux kernel and userspace libraries and programs.  The
header files define structures and constants that are needed for
building most standard programs and are also needed for rebuilding the
glibc package.
%endif

%package debuginfo-common
Summary: Kernel source files used by %{name}-debuginfo packages
Group: Development/Debug
Provides: %{name}-debuginfo-common-%{_target_cpu} = %{version}-%{release}
Provides: installonlypkg(%{installonly_variant_name})
AutoReq: no
%description debuginfo-common
This package is required by %{name}-debuginfo subpackages.
It provides the kernel source files common to all builds.

%if %{with_bpftool}

%package -n bpftool
Summary: Inspection and simple manipulation of eBPF programs and maps
License: GPLv2
%description -n bpftool
This package contains the bpftool, which allows inspection and simple
manipulation of eBPF programs and maps.

%package -n bpftool-debuginfo
Summary: Debug information for package bpftool
Group: Development/Debug
Requires: %{name}-debuginfo-common-%{_target_cpu} = %{version}-%{release}
AutoReqProv: no
%description -n bpftool-debuginfo
This package provides debug information for the bpftool package.

%{expand:%%global _find_debuginfo_opts %{?_find_debuginfo_opts} -p '.*%%{_sbindir}/bpftool(\.debug)?|XXX' -o bpftool-debuginfo.list}

#with_bpftool
%endif

%if %{with_tools}
%package -n kernel%{?variant}-tools
Summary: Assortment of tools for the Linux kernel
License: GPLv2
BuildRequires: libtraceevent
BuildRequires: libtraceevent-devel
Requires: libtraceevent
Requires: slang
%ifnarch aarch64
Provides: x86_energy_perf_policy = %{KVERREL}
Provides: turbostat = %{KVERREL}
%endif
Provides: perf = %{KVERREL}
Provides: installonlypkg(%{installonly_variant_name}-tools)
%description -n kernel%{?variant}-tools
This package contains some of tools/ directory binaries from the kernel source.
%endif

#
# This macro does requires, provides, conflicts, obsoletes for a kernel package.
#	%%kernel_reqprovconf <subpackage>
# It uses any kernel_<subpackage>_conflicts and kernel_<subpackage>_obsoletes
# macros defined above.
#
%define kernel_reqprovconf \
Provides: %{name} = %{rpmversion}-%{pkg_release}\
Provides: %{variant_name} = %{rpmversion}-%{pkg_release}\
Provides: %{variant_name}-%{_target_cpu} = %{rpmversion}-%{pkg_release}%{?1:.%{1}}\
Provides: %{variant_name}-uname-r = %{KVERREL}%{?1:.%{1}}\
Provides: %{name}-drm = 4.3.0\
Provides: %{name}-drm-nouveau = 12\
Provides: %{name}-modeset = 1\
Provides: oracleasm = 2.0.5\
%ifarch aarch64\
Provides: kernel = %{rpmversion}-%{pkg_release}\
Provides: kernel-uname-r = %{KVERREL}%{?1:.%{1}}\
%endif\
Requires: %{variant_name}-modules-core-uname-r = %{KVERREL}%{?1:.%{1}}\
Requires(pre): %{kernel_prereq}\
Requires(pre): %{initrd_prereq}\
Requires(pre): system-release\
Requires(post): /usr/bin/kernel-install\
Requires(preun): /usr/bin/kernel-install\
Requires: numactl-libs\
Conflicts: %{kernel_dot_org_conflicts}\
Conflicts: %{package_conflicts}\
Conflicts: shim-x64 <= 15.3-1.0.3\
Conflicts: shim-ia32 <= 15.3-1.0.3\
Provides: oracle(kernel-sig-key) == 202204\
%{expand:%%{?kernel%{?1:_%{1}}_conflicts:Conflicts: %%{kernel%{?1:_%{1}}_conflicts}}}\
%{expand:%%{?kernel%{?1:_%{1}}_obsoletes:Obsoletes: %%{kernel%{?1:_%{1}}_obsoletes}}}\
%{expand:%%{?kernel%{?1:_%{1}}_provides:Provides: %%{kernel%{?1:_%{1}}_provides}}}\
# We can't let RPM do the dependencies automatic because it'll then pick up\
# a correct but undesirable perl dependency from the module headers which\
# isn't required for the kernel proper to function\
AutoReq: no\
AutoProv: yes\
%{nil}

#
# This macro creates a kernel%%{?variant}-<subpackage>-debuginfo package.
#	%%kernel_debuginfo_package [-o] <subpackage>
# -o flag omits the hyphen preceding <subpackage> in the package name
#
%define kernel_debuginfo_package(o) \
%define variant_name kernel%{?variant}%{?1:%{!-o:-}%{1}}\
%package -n %{variant_name}-debuginfo\
Summary: Debug information for package %{variant_name}\
Group: Development/Debug\
Requires: %{name}-debuginfo-common-%{_target_cpu} = %{version}-%{release}\
Provides: %{variant_name}-debuginfo-%{_target_cpu} = %{version}-%{release}\
Provides: installonlypkg(%{installonly_variant_name})\
AutoReqProv: no\
%description -n %{variant_name}-debuginfo\
This package provides debug information for package %{variant_name}.\
This is required to use SystemTap with %{variant_name}-%{KVERREL}.\
%{expand:%%global _find_debuginfo_opts %{?_find_debuginfo_opts} -p '/.*/%%{KVERREL}%{?1:\.%{1}}/.*|/.*%%{KVERREL}%{?1:\.%{1}}(\.debug)?' -o debuginfo%{?1}.list}\
%{nil}

#
# This macro creates a kernel%%{?variant}-<subpackage>-devel package.
#	%%kernel_devel_package [-o] <subpackage> <pretty-name>
# -o flag omits the hyphen preceding <subpackage> in the package name
#
%define kernel_devel_package(o) \
%define variant_name kernel%{?variant}%{?1:%{!-o:-}%{1}}\
%package -n %{variant_name}-devel\
Summary: Development package for building kernel modules to match the %{?2:%{2}} kernel\
Group: System Environment/Kernel\
Provides: %{variant_name}-devel-%{_target_cpu} = %{version}-%{release}\
Provides: kernel%{?variant}-xen-devel = %{version}-%{release}%{?1:.%{1}}\
Provides: kernel%{?variant}-devel-%{_target_cpu} = %{version}-%{release}%{?1:.%{1}}\
Provides: kernel%{?variant}-devel = %{version}-%{release}%{?1:.%{1}}\
Provides: kernel%{?variant}-devel-uname-r = %{KVERREL}%{?1:.%{1}}\
%ifarch aarch64\
Provides: kernel-devel = %{version}-%{release}%{?1:.%{1}}\
Provides: kernel-devel-uname-r = %{KVERREL}%{?1:.%{1}}\
%endif\
Provides: installonlypkg(%{installonly_variant_name})\
AutoReqProv: no\
Requires(pre): /usr/bin/find\
Requires: elfutils-libelf-devel\
Requires: elfutils-libs\
Requires: gcc-toolset-13-annobin-plugin-gcc\
Requires: gcc-toolset-13-binutils\
Requires: gcc-toolset-13-gcc\
Requires: gcc-toolset-13-gcc-c++\
Requires: gcc-toolset-13-runtime\
Requires: gcc-toolset-13-binutils-devel\
%description -n %{variant_name}-devel\
This package provides kernel headers and makefiles sufficient to build modules\
against the %{?2:%{2}} kernel package.\
%{nil}

#
# This macro creates a kernel%%{?variant}-<subpackage>-modules-extra package.
#       %%kernel_modules_extra_package [-o] <subpackage> <pretty-name>
# -o flag omits the hyphen preceding <subpackage> in the package name
#
%define kernel_modules_extra_package(o) \
%define variant_name kernel%{?variant}%{?1:%{!-o:-}%{1}}\
%package -n %{variant_name}-modules-extra\
Summary: Extra kernel modules to match the %{?2:%{2}-}core kernel\
Group: System Environment/Kernel\
Provides: %{variant_name}-modules-extra-%{_target_cpu} = %{version}-%{release}%{?1:.%{1}}\
Provides: %{variant_name}-modules-extra = %{version}-%{release}%{?1:.%{1}}\
Provides: installonlypkg(%{installonly_variant_name}-modules)\
Provides: %{variant_name}-modules-extra-uname-r = %{KVERREL}%{?1:.%{1}}\
Requires: %{variant_name}-modules-uname-r = %{KVERREL}%{?1:.%{1}}\
Requires: %{variant_name}-modules-core-uname-r = %{KVERREL}%{?1:.%{1}}\
AutoReq: no\
AutoProv: yes\
%description -n %{variant_name}-modules-extra\
This package provides less commonly used kernel modules for the %{?2:%{2}-}core kernel package.\
%{nil}

#
# This macro creates a kernel%%{?variant}-<subpackage>-modules package.
#       %%kernel_modules_package [-o] <subpackage> <pretty-name>
# -o flag omits the hyphen preceding <subpackage> in the package name
#
%define kernel_modules_package(o) \
%define variant_name kernel%{?variant}%{?1:%{!-o:-}%{1}}\
%package -n %{variant_name}-modules\
Summary: kernel modules to match the %{?2:%{2}-}core kernel\
Group: System Environment/Kernel\
Provides: %{variant_name}-modules-%{_target_cpu} = %{version}-%{release}%{?1:.%{1}}\
Provides: %{variant_name}-modules = %{version}-%{release}%{?1:.%{1}}\
Provides: installonlypkg(%{installonly_variant_name}-modules)\
Provides: %{variant_name}-modules-uname-r = %{KVERREL}%{?1:.%{1}}\
Requires: %{variant_name}-uname-r = %{KVERREL}%{?1:.%{1}}\
Requires: %{variant_name}-modules-core-uname-r = %{KVERREL}%{?1:.%{1}}\
Requires: linux-firmware >= 999:20230516-999.26.git6c9e0ed5\
AutoReq: no\
AutoProv: yes\
%description -n %{variant_name}-modules\
This package provides commonly used kernel modules for the %{?2:%{2}-}core kernel package.\
%{nil}

#
# This macro creates a kernel%%{?variant}-<subpackage>-modules-core package.
#       %%kernel_modules_core_package [-o] <subpackage> <pretty-name>
# -o flag omits the hyphen preceding <subpackage> in the package name
#
%define kernel_modules_core_package(o) \
%define variant_name kernel%{?variant}%{?1:%{!-o:-}%{1}}\
%package -n %{variant_name}-modules-core\
Summary: Core kernel modules to match the %{?2:%{2}-}core kernel\
Group: System Environment/Kernel\
Provides: %{variant_name}-modules-core-%{_target_cpu} = %{version}-%{release}%{?1:.%{1}}\
Provides: %{variant_name}-modules-core = %{version}-%{release}%{?1:.%{1}}\
Provides: installonlypkg(%{installonly_variant_name}-modules-core)\
Provides: %{variant_name}-modules-core-uname-r = %{KVERREL}%{?1:.%{1}}\
Requires: %{variant_name}-core-uname-r = %{KVERREL}%{?1:.%{1}}\
Requires: linux-firmware-core >= 999:20230516-999.26.git6c9e0ed5\
Requires: libdnf >= 0.63.0-17.0.2\
AutoReq: no\
AutoProv: yes\
%description -n %{variant_name}-modules-core\
This package provides essential kernel modules for the %{?2:%{2}-}core kernel package.\
%{nil}

#
# This macro creates a kernel%%{?variant}-<subpackage> meta package.
#       %%kernel_meta_package [-o] <subpackage>
# -o flag omits the hyphen preceding <subpackage> in the package name
#
%define kernel_meta_package(o) \
%define variant_name kernel%{?variant}%{?1:%{!-o:-}%{1}}\
%package -n %{variant_name}\
Summary: Kernel meta-package for the %{1} kernel\
Group: System Environment/Kernel\
Requires: %{variant_name}-core-uname-r = %{KVERREL}.%{1}\
Requires: %{variant_name}-modules-uname-r = %{KVERREL}.%{1}\
Requires: %{variant_name}-modules-core-uname-r = %{KVERREL}.%{1}\
Provides: installonlypkg(%{installonly_variant_name})\
%description -n %{variant_name}\
The meta-package for the %{1} kernel\
%{nil}

#
# This macro creates a kernel%%{?variant}-<subpackage> and its -devel and -debuginfo too.
#	%%define variant_summary The Linux kernel compiled for <configuration>
#	%%kernel_variant_package [-n <pretty-name>] [-o] <subpackage>
# -o flag omits the hyphen preceding <subpackage> in the package name
#
%define kernel_variant_package(n:o) \
%define variant_name kernel%{?variant}%{?1:%{!-o:-}%{1}}\
%package -n %{variant_name}-core\
Summary: %{variant_summary}\
Group: System Environment/Kernel\
Provides: %{variant_name}-core-uname-r = %{KVERREL}%{?1:.%{1}}\
Provides: installonlypkg(%{installonly_variant_name}-core)\
%ifarch x86_64\
%if %{?1:0}%{!?1:1}\
Provides: kernel-ueknano = %{KVERREL}%{?1:.%{1}}\
%endif\
%endif\
%{expand:%%kernel_reqprovconf}\
%if %{?1:1} %{!?1:0} \
%{expand:%%kernel_meta_package %{-o:%{-o}} %{?1:%{1}}}\
%endif\
%{expand:%%kernel_devel_package %{-o:%{-o}} %{?1:%{1}} %{!?{-n}:%{1}}%{?{-n}:%{-n*}}}\
%{expand:%%kernel_modules_package %{-o:%{-o}} %{?1:%{1}} %{!?{-n}:%{1}}%{?{-n}:%{-n*}}}\
%{expand:%%kernel_modules_core_package %{-o:%{-o}} %{?1:%{1}} %{!?{-n}:%{1}}%{?{-n}:%{-n*}}}\
%{expand:%%kernel_modules_extra_package %{-o:%{-o}} %{?1:%{1}} %{!?{-n}:%{1}}%{?{-n}:%{-n*}}}\
%{expand:%%kernel_debuginfo_package %{-o:-o} %{?1:%{1}}}\
%{nil}

# Now, each variant package.
%define variant_summary A aarch64 kernel with 64k page size.
%kernel_variant_package -o 64k
%description -n kernel%{?variant}64k-core
This package includes 64k page size for aarch64 kernel.

%define variant_summary The Aarch64 Linux kernel compiled with extra debugging enabled
%kernel_variant_package -o 64kdebug
%description -n kernel%{?variant}64kdebug-core
This package include debug kernel for 64k page size.

%define variant_summary The Aarch64 Linux kernel compiled for the Bluefield 3 platform
%kernel_variant_package -o emb3
%description -n kernel%{?variant}emb3-core
This package includes Bluefield 3 kernel for aarch64 platform

%define variant_summary The Aarch64 Bluefield 3 Linux kernel compiled with extra debugging enabled
%kernel_variant_package -o emb3debug
%description -n kernel%{?variant}emb3debug-core
This package includes debug kernel  for Bluefield 3 platform

%define variant_summary The Linux kernel compiled with extra debugging enabled
%kernel_variant_package debug
%description debug-core
The kernel package contains the Linux kernel (vmlinuz), the core of any
Linux operating system.  The kernel handles the basic functions
of the operating system:  memory allocation, process allocation, device
input and output, etc.

This variant of the kernel has numerous debugging options enabled.
It should only be installed when trying to gather additional information
on kernel bugs, as some of these options impact performance noticably.

# And finally the main -core package
%define variant_summary The Linux kernel
%kernel_variant_package
%description core
The kernel package contains the Linux kernel (vmlinuz), the core of any
Linux operating system.  The kernel handles the basic functions
of the operating system: memory allocation, process allocation, device
input and output, etc.

%prep
# Enable gcc-toolset-13
source /opt/rh/gcc-toolset-13/enable
gcc --version

# do a few sanity-checks for --with *only builds
%if %{with_baseonly}
%if !%{with_up}
echo "Cannot build --with baseonly, up build is disabled"
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
  if ! egrep "^Patch[0-9]+: $patch\$" %{_specdir}/%{name}*.spec ; then
    [ "${patch:0:10}" != "patch-2.6." ] && echo "Patch $patch not listed in specfile" && exit 1;
  fi
  case "$patch" in
  *.bz2) bunzip2 < "$RPM_SOURCE_DIR/$patch" | $patch_command ${1+"$@"} ;;
  *.gz) gunzip < "$RPM_SOURCE_DIR/$patch" | $patch_command ${1+"$@"} ;;
  *) $patch_command ${1+"$@"} < "$RPM_SOURCE_DIR/$patch" ;;
  esac
}

# First we unpack the kernel tarball.
# If this isn't the first make prep, we use links to the existing clean tarball
# which speeds things up quite a bit.

# Update to latest upstream.
%if 0%{?released_kernel}
%define vanillaversion 6.12.%{base_sublevel}
# non-released_kernel case
%else
%if 0%{?rcrev}
%define vanillaversion 6.12.%{upstream_sublevel}-rc%{rcrev}
%if 0%{?gitrev}
%define vanillaversion 6.12.%{upstream_sublevel}-rc%{rcrev}-git%{gitrev}
%endif
%else
# pre-{base_sublevel+1}-rc1 case
%if 0%{?gitrev}
%define vanillaversion 6.12.%{base_sublevel}-git%{gitrev}
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

cp -rl vanilla-%{vanillaversion} linux-%{kversion}-%{release}
cd linux-%{kversion}-%{release}

# released_kernel with possible stable updates
%if 0%{?stable_base}
ApplyPatch %{stable_patch_00}
%endif
%if 0%{?stable_rc}
ApplyPatch %{stable_patch_01}
%endif

# only deal with configs if we are going to build for the arch
# %ifnarch %nobuildarches

mkdir -p configs
%ifarch x86_64
	cp %{SOURCE1002} configs/config-container
	cp %{SOURCE1001} configs/config-debug
	cp %{SOURCE1000} configs/config
%endif

%ifarch aarch64
	cp %{SOURCE1009} configs/config-container
	cp %{SOURCE1008} configs/config-debug
	cp %{SOURCE1007} configs/config
	cp %{SOURCE1010} configs/config-emb3
	cp %{SOURCE1011} configs/config-emb3-debug
%endif

# get rid of unwanted files resulting from patch fuzz
find . \( -name "*.orig" -o -name "*~" \) -exec rm -f {} \; >/dev/null

###
### build
###
%build
# Enable gcc-toolset-13
source /opt/rh/gcc-toolset-13/enable
gcc --version

%if %{with_sparse}
%define sparse_mflags	C=1
%endif

%if %{with_compression}
%define zipsed -e 's/\.ko$/\.ko.xz/'
%endif

cp_vmlinux()
{
  eu-strip --remove-comment -o "$2" "$1"
}

# We rely on CONFIG_BUILD_SALT to get unique build IDs for the kernel
# and modules with different versions, yet identical code. But for
# host programs, the build salt is not applied so we still get build
# ID collisions. Fall back to using UUID-based build IDs in this case,
# which is less reproducible, but is simple and avoids collisions.

%define build_hostcflags  %{?build_cflags}
%define build_hostldflags %{?build_ldflags} -Wl,--build-id=uuid

%define make %{__make} %{?make_opts} HOSTCFLAGS="%{?build_hostcflags}" HOSTLDFLAGS="%{?build_hostldflags}"

# adapted from scripts/subarch.incl
Arch=$(echo %{_target_cpu} | sed -e s/i.86/x86/ -e s/x86_64/x86/ \
				 -e s/sun4u/sparc64/ \
				 -e s/arm.*/arm/ -e s/sa110/arm/ \
				 -e s/s390x/s390/ \
				 -e s/ppc.*/powerpc/ -e s/mips.*/mips/ \
				 -e s/sh[234].*/sh/ -e s/aarch64.*/arm64/ \
				 -e s/riscv.*/riscv/ -e s/loongarch.*/loongarch/)

BuildContainerKernel() {
    MakeTarget=$1
    KernelImage=$2
    Flavour=$3

    ExtraVer="-%{release}.container"

    echo BUILDING A KERNEL FOR ${Flavour} %{_target_cpu}...

    perl -p -i -e "s/^EXTRAVERSION.*/EXTRAVERSION = ${ExtraVer}/" Makefile

    %{make} mrproper
    cp configs/config-container .config

    %{make} ARCH=$Arch %{?_kernel_cc} olddefconfig > /dev/null

    # This ensures build-ids are unique to allow parallel debuginfo
    perl -p -i -e "s/^CONFIG_BUILD_SALT.*/CONFIG_BUILD_SALT=\"%{KVERREL}\"/" .config

    %{make} %{?container_cflags} %{?_smp_mflags} ARCH=$Arch %{?_kernel_cc} %{?sparse_mflags} || exit 1

    # Install
    KernelVer=%{kversion}-%{release}
    KernelDir=%{buildroot}/usr/share/kata-containers

    mkdir   -p ${KernelDir}

    install -m 755 $KernelImage ${KernelDir}/vmlinuz-$KernelVer
    ln -sf vmlinuz-$KernelVer ${KernelDir}/vmlinuz.container

    eu-strip --remove-comment vmlinux -o ${KernelDir}/vmlinux-$KernelVer
    chmod 755 ${KernelDir}/vmlinux-$KernelVer
    ln -sf vmlinux-$KernelVer ${KernelDir}/vmlinux.container

    install -m 644 .config "${KernelDir}/config-${KernelVer}"
    install -m 644 System.map "${KernelDir}/System.map-${KernelVer}"
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

    KernelVer=%{version}-%{release}.%{_target_cpu}${Flavour:+.${Flavour}}
    echo BUILDING A KERNEL FOR ${Flavour} %{_target_cpu}...

    # make sure EXTRAVERSION says what we want it to say
    perl -p -i -e "s/^EXTRAVERSION.*/EXTRAVERSION = %{?stablerev}-%{release}.%{_target_cpu}${Flavour:+.${Flavour}}/" Makefile
    #perl -p -i -e "s/^SUBLEVEL.*/SUBLEVEL = %{base_sublevel}/" Makefile

    %{make} mrproper

%if %{signkernel}%{signmodules}
    cp %{SOURCE10} certs/.
%endif

    if [ "$Flavour" == "debug" ]; then
	cp configs/config-debug .config
	modlistVariant=../kernel%{?variant}-debug
    elif [ "$Flavour" == "64k" ]; then
	sed -i '/^CONFIG_ARM64_[0-9]\+K_PAGES=/d' configs/config
	echo 'CONFIG_ARM64_64K_PAGES=y' >> configs/config
	cp configs/config .config
	modlistVariant=../kernel%{?variant}64k
    elif [ "$Flavour" == "64kdebug" ]; then
	sed -i '/^CONFIG_ARM64_[0-9]\+K_PAGES=/d' configs/config-debug
	echo 'CONFIG_ARM64_64K_PAGES=y' >> configs/config-debug
	cp configs/config-debug .config
	modlistVariant=../kernel%{?variant}64kdebug
    elif [ "$Flavour" == "emb3" ]; then
        cp configs/config-emb3 .config
	modlistVariant=../kernel%{?variant}emb3
    elif [ "$Flavour" == "emb3debug" ]; then
        cp configs/config-emb3-debug .config
	modlistVariant=../kernel%{?variant}emb3debug
    else
	cp configs/config .config
	modlistVariant=../kernel%{?variant}${Flavour:+-${Flavour}}
    fi

    echo USING ARCH=$Arch
    %{make} ARCH=$Arch %{?_kernel_cc} olddefconfig > /dev/null

    # This ensures build-ids are unique to allow parallel debuginfo
    perl -p -i -e "s/^CONFIG_BUILD_SALT.*/CONFIG_BUILD_SALT=\"%{KVERREL}\"/" .config

    if [ "$Flavour" != "64k" ] && [ "$Flavour" != "64kdebug" ] && [ "$Flavour" != "emb3" ] && [ "$Flavour" != "emb3debug" ]; then
       %{make} ARCH=$Arch KBUILD_SYMTYPES=y %{?_kernel_cc} %{?_smp_mflags} $MakeTarget modules %{?sparse_mflags} || exit 1
    else
       %{make} ARCH=$Arch %{?_kernel_cc} %{?_smp_mflags} $MakeTarget modules %{?sparse_mflags} || exit 1
    fi
    mkdir -p $RPM_BUILD_ROOT/%{image_install_path}
    mkdir -p $RPM_BUILD_ROOT/lib/modules/$KernelVer
%ifarch %{arm} aarch64
    %{make} ARCH=$Arch %{?_kernel_cc} dtbs dtbs_install INSTALL_DTBS_PATH=$RPM_BUILD_ROOT/%{image_install_path}/dtb-$KernelVer
    cp -r $RPM_BUILD_ROOT/%{image_install_path}/dtb-$KernelVer $RPM_BUILD_ROOT/lib/modules/$KernelVer/dtb
    find arch/$Arch/boot/dts -name '*.dtb' -type f | xargs rm -f
%endif

    # Start installing the results
%if %{with_debuginfo}
    mkdir -p $RPM_BUILD_ROOT%{debuginfodir}/boot
    mkdir -p $RPM_BUILD_ROOT%{debuginfodir}/%{image_install_path}
%endif
    mkdir -p $RPM_BUILD_ROOT/%{image_install_path}
    mkdir -p $RPM_BUILD_ROOT/lib/modules/$KernelVer
    install -m 644 .config $RPM_BUILD_ROOT/boot/config-$KernelVer
    install -m 644 .config $RPM_BUILD_ROOT/lib/modules/$KernelVer/config
    install -m 644 System.map $RPM_BUILD_ROOT/boot/System.map-$KernelVer
    install -m 644 System.map $RPM_BUILD_ROOT/lib/modules/$KernelVer/System.map

    # We estimate the size of the initramfs because rpm needs to take this size
    # into consideration when performing disk space calculations. (See bz #530778)
    dd if=/dev/zero of=$RPM_BUILD_ROOT/boot/initramfs-$KernelVer.img bs=1M count=20

    if [ -f arch/$Arch/boot/zImage.stub ]; then
      cp arch/$Arch/boot/zImage.stub $RPM_BUILD_ROOT/%{image_install_path}/zImage.stub-$KernelVer || :
    fi
%if %{signkernel}
    # Sign the image if we're using EFI
    %pesign -s -i $KernelImage -o $KernelImage.signed -a %{SOURCE21} -c %{sb_cer} -n oraclesecureboot
    mv $KernelImage.signed $KernelImage
%endif
    $CopyKernel $KernelImage \
		$RPM_BUILD_ROOT/%{image_install_path}/$InstallName-$KernelVer
    chmod 755 $RPM_BUILD_ROOT/%{image_install_path}/$InstallName-$KernelVer
    cp $RPM_BUILD_ROOT/%{image_install_path}/$InstallName-$KernelVer $RPM_BUILD_ROOT/lib/modules/$KernelVer/$InstallName

    # hmac sign the kernel for FIPS
    echo "Creating hmac file: $RPM_BUILD_ROOT/%{image_install_path}/.vmlinuz-$KernelVer.hmac"
    ls -l $RPM_BUILD_ROOT/%{image_install_path}/$InstallName-$KernelVer
    sha512hmac $RPM_BUILD_ROOT/%{image_install_path}/$InstallName-$KernelVer | sed -e "s,$RPM_BUILD_ROOT,," > $RPM_BUILD_ROOT/%{image_install_path}/.vmlinuz-$KernelVer.hmac;
    cp $RPM_BUILD_ROOT/%{image_install_path}/.vmlinuz-$KernelVer.hmac $RPM_BUILD_ROOT/lib/modules/$KernelVer/.vmlinuz.hmac

    mkdir -p $RPM_BUILD_ROOT/lib/modules/$KernelVer
    %{make} ARCH=$Arch %{?_kernel_cc} %{?_smp_mflags} INSTALL_MOD_PATH=$RPM_BUILD_ROOT modules_install KERNELRELEASE=$KernelVer
    # check if the modules are being signed

%ifarch %{vdso_arches}
    %{make} ARCH=$Arch %{?_kernel_cc} %{?_smp_mflags} INSTALL_MOD_PATH=$RPM_BUILD_ROOT vdso_install KERNELRELEASE=$KernelVer
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
    if grep -q '^CONFIG_STACK_VALIDATION=y' .config ; then
      cp --parents `find tools/objtool -type f -executable` $RPM_BUILD_ROOT/lib/modules/$KernelVer/build
    fi
    if [ ! -e Module.symvers ]; then
      touch Module.symvers
    fi
    cp Module.symvers $RPM_BUILD_ROOT/lib/modules/$KernelVer/build
    cp System.map $RPM_BUILD_ROOT/lib/modules/$KernelVer/build
    if [ -s Module.markers ]; then
      cp Module.markers $RPM_BUILD_ROOT/lib/modules/$KernelVer/build
    fi

    # create the kABI metadata for use in packaging
    echo "**** GENERATING kernel ABI metadata ****"
    gzip -c9 < Module.symvers > $RPM_BUILD_ROOT/boot/symvers-$KernelVer.gz
    cp $RPM_BUILD_ROOT/boot/symvers-$KernelVer.gz $RPM_BUILD_ROOT/lib/modules/$KernelVer/symvers.gz
    chmod 0755 %_sourcedir/kabitool
    if [ -e $RPM_SOURCE_DIR/kabi_lockedlist_%{_target_cpu}$Flavour ]; then
       cp $RPM_SOURCE_DIR/kabi_lockedlist_%{_target_cpu}$Flavour $RPM_BUILD_ROOT/lib/modules/$KernelVer/build/kabi_lockedlist
    fi
    rm -f %{_tmppath}/kernel-$KernelVer-kabideps
    %_sourcedir/kabitool -s Module.symvers -o %{_tmppath}/kernel-$KernelVer-kabideps

%if %{with_kabichk}
    if [ "$Flavour" != "64k" ] && [ "$Flavour" != "64kdebug" ] && [ "$Flavour" != "emb3" ] && [ "$Flavour" != "emb3debug" ]; then
       # Create symbol type data which can be used to introspect kABI breakages
       python3 $RPM_SOURCE_DIR/kabi collect . -o Symtypes.build

       echo "**** kABI checking is enabled in kernel SPEC file for %{_target_cpu}. ****"
       chmod 0755 $RPM_SOURCE_DIR/check-kabi
       if [ -e $RPM_SOURCE_DIR/Module.kabi_%{_target_cpu}$Flavour ]; then
          cp $RPM_SOURCE_DIR/Module.kabi_%{_target_cpu}$Flavour $RPM_BUILD_ROOT/Module.kabi
          cp $RPM_SOURCE_DIR/Symtypes.kabi_%{_target_cpu}$Flavour $RPM_BUILD_ROOT/Symtypes.kabi
          cp $RPM_SOURCE_DIR/kabi_lockedlist_%{_target_cpu}$Flavour $RPM_BUILD_ROOT/kabi_lockedlist
          if ! $RPM_SOURCE_DIR/check-kabi -k $RPM_BUILD_ROOT/Module.kabi -s Module.symvers ; then
              python3 $RPM_SOURCE_DIR/kabi compare --no-print-symbols \
                  $RPM_BUILD_ROOT/Symtypes.kabi Symtypes.build
              exit 1
          fi
          # Smoke tests verify that the kABI definitions are internally consistent:
          # they contain the exact same set of symbols and symbol versions.
          python3 $RPM_SOURCE_DIR/kabi smoke -v $RPM_BUILD_ROOT/Module.kabi \
                                             -t $RPM_BUILD_ROOT/Symtypes.kabi \
                                             -l $RPM_BUILD_ROOT/kabi_lockedlist || exit 1
          # For now, don't keep these around
          rm $RPM_BUILD_ROOT/Module.kabi
          rm $RPM_BUILD_ROOT/Symtypes.kabi
          rm $RPM_BUILD_ROOT/kabi_lockedlist
       else
          echo "**** NOTE: Cannot find reference Module.kabi file. ****"
          exit 1
       fi
    else
       echo "**** kABI checking is NOT enabled in kernel SPEC file for %{_target_cpu}. ****"
    fi
%else
    echo "**** kABI checking is NOT enabled in kernel SPEC file for %{_target_cpu}. ****"
%endif

    # then drop all but the needed Makefiles/Kconfig files
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
    if [ -d arch/%{asmarch}/include ]; then
      cp -a --parents arch/%{asmarch}/include $RPM_BUILD_ROOT/lib/modules/$KernelVer/build/
    fi
%ifarch aarch64
    cp -a --parents arch/arm/include/asm/xen $RPM_BUILD_ROOT/lib/modules/$KernelVer/build/
    cp -a --parents arch/arm/include/asm/opcodes.h $RPM_BUILD_ROOT/lib/modules/$KernelVer/build/
%endif
%ifarch %{arm}
    if [ -d arch/%{asmarch}/mach-${Flavour}/include ]; then
      cp -a --parents arch/%{asmarch}/mach-${Flavour}/include $RPM_BUILD_ROOT/lib/modules/$KernelVer/build/
    fi
    # include a few files for 'make prepare'
    cp -a --parents arch/arm/tools/gen-mach-types $RPM_BUILD_ROOT/lib/modules/$KernelVer/build/
    cp -a --parents arch/arm/tools/mach-types $RPM_BUILD_ROOT/lib/modules/$KernelVer/build/
%endif
    cp -a --parents Kbuild $RPM_BUILD_ROOT/lib/modules/$KernelVer/build/
    cp -a --parents kernel/bounds.c $RPM_BUILD_ROOT/lib/modules/$KernelVer/build/
    cp -a --parents arch/%{asmarch}/kernel/asm-offsets.c $RPM_BUILD_ROOT/lib/modules/$KernelVer/build/
%ifnarch aarch64
    cp -a --parents arch/%{asmarch}/kernel/asm-offsets_64.c $RPM_BUILD_ROOT/lib/modules/$KernelVer/build/
%endif
    cp -a --parents security/selinux/include $RPM_BUILD_ROOT/lib/modules/$KernelVer/build/

    mkdir -p $RPM_BUILD_ROOT/lib/modules/$KernelVer/build/include
    cd include
    find ./* -maxdepth 0 -type d -exec cp -a {} $RPM_BUILD_ROOT/lib/modules/$KernelVer/build/include/ \;
    asmdir=../arch/%{asmarch}/include/asm
    cp -a $asmdir $RPM_BUILD_ROOT/lib/modules/$KernelVer/build/include/
    cd $RPM_BUILD_ROOT/lib/modules/$KernelVer/build/include
    ln -s $asmdir asm
    cd -
    # Make sure the Makefile and version.h have a matching timestamp so that
    # external modules can be built
    touch -r $RPM_BUILD_ROOT/lib/modules/$KernelVer/build/Makefile $RPM_BUILD_ROOT/lib/modules/$KernelVer/build/include/generated/uapi/linux/version.h
    # Copy .config to include/config/auto.conf so "make prepare" is unnecessary.
    cp $RPM_BUILD_ROOT/lib/modules/$KernelVer/build/.config $RPM_BUILD_ROOT/lib/modules/$KernelVer/build/include/config/auto.conf
    cd ..

    #
    # save the vmlinux file for kernel debugging into the kernel-debuginfo rpm
    #
%if %{with_debuginfo}
    mkdir -p $RPM_BUILD_ROOT%{debuginfodir}/lib/modules/$KernelVer
    cp vmlinux $RPM_BUILD_ROOT%{debuginfodir}/lib/modules/$KernelVer
    # also include Symtypes.build for kABI maintenance
    [ -f Symtypes.build ] && gzip -c9 < Symtypes.build > $RPM_BUILD_ROOT%{debuginfodir}/lib/modules/$KernelVer/Symtypes.build.gz
%endif
    rm -f Symtypes.build

    find $RPM_BUILD_ROOT/lib/modules/$KernelVer -name "*.ko" -type f > modnames

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
			 'register_netdev|ieee80211_register_hw|usbnet_probe|phy_driver_register|register_netdevice'
    collect_modules_list block \
			 'ata_scsi_ioctl|scsi_add_host|scsi_add_host_with_dma|blk_init_queue|register_mtd_blktrans|scsi_esp_register|scsi_register_device_handler|blk_queue_physical_block_size'
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

    remove_depmod_files()
    {
        # remove files that will be auto generated by depmod at rpm -i time
        pushd $RPM_BUILD_ROOT/lib/modules/$KernelVer/
            rm -f modules.{alias,alias.bin,builtin.alias.bin,builtin.bin} \
                  modules.{dep,dep.bin,devname,softdep,symbols,symbols.bin}
        popd
    }

    remove_depmod_files

    # Identify modules in the kernel%{?variant}-modules-extras package
    %{SOURCE11} $RPM_BUILD_ROOT lib/modules/$KernelVer $RPM_SOURCE_DIR/mod-extra.list

    #
    # Generate the kernel%{?variant}-modules-core and kernel%{?variant}-modules files lists
    #

    # Copy the System.map file for depmod to use, and create a backup of the
    # full module tree so we can restore it after we're done filtering
    cp System.map $RPM_BUILD_ROOT/.
    pushd $RPM_BUILD_ROOT
    mkdir restore
    cp -r lib/modules/$KernelVer/* restore/.

    # don't include anything going into kernel%{?variant}-modules-extra in the file lists
    xargs rm -rf < mod-extra.list

    # Run depmod on the resulting module tree and make sure it isn't broken
    depmod -b . -aeF ./System.map $KernelVer &> depmod.out
    if [ -s depmod.out ]; then
        echo "Depmod failure. Modules from modules-extra list may be needed"
        cat depmod.out
        exit 1
    else
        rm depmod.out
    fi

    remove_depmod_files

    # Find all the module files and filter them out into the core and
    # modules lists.  This actually removes anything going into -modules
    # from the dir.
    find lib/modules/$KernelVer/kernel -name *.ko | sort -n > modules.list

    cp $RPM_SOURCE_DIR/filter-modules.sh .
    if [ "$Flavour" == "emb3" ] || [ "$Flavour" == "emb3debug" ]; then
      cp $RPM_SOURCE_DIR/core-emb3-%{_target_cpu}.list modules-core.list
    else
      cp $RPM_SOURCE_DIR/modules-core-%{_target_cpu}.list modules-core.list
    fi

    # Append full path to the beginning of each line.
    sed -i "s/^/lib\/modules\/$KernelVer\//" modules-core.list

    ./filter-modules.sh modules-core.list modules.list
    rm filter-modules.sh

    # Run depmod on the resulting module tree and make sure it isn't broken
    depmod -b . -aeF ./System.map $KernelVer &> depmod.out
    if [ -s depmod.out ]; then
        echo "Depmod failure. You may have to add missing modules to modules-core list"
        cat depmod.out
        exit 1
    else
        rm depmod.out
    fi

    remove_depmod_files

    # Go back and find all of the various directories in the tree.  We use this
    # for the dir lists in kernel-uek-modules-core
    find lib/modules/$KernelVer/kernel -mindepth 1 -type d | sort -n > module-dirs.list

    # Cleanup
    rm System.map
    cp -r restore/* lib/modules/$KernelVer/.
    rm -rf restore
    popd

    # Make sure the files lists start with absolute paths or rpmbuild fails.
    # Also add in the dir entries
    sed -e 's/^lib*/\/lib/' %{?zipsed} $RPM_BUILD_ROOT/modules.list > ${modlistVariant}-modules.list
    sed -e 's/^lib*/%dir \/lib/' %{?zipsed} $RPM_BUILD_ROOT/module-dirs.list > ${modlistVariant}-modules-core.list
    sed -e 's/^lib*/\/lib/' %{?zipsed} $RPM_BUILD_ROOT/modules-core.list >> ${modlistVariant}-modules-core.list
    sed -e 's/^lib*/\/lib/' %{?zipsed} $RPM_BUILD_ROOT/mod-extra.list >> ${modlistVariant}-modules-extra.list

    # Cleanup
    rm -f $RPM_BUILD_ROOT/modules-core.list
    rm -f $RPM_BUILD_ROOT/modules.list
    rm -f $RPM_BUILD_ROOT/module-dirs.list
    rm -f $RPM_BUILD_ROOT/mod-extra.list

%if %{signmodules}
    cp certs/signing_key.pem certs/signing_key.pem.sign${Flavour:+.${Flavour}}
    cp certs/signing_key.x509 certs/signing_key.x509.sign${Flavour:+.${Flavour}}
%endif

    # Move the devel headers out of the root file system
    mkdir -p $RPM_BUILD_ROOT/usr/src/kernels
    mv $RPM_BUILD_ROOT/lib/modules/$KernelVer/build $RPM_BUILD_ROOT/$DevelDir
    if [ -f arch/$Arch/kernel/module.lds ]; then
      cp arch/$Arch/kernel/module.lds $RPM_BUILD_ROOT/$DevelDir/arch/$Arch/kernel/module.lds || :
    fi
    ln -sf $DevelDir $RPM_BUILD_ROOT/lib/modules/$KernelVer/build

    # prune junk from kernel-devel
    find $RPM_BUILD_ROOT/usr/src/kernels -name ".*.cmd" -exec rm -f {} \;

    # build a BLS config for this kernel
    %{SOURCE43} "$KernelVer" "$RPM_BUILD_ROOT" "%{?variant}"

    # UEFI Secure Boot cert, which can verify kernel signature
    mkdir -p $RPM_BUILD_ROOT%{_datadir}/doc/kernel-keys/$KernelVer
    install -m 0644 %{sb_cer} $RPM_BUILD_ROOT%{_datadir}/doc/kernel-keys/$KernelVer/kernel-signing.cer
}

###
# DO it...
###

# prepare directories
rm -rf $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT/boot

cd linux-%{version}-%{release}

%if %{with_container}
BuildContainerKernel %make_target %kernel_image container
%endif

%if %{with_debug}
%if %{with_up}
BuildKernel %make_target %kernel_image debug
%endif
%endif

%if %{with_up}
BuildKernel %make_target %kernel_image
%endif

%if %{with_64k_ps}
BuildKernel %make_target %kernel_image 64k
%endif

%if %{with_64k_ps_debug}
BuildKernel %make_target %kernel_image 64kdebug
%endif

%if %{with_embedded}
BuildKernel %make_target %kernel_image emb3
%endif

%if %{with_embedded_debug}
BuildKernel %make_target %kernel_image emb3debug
%endif

%global bpftool_make \
  %{make} EXTRA_CFLAGS="${RPM_OPT_FLAGS//redhat-annobin-cc1/redhat-annobin-select-annobin-built-plugin}" EXTRA_LDFLAGS="%{__global_ldflags}" DESTDIR=$RPM_BUILD_ROOT
%if %{with_bpftool}
pushd tools/bpf/bpftool
%{bpftool_make}
popd
%endif

%if %{with_tools}
%ifarch %{vdso_arches}
%ifnarch noarch
    # build tools/perf:
    if [ -d tools/perf ]; then
        pushd tools/perf
        %{make} %{?_smp_mflags} NO_LIBPERL=1 EXTRA_CFLAGS="-Wno-format-truncation -Wno-format-overflow" all
        popd
    fi
%endif
%endif

%ifarch x86_64 %{all_x86}
    # build tools/power/x86/x86_energy_perf_policy:
    if [ -d tools/power/x86/x86_energy_perf_policy ]; then
       pushd tools/power/x86/x86_energy_perf_policy
       %{make} %{?_smp_mflags} EXTRA_CFLAGS="-Wno-format-truncation -Wno-format-overflow"
       popd
    fi

    # build tools/power/x86/turbostat:
    if [ -d tools/power/x86/turbostat ]; then
       pushd tools/power/x86/turbostat
       %{make} %{?_smp_mflags} EXTRA_CFLAGS="-Wno-format-truncation -Wno-format-overflow"
       popd
    fi
%endif
%endif

%if %{with_doc}
# Make the HTML pages.
%{make} %{?_smp_mflags} htmldocs || %{doc_build_fail}
%endif

%define dgst $((grep '^CONFIG_MODULE_SIG_SHA512=y$' .config >/dev/null && grep '^CONFIG_MODULE_SIG_HASH=\"sha512\"$' .config >/dev/null && echo sha512) || (grep '^CONFIG_MODULE_SIG_SHA256=y$' .config >/dev/null && grep '^CONFIG_MODULE_SIG_HASH=\"sha256\"$' .config >/dev/null && echo sha256))

%define __modsign_install_post \
  if [ "%{signmodules}" == "1" ]; then \
    if [ "%{with_debug}" != "0" ]; then \
      mv certs/signing_key.pem.sign.debug certs/signing_key.pem \
      mv certs/signing_key.x509.sign.debug certs/signing_key.x509 \
      %{modsign_cmd} %{?_smp_mflags} $RPM_BUILD_ROOT/lib/modules/%{KVERREL}.debug/ %{dgst} \
    fi \
    if [ "%{with_up}" != "0" ]; then \
      mv certs/signing_key.pem.sign certs/signing_key.pem \
      mv certs/signing_key.x509.sign certs/signing_key.x509 \
      %{modsign_cmd} %{?_smp_mflags} $RPM_BUILD_ROOT/lib/modules/%{KVERREL}/ %{dgst} \
    fi \
    if [ "%{with_64k_ps}" -ne "0" ]; then \
       mv certs/signing_key.pem.sign.64k certs/signing_key.pem \
       mv certs/signing_key.x509.sign.64k certs/signing_key.x509 \
       %{modsign_cmd} %{?_smp_mflags} $RPM_BUILD_ROOT/lib/modules/%{KVERREL}.64k/ %{dgst} \
    fi \
    if [ "%{with_64k_ps_debug}" -ne "0" ]; then \
       mv certs/signing_key.pem.sign.64kdebug certs/signing_key.pem \
       mv certs/signing_key.x509.sign.64kdebug certs/signing_key.x509 \
       %{modsign_cmd} %{?_smp_mflags} $RPM_BUILD_ROOT/lib/modules/%{KVERREL}.64kdebug/ %{dgst} \
     fi \
    if [ "%{with_embedded}" -ne "0" ]; then \
       mv certs/signing_key.pem.sign.emb3 certs/signing_key.pem \
       mv certs/signing_key.x509.sign.emb3 certs/signing_key.x509 \
       %{modsign_cmd} %{?_smp_mflags} $RPM_BUILD_ROOT/lib/modules/%{KVERREL}.emb3/ %{dgst} \
    fi \
    if [ "%{with_embedded_debug}" -ne "0" ]; then \
       mv certs/signing_key.pem.sign.emb3debug certs/signing_key.pem \
       mv certs/signing_key.x509.sign.emb3debug certs/signing_key.x509 \
       %{modsign_cmd} %{?_smp_mflags} $RPM_BUILD_ROOT/lib/modules/%{KVERREL}.emb3debug/ %{dgst} \
     fi \
  fi \
%{nil}

## Compress ca. 2000 modules
# We force xz to single-threaded mode because xargs is used to control
# the amount of parallelization.
%define __modcompress_install_post \
  if [ "%{with_compression}" == "1" ]; then \
     find $RPM_BUILD_ROOT/lib/modules/ -type f -name '*.ko' -print0 | \
	xargs -0r -P$( nproc ) -n 1 /usr/bin/xz -T1 -f \
  fi \
%{nil}

###
### Special hacks for debuginfo subpackages.
###

# This macro is used by install, so we must redefine it before that.
# TEMPORARY HACK: use the debuginfo in the build tree, passing it -g1 so as
# to strip out only debugging sections.
%define debug_package %{nil}

%if %{with_debuginfo}
%ifnarch noarch
%global __debug_package 1
%files debuginfo-common
%defattr(-,root,root)
%dir /usr/src/debug
/usr/src/debug/kernel-%{version}/linux-%{kversion}-%{release}
%dir %{debuginfodir}
%dir %{debuginfodir}/%{image_install_path}
%dir %{debuginfodir}/lib
%dir %{debuginfodir}/lib/modules
%dir %{debuginfodir}/usr/src/kernels
%endif
%endif

#
# Disgusting hack alert! We need to ensure we sign modules *after* all
# invocations of strip occur, which is in __debug_install_post if
# find-debuginfo.sh runs, and __os_install_post if not.
#
%define __spec_install_post \
  %{?__debug_package:%{__debug_install_post}}\
  %{__arch_install_post}\
  %{__os_install_post}\
  %{__modsign_install_post}\
  %{__modcompress_install_post}

###
### install
###

%install
# Enable gcc-toolset-13
source /opt/rh/gcc-toolset-13/enable
gcc --version

cd linux-%{version}-%{release}

%if %{with_doc}
# copy the output files
docdir=$RPM_BUILD_ROOT%{_datadir}/doc/kernel%{variant}-doc-%{rpmversion}
mkdir -p $docdir
cp -a Documentation/output/* $docdir
%endif

%if %{with_tools}
%ifnarch noarch
mkdir -p $RPM_BUILD_ROOT/usr/sbin/
cp $RPM_SOURCE_DIR/perf $RPM_BUILD_ROOT/usr/sbin/perf
chmod 0755 $RPM_BUILD_ROOT/usr/sbin/perf
mkdir -p $RPM_BUILD_ROOT/usr/libexec/
install -m 755 tools/perf/perf $RPM_BUILD_ROOT/usr/libexec/perf.%{KVERREL}
%if %{with_debug}
ln -sf perf.%{KVERREL} $RPM_BUILD_ROOT/usr/libexec/perf.%{KVERREL}.debug
%endif
%if %{with_64k_ps}
ln -sf perf.%{KVERREL} $RPM_BUILD_ROOT/usr/libexec/perf.%{KVERREL}.64k
%endif
%if %{with_64k_ps_debug}
ln -sf perf.%{KVERREL} $RPM_BUILD_ROOT/usr/libexec/perf.%{KVERREL}.64kdebug
%endif
%endif

%ifarch x86_64 %{all_x86}
mkdir -p $RPM_BUILD_ROOT/usr/sbin/
cp $RPM_SOURCE_DIR/x86_energy_perf_policy $RPM_BUILD_ROOT/usr/sbin/x86_energy_perf_policy
chmod 0755 $RPM_BUILD_ROOT/usr/sbin/x86_energy_perf_policy
mkdir -p $RPM_BUILD_ROOT/usr/libexec/
install -m 755 tools/power/x86/x86_energy_perf_policy/x86_energy_perf_policy $RPM_BUILD_ROOT/usr/libexec/x86_energy_perf_policy.%{KVERREL}
%if %{with_debug}
ln -sf x86_energy_perf_policy.%{KVERREL} $RPM_BUILD_ROOT/usr/libexec/x86_energy_perf_policy.%{KVERREL}.debug
%endif

mkdir -p $RPM_BUILD_ROOT/usr/sbin/
cp $RPM_SOURCE_DIR/turbostat $RPM_BUILD_ROOT/usr/sbin/turbostat
chmod 0755 $RPM_BUILD_ROOT/usr/sbin/turbostat
mkdir -p $RPM_BUILD_ROOT/usr/libexec/
install -m 755 tools/power/x86/turbostat/turbostat $RPM_BUILD_ROOT/usr/libexec/turbostat.%{KVERREL}
%if %{with_debug}
ln -sf turbostat.%{KVERREL} $RPM_BUILD_ROOT/usr/libexec/turbostat.%{KVERREL}.debug
%endif
%endif
%endif

%if %{with_headers}
# Install kernel headers
%{make} ARCH=%{hdrarch} INSTALL_HDR_PATH=$RPM_BUILD_ROOT/usr headers_install

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

%if %{with_bpftool}
pushd tools/bpf/bpftool
%{bpftool_make} prefix=%{_prefix} bash_compdir=%{_sysconfdir}/bash_completion.d/ mandir=%{_mandir} install doc-install
popd
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
#	%%kernel_devel_post [-o] [<subpackage>]
# -o flag omits the hyphen preceding <subpackage> in the package name
#
%define kernel_devel_post(o) \
%{expand:%%post -n kernel%{?variant}%{?1:%{!-o:-}%{1}}-devel}\
if [ -f /etc/sysconfig/kernel ]\
then\
    . /etc/sysconfig/kernel || exit $?\
fi\
if [ "$HARDLINK" != "no" -a -x /usr/sbin/hardlink ]\
then\
    (cd /usr/src/kernels/%{kversion}-%{release}.%{_arch}%{?1:.%{1}} &&\
     /usr/bin/find . -type f | while read f; do\
       hardlink -c /usr/src/kernels/*.fc*.*/$f $f\
     done)\
fi\
%{nil}

#
# This macro defines a %%post script for a kernel*-modules-extra package.
# It also defines a %%postun script that does the same thing.
# -o flag omits the hyphen preceding <subpackage> in the package name
#       %%kernel_modules_extra_post [-o] [<subpackage>]
#
%define kernel_modules_extra_post(o) \
%{expand:%%post -n kernel%{?variant}%{?1:%{!-o:-}%{1}}-modules-extra}\
/sbin/depmod -a %{KVERREL}%{?1:.%{1}}\
%{nil}\
%{expand:%%postun -n kernel%{?variant}%{?1:%{!-o:-}%{1}}-modules-extra}\
/sbin/depmod -a %{KVERREL}%{?1:.%{1}}\
%{nil}

#
# This macro defines a %%post script for a kernel*-modules package.
# It also defines a %%postun script that does the same thing.
# -o flag omits the hyphen preceding <subpackage> in the package name
#       %%kernel_modules_post [-o] [<subpackage>]
#
%define kernel_modules_post(o) \
%{expand:%%post -n kernel%{?variant}%{?1:%{!-o:-}%{1}}-modules}\
/sbin/depmod -a %{KVERREL}%{?1:.%{1}}\
if [ ! -f %{_localstatedir}/lib/rpm-state/%{name}/installing_core_%{KVERREL}%{?1:.%{1}} ]; then\
        mkdir -p %{_localstatedir}/lib/rpm-state/%{name}\
        touch %{_localstatedir}/lib/rpm-state/%{name}/need_to_run_dracut_%{KVERREL}%{?1:.%{1}}\
fi\
%{nil}\
%{expand:%%postun -n kernel%{?variant}%{?1:%{!-o:-}%{1}}-modules}\
/sbin/depmod -a %{KVERREL}%{?1:.%{1}}\
%{nil}\
%{expand:%%posttrans -n kernel%{?variant}%{?1:%{!-o:-}%{1}}-modules}\
if [ -f %{_localstatedir}/lib/rpm-state/%{name}/need_to_run_dracut_%{KVERREL}%{?1:.%{1}} ]; then\
        rm -f %{_localstatedir}/lib/rpm-state/%{name}/need_to_run_dracut_%{KVERREL}%{?1:.%{1}}\
        echo "Running: dracut -f --kver %{KVERREL}%{?1:.%{1}}"\
        dracut -f --kver "%{KVERREL}%{?1:.%{1}}" || exit $?\
fi\
%{nil}

#
# This macro defines a %%post script for a kernel*-modules-core package.
# It also defines a %%postun script that does the same thing.
# -o flag omits the hyphen preceding <subpackage> in the package name
#       %%kernel_modules_core_post [-o] [<subpackage>]
#
%define kernel_modules_core_post(o) \
%{expand:%%posttrans -n kernel%{?variant}%{?1:%{!-o:-}%{1}}-modules-core}\
/sbin/depmod -a %{KVERREL}%{?1:.%{1}}\
%{nil}\
%{expand:%%postun -n kernel%{?variant}%{?1:%{!-o:-}%{1}}-modules-core}\
ls /lib/modules/%{KVERREL}%{?1:.%{1}}/modules.* | grep -v builtin | xargs rm -f\
%{nil}

# This macro defines a %%posttrans script for a kernel package.
#	%%kernel_variant_posttrans [-o] [<subpackage>]
# -o flag omits the hyphen preceding <subpackage> in the package name
# More text can follow to go at the end of this variant's %%post.
#
%define kernel_variant_posttrans(o) \
%{expand:%%posttrans -n kernel%{?variant}%{?1:%{!-o:-}%{1}}-core}\
if [ -x /sbin/weak-modules ]\
then\
    /sbin/weak-modules --add-kernel %{KVERREL}%{?1:.%{1}} || exit $?\
fi\
rm -f %{_localstatedir}/lib/rpm-state/%{name}/installing_core_%{KVERREL}%{?1:.%{1}}\
/bin/kernel-install add %{KVERREL}%{?1:.%{1}} /lib/modules/%{KVERREL}%{?1:.%{1}}/vmlinuz || exit $?\
if [[ ! -e "/boot/symvers-%{KVERREL}%{?1:.%{1}}.gz" ]]; then\
    ln -sf "/lib/modules/%{KVERREL}%{?1:.%{1}}/symvers.gz" "/boot/symvers-%{KVERREL}%{?1:.%{1}}.gz"\
    command -v restorecon &>/dev/null && restorecon "/boot/symvers-%{KVERREL}%{?1:.%{1}}.gz" \
fi\
%{nil}

#
# This macro defines a %%post script for a kernel package and its devel package.
#	%%kernel_variant_post [-o][-v <subpackage>] [-r <replace>]
# -o flag omits the hyphen preceding <subpackage> in the package name
# More text can follow to go at the end of this variant's %%post.
#
%define kernel_variant_post(ov:r:) \
%{expand:%%kernel_devel_post %{-o:-o} %{?-v:%{?-v*}}}\
%{expand:%%kernel_modules_post %{-o:-o} %{?-v:%{?-v*}}}\
%{expand:%%kernel_modules_core_post %{-o:-o} %{?-v:%{?-v*}}}\
%{expand:%%kernel_modules_extra_post %{-o:-o} %{?-v:%{?-v*}}}\
%{expand:%%kernel_variant_posttrans %{-o:-o} %{?-v:%{?-v*}}}\
%{expand:%%post -n kernel%{?variant}%{?-v*:%{!-o:-}%{-v*}}-core}\
%{-r:\
if [ `uname -i` == "x86_64" -o `uname -i` == "aarch64" ] &&\
   [ -f /etc/sysconfig/kernel ] &&\
   [ "%{?variant}" == "-uek" ] &&\
   [ $1 -eq 1 ]; then\
   NEW_DEFAULT="kernel%{?variant}%{?-v:%{!-o:-}%{-v*}}-core"\
  /bin/sed -r -i "s/^DEFAULTKERNEL=.*$/DEFAULTKERNEL=${NEW_DEFAULT}/" /etc/sysconfig/kernel || exit $?\
fi}\
mkdir -p %{_localstatedir}/lib/rpm-state/%{name}\
touch %{_localstatedir}/lib/rpm-state/%{name}/installing_core_%{KVERREL}%{?-v:.%{-v*}}\
%{nil}

#
# This macro defines a %%postun script for a kernel package.
#      %%kernel_variant_postun [-o] <subpackage>
# -o flag omits the hyphen preceding <subpackage> in the package name
#
%define kernel_variant_postun(o) \
%{expand:%%postun -n kernel%{?variant}%{?1:%{!-o:-}%{1}}-core}\
if [ $1 -eq 0 ] && \
   [ "$(uname -i)" == "x86_64" -o "$(uname -i)" == "aarch64" ] && \
   [ -f /etc/sysconfig/kernel ]; then\
    CUR_DEFAULT=$(grep '^DEFAULTKERNEL' /etc/sysconfig/kernel | cut -d= -f2);\
    THIS_KERNEL="kernel%{?variant}%{?-v:%{!-o:-}%{-v*}}-core";\
    NEW_DEFAULT="";\
    if [ "%{?variant}" == "-uek" ] && \
       [ "${CUR_DEFAULT}" == "${THIS_KERNEL}" ] && \
       [ "$(uname -i)" == "x86_64" ]; then\
        NEW_DEFAULT="kernel-core";\
    elif [ "%{?variant}" != "-uek" ] && \
         [ "${CUR_DEFAULT}" == "${THIS_KERNEL}" ]; then\
        if rpm -q kernel-uek-core >& /dev/null; then\
            NEW_DEFAULT="kernel-uek-core";\
        elif rpm -q kernel-ueknano >& /dev/null; then\
            NEW_DEFAULT="kernel-ueknano";\
        elif rpm -q kernel-uek >& /dev/null; then\
            NEW_DEFAULT="kernel-uek";\
        else\
            NEW_DEFAULT="kernel-core";\
        fi\
    fi;\
    if [ -n "${NEW_DEFAULT}" ]; then\
        /bin/sed -i "s/^DEFAULTKERNEL=.*$/DEFAULTKERNEL=${NEW_DEFAULT}/" /etc/sysconfig/kernel || exit $?;\
    fi\
fi\
%{nil}

#
# This macro defines a %%preun script for a kernel package.
#	%%kernel_variant_preun [-o] <subpackage>
# -o flag omits the hyphen preceding <subpackage> in the package name
#
%define kernel_variant_preun(o) \
%{expand:%%preun -n kernel%{?variant}%{?1:%{!-o:-}%{1}}-core}\
/bin/kernel-install remove %{KVERREL}%{?1:.%{1}} /lib/modules/%{KVERREL}%{?1:.%{1}}/vmlinuz || exit $?\
%{nil}

#
# This macro defines a %%pre script for a kernel package.
#	%%kernel_variant_pre [-o] <subpackage>
# -o flag omits the hyphen preceding <subpackage> in the package name
#
%define kernel_variant_pre(o) \
%{expand:%%pre -n kernel%{?variant}%{?1:%{!-o:-}%{1}}-core}\
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
%kernel_variant_postun
%kernel_variant_post -r (kernel%{variant}|kernel%{variant}-debug|kernel-ovs)

%kernel_variant_pre debug
%kernel_variant_preun debug
%kernel_variant_postun debug
%kernel_variant_post -v debug

%kernel_variant_pre -o 64k
%kernel_variant_preun -o 64k
%kernel_variant_postun -o 64k
%kernel_variant_post -o -v 64k -r (kernel%{variant}|kernel%{variant}-debug)

%kernel_variant_pre -o 64kdebug
%kernel_variant_preun -o 64kdebug
%kernel_variant_postun -o 64kdebug
%kernel_variant_post -o -v 64kdebug

%kernel_variant_pre -o emb3
%kernel_variant_preun -o emb3
%kernel_variant_postun -o emb3
%kernel_variant_post -o -v emb3

%kernel_variant_pre -o emb3debug
%kernel_variant_preun -o emb3debug
%kernel_variant_postun -o emb3debug
%kernel_variant_post -o -v emb3debug

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

%if %{with_container}
%files -n kernel%{variant}-container
%dir /usr/share/kata-containers
/usr/share/kata-containers/vmlinux-%{kversion}-%{release}
/usr/share/kata-containers/vmlinux.container
/usr/share/kata-containers/vmlinuz-%{kversion}-%{release}
/usr/share/kata-containers/vmlinuz.container

%files -n kernel%{variant}-container-debug
%dir /usr/share/kata-containers
/usr/share/kata-containers/config-%{kversion}-%{release}
/usr/share/kata-containers/System.map-%{kversion}-%{release}
%endif

%if %{with_bpftool}
%files -n bpftool
%{_sbindir}/bpftool
%{_sysconfdir}/bash_completion.d/bpftool
%{_mandir}/man8/bpftool-cgroup.8.gz
%{_mandir}/man8/bpftool-gen.8.gz
%{_mandir}/man8/bpftool-iter.8.gz
%{_mandir}/man8/bpftool-link.8.gz
%{_mandir}/man8/bpftool-map.8.gz
%{_mandir}/man8/bpftool-prog.8.gz
%{_mandir}/man8/bpftool-perf.8.gz
%{_mandir}/man8/bpftool.8.gz
%{_mandir}/man8/bpftool-net.8.gz
%{_mandir}/man8/bpftool-feature.8.gz
%{_mandir}/man8/bpftool-btf.8.gz
%{_mandir}/man8/bpftool-struct_ops.8.gz

%if %{with_debuginfo}
%files -f bpftool-debuginfo.list -n bpftool-debuginfo
%defattr(-,root,root)
%endif
%endif

%if %{with_tools}
%files -n kernel%{?variant}-tools
/usr/libexec/
/usr/sbin/perf
%ifarch x86_64 %{all_x86}
/usr/sbin/x86_energy_perf_policy
/usr/sbin/turbostat
%endif
%endif

# only some architecture builds need kernel-doc
%if %{with_doc}
%files doc
%defattr(-,root,root)
%{_datadir}/doc/kernel%{variant}-doc-%{rpmversion}/*
%dir %{_datadir}/doc/kernel%{variant}-doc-%{rpmversion}
%endif

# This is image_install_path on an arch where that includes ELF files,
# or empty otherwise.
%define elf_image_install_path %{?kernel_image_elf:%{image_install_path}}

#
# This macro defines the %%files sections for a kernel package
# and its devel and debuginfo packages.
#	%%kernel_variant_files [-k vmlinux] [-o] <condition> <subpackage>
# -o flag omits the hyphen preceding <subpackage> in the package name
#
%define kernel_variant_files(k:o) \
%if %{1}\
%define variant_name kernel%{?variant}%{?2:%{!-o:-}%{2}}\
%{expand:%%files -n %{variant_name}}\
%{expand:%%files -n %{variant_name}-core}\
%defattr(-,root,root)\
%dir /lib/modules/%{KVERREL}%{?2:.%{2}}\
/lib/modules/%{KVERREL}%{?2:.%{2}}/%{?-k:%{-k*}}%{!?-k:vmlinuz}\
%ghost /%{image_install_path}/%{?-k:%{-k*}}%{!?-k:vmlinuz}-%{KVERREL}%{?2:.%{2}}\
/lib/modules/%{KVERREL}%{?2:.%{2}}/.vmlinuz.hmac \
%ghost /%{image_install_path}/.vmlinuz-%{KVERREL}%{?2:.%{2}}.hmac \
%ifarch %{arm} aarch64\
/lib/modules/%{KVERREL}%{?2:.%{2}}/dtb \
%ghost /%{image_install_path}/dtb-%{KVERREL}%{?2:.%{2}} \
%endif\
%attr(600,root,root) /lib/modules/%{KVERREL}%{?2:.%{2}}/System.map\
%ghost /boot/System.map-%{KVERREL}%{?2:.%{2}}\
/lib/modules/%{KVERREL}%{?2:.%{2}}/symvers.gz\
/lib/modules/%{KVERREL}%{?2:.%{2}}/config\
/lib/modules/%{KVERREL}%{?2:.%{2}}/modules.builtin*\
%ghost /boot/symvers-%{KVERREL}%{?2:.%{2}}.gz\
%ghost /boot/initramfs-%{KVERREL}%{?2:.%{2}}.img\
%ghost /boot/config-%{KVERREL}%{?2:.%{2}}\
%{expand:%%files -f %{variant_name}-modules-core.list -n %{variant_name}-modules-core}\
%dir /lib/modules/%{KVERREL}%{?2:.%{2}}/kernel\
/lib/modules/%{KVERREL}%{?2:.%{2}}/build\
/lib/modules/%{KVERREL}%{?2:.%{2}}/source\
/lib/modules/%{KVERREL}%{?2:.%{2}}/updates\
/lib/modules/%{KVERREL}%{?2:.%{2}}/weak-updates\
/lib/modules/%{KVERREL}%{?2:.%{2}}/bls.conf\
%{_datadir}/doc/kernel-keys/%{KVERREL}%{?2:.%{2}}/kernel-signing.cer\
%ifarch %{vdso_arches}\
/lib/modules/%{KVERREL}%{?2:.%{2}}/vdso\
%endif\
/lib/modules/%{KVERREL}%{?2:.%{2}}/modules.block\
/lib/modules/%{KVERREL}%{?2:.%{2}}/modules.drm\
/lib/modules/%{KVERREL}%{?2:.%{2}}/modules.modesetting\
/lib/modules/%{KVERREL}%{?2:.%{2}}/modules.networking\
/lib/modules/%{KVERREL}%{?2:.%{2}}/modules.order\
%{expand:%%files -f %{variant_name}-modules.list -n %{variant_name}-modules}\
%{expand:%%files -f %{variant_name}-modules-extra.list -n %{variant_name}-modules-extra}\
%config(noreplace) /etc/modprobe.d/*-blacklist.conf\
%{expand:%%files -n %{variant_name}-devel}\
%defattr(-,root,root)\
%dir /usr/src/kernels\
%verify(not mtime) /usr/src/kernels/%{KVERREL}%{?2:.%{2}}\
/usr/src/kernels/%{KVERREL}%{?2:.%{2}}\
%if %{with_debuginfo}\
%ifnarch noarch\
%{expand:%%files -n %{variant_name}-debuginfo}\
%defattr(-,root,root)\
%if "%{elf_image_install_path}" != ""\
%{debuginfodir}/%{elf_image_install_path}/*-%{KVERREL}%{?2:.%{2}}.debug\
%endif\
%{debuginfodir}/lib/modules/%{KVERREL}%{?2:.%{2}}\
%{debuginfodir}/usr/src/kernels/%{KVERREL}%{?2:.%{2}}\
%endif\
%endif\
%endif\
%{nil}

%kernel_variant_files %{with_up}
%if %{with_up}
%kernel_variant_files %{with_debug} debug
%endif

%kernel_variant_files -o %{with_64k_ps} 64k
%kernel_variant_files -o %{with_64k_ps_debug} 64kdebug

%kernel_variant_files -o %{with_embedded} emb3
%kernel_variant_files -o %{with_embedded_debug} emb3debug

%changelog
