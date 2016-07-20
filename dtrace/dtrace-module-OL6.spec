%ifarch i686
%define karch i686
%endif
%ifarch x86_64
%define karch x86_64
%endif
%ifarch sparc64
%define karch sparc64
%endif

# Redefine 'build_variant' at build time to create a kernel package named
# something like 'kernel-uek-dtrace'.
%define variant %{?build_variant:%{build_variant}}%{!?build_variant:-uek}

# Set this to the version of the kernel this module is compiled against.
%define kver %{?build_kver:%{build_kver}}%{!?build_kver:4.1.12-43.el6uek}

%define _signmodules %{?signmodules: %{signmodules}} %{?!signmodules: 1}

# Select the correct source code version based on the kernel version.
# Failing to pick the correct version can have disasterous effects!
# For safety, we assume that the kernel version is not supported, unless we
# explicitly recognize it below...  Unsupported versions will always have
# version code 0.
#
# We also set a version code (vercode) to make it possible to make parts of
# the specfile conditional on the modules version.
%define dt_vcode	0
%define dt_0_3_2	770
%define dt_0_4_0	1024
%define dt_0_4_1	1025
%define dt_0_4_2	1026
%define dt_0_4_3	1027
%define dt_0_4_4	1028
%define dt_0_4_5	1029
%define dt_0_4_6	1030
%define dt_0_5_0	1280
%define dt_0_5_1	1281
%define dt_0_5_2	1282
%define dt_0_5_3	1283
%{lua:
	local kver = rpm.expand("%{kver}")

	if rpm.vercmp(kver, "4.1.4-3") >= 0 then
		rpm.define("arches x86_64 sparc64")
	else
		rpm.define("arches x86_64")
	end

	if rpm.vercmp(kver, "4.1.12-61") >= 0 then
		rpm.define("srcver 0.5.3")
		rpm.define("bldrel 2")
		rpm.define("dt_vcode "..rpm.expand("%{dt_0_5_3}"))
	elseif rpm.vercmp(kver, "4.1.12-33") >= 0 then
		rpm.define("srcver 0.5.2")
		rpm.define("bldrel 1")
		rpm.define("dt_vcode "..rpm.expand("%{dt_0_5_2}"))
	elseif rpm.vercmp(kver, "4.1.12-24") >= 0 then
		rpm.define("srcver 0.5.1")
		rpm.define("bldrel 1")
		rpm.define("dt_vcode "..rpm.expand("%{dt_0_5_1}"))
	elseif rpm.vercmp(kver, "4.1.4-3") >= 0 then
		rpm.define("srcver 0.5.0")
		rpm.define("bldrel 4")
		rpm.define("dt_vcode "..rpm.expand("%{dt_0_5_0}"))
--	elseif rpm.vercmp(kver, "3.8.13-119") >= 0 then
--		rpm.define("srcver 0.4.6")
--		rpm.define("bldrel 1")
--		rpm.define("dt_vcode "..rpm.expand("%{dt_0_4_6}"))
	elseif rpm.vercmp(kver, "3.8.13-87") >= 0 then
		rpm.define("srcver 0.4.5")
		rpm.define("bldrel 3")
		rpm.define("dt_vcode "..rpm.expand("%{dt_0_4_5}"))
	elseif rpm.vercmp(kver, "3.8.13-69") >= 0 then
		rpm.define("srcver 0.4.4")
		rpm.define("bldrel 1")
		rpm.define("dt_vcode "..rpm.expand("%{dt_0_4_4}"))
	elseif rpm.vercmp(kver, "3.8.13-33") >= 0 then
		rpm.define("srcver 0.4.3")
		rpm.define("bldrel 4")
		rpm.define("dt_vcode "..rpm.expand("%{dt_0_4_3}"))
	elseif rpm.vercmp(kver, "3.8.13-22") >= 0 then
		rpm.define("srcver 0.4.2")
		rpm.define("bldrel 3")
		rpm.define("dt_vcode "..rpm.expand("%{dt_0_4_2}"))
	elseif rpm.vercmp(kver, "3.8.13-16.2.1") >= 0 then
		rpm.define("srcver 0.4.1")
		rpm.define("bldrel 3")
		rpm.define("dt_vcode "..rpm.expand("%{dt_0_4_1}"))
	elseif rpm.vercmp(kver, "3.8.13-16") >= 0 then
		rpm.define("srcver 0.4.0")
		rpm.define("bldrel 3")
		rpm.define("dt_vcode "..rpm.expand("%{dt_0_4_0}"))
	elseif rpm.vercmp(kver, "3") >= 0 then
		-- No DTrace in 3.x kernels prior to 3.8.13-16
	elseif rpm.vercmp(kver, "2.6.39-201.0.2") >= 0 then
		rpm.define("srcver 0.3.2")
		rpm.define("bldrel 2")
		rpm.define("dt_vcode "..rpm.expand("%{dt_0_3_2}"))
	end
}
%if %{dt_vcode} == 0
 %{error:Kernel %{kver} is not supported for DTrace or source code missing}
%endif

#
# Current (new) RPM specification, with cleaned up dependencies.
#
%if %{dt_vcode} >= %{dt_0_4_2}

%if %{dt_vcode} >= %{dt_0_4_4}
%define header_pkg dtrace-modules-shared-headers
%else
%define header_pkg dtrace-modules-headers
%endif

Name: dtrace-modules-%{kver}
Summary: dtrace module
Version: %{srcver}
Release: %{bldrel}.el6
Provides: dtrace-modules
%if %{dt_vcode} >= %{dt_0_4_6}
Requires: at
%else
Requires: kernel%{variant} = %{kver}
%endif
License: CDDL
Group: System Environment/Kernel
Source0: dtrace-module-%{srcver}.tar.bz2
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
BuildRequires: kernel%{variant}-devel = %{kver}
BuildRequires: libdtrace-ctf
ExclusiveArch: x86_64 sparc64

%if %{_signmodules}
Source1: mod-sign.sh
%define modsign_cmd %{SOURCE1}
%endif

%description
DTrace kernel modules.

This package contains the DTrace core module, and standard provider modules:
dtrace, profile, syscall, sdt (io, proc,sched), and fasttrap (USDT).

Maintainers:
------------
Nick Alcock <nick.alcock@oracle.com>
Kris Van Hees <kris.van.hees@oracle.com>

%if %{dt_vcode} >= %{dt_0_4_6}
# If this package is not removed, but its dependent kernel is, schedule
# a later removal via at, late enough that this yum job is probably over.
%triggerun -- kernel%{variant} = %{kver}

at now + 4 hours >/dev/null 2>&1 <<'EOF'
rpm --quiet -e dtrace-modules-%{kver}
EOF
%endif

%package -n %{header_pkg}
Summary:	Header files for communication with the DTrace kernel module.
%if %{dt_vcode} >= %{dt_0_4_4}
Obsoletes:      dtrace-modules-headers
Provides:       dtrace-modules-headers 1:1
%endif
%description -n %{header_pkg}
This package contains header files describing the protocol used by userspace to
communicate with the DTrace kernel module.

%package -n dtrace-modules-provider-headers
Summary:	Header files for implementation of DTrace providers.
Requires:	%{header_pkg}
%{lua:
	local obsoleted = {"16.1.1", "16.2.1", "16.2.2", "16.2.3", "16.3.1",
                           "16.3.2", "16.3.3", "16"}

        for ignore, vers in ipairs(obsoleted) do
                print("Obsoletes: dtrace-modules-3.8.13-" .. vers ..
                      ".el6uek-provider-headers\n")
        end
}
%description -n dtrace-modules-provider-headers
This package contains header files defining the API used to implement DTrace
providers.

%else

Name: dtrace-modules-%{kver}
Summary: dtrace module
Version: %{srcver}
Release: %{bldrel}.el6
Provides: dtrace-kernel-interface = 1
License: CDDL
Group: System Environment/Kernel
%if %{dt_vcode} < %{dt_0_4_6}
Requires: kernel%{variant} = %{kver}
%endif
Source0: dtrace-module-%{srcver}.tar.bz2
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
BuildRequires: kernel%{variant}-devel = %{kver}
BuildRequires: libdtrace-ctf
ExclusiveArch: x86_64 sparc64

%description
DTrace kernel modules.

This package contains the DTrace core module, and standard provider modules:
dtrace, profile, syscall, sdt (io, proc,sched), and fasttrap (USDT).

Maintainers:
------------
Nick Alcock <nick.alcock@oracle.com>
Kris Van Hees <kris.van.hees@oracle.com>

%package headers
Summary:	Header files for communication with the DTrace kernel module.
Requires:	dtrace-modules-%{kver}
Provides:	dtrace-modules-headers = 1
%description headers
This package contains header files describing the protocol used by userspace to
communicate with the DTrace kernel module.

%package provider-headers
Summary:	Header files for implementation of DTrace providers.
Requires:	dtrace-modules-headers = 1
Provides:	dtrace-modules-provider-headers = 1
%description provider-headers
This package contains header files defining the API used to implement DTrace
providers.

%endif

%prep
rm -rf %{BuildRoot}

%setup -c -n %{name}

%build
cd dtrace
KSRC=/usr/src/kernels/%{kver}.%{karch}
make KERNELDIR=$KSRC karch=%{karch} modules

%if %{_signmodules}
%{modsign_cmd} ${RPM_BUILD_DIR}/%{name}/dtrace
%endif

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}/lib/modules/%{kver}.%{karch}/kernel/drivers/dtrace
install -m0644 ${RPM_BUILD_DIR}/%{name}/dtrace/*.ko %{buildroot}/lib/modules/%{kver}.%{karch}/kernel/drivers/dtrace/
mkdir -p %{buildroot}/usr/share/doc/dtrace-modules-%{kver}
install -m0644 ${RPM_BUILD_DIR}/%{name}/dtrace/NEWS %{buildroot}/usr/share/doc/dtrace-modules-%{kver}
cd dtrace
KSRC=/usr/src/kernels/%{kver}.%{karch}
make KERNELDIR=$KSRC karch=%{karch} headers_install INSTALL_HDR_PATH=%{buildroot}

%post
depmod -a %{kver}.%{karch} > /dev/null 2> /dev/null

%clean
rm -rf %{buildroot}

%files
%defattr(-,root,root,-)
/lib
/usr/share/doc

%if %{dt_vcode} >= %{dt_0_4_2}

%files -n %{header_pkg}
%defattr(-,root,root,-)
/usr/include/linux/dtrace
%exclude /usr/include/linux/dtrace/provider*.h
%exclude /usr/include/linux/dtrace/types.h

%files -n dtrace-modules-provider-headers
%defattr(-,root,root,-)
/usr/include/linux/dtrace/provider*.h
/usr/include/linux/dtrace/types.h

%else

%files headers
%defattr(-,root,root,-)
/usr/include/linux/dtrace
%exclude /usr/include/linux/dtrace/provider*.h
%exclude /usr/include/linux/dtrace/types.h

%files provider-headers
%defattr(-,root,root,-)
/usr/include/linux/dtrace/provider*.h
/usr/include/linux/dtrace/types.h

%endif

%changelog
%if %{dt_vcode} >= %{dt_0_5_3}
* Wed Jul 20 2016 Nick Alcock <nick.alcock@oracle.com> - 0.5.3-2
- Re-enable 0.5.3 release after bugfix [Orabug: 23344927]
* Mon May 23 2016 Kris Van Hees <kris.van.hees@oracle.com> - 0.5.3-1
- Provider 'perf' added to SDT for perf events.
  (Nick Alcock) [Orabug: 23004534]
- Fix to ensure that pdata and sdt_tab handling works across module reloads.
  [Orabug: 23331667]
- Moving pdata size assertion checking to arch-specific code.
  (Nick Alcock) [Orabug: 23331667]
%endif
%if %{dt_vcode} >= %{dt_0_5_2}
* Thu Feb  4 2016 Kris Van Hees <kris.van.hees@oracle.com> - 0.5.2-1
- Correct probe disable/enable mechanism for syscalls.
  [Orabug: 22352636]
- Fix access to uregs[I_R7] for sparc64.
  (Nick Alcock) [Orabug: 22602870]
- Use a more efficient, consistent, and reliable mechanism to read user
  stack locations.
  (Nick Alcock) [Orabug: 22629102]
%endif
%if %{dt_vcode} >= %{dt_0_5_1}
* Tue Nov 17 2015 Kris Van Hees <kris.van.hees@oracle.com> - 0.5.1-1
- Remove explicit dependency on kernel RPM.
  [Orabug: 21669543]
- Ensure safety checks are enforced on copyout() and copyoutstr().
  [Orabug: 21930954]
- Fix device file minor number for dt_perf.
  [Orabug: 21814949]
%endif
%if %{dt_vcode} >= %{dt_0_5_0}
* Fri Sep 18 2015 Kris Van Hees <kris.van.hees@oracle.com> - 0.5.0-3
- Enable building DTrace modules for SPARC64.
* Mon Aug 10 2015 Natalya Naumova <natalya.naumova@oracle.com> - 0.5.0-2
- modules signing support
* Mon Aug 10 2015 Kris Van Hees <kris.van.hees@oracle.com> - 0.5.0-1
- Use kernel-provided SDT trampoline memory area for SPARC64.
  [Orabug: 21220344]
- Add support for sparc64.
  [Orabug: 19005048]
- Update uid / gid handling in view of namespaces in UEK4 kernels.
  [Orabug: 20456825]
%else
%if %{dt_vcode} >= %{dt_0_4_6}
* Tue Nov 17 2015 Kris Van Hees <kris.van.hees@oracle.com> - 0.4.6-1
- Remove explicit dependency on kernel RPM.
  [Orabug: 21669543]
- Ensure safety checks are enforced on copyout() and copyoutstr().
  [Orabug: 21930954]
- Fix device file minor number for dt_perf.
  [Orabug: 21814949]
%endif
%endif
%if %{dt_vcode} >= %{dt_0_4_5}
* Tue Jul  7 2015 Kris Van Hees <kris.van.hees@oracle.com> - 0.4.5-3
- Synchronize versions with OL7
* Tue Jun 23 2015 Kris Van Hees <kris.van.hees@oracle.com> - 0.4.5-2
- Validate d_path() argument pointer to avoid crash.
  [Orabug: 21304207]
* Wed Jun 17 2015 Kris Van Hees <kris.van.hees@oracle.com> - 0.4.5-1
- Support USDT for 32-bit applications on 64-bit hosts.
  [Orabug: 21219315]
- Convert from sdt_instr_t to asm_instr_t.
  [Orabug: 21219374]
- Restructuring to support DTrace on multiple architectures.
  [Orabug: 21273259]
- Fix dtrace_helptrace_buffer memory leak.
  [Orabug: 20514336]
- Add .gitignore file.
  [Orabug: 20266608]
%endif
%if %{dt_vcode} >= %{dt_0_4_4}
* Thu Mar  9 2015 Nick Alcock <nick.alcock@oracle.com> - 0.4.4-1
- Rename dtrace-modules-headers to dtrace-modules-shared-headers.
  [Orabug: 20508087]
%endif
%if %{dt_vcode} >= %{dt_0_4_3}
* Fri Apr 24 2014 Kris Van Hees <kris.van.hees@oracle.com> - 0.4.3-4
- Updated NEWS file: test stress/buffering/tst.resize1.d is XFAIL for now.
- Align with kernel header file change: FOLL_NOFAULT -> FOLL_IMMED.
  [Orabug: 18653713]
* Fri Apr 24 2014 Kris Van Hees <kris.van.hees@oracle.com> - 0.4.3-3
- Rebuild with cleaned up source tree.
* Thu Apr 24 2014 Nick Alcock <nick.alcock@oracle.com> - 0.4.3-2
- Various fixes to handle multi-threaded processes.
  [Orabug: 18412802]
* Tue Apr 15 2014 Kris Van Hees <kris.van.hees@oracle.com> - 0.4.3-1
- Implmentation of profile-* probes in the profile provider.
  [Orabug: 18323513]
%endif
%if %{dt_vcode} >= %{dt_0_4_2}
* Wed Jan 29 2014 Nick Alcock <nick.alcock@oracle.com> - 0.4.2-3
- Obsolete the old provider headers package.
  [Orabug: 18061595]
* Mon Jan 27 2014 Nick Alcock <nick.alcock@oracle.com> - 0.4.2-2
- Change name of provider headers package, to avoid conflicts on yum update.
  [Orabug: 18061595]
* Fri Dec 20 2013 Kris Van Hees <kris.van.hees@oracle.com> - 0.4.2-1
- Fix 'vtimestamp' implementation.
  [Orabug: 17741477]
- Support SDT probes points in kernel modules.
  [Orabug: 17851716]
%endif
%if %{dt_vcode} >= %{dt_0_4_1}
* Wed Nov  6 2013 Kris Van Hees <kris.van.hees@oracle.com> - 0.4.1-3
- Fix 'errno' implementation.
  [Orabug: 17704568]
* Wed Oct 26 2013 Kris Van Hees <kris.van.hees@oracle.com> - 0.4.1-2
- Fix lock ordering issues.
  [Orabug: 17624236]
* Wed Oct 16 2013 Kris Van Hees <kris.van.hees@oracle.com> - 0.4.1-1
- Align with new cyclic implementation in UEK3 kernel.
  [Orabug: 17553446]
- Bugfix for module reference counting.
- Fix memory leak.
- Fix race condition in speculative tracing buffer cleaning.
  [Orabug: 17591351]
- Ensure safe access to userspace stack memory location.
  [Orabug: 17591351]
%endif
%if %{dt_vcode} == %{dt_0_4_0}
* Thu Oct 17 2013 Nick Alcock <nick.alcock@oracle.com> - 0.4.0-3
- fix changelog, no code changes
%endif
%if %{dt_vcode} >= %{dt_0_4_0}
* Thu Oct 10 2013 Kris Van Hees <kris.van.hees@oracle.com> - 0.4.0-2
- Bugfix for ustack() to avoid using vma data.
* Wed Aug  7 2013 Kris Van Hees <kris.van.hees@oracle.com> - 0.4.0-1
- Bugfix for module unloading.
- Support meta-providers, USDT, and fasttrap (for USDT only).
- Export DTrace kernel headers to userspace.
- Improved ustack() robustness.
  [Orabug: 17591351]
- Reimplemented ustack().
  (Nick Alcock) [Orabug: 17591351]
- Bugfixes.
%endif
%if %{dt_vcode} >= %{dt_0_3_2}
* Fri Nov  2 2012 Nick Alcock <nick.alcock@oracle.com> - 0.3.2
- Release for new kernel and CTF section layout
%endif
* Mon Oct  1 2012 Kris Van Hees <kris.van.hees@oracle.com> - 0.3.1
- Skipped version number
* Mon Sep 17 2012 Kris Van Hees <kris.van.hees@oracle.com> - 0.3.0-2
- Remove development-only providers because they should not be built/released.
* Fri Sep 14 2012 Kris Van Hees <kris.van.hees@oracle.com> - 0.3.0
- Release of the DTrace kernel modules for UEK2 2.6.39-201.0.1 (DTrace kernel).
* Mon Mar 19 2012 Nick Alcock <nick.alcock@oracle.com> - 0.2.5-2
- Fix typo causing unconditional depmod at postinstall time
* Tue Mar 13 2012 Nick Alcock <nick.alcock@oracle.com> - 0.2.5
- New kernel, new userspace: no module changes.
* Wed Feb 15 2012 Kris van Hees <kris.van.hees@oracle.com> - 0.2.4
- Ban unloading of in-use dtrace modules while dtrace is running.
* Thu Feb  9 2012 Nick Alcock <nick.alcock@oracle.com> - 0.2.3
- There is one new DTrace option now, used internally by the
  testsuite.
* Tue Feb  7 2012 Kris Van Hees <kris.van.hees@oracle.com> - 0.2.2
- Switch MUTEX_HELD() from using mutex_is_locked() to new mutex_owned().
* Mon Jan 23 2012 Kris Van Hees <kris.van.hees@oracle.com> - 0.2.1
- Ensure that allocation attempts are done in atomic fashion so that a failing
  allocation attempt won't interfere with other allocations.
- Surpress OOM warnings.
* Mon Jan 23 2012 Kris Van Hees <kris.van.hees@oracle.com> - 0.2.0
- Release of the DTrace kernel modules for UEK2 2.6.39-101.0.1 (DTrace kernel).
* Wed Oct 19 2011 Kris Van Hees <kris.van.hees@oracle.com> - 0.1.0-1.el6
- Disable stub-based syscalls in the release pending merging in fixes.
* Thu Sep 29 2011 Maxim Uvarov <maxim.uvarov@oracle.com> - 0.1
- Initial release.
