

# KMP is disabled by default
%{!?KMP: %global KMP 0}

# take cpu arch from uname -m
%global cpu_arch %(uname -m)
%global docdir /etc/mstflint
%global mlxfwreset_ko_path %{docdir}/mlxfwreset/


# take kernel version or default to uname -r
%{!?KVERSION: %global KVERSION %(uname -r)}
%global kernel_version %{KVERSION}
%global krelver %(echo -n %{KVERSION} | sed -e 's/-/_/g')
# take path to kernel sources if provided, otherwise look in default location (for non KMP rpms).
%{!?K_SRC: %global K_SRC /lib/modules/%{KVERSION}/build}

%if "%{KMP}" == "1"
%global _name kernel-mstflint-mlnx
%else
%global _name kernel-mstflint
%endif

%{!?version: %global version 4.13.1}
%{!?_release: %global _release 1}
%global _kmp_rel %{_release}%{?_kmp_build_num}%{?_dist}

Name: %{_name}
Summary: %{name} Kernel Module for the %{KVERSION} kernel
Version: %{version}
Release: %{!?source:%{krelver}%{?_dist}}%{?source:%{_release}%{?_dist}}
License: Dual BSD/GPL #make sure it's the needed license
Group: System Environment/Kernel
BuildRoot: /var/tmp/%{name}-%{version}-build
Source: %{name}-%{version}.tar.gz
Vendor: Mellanox Technologies Ltd.
Packager: Eran Jakoby <eranj@mellanox.com>
%description
mstflint kernel module for secure boot

%global debug_package %{nil}

# build KMP rpms?
%if "%{KMP}" == "1"
%global kernel_release() $(make -C %{1} kernelrelease | grep -v make | tail -1)
BuildRequires: %kernel_module_package_buildreqs
# prep file list for kmp rpm
%(cat > %{_builddir}/kmp.files << EOF
%defattr(644,root,root,755)
/lib/modules/%2-%1
%if "%{_vendor}" == "redhat"
%config(noreplace) /etc/depmod.d/kernel-mft.conf
%endif
EOF)
%{kernel_module_package -f %{_builddir}/kmp.files -r %{_kmp_rel} }
%else
%global kernel_source() %{K_SRC}
%global kernel_release() %{KVERSION}
%global flavors_to_build default
%endif

%description
This package provides a %{name} kernel module for kernel.

#
# setup module sign scripts if paths to the keys are given
#
%global WITH_MOD_SIGN %(if ( test -f "$MODULE_SIGN_PRIV_KEY" && test -f "$MODULE_SIGN_PUB_KEY" ); \
	then \
		echo -n '1'; \
	else \
		echo -n '0'; fi)

%if "%{WITH_MOD_SIGN}" == "1"
# call module sign script
%global __modsign_install_post \
    $RPM_BUILD_DIR/kernel-mstflint-%{version}/source/tools/sign-modules $RPM_BUILD_ROOT/lib/modules/ %{kernel_source default} || exit 1 \
%{nil}

# Disgusting hack alert! We need to ensure we sign modules *after* all
# invocations of strip occur, which is in __debug_install_post if
# find-debuginfo.sh runs, and __os_install_post if not.
#
%global __spec_install_post \
  %{?__debug_package:%{__debug_install_post}} \
  %{__arch_install_post} \
  %{__os_install_post} \
  %{__modsign_install_post} \
%{nil}

%endif # end of setup module sign scripts

%if "%{_vendor}" == "redhat"
%global __find_requires %{nil}
%endif

# set modules dir
%if "%{_vendor}" == "redhat"
%if 0%{?fedora}
%global install_mod_dir updates
%else
%global install_mod_dir extra/%{name}
%endif
%endif

%if "%{_vendor}" == "suse"
%global install_mod_dir updates
%endif

%{!?install_mod_dir: %global install_mod_dir updates}

%prep
%setup -n kernel-mstflint-%{version}
set -- *
mkdir source
mv "$@" source/
mkdir obj

%build
rm -rf $RPM_BUILD_ROOT
export EXTRA_CFLAGS='-DVERSION=\"%version\"'
for flavor in %{flavors_to_build}; do
	rm -rf obj/$flavor
	cp -a source obj/$flavor
	cd $PWD/obj/$flavor
	export KSRC=%{kernel_source $flavor}
	export KVERSION=%{kernel_release $KSRC}
	make KPVER=$KVERSION
	cd -
done

%install
export INSTALL_MOD_PATH=$RPM_BUILD_ROOT
export INSTALL_MOD_DIR=%{install_mod_dir}
mkdir -p %{install_mod_dir}
for flavor in %{flavors_to_build}; do
	export KSRC=%{kernel_source $flavor}
	export KVERSION=%{kernel_release $KSRC}
	install -d $INSTALL_MOD_PATH/lib/modules/$KVERSION/%{install_mod_dir}
	cp $PWD/obj/$flavor/mstflint_access.ko $INSTALL_MOD_PATH/lib/modules/$KVERSION/%{install_mod_dir}/
done

%if "%{_vendor}" == "redhat"
# Set the module(s) to be executable, so that they will be stripped when packaged.
find %{buildroot} -type f -name \*.ko -exec %{__chmod} u+x \{\} \;
%if "%{KMP}" == "1"
%{__install} -d $RPM_BUILD_ROOT%{_sysconfdir}/depmod.d/
echo "override mstflint_access * weak-updates/mstflint" > $RPM_BUILD_ROOT%{_sysconfdir}/depmod.d/kernel-mstflint.conf
%endif
%else
find %{buildroot} -type f -name \*.ko -exec %{__strip} -p --strip-debug --discard-locals -R .comment -R .note \{\} \;
%endif

%post
/sbin/depmod %{KVERSION}

%postun
/sbin/depmod %{KVERSION}

%if "%{KMP}" != "1"
%files
%defattr(-,root,root,-)
/lib/modules/%{KVERSION}/%{install_mod_dir}/
%endif
%if "%{cpu_arch}" == "ppc64" || "%{cpu_arch}" == "ppc64le"
%if "%{KMP}" == "1"
%files utils
%defattr(-,root,root,-)
%endif
%{docdir}
%endif

%changelog
* Sun Dec 17 2017 Mahmoud Hasan <mahmodh@mellanox.com>
- Initial revision
