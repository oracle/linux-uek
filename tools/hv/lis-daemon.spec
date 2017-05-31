
# nodebuginfo
# norootforbuild


%define releasetag public
%define release %(date +%Y%m%d)
%define _unpackaged_files_terminate_build 0

Name:			msft-daemons
License:		GPLv2+
Summary:		Microsoft hyper-v daemons
Version:		1
Release:		0.29%{?snapver}%{?dist}
Source0:		hv_kvp_daemon.c
Source1:		hv_kvp_daemon.service
Source2:		70-hv_kvp.rules
Source3:		hv_get_dhcp_info.sh
Source4:		hv_get_dns_info.sh
Source5:		hv_set_ifconfig.sh
Source6:		hv_kvp_daemon.service
Source7:		hv_vss_daemon.c
Source8:		70-hv_vss.rules
Source9:		hv_vss_daemon.service
Source10:		hv_fcopy_daemon.c
Source11:		70-hv_fcopy.rules
Source12:		hv_fcopy_daemon.service
BuildRoot:		%{_tmppath}/%{name}-%{version}-build
Requires:		kernel >= 3.10.0-384.el7
BuildRequires:		systemd, kernel-headers
Requires(post):		systemd
Requires(preun):	systemd
Requires(postun):	systemd


%description
This package utilities for the Microsoft Hyper-V environment.

%prep
%setup -Tc
cp -pvL %{SOURCE0} hv_kvp_daemon.c
cp -pvL %{SOURCE3} hv_get_dhcp_info.sh
cp -pvL %{SOURCE4} hv_get_dns_info.sh
cp -pvL %{SOURCE5} hv_set_ifconfig.sh
cp -pvL %{SOURCE1} hv_kvp_daemon.service

cp -pvL %{SOURCE7} hv_vss_daemon.c
cp -pvL %{SOURCE9} hv_vss_daemon.service

cp -pvL %{SOURCE10} hv_fcopy_daemon.c
cp -pvL %{SOURCE12} hv_fcopy_daemon.service

%build
make

%install

mkdir -p %{buildroot}%{_sbindir}
install -p -m 0755 %{hv_kvp_daemon} %{buildroot}%{_sbindir}
install -p -m 0755 %{hv_vss_daemon} %{buildroot}%{_sbindir}
install -p -m 0755 %{hv_fcopy_daemon} %{buildroot}%{_sbindir}

# Systemd unit file
mkdir -p %{buildroot}%{_unitdir}
install -p -m 0644 %{SOURCE1} %{buildroot}%{_unitdir}
install -p -m 0644 %{SOURCE9} %{buildroot}%{_unitdir}
install -p -m 0644 %{SOURCE12} %{buildroot}%{_unitdir}

# Udev rules
mkdir -p %{buildroot}%{_udevrulesdir}
install -p -m 0644 %{SOURCE2} %{buildroot}%{_udevrulesdir}/%{udev_prefix}-70-hv_kvp.rules
install -p -m 0644 %{SOURCE8} %{buildroot}%{_udevrulesdir}/%{udev_prefix}-70-hv_vss.rules
install -p -m 0644 %{SOURCE11} %{buildroot}%{_udevrulesdir}/%{udev_prefix}-70-hv_fcopy.rules

# Shell scripts for the KVP daemon
mkdir -p %{buildroot}%{_libexecdir}/%{hv_kvp_daemon}
install -p -m 0755 %{SOURCE3} %{buildroot}%{_libexecdir}/%{hv_kvp_daemon}/hv_get_dhcp_info
install -p -m 0755 %{SOURCE4} %{buildroot}%{_libexecdir}/%{hv_kvp_daemon}/hv_get_dns_info
install -p -m 0755 %{SOURCE5} %{buildroot}%{_libexecdir}/%{hv_kvp_daemon}/hv_set_ifconfig

# Directory for pool files
mkdir -p %{buildroot}%{_sharedstatedir}/hyperv


echo "Starting KVP Daemon...."
systemctl daemon-reload
systemctl enable hv_kvp_daemon.service > /dev/null 2>&1

echo "Starting VSS Daemon...."
systemctl enable hv_vss_daemon.service > /dev/null 2>&1

echo "Starting FCOPY Daemon...."
systemctl enable hv_fcopy_daemon.service > /dev/null 2>&1

%preun
if [ $1 -eq 0 ]; then # package is being erased, not upgraded
    echo "Removing Package.."
    echo "Stopping KVP Daemon...."
    systemctl stop hv_kvp_daemon
    echo "Stopping FCOPY Daemon...."
    systemctl stop hv_fcopy_daemon
    echo "Stopping VSS Daemon...."
    systemctl stop hv_vss_daemon
    rm -rf %{_sharedstatedir}/hyperv || :
fi

%post
if [ $1 > 1 ] ; then
        # Upgrade
        systemctl --no-reload disable hv_kvp_daemon.service  >/dev/null 2>&1 || :
	systemctl --no-reload disable hv_vss_daemon.service  >/dev/null 2>&1 || :
	systemctl --no-reload disable hv_fcopy_daemon.service  >/dev/null 2>&1 || :
fi

%postun
%systemd_postun hypervkvpd.service
%systemd_postun hypervkvpd.service
%systemd_postun hypervkvpd.service

%files
%defattr(0644, root, root)
%{_sbindir}/%{hv_kvp_daemon}
%{_unitdir}/hv_kvp_daemon.service
%{_udevrulesdir}/%{udev_prefix}-70-hv_kvp.rules
%dir %{_libexecdir}/%{hv_kvp_daemon}
%{_libexecdir}/%{hv_kvp_daemon}/*
%dir %{_sharedstatedir}/hyperv
%{_sbindir}/%{hv_vss_daemon}
%{_unitdir}/hv_vss_daemon.service
%{_udevrulesdir}/%{udev_prefix}-70-hv_vss.rules
%{_sbindir}/%{hv_fcopy_daemon}
%{_unitdir}/hv_fcopy_daemon.service
%{_udevrulesdir}/%{udev_prefix}-70-hv_fcopy.rules



%changelog
