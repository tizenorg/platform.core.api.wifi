Name:       capi-network-wifi
Summary:    Network Wi-Fi library in TIZEN C API
Version:    0.1.2_24
Release:    1
Group:      System/Network
License:    Apache-2.0
Source0:    %{name}-%{version}.tar.gz
Source1001: 	capi-network-wifi.manifest
BuildRequires:  cmake
BuildRequires:  pkgconfig(dlog)
BuildRequires:  pkgconfig(glib-2.0)
BuildRequires:  pkgconfig(vconf)
BuildRequires:  pkgconfig(capi-base-common)
BuildRequires:  pkgconfig(winet-lib)
BuildRequires:  pkgconfig(connman-lib)

%description
Network Wi-Fi library in Tizen C API

%package devel
Summary:  Network Wi-Fi library in Tizen C API (Development)
Group:    System/Network
Requires: %{name} = %{version}-%{release}

%description devel
Network Wi-Fi library in Tizen C API (Development)

%package test
Summary:    Test case for wifi (DEV)
Requires:   %{name} = %{version}

%description test
Test case for wifi (DEV). Some test programs to test the APIs
and interfaces about wifi or other inner code.

%prep
%setup -q
cp %{SOURCE1001} .


%build
MAJORVER=`echo %{version} | awk 'BEGIN {FS="."}{print $1}'`
%cmake . -DFULLVER=%{version} -DMAJORVER=${MAJORVER}

make %{?_smp_mflags}


%install
%make_install

#License
mkdir -p %{buildroot}%{_datadir}/license
cp LICENSE.APLv2 %{buildroot}%{_datadir}/license/capi-network-wifi

%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig


%files
%manifest %{name}.manifest
%attr(644,-,-) %{_libdir}/libcapi-network-wifi.so.*
%{_datadir}/license/capi-network-wifi

%files devel
%manifest %{name}.manifest
%{_includedir}/network/*.h
%{_libdir}/pkgconfig/*.pc
%{_libdir}/libcapi-network-wifi.so

%files test
%manifest %{name}.manifest
%{_libdir}/winet-capi-test/capi-wifi-test