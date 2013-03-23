Name:       capi-network-wifi
Summary:    Network Wi-Fi library in TIZEN C API
Version:    0.1.2_17
Release:    1
Group:      System/Network
License:    Apache-2.0
Source0:    %{name}-%{version}.tar.gz
BuildRequires:  cmake
BuildRequires:  pkgconfig(dlog)
BuildRequires:  pkgconfig(glib-2.0)
BuildRequires:  pkgconfig(vconf)
BuildRequires:  pkgconfig(capi-base-common)
BuildRequires:  pkgconfig(network)

%description
Network Wi-Fi library in Tizen C API

%package devel
Summary:  Network Wi-Fi library in Tizen C API (Development)
Group:    System/Network
Requires: %{name} = %{version}-%{release}

%description devel
Network Wi-Fi library in Tizen C API (Development)

%prep
%setup -q


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
%manifest capi-network-wifi.manifest
%attr(644,-,-) %{_libdir}/libcapi-network-wifi.so.*
%{_datadir}/license/capi-network-wifi

%files devel
%{_includedir}/network/*.h
%{_libdir}/pkgconfig/*.pc
%{_libdir}/libcapi-network-wifi.so
