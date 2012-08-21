#sbs-git:api/wifi

Name:       capi-network-wifi
Summary:    Network Wi-Fi library in TIZEN C API
Version:    0.1.1_2
Release:    1
Group:      System/Network
License:    Apache License Version 2.0
Source0:    %{name}-%{version}.tar.gz
BuildRequires:  cmake
BuildRequires:  pkgconfig(dlog)
BuildRequires:  pkgconfig(glib-2.0)
BuildRequires:  pkgconfig(vconf)
BuildRequires:  pkgconfig(capi-base-common)
BuildRequires:  pkgconfig(network)
Requires(post): /sbin/ldconfig
Requires(postun): /sbin/ldconfig

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
cmake . -DCMAKE_INSTALL_PREFIX=/usr -DFULLVER=%{version} -DMAJORVER=${MAJORVER}


make %{?jobs:-j%jobs}

%install
rm -rf %{buildroot}
%make_install

%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig


%files
%{_libdir}/libcapi-network-wifi.so.*

%files devel
%{_includedir}/network/*.h
%{_libdir}/pkgconfig/*.pc
%{_libdir}/libcapi-network-wifi.so
