#
# spec file for package juptune
#
# Copyright (c) 2024 SUSE LLC
#
# All modifications and additions to the file contributed by third parties
# remain the property of their copyright owners, unless otherwise agreed
# upon. The license for this file, and modifications and additions to the
# file, is the same license as for the pristine package itself (unless the
# license for the pristine package is not an Open Source License, in which
# case the license is the MIT License). An "Open Source License" is a
# license that conforms to the Open Source Definition (Version 1.9)
# published by the Open Source Initiative.

# Please submit bugfixes or comments via https://bugs.opensuse.org/
#


%define lib_name        lib%{name}
%define include_dir     juptune
%define pkgconfig_name  juptune
%define meson_buildtype release

Name:           juptune
Version:        0.0.0
Release:        0
Summary:        Async I/O framework for D
License:        MPL-2.0
Group:          System/Libraries
URL:            https://github.com/Juptune/juptune
Source0:        juptune-%{version}.tar
BuildRequires:  ldc
BuildRequires:  ldc-phobos-devel
BuildRequires:  ldc-runtime-devel
BuildRequires:  meson
BuildRequires:  pkgconfig
BuildRequires:  pkgconfig(libsodium)
ExclusiveArch:  x86_64

%description
Contains runtime shared libraries required by all applications
that use Juptune. Juptune is a library that provides D applications
access to asynchronous I/O, as well as features such as HTTP
client/server implementations.

%package        devel
Summary:        Development files for %{name}
License:        MPL-2.0 AND ISC
Group:          Development/Libraries/Other
Requires:       %{name} = %{version}

%description devel
The %{name}-devel package contains libraries and header files for
developing applications that use %{name}.

%prep
%setup -q

# For some reason, `osc build` is adding in a bad `--flto=auto` flag which LDC2 doesn't support.
# This doesn't happen with a raw `rpmbuild`. It's simple enough to fix though - we just won't use the meson setup macro.
%build
%{_bindir}/meson setup \
    --buildtype=%{meson_buildtype} \
    --prefix=%{_prefix} \
    --libdir=%{_libdir} \
    --libexecdir=%{_libexecdir} \
    --bindir=%{_bindir} \
    --sbindir=%{_sbindir} \
    --includedir=%{_includedir} \
    --datadir=%{_datadir} \
    --mandir=%{_mandir} \
    --infodir=%{_infodir} \
    --localedir=%{_localedir} \
    --sysconfdir=%{_sysconfdir} \
    --localstatedir=%{_localstatedir} \
    --sharedstatedir=%{_sharedstatedir} \
    --wrap-mode=nodownload \
    --auto-features=enabled \
    --strip \
    %{_vpath_srcdir} \
    %{_vpath_builddir}
%meson_build

%install
%meson_install

%if "%{meson_buildtype}" == "debug" || "%{meson_buildtype}" == "debugoptimized"
%check
%meson_test
%endif

%post -p /sbin/ldconfig
%postun -p /sbin/ldconfig

%files
%license LICENSE.txt
%doc README.md
%{_libdir}/%{lib_name}.so.*

%files devel
%dir %{_includedir}/d/
%{_includedir}/d/%{include_dir}/
%{_libdir}/pkgconfig/%{pkgconfig_name}.pc
%{_libdir}/%{lib_name}.so

%changelog
