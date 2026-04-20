%global         pg_major %{?pg_major}%{!?pg_major:16}
%global         pg_libdir     %{_libdir}/pgsql
%global         pg_extensiondir %{_datadir}/pgsql/extension

# Caller passes --define "pg_major 16|17|18" to pick the matching
# prebuilt .so from dist/${arch}/fractalsql_pg${pg_major}.so.

Name:           postgresql-%{pg_major}-fractalsql
Version:        1.0.0
Release:        1%{?dist}
Summary:        Stochastic Fractal Search extension for PostgreSQL %{pg_major}

License:        MIT
URL:            https://github.com/FractalSQLabs/postgresql-fractalsql
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  gcc, make, postgresql%{pg_major}-devel
Requires:       postgresql%{pg_major}-server

%description
FractalSQL registers the fractal_search() and fractal_search_explore()
functions — a LuaJIT-backed Stochastic Fractal Search optimizer for
high-diversity vector search inside PostgreSQL %{pg_major}. LuaJIT is
statically linked into the extension; no external luajit runtime is
required.

%prep
%setup -q

%build
# The per-PG-version .so is produced out-of-band by build.sh on a Docker
# builder; this spec just stages it into the RPM.
test -f dist/fractalsql_pg%{pg_major}.so

%install
install -Dm0755 dist/fractalsql_pg%{pg_major}.so \
    %{buildroot}/usr/pgsql-%{pg_major}/lib/fractalsql.so
install -Dm0644 fractalsql.control \
    %{buildroot}/usr/pgsql-%{pg_major}/share/extension/fractalsql.control
install -Dm0644 sql/fractalsql--1.0.sql \
    %{buildroot}/usr/pgsql-%{pg_major}/share/extension/fractalsql--1.0.sql

%files
%license LICENSE
%license LICENSE-THIRD-PARTY
/usr/pgsql-%{pg_major}/lib/fractalsql.so
/usr/pgsql-%{pg_major}/share/extension/fractalsql.control
/usr/pgsql-%{pg_major}/share/extension/fractalsql--1.0.sql

%changelog
* Sat Apr 18 2026 FractalSQLabs <ops@fractalsqlabs.io> - 1.0.0-1
- Initial Factory-standardized release for PostgreSQL 16 / 17 / 18.
