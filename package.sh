#!/bin/bash
#
# postgresql-fractalsql packaging.
#
# Assumes ./build.sh ${ARCH} has already produced:
#   dist/${ARCH}/fractalsql_pg14.so
#   dist/${ARCH}/fractalsql_pg15.so
#   dist/${ARCH}/fractalsql_pg16.so
#   dist/${ARCH}/fractalsql_pg17.so
#   dist/${ARCH}/fractalsql_pg18.so
#
# Emits one .deb and one .rpm per (PG major, arch) pair into
# dist/packages/:
#   dist/packages/postgresql-14-fractalsql-amd64.deb
#   dist/packages/postgresql-14-fractalsql-amd64.rpm
#   dist/packages/postgresql-18-fractalsql-arm64.deb
#   ...
#
# Usage:
#   ./package.sh [amd64|arm64]     # default: amd64

set -euo pipefail

VERSION="1.0.0"
ITERATION="1"
DIST_DIR="dist/packages"
mkdir -p "${DIST_DIR}"

# Absolute repo root, captured before any -C chdir'd fpm invocation.
# Used as the source side of the license-file mappings below so they
# resolve outside each per-package STAGE dir.
REPO_ROOT="$(pwd)"
for f in LICENSE LICENSE-THIRD-PARTY; do
    if [ ! -f "${REPO_ROOT}/${f}" ]; then
        echo "missing ${REPO_ROOT}/${f} — refusing to package without it" >&2
        exit 1
    fi
done

PKG_ARCH="${1:-amd64}"
case "${PKG_ARCH}" in
    amd64|arm64) ;;
    *)
        echo "unknown arch '${PKG_ARCH}' — expected amd64 or arm64" >&2
        exit 2
        ;;
esac

case "${PKG_ARCH}" in
    amd64) RPM_ARCH="x86_64" ;;
    arm64) RPM_ARCH="aarch64" ;;
esac

SRC_DIR="dist/${PKG_ARCH}"

for PG_VER in 14 15 16 17 18; do
    SO="${SRC_DIR}/fractalsql_pg${PG_VER}.so"
    if [ ! -f "${SO}" ]; then
        echo "missing ${SO} — run ./build.sh ${PKG_ARCH} first" >&2
        exit 1
    fi

    PKG_NAME="postgresql-${PG_VER}-fractalsql"
    DEB_OUT="${DIST_DIR}/${PKG_NAME}-${PKG_ARCH}.deb"
    RPM_OUT="${DIST_DIR}/${PKG_NAME}-${PKG_ARCH}.rpm"

    # Build a staging root that mirrors the on-disk layout of a PG-X
    # extension so fpm can just tar it up.
    STAGE="$(mktemp -d)"
    trap 'rm -rf "${STAGE}"' EXIT

    install -Dm0755 "${SO}" \
        "${STAGE}/usr/lib/postgresql/${PG_VER}/lib/fractalsql.so"
    install -Dm0644 fractalsql.control \
        "${STAGE}/usr/share/postgresql/${PG_VER}/extension/fractalsql.control"
    install -Dm0644 sql/fractalsql--1.0.sql \
        "${STAGE}/usr/share/postgresql/${PG_VER}/extension/fractalsql--1.0.sql"

    # LICENSE ledger: staged into /usr/share/doc/<pkg>/ so the usr\
    # walk below picks them up. Explicit src=dst fpm mappings won't
    # work here — fpm's -C chroots absolute source paths too, so any
    # arg like ${REPO_ROOT}/LICENSE is resolved as ${STAGE}${REPO_ROOT}/…
    # and fpm can't find the file.
    install -Dm0644 "${REPO_ROOT}/LICENSE" \
        "${STAGE}/usr/share/doc/${PKG_NAME}/LICENSE"
    install -Dm0644 "${REPO_ROOT}/LICENSE-THIRD-PARTY" \
        "${STAGE}/usr/share/doc/${PKG_NAME}/LICENSE-THIRD-PARTY"

    echo "------------------------------------------"
    echo "Packaging ${PKG_NAME} (${PKG_ARCH})"
    echo "------------------------------------------"

    # LuaJIT is statically linked into fractalsql.so — no runtime
    # luajit/libluajit dependency is declared on either package.
    fpm -s dir -t deb \
        -n "${PKG_NAME}" \
        -v "${VERSION}" \
        -a "${PKG_ARCH}" \
        --iteration "${ITERATION}" \
        --description "FractalSQL: Stochastic Fractal Search extension for PostgreSQL ${PG_VER}" \
        --license "MIT" \
        --depends "libc6 (>= 2.38)" \
        --depends "postgresql-${PG_VER}" \
        -C "${STAGE}" \
        -p "${DEB_OUT}" \
        usr

    fpm -s dir -t rpm \
        -n "${PKG_NAME}" \
        -v "${VERSION}" \
        -a "${RPM_ARCH}" \
        --iteration "${ITERATION}" \
        --description "FractalSQL: Stochastic Fractal Search extension for PostgreSQL ${PG_VER}" \
        --license "MIT" \
        --depends "postgresql${PG_VER}-server" \
        -C "${STAGE}" \
        -p "${RPM_OUT}" \
        usr

    rm -rf "${STAGE}"
    trap - EXIT
done

echo
echo "Done. Packages in ${DIST_DIR}:"
ls -l "${DIST_DIR}"
