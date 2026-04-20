#!/bin/bash
#
# postgresql-fractalsql multi-version, multi-arch build.
#
# Drives docker/Dockerfile to produce one .so per PG major for a single
# target architecture. Output layout:
#   dist/amd64/fractalsql_pg16.so
#   dist/amd64/fractalsql_pg17.so
#   dist/amd64/fractalsql_pg18.so
#   dist/arm64/fractalsql_pg16.so
#   ...
#
# Usage:
#   ./build.sh [amd64|arm64]        # default: amd64
#
# Cross-arch builds need QEMU + binfmt_misc. In CI this is handled by
# docker/setup-qemu-action; locally:
#   docker run --privileged --rm tonistiigi/binfmt --install all

set -euo pipefail

ARCH="${1:-amd64}"
case "${ARCH}" in
    amd64|arm64) ;;
    *)
        echo "unknown arch '${ARCH}' — expected amd64 or arm64" >&2
        exit 2
        ;;
esac

DIST_DIR="${DIST_DIR:-./dist}"
DOCKERFILE="${DOCKERFILE:-docker/Dockerfile}"
PLATFORM="linux/${ARCH}"
OUT_DIR="${DIST_DIR}/${ARCH}"

mkdir -p "${OUT_DIR}"

echo "------------------------------------------"
echo "Building postgresql-fractalsql for ${PLATFORM}"
echo "  -> ${OUT_DIR}/fractalsql_pg{16,17,18}.so"
echo "------------------------------------------"

DOCKER_BUILDKIT=1 docker buildx build \
    --platform "${PLATFORM}" \
    --target export \
    --output "type=local,dest=${OUT_DIR}" \
    -f "${DOCKERFILE}" \
    .

echo
echo "Built artifacts for ${ARCH}:"
ls -l "${OUT_DIR}"/fractalsql_pg*.so
