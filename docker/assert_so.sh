#!/bin/sh
# docker/assert_so.sh — zero-dependency posture check for fractalsql.so.
#
# Usage: assert_so.sh <path/to/fractalsql_pgN.so> <size_ceiling_bytes>
#
# Fails the build if:
#   * ldd reports any dynamic library outside the glibc shortlist
#   * nm reports __cxx11::basic_string symbols (cxx11 ABI leak)
#   * the .so exceeds the size ceiling
#
# Run inside each per-PG-major builder stage so problems are caught
# before the .so is emitted to the export stage.

set -eu

SO="${1:?usage: assert_so.sh <so> <ceiling>}"
CEILING="${2:?usage: assert_so.sh <so> <ceiling>}"

echo "=== assert_so.sh ${SO} (ceiling ${CEILING} bytes) ==="

echo "--- file ---"
file "${SO}"

echo "--- ldd ---"
# Resolve dynamic deps. ldd returns non-zero for statically linked
# binaries, but that's not expected for a .so; still, don't fail the
# shell on it.
ldd "${SO}" || true

# Assertion 1: no dynamic libluajit / libstdc++ dependency.
if ldd "${SO}" | grep -E 'libluajit|libstdc\+\+' >/dev/null; then
    echo "FAIL: ${SO} links dynamic libluajit or libstdc++" >&2
    exit 1
fi

# Assertion 2: every library listed by ldd is on the glibc shortlist.
# Allowed SONAME prefixes (bookworm glibc 2.36+):
#   linux-vdso.so.1       (kernel-provided, no file)
#   libc.so.6
#   libm.so.6
#   libdl.so.2            (merged into libc on glibc 2.34+, may still appear)
#   libpthread.so.0       (merged into libc on glibc 2.34+, may still appear)
#   /lib*/ld-linux-*.so.* (dynamic loader)
BAD=$(ldd "${SO}" \
        | awk '{print $1}' \
        | grep -vE '^(linux-vdso\.so\.1|libc\.so\.6|libm\.so\.6|libdl\.so\.2|libpthread\.so\.0|/.*/ld-linux.*\.so\.[0-9]+)$' \
        | grep -v '^$' || true)
if [ -n "${BAD}" ]; then
    echo "FAIL: ${SO} has disallowed dynamic deps:" >&2
    echo "${BAD}" >&2
    exit 1
fi

# Assertion 3: no __cxx11::basic_string symbols (ABI hygiene).
echo "--- nm -D -C | grep __cxx11::basic_string ---"
if nm -D -C "${SO}" 2>/dev/null | grep -F '__cxx11::basic_string' >/dev/null; then
    echo "FAIL: ${SO} exposes __cxx11::basic_string symbols" >&2
    nm -D -C "${SO}" | grep -F '__cxx11::basic_string' >&2 || true
    exit 1
fi

# Assertion 4: size ceiling.
SZ=$(stat -c '%s' "${SO}")
echo "size: ${SZ} bytes (ceiling ${CEILING})"
if [ "${SZ}" -gt "${CEILING}" ]; then
    echo "FAIL: ${SO} exceeds size ceiling ${CEILING}" >&2
    exit 1
fi

echo "OK: ${SO}"
