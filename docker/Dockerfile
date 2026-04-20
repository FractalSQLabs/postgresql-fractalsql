# syntax=docker/dockerfile:1.7
#
# postgresql-fractalsql Factory build — zero-dependency posture.
#
# LuaJIT is compiled from source as a PIC static archive and folded
# into each per-PG-major fractalsql.so. The resulting extension depends
# on glibc only — no libluajit-5.1.so, no libstdc++, no dynamic C++ ABI.
#
# Build artifacts (collected in the final `export` stage, emitted to
# the host via `docker buildx --output type=local,dest=...`):
#   /fractalsql_pg14.so
#   /fractalsql_pg15.so
#   /fractalsql_pg16.so
#   /fractalsql_pg17.so
#   /fractalsql_pg18.so
#
# Usage:
#   DOCKER_BUILDKIT=1 docker buildx build \
#     --platform linux/amd64 \
#     --target export \
#     --output type=local,dest=./dist/amd64 \
#     -f docker/Dockerfile .
#
# build.sh drives this for amd64 and arm64 in turn.
#
# --------------------------------------------------------------------
# Important build-system notes:
#
#  * The distro libluajit-5.1-dev ships a non-PIC .a, which fails to
#    link into a .so on most toolchains. We build LuaJIT 2.1 ourselves
#    with -fPIC + BUILDMODE=static and stage it into /opt/luajit.
#
#  * Extra flags are injected through PG_CPPFLAGS / SHLIB_LINK — PGXS
#    appends these to its own invocations, so the canonical
#    EXTENSION / MODULE_big rules stay untouched.
#
#  * -fvisibility=hidden is deliberately NOT set on the extension TU.
#    Postgres' loader resolves _PG_init and PG_MODULE_MAGIC via the
#    .dynsym of the opened .so; hiding them breaks CREATE EXTENSION.
#
#  * Post-link assertions (ldd / nm / size) run in each builder stage
#    so the build fails fast if a dynamic luajit/libstdc++ dependency
#    ever sneaks back in.

# --------------------------------------------------------------------
# Global build ARGs (declared before the first FROM so all stages
# below can re-import them with `ARG NAME` and pick up these defaults).
# --------------------------------------------------------------------
#
# LuaJIT clone source. We use Mike Pall's official GitHub mirror
# rather than luajit.org/git — the latter serves dumb HTTP, which
# doesn't advertise shallow-clone capabilities, so `git clone
# --depth=1` fails with "dumb http transport does not support shallow
# capabilities". The GitHub mirror is smart-HTTPS and well-maintained.
# Pin LUAJIT_GIT_REF to a sha when we cut a reproducible release;
# until then, HEAD of v2.1 is the upstream-recommended branch.
ARG LUAJIT_GIT_URL=https://github.com/LuaJIT/LuaJIT.git
ARG LUAJIT_GIT_REF=v2.1

# EXT_CFLAGS / EXT_LDFLAGS — appended onto PGXS's own CFLAGS / LDFLAGS
# via PG_CPPFLAGS and SHLIB_LINK inside each build-pgNN stage.
#
# -D_GLIBCXX_USE_CXX11_ABI=0: keeps us on the pre-C++11 std::string ABI,
#   so symbols never reference __cxx11::basic_string even if anything
#   in the toolchain pulled libstdc++ headers.
# -ffunction-sections / -fdata-sections: per-symbol section emission;
#   pairs with -Wl,--gc-sections to drop unused LuaJIT code paths.
# -fvisibility=default: PGXS on PG 16/17/18 debian packages injects
#   -fvisibility=hidden into CFLAGS. _PG_init/_PG_fini in our TU aren't
#   annotated PGDLLEXPORT, so hidden default would drop them out of
#   .dynsym and CREATE EXTENSION would fail with "symbol not found".
#   Appending -fvisibility=default via PG_CPPFLAGS lets the last
#   -fvisibility=* on the gcc command line win and restore visibility.
# -static-libgcc / -static-libstdc++: link the C/C++ runtime helpers
#   statically; combined with --exclude-libs,ALL they stay invisible
#   in the .dynsym.
# -Wl,--strip-all: drop .symtab. .dynsym survives (required for
#   _PG_init / PG_MODULE_MAGIC resolution at CREATE EXTENSION time).
ARG EXT_CFLAGS="-D_GLIBCXX_USE_CXX11_ABI=0 -ffunction-sections -fdata-sections -fvisibility=default"
ARG EXT_LDFLAGS="-static-libgcc -static-libstdc++ -Wl,--gc-sections -Wl,--strip-all -Wl,--exclude-libs,ALL"

# Ceiling on the resulting .so. SQLite's equivalent build landed at
# 654 KB; PG has a heavier ABI surface, so we set this looser. Bump
# only with a note in the commit message — unexpected growth usually
# means something got linked in that shouldn't have.
ARG SIZE_CEILING_BYTES=3145728

# --------------------------------------------------------------------
# Stage: PIC-built LuaJIT static archive
# --------------------------------------------------------------------
FROM debian:bookworm-slim AS luajit-static
ARG LUAJIT_GIT_URL
ARG LUAJIT_GIT_REF
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        build-essential ca-certificates git \
 && rm -rf /var/lib/apt/lists/*
RUN git clone --depth=1 --branch "${LUAJIT_GIT_REF}" \
        "${LUAJIT_GIT_URL}" /src/luajit
WORKDIR /src/luajit
# BUILDMODE=static avoids producing the .so; XCFLAGS=-fPIC makes the
# .a foldable into a downstream shared object.
RUN make BUILDMODE=static XCFLAGS="-fPIC" PREFIX=/opt/luajit -j"$(nproc)" \
 && make install BUILDMODE=static PREFIX=/opt/luajit \
 && test -f /opt/luajit/lib/libluajit-5.1.a \
 && ! test -f /opt/luajit/lib/libluajit-5.1.so

# --------------------------------------------------------------------
# Stage: PG 14 builder
# --------------------------------------------------------------------
FROM postgres:14-bookworm AS build-pg14
USER root
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        build-essential \
        binutils \
        file \
        postgresql-server-dev-14 \
 && rm -rf /var/lib/apt/lists/*
COPY --from=luajit-static /opt/luajit /opt/luajit

WORKDIR /build
COPY Makefile            /build/Makefile
COPY fractalsql.control  /build/fractalsql.control
COPY src/                /build/src/
COPY include/            /build/include/
COPY sql/                /build/sql/
COPY docker/assert_so.sh /build/docker/assert_so.sh

ARG EXT_CFLAGS
ARG EXT_LDFLAGS
ARG SIZE_CEILING_BYTES

RUN make clean \
 && make PG_CONFIG=/usr/lib/postgresql/14/bin/pg_config \
        PG_CPPFLAGS="-I/opt/luajit/include/luajit-2.1 -Iinclude ${EXT_CFLAGS}" \
        SHLIB_LINK="/opt/luajit/lib/libluajit-5.1.a -lm -ldl ${EXT_LDFLAGS}" \
 && cp fractalsql.so /fractalsql_pg14.so \
 && sh /build/docker/assert_so.sh /fractalsql_pg14.so "${SIZE_CEILING_BYTES}"

# --------------------------------------------------------------------
# Stage: PG 15 builder
# --------------------------------------------------------------------
FROM postgres:15-bookworm AS build-pg15
USER root
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        build-essential \
        binutils \
        file \
        postgresql-server-dev-15 \
 && rm -rf /var/lib/apt/lists/*
COPY --from=luajit-static /opt/luajit /opt/luajit

WORKDIR /build
COPY Makefile            /build/Makefile
COPY fractalsql.control  /build/fractalsql.control
COPY src/                /build/src/
COPY include/            /build/include/
COPY sql/                /build/sql/
COPY docker/assert_so.sh /build/docker/assert_so.sh

ARG EXT_CFLAGS
ARG EXT_LDFLAGS
ARG SIZE_CEILING_BYTES

RUN make clean \
 && make PG_CONFIG=/usr/lib/postgresql/15/bin/pg_config \
        PG_CPPFLAGS="-I/opt/luajit/include/luajit-2.1 -Iinclude ${EXT_CFLAGS}" \
        SHLIB_LINK="/opt/luajit/lib/libluajit-5.1.a -lm -ldl ${EXT_LDFLAGS}" \
 && cp fractalsql.so /fractalsql_pg15.so \
 && sh /build/docker/assert_so.sh /fractalsql_pg15.so "${SIZE_CEILING_BYTES}"

# --------------------------------------------------------------------
# Stage: PG 16 builder
# --------------------------------------------------------------------
FROM postgres:16-bookworm AS build-pg16
USER root
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        build-essential \
        binutils \
        file \
        postgresql-server-dev-16 \
 && rm -rf /var/lib/apt/lists/*
COPY --from=luajit-static /opt/luajit /opt/luajit

WORKDIR /build
COPY Makefile            /build/Makefile
COPY fractalsql.control  /build/fractalsql.control
COPY src/                /build/src/
COPY include/            /build/include/
COPY sql/                /build/sql/
COPY docker/assert_so.sh /build/docker/assert_so.sh

ARG EXT_CFLAGS
ARG EXT_LDFLAGS
ARG SIZE_CEILING_BYTES

RUN make clean \
 && make PG_CONFIG=/usr/lib/postgresql/16/bin/pg_config \
        PG_CPPFLAGS="-I/opt/luajit/include/luajit-2.1 -Iinclude ${EXT_CFLAGS}" \
        SHLIB_LINK="/opt/luajit/lib/libluajit-5.1.a -lm -ldl ${EXT_LDFLAGS}" \
 && cp fractalsql.so /fractalsql_pg16.so \
 && sh /build/docker/assert_so.sh /fractalsql_pg16.so "${SIZE_CEILING_BYTES}"

# --------------------------------------------------------------------
# Stage: PG 17 builder
# --------------------------------------------------------------------
FROM postgres:17-bookworm AS build-pg17
USER root
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        build-essential \
        binutils \
        file \
        postgresql-server-dev-17 \
 && rm -rf /var/lib/apt/lists/*
COPY --from=luajit-static /opt/luajit /opt/luajit

WORKDIR /build
COPY Makefile            /build/Makefile
COPY fractalsql.control  /build/fractalsql.control
COPY src/                /build/src/
COPY include/            /build/include/
COPY sql/                /build/sql/
COPY docker/assert_so.sh /build/docker/assert_so.sh

ARG EXT_CFLAGS
ARG EXT_LDFLAGS
ARG SIZE_CEILING_BYTES

RUN make clean \
 && make PG_CONFIG=/usr/lib/postgresql/17/bin/pg_config \
        PG_CPPFLAGS="-I/opt/luajit/include/luajit-2.1 -Iinclude ${EXT_CFLAGS}" \
        SHLIB_LINK="/opt/luajit/lib/libluajit-5.1.a -lm -ldl ${EXT_LDFLAGS}" \
 && cp fractalsql.so /fractalsql_pg17.so \
 && sh /build/docker/assert_so.sh /fractalsql_pg17.so "${SIZE_CEILING_BYTES}"

# --------------------------------------------------------------------
# Stage: PG 18 builder
# --------------------------------------------------------------------
FROM postgres:18-bookworm AS build-pg18
USER root
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        build-essential \
        binutils \
        file \
        postgresql-server-dev-18 \
 && rm -rf /var/lib/apt/lists/*
COPY --from=luajit-static /opt/luajit /opt/luajit

WORKDIR /build
COPY Makefile            /build/Makefile
COPY fractalsql.control  /build/fractalsql.control
COPY src/                /build/src/
COPY include/            /build/include/
COPY sql/                /build/sql/
COPY docker/assert_so.sh /build/docker/assert_so.sh

ARG EXT_CFLAGS
ARG EXT_LDFLAGS
ARG SIZE_CEILING_BYTES

RUN make clean \
 && make PG_CONFIG=/usr/lib/postgresql/18/bin/pg_config \
        PG_CPPFLAGS="-I/opt/luajit/include/luajit-2.1 -Iinclude ${EXT_CFLAGS}" \
        SHLIB_LINK="/opt/luajit/lib/libluajit-5.1.a -lm -ldl ${EXT_LDFLAGS}" \
 && cp fractalsql.so /fractalsql_pg18.so \
 && sh /build/docker/assert_so.sh /fractalsql_pg18.so "${SIZE_CEILING_BYTES}"

# --------------------------------------------------------------------
# Export stages — scratch, so `buildx --output=local` drops just the
# chosen .so file(s) onto the host.
#
#   --target export         -> all five .so's (build.sh default)
#   --target export-pg14    -> fractalsql_pg14.so only
#   --target export-pg15    -> fractalsql_pg15.so only
#   --target export-pg16    -> fractalsql_pg16.so only
#   --target export-pg17    -> fractalsql_pg17.so only
#   --target export-pg18    -> fractalsql_pg18.so only
# --------------------------------------------------------------------
FROM scratch AS export-pg14
COPY --from=build-pg14 /fractalsql_pg14.so /fractalsql_pg14.so

FROM scratch AS export-pg15
COPY --from=build-pg15 /fractalsql_pg15.so /fractalsql_pg15.so

FROM scratch AS export-pg16
COPY --from=build-pg16 /fractalsql_pg16.so /fractalsql_pg16.so

FROM scratch AS export-pg17
COPY --from=build-pg17 /fractalsql_pg17.so /fractalsql_pg17.so

FROM scratch AS export-pg18
COPY --from=build-pg18 /fractalsql_pg18.so /fractalsql_pg18.so

FROM scratch AS export
COPY --from=build-pg14 /fractalsql_pg14.so /fractalsql_pg14.so
COPY --from=build-pg15 /fractalsql_pg15.so /fractalsql_pg15.so
COPY --from=build-pg16 /fractalsql_pg16.so /fractalsql_pg16.so
COPY --from=build-pg17 /fractalsql_pg17.so /fractalsql_pg17.so
COPY --from=build-pg18 /fractalsql_pg18.so /fractalsql_pg18.so
