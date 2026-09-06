#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Daniel Gardiner d/b/a FractalSQLabs
#
# build_test.sh — post-build validation gate runner for
# fractalsql-postgresql. Mirrors what CI runs, so local == CI.
#
# Builds the extension for a target PostgreSQL major and validates it
# against a THROWAWAY cluster (no root: initdb + a private socket dir in
# /tmp, torn down on exit).
#
# Gates:
#   01  build          make against the target major's pg_config      ~5s
#   02  smoke          load + version + fractal_search convergence    ~5s
#   03  schema_context introspection (PK / NOT NULL / comment / FK)   ~3s
#   04  text_to_sql    allowlist fuzz matrix + never-executes proof   ~8s
#                      (uses tests/mock_reasoning_plugin.c)
#   05  evil_overread  guard-page non-terminated response survives,   ~3s
#                      at GENERATE, REVIEW, and bare fractal_reason()
#                      (uses tests/evil_nonterminating_plugin.c)
#   06  crash_recovery deliberately-segfaulting plugin: connection    ~10s
#                      drops, cluster auto-restarts, prior data intact
#                      (uses tests/evil_crash_plugin.c)
#   07  evil_lying_length  guard_ai_response_len rejects an implausible ~3s
#                      claimed length before any read, at GENERATE,
#                      REVIEW, and bare fractal_reason()
#                      (uses tests/evil_lying_length_plugin.c)
#   08  authz          low-priv role blocked from schema_context on a  ~1s
#                      table it lacks SELECT on (info-disclosure fix)
#   09  guc_superuser   non-superuser rejected from setting            ~1s
#                      reasoning_plugin (GUC_SUPERUSER_ONLY fix)
#   10  dos_and_injection  512-table cap fires at 513; SQL-injection-  ~1s
#                      shaped table_names cleanly rejected, not executed
#   11  scout           fractal_search_explore: full population       ~2s
#                      returned, disperses across >1 island
#   12  soak            SOAK_WORKERS concurrent backends x SOAK_ITERS   ~5s
#                      mixed benign calls each; asserts no failures
#                      and the cluster stays responsive under load
#   13  siu_mode        text_to_sql_allowed_statements=select_insert_   ~2s
#                      update: INSERT/UPDATE returned (never executed),
#                      DDL/DELETE still rejected
#   14  retry           max_attempts=2 retry-with-feedback: attempt 1   ~1s
#                      rejected, attempt 2 succeeds, rejection reason
#                      threaded into the attempt-2 prompt
#                      (uses tests/retry_reasoning_plugin.c)
#   15  embed           fractal_embed() + the vectorizer: create/       ~3s
#                      backfill/process_queue/status against a canned
#                      embedding, real dispatch through the three-tier
#                      ensure_embed_ctx() path (not just error paths);
#                      NULL input, bad plugin path, over-limit embedding
#                      array (evil_embed_plugin.c), injection-shaped
#                      source_table, double-create
#                      (uses tests/mock_embed_plugin.c, evil_embed_plugin.c)
#   16  embed_authz     vectorizer authz: a role that owns its table    ~1s
#                      can fully use its own vectorizer with no extra
#                      DBA grants; a different role with no SELECT on
#                      that table cannot read/embed it via the GLOBAL
#                      process_queue() (mirrors gate 08's boundary for
#                      the vectorizer specifically)
#   17  embed_soak      concurrent fractal_vectorizer_process_queue()   ~3s
#                      calls (10 workers) against a 100-row shared
#                      queue -- proves SELECT ... FOR UPDATE SKIP LOCKED
#                      really does prevent double-processing (mirrors
#                      gate 12's soak pattern)
#   18  embed_crash     deliberately-segfaulting plugin mid-           ~10s
#                      process_queue(): proves a crash rolls the WHOLE
#                      in-flight call back (rows revert to 'pending',
#                      not stuck 'processing' needing stale_after) and
#                      that a normal call afterward recovers cleanly
#                      (uses tests/evil_crash_plugin.c, mirrors gate 06)
#   19  sfs_bounds      validate_sfs_params() bounds for fractal_search/  ~1s
#                      _debug/_explore (iterations/population_size/
#                      diffusion_factor/dim, never exercised before this
#                      gate) plus an injection-shaped table_name into
#                      fractal_search_explore (mirrors gate 10's
#                      equivalent test for fractal_schema_context)
#   20  api_func        closes 5 API-surface coverage gaps found by a     ~2s
#                      gap analysis against README's API table:
#                      fractal_reason() happy-path correctness (never
#                      checked before -- only ever "didn't crash"),
#                      fractal_reason(NULL) and fractal_text_to_sql(NULL)
#                      rejection, fractal_search_explore()'s own bounds
#                      via its options jsonb (shares validate_sfs_params
#                      but was never proven), and
#                      fractal_vectorizer_process_queue()'s stale_after
#                      reclaim UPDATE (staged directly, with a
#                      within-window negative control)
#   21  fuzz_smoke      FUZZ ONLY (--fuzz, not in DEFAULT/QUICK). Builds  ~90s
#                      + briefly runs (FSQL_FUZZ_TIME seconds each,
#                      default 30) libFuzzer drivers against the 3
#                      hand-rolled parsers in src/fractalsql_parse.c
#                      (factored out of fractalsql.c specifically so
#                      they can link standalone, no postgres backend
#                      needed): fsql_parse_embedding_array (highest
#                      priority -- parses fractal_embed()'s raw response
#                      from whatever endpoint fractalsql.http_embed_url
#                      points at, genuinely externally-adversarial
#                      input), fsql_extract_best_point and
#                      fsql_extract_population (parse the vendored
#                      core's own result JSON -- lower risk, included as
#                      defense-in-depth). No live cluster needed.
#                      Requires a libFuzzer-capable clang (set
#                      FSQL_FUZZ_CC to override auto-detection); skips
#                      cleanly if none is found.
#
# Gate sets:
#   QUICK   = 01 02                                   post-edit sanity loop
#   DEFAULT = 01 02 03 04 05 06 07 08 09 10 11 12 13 14 15 16 17 18 19 20 22 23  pre-push / CI (one major)
#   FUZZ    = 21                                       --fuzz, not part of DEFAULT (adds real wall-time)
#
# Cross-version: pass --cross to run DEFAULT against every installed
# major in 14..18 (skips majors whose server binaries are absent). This
# is what the release matrix exercises.
#
# Usage:
#   ./build_test.sh                 # DEFAULT against PG_MAJOR (default 16)
#   ./build_test.sh --quick
#   ./build_test.sh --pg 15
#   ./build_test.sh --cross
#   ./build_test.sh --fuzz          # gate 21 only -- libFuzzer smoke, no cluster
#   ./build_test.sh --gate 04
#   ./build_test.sh --list
#   ./build_test.sh --coverage      # gcov-instrumented build; DEFAULT
#                                    # gates; lcov/genhtml report after
#
# --coverage notes:
#   Rebuilds with `make COVERAGE=1` (Makefile: --coverage on compile +
#   link for src/fractalsql.o only, not the vendored core archive).
#   Needs lcov+genhtml on PATH. This repo checks out onto a vboxsf bind
#   mount in this environment -- gcov's .gcda updates can hang there,
#   so GCOV_PREFIX/GCOV_PREFIX_STRIP redirect the live writes
#   to /tmp for the duration of the run; the result is copied back
#   next to the .gcno afterward, once, as a plain file copy (safe).
#   Report: coverage_html/index.html + a text summary on stdout.
#
# Environment:
#   PG_MAJOR             target major (default: 16)
#   PG_BINDIR             override /usr/lib/postgresql/$PG_MAJOR/bin
#   FSQL_TEST_TIMEOUT_MULT  scales gate 06/18's crash-recovery poll
#                           budget (default 1; auto-defaults to 4 under
#                           --asan/--ubsan, since ASan's overhead alone
#                           is enough to blow the default 15s budget on
#                           real hardware -- set this explicitly to
#                           override that auto-bump either direction).
#                           Bump further on a loaded/VM host where WAL
#                           replay + shared-memory reinit runs slower
#                           still.
#   FSQL_FUZZ_CC            libFuzzer-capable clang for gate 21 (default:
#                           auto-detect clang-18/17/16/15/clang on PATH,
#                           probed for -fsanitize=fuzzer support before
#                           use -- a bare `clang` shadowed by an
#                           unrelated toolchain is a real failure mode,
#                           not hypothetical).
#   FSQL_FUZZ_TIME          seconds per fuzz target in gate 21 (default
#                           30). This is a pre-push SMOKE run, not a
#                           campaign -- bump it locally for real
#                           crash-finding, same binaries either way.

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

# Canonical (symlink-resolved) tmp root. fractalsql-core's
# fsql_load_reasoning() deliberately rejects any plugin path where
# realpath(path) != path -- a defense against symlink pivots (see its
# own header comment in fractalsql-core/src/fsql.c). On Linux /tmp is a
# real directory, so this is a no-op. On macOS /tmp is ITSELF a
# standard, OS-provided symlink to /private/tmp, so any plugin path
# built as literal "/tmp/..." fails that check even though nothing
# malicious is going on -- confirmed on real Darwin hardware: "path is
# not canonical (got '/tmp/fractalsql_bt_mock_16.so', resolves to
# '/private/tmp/fractalsql_bt_mock_16.so')" on every gate that loads a
# mock/evil test plugin. Resolving once here and building every plugin
# path from $TMPROOT (not a literal "/tmp") fixes this at the source
# instead of weakening the security check itself.
TMPROOT="$(cd /tmp && pwd -P)"

# fsql_pg_dlsuffix <pg_config> -- echoes the DLSUFFIX the GIVEN target's
# own PGXS will actually use. Confirmed on real CI hardware (2026-08):
# this is NOT simply "uname -s == Darwin" -> .dylib -- PostgreSQL itself
# changed its own default Darwin DLSUFFIX from .so to .dylib at a
# specific major-version boundary, and that boundary lands INSIDE our
# own supported range (PG14/15 still use .so; PG16-18 use .dylib, each
# confirmed directly from a real link command in CI). A hardcoded guess
# here built fine either way (make itself doesn't care what name it
# writes), but every RUNTIME load failed on whichever majors guessed
# wrong, since Postgres's dfmgr.c looks for that exact suffix with no
# fallback. A prior version of this function parsed Makefile.global's
# own DLSUFFIX default directly -- but that value can be overridden
# LATER by an `include .../Makefile.port` line inside Makefile.global
# (Makefile.port wins, since it's included last), so parsing only
# Makefile.global silently missed the override on PG14/15 and always
# fell back to the wrong guess there. PGXS ships a `show_dl_suffix`
# target for exactly this ("Show the DLSUFFIX to build scripts (e.g.
# buildfarm)") -- ask the same Makefile/PGXS chain the real build uses
# instead of re-deriving the include/override logic ourselves.
fsql_pg_dlsuffix() {
  local pg_config="$1" suffix=""
  suffix="$(make PG_CONFIG="$pg_config" show_dl_suffix 2>/dev/null | tail -1)"
  if [[ -n "$suffix" ]]; then
    printf '%s' "$suffix"
  elif [[ "$(uname -s)" = "Darwin" ]]; then
    printf '%s' ".dylib"
  else
    printf '%s' ".so"
  fi
}

DEFAULT_GATES=(01 02 03 04 05 06 07 08 09 10 11 12 13 14 15 16 17 18 19 20 22 23 24 25 26 27)
QUICK_GATES=(01 02)
FUZZ_GATES=(21)

PG_MAJOR="${PG_MAJOR:-16}"
MODE="default"
ONE_GATE=""
COVERAGE=0
ASAN=0
UBSAN=0

# Scales the poll-loop budgets below (pg_swap_plugin's reload wait,
# gate 06/18's post-crash restart wait). Loaded/VM hosts can make crash
# recovery (WAL replay + shared-memory reinit) take noticeably longer
# than on a quiet dev box. Bump this rather than adding a
# skip/retry hack: e.g. FSQL_TEST_TIMEOUT_MULT=3 ./build_test.sh --cross
#
# --asan/--ubsan auto-bump to 4 (unless FSQL_TEST_TIMEOUT_MULT is
# explicitly set): confirmed empirically, not theoretical -- ASan's
# instrumentation adds real overhead to crash recovery's WAL replay +
# shared-memory reinit, enough that the default 15s budget
# (TIMEOUT_MULT=1) times out on real hardware, not just a loaded VM.
# Once gate 06 times out the cluster is STILL mid-recovery, which then
# cascades into every later gate failing with "database system is in
# recovery mode" -- a single missed env var turning one real timeout
# into 30+ confusing failures. Auto-bumping removes the need to
# remember FSQL_TEST_TIMEOUT_MULT=4 every time --asan is passed, which
# is exactly the mistake that caused that cascade in practice.
if [[ -n "${FSQL_TEST_TIMEOUT_MULT:-}" ]]; then
  TIMEOUT_MULT="$FSQL_TEST_TIMEOUT_MULT"
elif [[ "$ASAN" -eq 1 ]] || [[ "$UBSAN" -eq 1 ]]; then
  TIMEOUT_MULT=4
else
  TIMEOUT_MULT=1
fi

# --- colours ----------------------------------------------------------
if [[ -t 1 ]]; then G="\033[32m"; R="\033[31m"; Y="\033[33m"; Z="\033[0m"; else G=""; R=""; Y=""; Z=""; fi
pass() { printf "  [${G}PASS${Z}] %s\n" "$1"; }
fail() { printf "  [${R}FAIL${Z}] %s\n" "$1"; FAILED=1; }
skip() { printf "  [${Y}SKIP${Z}] %s\n" "$1"; }

usage() { sed -n '4,40p' "$0"; exit 0; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --quick)   MODE="quick" ;;
    --cross)   MODE="cross" ;;
    --fuzz)    MODE="fuzz" ;;
    --pg)      PG_MAJOR="$2"; shift ;;
    --gate)    ONE_GATE="$2"; shift ;;
    --coverage) COVERAGE=1 ;;
    --asan)    ASAN=1 ;;
    --ubsan)   UBSAN=1 ;;
    --list)    printf "gates: %s\nfuzz gates: %s\n" "${DEFAULT_GATES[*]}" "${FUZZ_GATES[*]}"; exit 0 ;;
    -h|--help) usage ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
  shift
done

# --- per-major state (set by pg_setup) --------------------------------
BIN=""; SO=""; MOCK=""; EVIL=""; CRASH=""; LYING=""; RETRY=""; EMBED=""; THINK=""; DATADIR=""; SOCKDIR=""; PORT=""; PSQL=()
FAILED=0

pg_bindir() {
  if [[ -n "${PG_BINDIR:-}" ]]; then
    echo "$PG_BINDIR"
  elif [[ "$(uname -s)" = "Darwin" ]]; then
    # Homebrew's postgresql@$MAJOR keg -- matches
    # .github/workflows/install-test.yml's macos-install job exactly
    # (PG_CONFIG="$(brew --prefix postgresql@17)/bin/pg_config"). `brew
    # --prefix` on an uninstalled formula still prints the theoretical
    # path (doesn't fail), so probe it for a real pg_config before
    # trusting it. If that fails, fall back to the official EDB .dmg
    # installer's layout (/Library/PostgreSQL/$MAJOR/bin -- same family
    # as the Windows EDB installer's C:\Program Files\PostgreSQL\
    # $MAJOR\) instead of just failing when Homebrew isn't how
    # PostgreSQL got installed. pg_setup()'s own -x initdb/-x pg_config
    # check downstream still fires either way -- same contract as the
    # Linux branch below -- this only widens what gets tried first.
    local brew_bin
    if command -v brew >/dev/null 2>&1; then
      brew_bin="$(brew --prefix "postgresql@$1" 2>/dev/null)/bin"
    else
      brew_bin="/opt/homebrew/opt/postgresql@$1/bin"
    fi
    if [[ -x "$brew_bin/pg_config" ]]; then
      echo "$brew_bin"
    elif [[ -x "/Library/PostgreSQL/$1/bin/pg_config" ]]; then
      echo "/Library/PostgreSQL/$1/bin"
    else
      echo "$brew_bin"
    fi
  else
    echo "/usr/lib/postgresql/$1/bin"
  fi
}

# Resolves a sanitizer runtime's real .so path: `cc -print-file-name=
# libasan.so` on EL/RHEL-family distros often returns a LINKER SCRIPT
# (ASCII text with INPUT(...) directives), not an ELF -- LD_PRELOAD
# rejects those with "file too short". Falls back to the versioned ELF
# resolved via ldconfig when that happens.
resolve_san_rt() {
  local libname="$1"
  if [[ "$(uname -s)" = "Darwin" ]]; then
    # Apple clang's runtime layout is completely different from Linux's
    # -- no libasan.so/libubsan.so at all. `-print-resource-dir` finds
    # the active Xcode/CLT toolchain's compiler-rt tree; the dylib is
    # unified under lib/darwin/ regardless of arm64/x86_64. UNVERIFIED
    # on real Darwin hardware as of this writing -- confirm the exact
    # filename on a real run; Apple has renamed compiler-rt dylibs across major
    # Xcode versions before.
    local resdir; resdir="$(${CC:-cc} -print-resource-dir 2>/dev/null)"
    [[ -n "$resdir" ]] || { printf ''; return; }
    case "$libname" in
      libasan.so)  printf '%s' "$resdir/lib/darwin/libclang_rt.asan_osx_dynamic.dylib" ;;
      libubsan.so) printf '%s' "$resdir/lib/darwin/libclang_rt.ubsan_osx_dynamic.dylib" ;;
      *)           printf '' ;;
    esac
    return
  fi
  local rt
  rt="$(${CC:-cc} -print-file-name="$libname" 2>/dev/null)"
  if [[ -f "$rt" ]] && ! file -b "$rt" | grep -qE 'ELF|shared object'; then
    local stem="${libname%.so}"
    local cand
    cand="$(ldconfig -p 2>/dev/null \
            | awk -v s="$stem" '$1 ~ "^"s"\\.so\\.[0-9]+$" {print $NF; exit}')"
    [[ -n "$cand" ]] && [[ -f "$cand" ]] && rt="$cand"
  fi
  printf '%s' "$rt"
}

cleanup() {
  [[ -n "$DATADIR" ]] && [[ -d "$DATADIR" ]] && "$BIN/pg_ctl" -D "$DATADIR" -m immediate stop >/dev/null 2>&1
  [[ -n "$DATADIR" ]] && rm -rf "$DATADIR"
  [[ -n "$SOCKDIR" ]] && rm -rf "$SOCKDIR"
  rm -f /tmp/fractalsql_bt_sql.txt /tmp/fractalsql_bt_evil_trigger_call.txt
}
trap cleanup EXIT

# --coverage: redirect gcov's live .gcda writes off the (possibly
# vboxsf-mounted) source tree for the run, so every backend that loads
# the instrumented .so writes to /tmp instead. GCOV_PREFIX_STRIP counts
# path components to drop from the .gcno-embedded absolute path before
# prefixing with GCOV_PREFIX -- computed from $HERE's own depth so this
# isn't hardcoded to one checkout location. Exported unconditionally
# (harmless no-op without a --coverage build); postmaster/backends
# inherit it since pg_setup() launches pg_ctl from this same shell.
if [[ "$COVERAGE" -eq 1 ]]; then
  export GCOV_PREFIX="/tmp/fractalsql_bt_gcov_$$"
  export GCOV_PREFIX_STRIP=$(($(echo "$HERE" | tr -cd '/' | wc -c)))
  mkdir -p "$GCOV_PREFIX"
fi

# Copy the redirected .gcda back next to the .gcno (one plain file
# copy — not the hot-path gcov flushing that vboxsf chokes on) and
# generate an lcov report. Called once after the gate matrix finishes.
run_coverage_report() {
  local gcda_src
  gcda_src="$(find "$GCOV_PREFIX" -name 'fractalsql.gcda' 2>/dev/null | head -1)"
  if [[ -z "$gcda_src" ]]; then
    fail "coverage: no .gcda produced (was --coverage gate 01 build ok?)"
    return
  fi
  cp "$gcda_src" src/fractalsql.gcda

  if ! command -v lcov >/dev/null 2>&1; then
    skip "coverage: lcov not installed, skipping report"
    return
  fi
  lcov --capture --directory src --output-file /tmp/fractalsql_bt_coverage_raw.info \
       --rc branch_coverage=1 >/tmp/fractalsql_bt_lcov.log 2>&1 \
    || { fail "coverage: lcov capture failed — see /tmp/fractalsql_bt_lcov.log"; return; }

  # Extract just our TU: --list's aggregate Rate% goes haywire (seen:
  # a nonsensical >1000% function rate) when the capture also includes
  # the handful of lines pulled in from system headers like postgres.h/
  # palloc.h -- those aren't our code and nobody's asking about their
  # coverage anyway.
  lcov --extract /tmp/fractalsql_bt_coverage_raw.info '*/src/fractalsql.c' \
       --output-file /tmp/fractalsql_bt_coverage.info \
       --rc branch_coverage=1 >>/tmp/fractalsql_bt_lcov.log 2>&1

  echo ""
  echo "=== coverage (src/fractalsql.c) ==="
  # Computed directly from the .info file's own LF/LH/FNF/FNH/BRF/BRH
  # totals rather than `lcov --list`'s table -- lcov 2.0-1's --list
  # renderer miscomputes its Rate% column against this intermediate
  # gcov-JSON-derived .info (seen: a nonsensical 1170% function rate)
  # even though the underlying LF:/LH:/etc. totals, and genhtml's own
  # report built from the same file, are both correct.
  awk -F: '
    /^LF:/ { lf += $2 } /^LH:/ { lh += $2 }
    /^FNF:/ { fnf += $2 } /^FNH:/ { fnh += $2 }
    /^BRF:/ { brf += $2 } /^BRH:/ { brh += $2 }
    END {
      printf "  lines:     %d/%d", lh, lf
      if (lf > 0) printf " (%.1f%%)", 100*lh/lf
      print ""
      printf "  functions: %d/%d", fnh, fnf
      if (fnf > 0) printf " (%.1f%%)", 100*fnh/fnf
      print ""
      printf "  branches:  %d/%d", brh, brf
      if (brf > 0) printf " (%.1f%%)", 100*brh/brf
      print ""
    }' /tmp/fractalsql_bt_coverage.info

  if command -v genhtml >/dev/null 2>&1; then
    genhtml /tmp/fractalsql_bt_coverage.info --output-directory coverage_html \
            --rc branch_coverage=1 >/tmp/fractalsql_bt_genhtml.log 2>&1 \
      && pass "coverage: report at coverage_html/index.html" \
      || fail "coverage: genhtml failed — see /tmp/fractalsql_bt_genhtml.log"
  fi
  rm -rf "$GCOV_PREFIX"
}

# Build the target-major extension and mock plugin, start a throwaway
# cluster with the mock reasoning plugin preloaded. Returns 1 (skip) if
# the major's server binaries are not installed.
pg_setup() {
  local v="$1"
  BIN="$(pg_bindir "$v")"
  if [[ ! -x "$BIN/initdb" ]] || [[ ! -x "$BIN/pg_config" ]]; then
    return 1
  fi
  # Independent of gate_01_build's own detection -- a single non-01
  # -Gate run reuses a prior build without gate_01_build ever running
  # this session, so FSQL_DLSUFFIX may not be set yet.
  FSQL_DLSUFFIX="$(fsql_pg_dlsuffix "$BIN/pg_config")"
  SO="$HERE/fractalsql$FSQL_DLSUFFIX"
  MOCK="$TMPROOT/fractalsql_bt_mock_$v.so"
  EVIL="$TMPROOT/fractalsql_bt_evil_$v.so"
  CRASH="$TMPROOT/fractalsql_bt_crash_$v.so"
  LYING="$TMPROOT/fractalsql_bt_lying_$v.so"
  RETRY="$TMPROOT/fractalsql_bt_retry_$v.so"
  EMBED="$TMPROOT/fractalsql_bt_embed_$v.so"
  EVIL_EMBED="$TMPROOT/fractalsql_bt_evil_embed_$v.so"
  THINK="$TMPROOT/fractalsql_bt_think_$v.so"
  DATADIR="/tmp/fractalsql_bt_data_$v"
  SOCKDIR="/tmp/fractalsql_bt_sock_$v"
  PORT=$(( 5600 + v ))
  rm -rf "$DATADIR" "$SOCKDIR"; mkdir -p "$SOCKDIR"
  rm -f /tmp/fractalsql_bt_evil_trigger_call.txt
  cc -shared -fPIC -std=c99 -Iinclude tests/mock_reasoning_plugin.c -o "$MOCK" 2>/tmp/fractalsql_bt_setup_$v.log \
    || { cat /tmp/fractalsql_bt_setup_$v.log >&2; return 2; }
  cc -shared -fPIC -std=c99 -Iinclude tests/evil_nonterminating_plugin.c -o "$EVIL" 2>/tmp/fractalsql_bt_setup_$v.log \
    || { cat /tmp/fractalsql_bt_setup_$v.log >&2; return 2; }
  cc -shared -fPIC -std=c99 -Iinclude tests/evil_crash_plugin.c -o "$CRASH" 2>/tmp/fractalsql_bt_setup_$v.log \
    || { cat /tmp/fractalsql_bt_setup_$v.log >&2; return 2; }
  cc -shared -fPIC -std=c99 -Iinclude tests/evil_lying_length_plugin.c -o "$LYING" 2>/tmp/fractalsql_bt_setup_$v.log \
    || { cat /tmp/fractalsql_bt_setup_$v.log >&2; return 2; }
  cc -shared -fPIC -std=c99 -Iinclude tests/retry_reasoning_plugin.c -o "$RETRY" 2>/tmp/fractalsql_bt_setup_$v.log \
    || { cat /tmp/fractalsql_bt_setup_$v.log >&2; return 2; }
  cc -shared -fPIC -std=c99 -Iinclude tests/mock_embed_plugin.c -o "$EMBED" 2>/tmp/fractalsql_bt_setup_$v.log \
    || { cat /tmp/fractalsql_bt_setup_$v.log >&2; return 2; }
  cc -shared -fPIC -std=c99 -Iinclude tests/evil_embed_plugin.c -o "$EVIL_EMBED" 2>/tmp/fractalsql_bt_setup_$v.log \
    || { cat /tmp/fractalsql_bt_setup_$v.log >&2; return 2; }
  cc -shared -fPIC -std=c99 -Iinclude tests/think_reasoning_plugin.c -o "$THINK" 2>/tmp/fractalsql_bt_setup_$v.log \
    || { cat /tmp/fractalsql_bt_setup_$v.log >&2; return 2; }
  rm -f /tmp/fractalsql_bt_retry_prompt.txt
  "$BIN/initdb" -D "$DATADIR" -U postgres --auth=trust >/tmp/fractalsql_bt_setup_$v.log 2>&1 \
    || { tail -20 /tmp/fractalsql_bt_setup_$v.log >&2; return 2; }
  # reasoning_plugin and text_to_sql_max_attempts go in postgresql.conf,
  # NOT -c on the command line: command-line-set GUC values outrank
  # ALTER SYSTEM/config-file/reload for the rest of the postmaster's
  # life, which would permanently defeat pg_set_guc()'s ALTER SYSTEM +
  # pg_reload_conf() (gates 05/06's plugin swap, gate 14's max_attempts
  # bump for the retry-with-feedback path).
  echo "fractalsql.reasoning_plugin = '$MOCK'" >> "$DATADIR/postgresql.conf"
  echo "fractalsql.text_to_sql_max_attempts = 1" >> "$DATADIR/postgresql.conf"
  # postgres (not itself sanitizer-instrumented) is the "host process"
  # that dlopens our now-instrumented fractalsql.so via
  # shared_preload_libraries: LD_PRELOAD the runtime so its symbols are
  # already resolved before the dlopen happens, or the backend fails to
  # start with undefined __asan_*/__ubsan_* symbol errors. Exported here
  # (not just locally) so pg_ctl's child postgres process inherits it
  # normally.
  # DYLD_INSERT_LIBRARIES is Darwin's LD_PRELOAD equivalent. A Homebrew-
  # installed postgres binary lives outside SIP-protected paths (/usr/bin,
  # /System, ...), so the var should NOT get silently stripped here --
  # but genuinely unverified until this actually runs on real hardware.
  # UBSan specifically: Apple's -fsanitize=undefined historically links
  # its minimal runtime statically into the compiled object rather than
  # needing a preloaded shared dylib the way Linux's libubsan.so does
  # -- if resolve_san_rt can't find a dylib for it on Darwin, that's
  # treated as "nothing to preload" (skip, not fail) rather than
  # assuming the gate is broken; confirm which is actually true on a
  # real run and tighten this back to a hard failure if UBSan turns out
  # to need the preload after all.
  local preload_var="LD_PRELOAD"
  [[ "$(uname -s)" = "Darwin" ]] && preload_var="DYLD_INSERT_LIBRARIES"
  if [[ "$ASAN" -eq 1 ]]; then
    # Darwin: DYLD_INSERT_LIBRARIES-injecting ASan into a postgres that
    # wasn't itself compiled with -fsanitize=address doesn't reliably
    # install ASan's malloc/free interceptor table on modern macOS
    # (chained fixups resolve libSystem calls before the late-injected
    # runtime can hook them) -- confirmed on real hardware: the dylib
    # loads fine, then ASan's own runtime aborts with "Interceptors are
    # not working ... loaded too late (e.g. via dlopen)". Signing has
    # nothing to do with it. Detect a plain (non-instrumented) binary
    # up front and skip cleanly instead of hard-failing pg_ctl start.
    if [[ "$(uname -s)" = "Darwin" ]] \
       && ! otool -L "$BIN/postgres" 2>/dev/null | grep -qi 'libclang_rt\.asan\|libasan'; then
      skip "PG$v cluster setup (Darwin ASan needs postgres itself built with -fsanitize=address; run against a source-built ASan postgres to exercise this gate here -- Linux/Windows ASan CI already cover this same portable C source)"
      return 3
    fi
    local asan_rt; asan_rt="$(resolve_san_rt libasan.so)"
    [[ -n "$asan_rt" ]] && [[ -f "$asan_rt" ]] || { echo "FAIL: could not resolve libasan.so runtime" >&2; return 2; }
    export "$preload_var"="$asan_rt"
    export ASAN_OPTIONS="detect_leaks=0:halt_on_error=1"
  elif [[ "$UBSAN" -eq 1 ]]; then
    local ubsan_rt; ubsan_rt="$(resolve_san_rt libubsan.so)"
    if [[ -n "$ubsan_rt" ]] && [[ -f "$ubsan_rt" ]]; then
      export "$preload_var"="$ubsan_rt"
    elif [[ "$(uname -s)" != "Darwin" ]]; then
      echo "FAIL: could not resolve libubsan.so runtime" >&2; return 2
    fi
    export UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1"
  fi
  "$BIN/pg_ctl" -D "$DATADIR" -w -l "$DATADIR/log" \
     -o "-p $PORT -k $SOCKDIR -c listen_addresses='' -c shared_preload_libraries=$SO" \
     start >/tmp/fractalsql_bt_setup_$v.log 2>&1 \
    || { tail -20 /tmp/fractalsql_bt_setup_$v.log >&2; [[ -f "$DATADIR/log" ]] && tail -20 "$DATADIR/log" >&2; return 2; }
  PSQL=("$BIN/psql" -h "$SOCKDIR" -p "$PORT" -U postgres -d postgres -X -tA)
  # register the functions from the freshly built .so
  "${PSQL[@]}" -c "
     CREATE FUNCTION fractal_version() RETURNS text AS '$SO','fractal_version' LANGUAGE C IMMUTABLE STRICT;
     CREATE FUNCTION fractal_edition() RETURNS text AS '$SO','fractal_edition' LANGUAGE C IMMUTABLE STRICT;
     CREATE FUNCTION fractal_search(query float8[], iterations int4 DEFAULT 30, population_size int4 DEFAULT 50, diffusion_factor int4 DEFAULT 2) RETURNS float8[] AS '$SO','fractal_search' LANGUAGE C VOLATILE STRICT;
     CREATE FUNCTION fractal_search_debug(query float8[], iterations int4 DEFAULT 30, population_size int4 DEFAULT 50, diffusion_factor int4 DEFAULT 2) RETURNS jsonb AS '$SO','fractal_search_debug' LANGUAGE C VOLATILE STRICT;
     CREATE FUNCTION fractal_schema_context(table_names text[] DEFAULT NULL, query_hint text DEFAULT NULL) RETURNS text AS '$SO','fractal_schema_context' LANGUAGE C;
     CREATE FUNCTION fractal_text_to_sql(question text, table_names text[] DEFAULT NULL) RETURNS text AS '$SO','fractal_text_to_sql' LANGUAGE C;
     CREATE FUNCTION fractal_reason(query text, context text DEFAULT '{}') RETURNS text AS '$SO','fractal_reason' LANGUAGE C;
     CREATE FUNCTION fractal_search_explore(table_name text, vector_col text, query float8[], options jsonb DEFAULT '{}'::jsonb) RETURNS SETOF float8[] AS '$SO','fractal_search_explore' LANGUAGE C VOLATILE STRICT;
     CREATE FUNCTION fractal_embed(input text) RETURNS float8[] AS '$SO','fractal_embed' LANGUAGE C;
  " >/tmp/fractalsql_bt_setup_$v.log 2>&1 \
    || { cat /tmp/fractalsql_bt_setup_$v.log >&2; return 2; }
  # Agent-tier (the 6 C-level "Universal Agent" functions + their composite
  # return types: fractal_search_agent, fractal_sql_agent, fractal_rag_agent,
  # fractal_agent_plan_explore, fractal_agent_trajectory_predict,
  # fractal_agent_detect_loop). This section sits between the core
  # (hand-registered above) and the Vectorizer marker; it references
  # MODULE_PATHNAME, so sed it to $SO. Engine G (fractal_agent_data_analyst)
  # composes fractal_sql_agent, so its fractal_sql_agent_result composite
  # type MUST exist before the agents extension slice loads -- PL/pgSQL
  # resolves DECLARE res fractal_sql_agent_result at CREATE time, so
  # without this slice engine G's CREATE fails with "type
  # fractal_sql_agent_result does not exist". (First surfaced on the first
  # live run after Stage 4 -- the gate-23 extension was parse-checked only.)
  awk '/^-- Agent-tier results types/{f=1} /^-- Vectorizer --/{f=0} f' sql/fractalsql--1.0.sql \
    | sed "s#MODULE_PATHNAME#$SO#g" \
    | "${PSQL[@]}" >/tmp/fractalsql_bt_setup_$v.log 2>&1 \
    || { cat /tmp/fractalsql_bt_setup_$v.log >&2; return 2; }
  # Vectorizer (tables/trigger function/fractal_vectorizer_create/
  # fractal_vectorizer_process_queue/fractal_vectorizer_status view) --
  # pure SQL/PL/pgSQL, no C symbols, so it's extracted straight from the
  # real sql/fractalsql--1.0.sql (from its own section marker onward)
  # rather than duplicated here by hand. Avoids this harness's copy
  # drifting from the real extension SQL the same way the hardcoded
  # CREATE FUNCTION list above already can (a known, accepted tradeoff
  # for the C functions -- not worth re-deriving those from MODULE_
  # PATHNAME substitution just for this), but for a much longer block
  # where drift risk is higher and substitution isn't needed anyway
  # (no MODULE_PATHNAME references in this section at all).
  awk '/^-- Vectorizer --/{f=1} f' sql/fractalsql--1.0.sql | "${PSQL[@]}" \
    >/tmp/fractalsql_bt_setup_$v.log 2>&1 \
    || { cat /tmp/fractalsql_bt_setup_$v.log >&2; return 2; }
  # v2.x additions (Diversify/Repulsion, feedback, dimension analysis,
  # portfolio optimization, domain geometry, named feature store) --
  # same extract-from-the-real-SQL-file pattern as the Vectorizer block
  # above, but this section DOES reference MODULE_PATHNAME (all its C
  # functions), which only CREATE EXTENSION substitutes automatically;
  # sed it to the freshly-built $SO before piping in, same as it would
  # be at real install time.
  awk '/^-- v2.x additions --/{f=1} f' sql/fractalsql--1.0.sql \
    | sed "s#MODULE_PATHNAME#$SO#g" \
    | "${PSQL[@]}" >/tmp/fractalsql_bt_setup_$v.log 2>&1 \
    || { cat /tmp/fractalsql_bt_setup_$v.log >&2; return 2; }
  # fractalsql_agents dependent extension: the parameterized PL/pgSQL agent
  # engines. Pure PL/pgSQL (no MODULE_PATHNAME), loaded raw like the Vectorizer
  # block -- but read from its own extension subdir, with the \echo ... \quit
  # guard line dropped (\quit would abort psql mid-script). The base functions
  # it composes (fractal_dimension_drift, fractal_reason,
  # fractal_optimize_portfolio) are already registered above, so PL/pgSQL
  # CREATE defers-resolution succeeds.
  grep -v '\\quit' fractalsql_agents/sql/fractalsql_agents--1.0.sql \
    | "${PSQL[@]}" >/tmp/fractalsql_bt_setup_$v.log 2>&1 \
    || { cat /tmp/fractalsql_bt_setup_$v.log >&2; return 2; }
  return 0
}

pg_teardown() {
  [[ -n "$DATADIR" ]] && "$BIN/pg_ctl" -D "$DATADIR" -m fast stop >/dev/null 2>&1
  rm -rf "$DATADIR" "$SOCKDIR" "$MOCK" "$EVIL" "$CRASH" "$LYING" "$RETRY" "$EMBED" "$EVIL_EMBED"
  DATADIR=""; SOCKDIR=""
}

# Generic PGC_SIGHUP GUC setter: ALTER SYSTEM + reload + poll until the
# new value is visible. ALTER SYSTEM cannot run inside a transaction
# block, and a multi-statement single -c string executes as an implicit
# one -- these must be two separate psql invocations, not one
# -c "A; B". Polls afterward since pg_reload_conf() only signals the
# postmaster and returns -- it does not wait for the reload to land.
#   $1 = GUC name, $2 = value AS WRITTEN in the SET statement (quote
#        strings yourself, e.g. "'/path'"), $3 = value AS READ BACK by
#        current_setting() (e.g. on/off for booleans, unquoted path text)
pg_set_guc() {
  "${PSQL[@]}" -c "ALTER SYSTEM SET $1 = $2;" >/dev/null 2>&1
  "${PSQL[@]}" -c "SELECT pg_reload_conf();" >/dev/null 2>&1
  local i v tries=$(( 10 * TIMEOUT_MULT ))
  for i in $(seq 1 "$tries"); do
    v=$("${PSQL[@]}" -c "SELECT current_setting('$1');" 2>/dev/null)
    [[ "$v" = "$3" ]] && return 0
    sleep 0.2
  done
  return 1
}

pg_swap_plugin() { pg_set_guc fractalsql.reasoning_plugin "'$1'" "$1"; }

# --- gates ------------------------------------------------------------

gate_01_build() {
  local v="$1" bin; bin="$(pg_bindir "$v")"
  if [[ ! -x "$bin/pg_config" ]]; then skip "01 build (PG$v pg_config absent)"; return; fi
  FSQL_DLSUFFIX="$(fsql_pg_dlsuffix "$bin/pg_config")"
  # PG_CONFIG must match the real build below -- without it this falls
  # back to Makefile's bare "pg_config" default, which silently fails
  # to resolve PGXS (and thus does nothing) whenever pg_config isn't on
  # PATH, e.g. a PG_BINDIR override pointing outside PATH. A no-op clean
  # here leaves stale .o files for the real build to (wrongly) reuse.
  make clean PG_CONFIG="$bin/pg_config" >/dev/null 2>&1
  local cov_arg=""
  # with_llvm=no: PGXS's separate JIT-bitcode compile (clang -emit-llvm)
  # shares PG_CPPFLAGS with the .o compile, so it also picks up
  # --coverage and (on this toolchain) clobbers gcc's just-written
  # fractalsql.gcno with an incompatible clang-format one afterward.
  # Bitcode is a runtime-JIT concern, irrelevant to a coverage run.
  [[ "$COVERAGE" -eq 1 ]] && cov_arg="COVERAGE=1 with_llvm=no"
  local san_arg=""
  # Confirmed on real hardware (this sandbox): unlike COVERAGE, ASan/UBSan
  # don't need with_llvm=no -- the JIT-bitcode compile picks up the same
  # -fsanitize= flags and builds cleanly (no .gcno-class file conflict,
  # since sanitizers don't produce their own on-disk artifacts the way
  # gcov does), so it's left enabled here.
  [[ "$ASAN" -eq 1 ]]  && san_arg="ASAN=1"
  [[ "$UBSAN" -eq 1 ]] && san_arg="UBSAN=1"
  if make $cov_arg $san_arg PG_CONFIG="$bin/pg_config" >/tmp/fractalsql_bt_build_$v.log 2>&1 && [[ -f "fractalsql$FSQL_DLSUFFIX" ]]; then
    pass "01 build (PG$v)"
  else
    fail "01 build (PG$v) — see /tmp/fractalsql_bt_build_$v.log"
    grep -iE "error:" "/tmp/fractalsql_bt_build_$v.log" | head -3 | sed 's/^/         /'
  fi
}

gate_02_smoke() {
  local ver; ver=$("${PSQL[@]}" -c "SELECT fractal_version();" 2>&1)
  [[ "$ver" = "2.0.11" ]] && pass "02 smoke: version=$ver" || fail "02 smoke: version='$ver' (want 2.0.11)"
  # fractal_search convergence: cosine similarity to query ~1
  local r; r=$("${PSQL[@]}" -c "
     WITH q AS (SELECT fractal_search(ARRAY[0.6,0.8]::float8[],100,50,2) AS v)
     SELECT CASE WHEN sqrt(v[1]*v[1]+v[2]*v[2])>1e-9
                  AND (v[1]*0.6+v[2]*0.8)/sqrt(v[1]*v[1]+v[2]*v[2])>0.99
                 THEN 'ok' ELSE 'FAIL' END FROM q;" 2>&1)
  [[ "$r" = "ok" ]] && pass "02 smoke: fractal_search convergence" || fail "02 smoke: convergence=$r"
  local ed; ed=$("${PSQL[@]}" -c "SELECT fractal_edition();" 2>&1)
  [[ -n "$ed" ]] && ! grep <<< "$ed" -q ERROR && pass "02 smoke: edition=$ed" || fail "02 smoke: edition='$ed'"
  # fractal_search_debug returns the FULL fsql_search_ptr result JSON
  # (not just the best_point extraction fractal_search uses) -- assert
  # the best_point key survives the jsonb_in round-trip.
  local dbg; dbg=$("${PSQL[@]}" -c "SELECT fractal_search_debug(ARRAY[0.6,0.8]::float8[],100,50,2);" 2>&1)
  grep <<< "$dbg" -q "best_point" && pass "02 smoke: fractal_search_debug has best_point" || fail "02 smoke: fractal_search_debug='$dbg'"
}

gate_03_schema_context() {
  "${PSQL[@]}" -c "
     DROP TABLE IF EXISTS bt_orders, bt_customers;
     CREATE TABLE bt_customers (id serial PRIMARY KEY, name text NOT NULL, status text);
     COMMENT ON TABLE bt_customers IS 'buyers';
     CREATE TABLE bt_orders (id serial PRIMARY KEY, customer_id int NOT NULL REFERENCES bt_customers(id), total int NOT NULL);
  " >/dev/null 2>&1
  local ctx; ctx=$("${PSQL[@]}" -c "SELECT fractal_schema_context(ARRAY['bt_customers','bt_orders']);" 2>&1)
  grep <<< "$ctx" -q "id integer PK"        && pass "03 schema_context: PK"       || fail "03 schema_context: PK"
  grep <<< "$ctx" -q "name text NOT NULL"   && pass "03 schema_context: NOT NULL" || fail "03 schema_context: NOT NULL"
  grep <<< "$ctx" -q "buyers"               && pass "03 schema_context: comment"  || fail "03 schema_context: comment"
  grep <<< "$ctx" -q "REFERENCES bt_customers" && pass "03 schema_context: FK"    || fail "03 schema_context: FK"
  # auto-discovery mode (table_names omitted/NULL): must find bt_customers
  # and bt_orders on its own. Relies on this gate running early, before
  # any other gate has created tables in the public schema.
  local auto; auto=$("${PSQL[@]}" -c "SELECT fractal_schema_context();" 2>&1)
  if grep <<< "$auto" -q "bt_customers" && grep <<< "$auto" -q "bt_orders"; then
    pass "03 schema_context: auto-discovery finds both tables"
  else
    fail "03 schema_context: auto-discovery='$auto'"
  fi
}

# helper: expect a text_to_sql rejection containing $2 (or PASS if $2 empty)
# $3 = label, prefixed with the calling gate's own number by the caller
# (e.g. "04 valid-SELECT", "13 siu-insert-allowed") since this helper is
# shared by gates 04 and 13.
t2s_expect() {
  local canned="$1" want="$2" label="$3"
  echo "$canned" > /tmp/fractalsql_bt_sql.txt
  local r; r=$("${PSQL[@]}" -c "SELECT fractal_text_to_sql('q', ARRAY['bt_customers','bt_orders']);" 2>&1)
  if [[ -z "$want" ]]; then
    grep <<< "$r" -q ERROR && fail "$label (expected PASS): $r" || pass "$label → returned"
  else
    if grep <<< "$r" -q "$want"; then pass "$label → rejected ($want)"; else fail "$label: got '$r' (want '$want')"; fi
  fi
}

gate_04_text_to_sql() {
  t2s_expect "SELECT count(*) FROM bt_orders"                                  ""                       "04 valid-SELECT"
  t2s_expect "SELECT 1; DROP TABLE bt_orders"                                  "exactly one SQL"        "04 stacked"
  t2s_expect "DROP TABLE bt_orders"                                            "not permitted"          "04 DDL"
  t2s_expect "DELETE FROM bt_orders"                                           "not permitted"          "04 DELETE"
  t2s_expect "WITH d AS (DELETE FROM bt_orders RETURNING *) SELECT * FROM d"   "data-modifying CTE"     "04 modifying-CTE"
  t2s_expect "SELECT nope FROM bt_orders"                                      "does not analyze"       "04 bad-column"
  t2s_expect "this is not sql at all ##"                                       "does not parse"         "04 unparseable"
  local n; n=$("${PSQL[@]}" -c "SELECT count(*) FROM bt_orders;" 2>&1)
  [[ "$n" = "0" ]] && pass "04 never-executes (bt_orders still empty)" || fail "04 never-executes: row count=$n"
  # auto-discovery mode (table_names omitted/NULL): the full GENERATE ->
  # ALLOWLIST -> EXPLAIN pipeline must still work off the auto-built
  # schema context, not just the explicit-table_names path every other
  # case above exercises.
  echo "SELECT count(*) FROM bt_orders" > /tmp/fractalsql_bt_sql.txt
  local auto; auto=$("${PSQL[@]}" -c "SELECT fractal_text_to_sql('q');" 2>&1)
  if grep <<< "$auto" -q "^SELECT count"; then
    pass "04 auto-discovery: text_to_sql without table_names"
  else
    fail "04 auto-discovery: got '$auto'"
  fi
}

# Guard-page plugin: response is deliberately NOT NUL-terminated and
# flush against an unmapped page, so any over-read SIGSEGVs instantly.
# Proves the pnstrdup(summary, summary_len) fix (fractalsql.c) holds —
# without it, this gate crashes the backend instead of getting a result.
# Also proves it at the OTHER two call sites that share the identical
# fix (bare fractal_reason(), and t2s_run_review() via trigger=2 —
# see the plugin's own header comment for why REVIEW needs a 2nd-call
# trigger rather than "misbehave every time").
gate_05_evil_overread() {
  pg_swap_plugin "$EVIL" || { fail "05 evil_overread: plugin swap did not take effect"; return; }

  echo "1" > /tmp/fractalsql_bt_evil_trigger_call.txt
  echo "SELECT 1" > /tmp/fractalsql_bt_sql.txt
  local r; r=$("${PSQL[@]}" -c "SELECT fractal_text_to_sql('q', ARRAY['bt_customers','bt_orders']);" 2>&1)
  if grep <<< "$r" -qE "server closed the connection|could not connect"; then
    fail "05 evil_overread: GENERATE path — backend crashed — $r"
  else
    pass "05 evil_overread: GENERATE path (non-terminated guard-page response) survived"
  fi

  local r2; r2=$("${PSQL[@]}" -c "SELECT fractal_reason('q');" 2>&1)
  if grep <<< "$r2" -qE "server closed the connection|could not connect"; then
    fail "05 evil_overread: bare fractal_reason() — backend crashed — $r2"
  else
    pass "05 evil_overread: bare fractal_reason() survived"
  fi

  pg_set_guc fractalsql.text_to_sql_use_review on on \
    || { fail "05 evil_overread: could not enable text_to_sql_use_review"; pg_swap_plugin "$MOCK"; return; }
  echo "2" > /tmp/fractalsql_bt_evil_trigger_call.txt
  local r3; r3=$("${PSQL[@]}" -c "SELECT fractal_text_to_sql('q', ARRAY['bt_customers','bt_orders']);" 2>&1)
  if grep <<< "$r3" -qE "server closed the connection|could not connect"; then
    fail "05 evil_overread: REVIEW path — backend crashed — $r3"
  else
    pass "05 evil_overread: REVIEW path (t2s_run_review) survived"
  fi
  pg_set_guc fractalsql.text_to_sql_use_review off off
  echo "1" > /tmp/fractalsql_bt_evil_trigger_call.txt

  pg_swap_plugin "$MOCK"
}

# Same three call sites as gate 05, but the adversarial claim is a
# lying summary_len (32 MiB, over a real 8-byte buffer) instead of a
# missing NUL terminator — proves guard_ai_response_len() rejects
# BEFORE any read is attempted, at all three sites that call it.
gate_07_evil_lying_length() {
  pg_swap_plugin "$LYING" || { fail "07 evil_lying_length: plugin swap did not take effect"; return; }

  echo "1" > /tmp/fractalsql_bt_evil_trigger_call.txt
  local r; r=$("${PSQL[@]}" -c "SELECT fractal_text_to_sql('q', ARRAY['bt_customers','bt_orders']);" 2>&1)
  if grep <<< "$r" -qE "server closed the connection|could not connect"; then
    fail "07 evil_lying_length: GENERATE path — backend crashed — $r"
  elif grep <<< "$r" -q "implausible response length"; then
    pass "07 evil_lying_length: GENERATE path rejected cleanly"
  else
    fail "07 evil_lying_length: GENERATE path — expected rejection, got: $r"
  fi

  local r2; r2=$("${PSQL[@]}" -c "SELECT fractal_reason('q');" 2>&1)
  if grep <<< "$r2" -qE "server closed the connection|could not connect"; then
    fail "07 evil_lying_length: bare fractal_reason() — backend crashed — $r2"
  elif grep <<< "$r2" -q "implausible response length"; then
    pass "07 evil_lying_length: bare fractal_reason() rejected cleanly"
  else
    fail "07 evil_lying_length: bare fractal_reason() — expected rejection, got: $r2"
  fi

  pg_set_guc fractalsql.text_to_sql_use_review on on \
    || { fail "07 evil_lying_length: could not enable text_to_sql_use_review"; pg_swap_plugin "$MOCK"; return; }
  echo "2" > /tmp/fractalsql_bt_evil_trigger_call.txt
  local r3; r3=$("${PSQL[@]}" -c "SELECT fractal_text_to_sql('q', ARRAY['bt_customers','bt_orders']);" 2>&1)
  if grep <<< "$r3" -qE "server closed the connection|could not connect"; then
    fail "07 evil_lying_length: REVIEW path — backend crashed — $r3"
  elif grep <<< "$r3" -q "implausible response length"; then
    pass "07 evil_lying_length: REVIEW path (t2s_run_review) rejected cleanly"
  else
    fail "07 evil_lying_length: REVIEW path — expected rejection, got: $r3"
  fi
  pg_set_guc fractalsql.text_to_sql_use_review off off
  echo "1" > /tmp/fractalsql_bt_evil_trigger_call.txt

  pg_swap_plugin "$MOCK"
}

# Regression test for a real information-disclosure bug found + fixed
# 2026-08-04: append_table_context()'s explicit-table_names path
# resolved names via to_regclass() (visibility only, NOT privilege) and
# then queried pg_attribute/pg_constraint directly (globally-readable
# catalogs) -- so a caller naming a table it had ZERO grants on could
# still read its full column/PK/FK/comment structure. Fixed by adding
# has_table_privilege(..., 'SELECT') to the resolution query. The
# auto-discovery path (table_names IS NULL) already had this check;
# this proves the explicit path now matches it.
gate_08_authz() {
  "${PSQL[@]}" -c "
     DROP TABLE IF EXISTS bt_secret;
     CREATE TABLE bt_secret (id serial PRIMARY KEY, ssn text);
     COMMENT ON TABLE bt_secret IS 'PII - restricted';
     REVOKE ALL ON bt_secret FROM PUBLIC;
     DROP ROLE IF EXISTS bt_lowpriv;
     CREATE ROLE bt_lowpriv LOGIN;
  " >/dev/null 2>&1

  local lowpriv_psql=("$BIN/psql" -h "$SOCKDIR" -p "$PORT" -U bt_lowpriv -d postgres -X -tA)
  local r; r=$("${lowpriv_psql[@]}" -c "SELECT fractal_schema_context(ARRAY['bt_secret']);" 2>&1)
  if grep <<< "$r" -q "ssn"; then
    fail "08 authz: low-priv role saw bt_secret's columns (info disclosure): $r"
  elif grep <<< "$r" -q "not found or not visible"; then
    pass "08 authz: low-priv role correctly blocked from bt_secret"
  else
    fail "08 authz: unexpected result: $r"
  fi

  "${PSQL[@]}" -c "GRANT SELECT ON bt_secret TO bt_lowpriv;" >/dev/null 2>&1
  local r2; r2=$("${lowpriv_psql[@]}" -c "SELECT fractal_schema_context(ARRAY['bt_secret']);" 2>&1)
  grep <<< "$r2" -q "ssn" && pass "08 authz: SELECT grant restores visibility" \
                              || fail "08 authz: granted role still blocked: $r2"

  "${PSQL[@]}" -c "DROP ROLE bt_lowpriv; DROP TABLE bt_secret;" >/dev/null 2>&1
}

# Regression test for today's GUC_SUPERUSER_ONLY fix (fractalsql.c):
# a non-superuser must not be able to point reasoning_plugin at an
# arbitrary .so path (that's native code execution in every backend).
gate_09_guc_superuser() {
  "${PSQL[@]}" -c "DROP ROLE IF EXISTS bt_lowpriv2; CREATE ROLE bt_lowpriv2 LOGIN;" >/dev/null 2>&1
  local lowpriv_psql=("$BIN/psql" -h "$SOCKDIR" -p "$PORT" -U bt_lowpriv2 -d postgres -X -tA)
  local r; r=$("${lowpriv_psql[@]}" -c "ALTER SYSTEM SET fractalsql.reasoning_plugin = '/tmp/evil.so';" 2>&1)
  grep <<< "$r" -qiE "permission denied|must be a?n? ?superuser" \
    && pass "09 guc_superuser: non-superuser rejected from setting reasoning_plugin" \
    || fail "09 guc_superuser: expected rejection, got: $r"
  "${PSQL[@]}" -c "DROP ROLE bt_lowpriv2;" >/dev/null 2>&1
}

# MAX_SCHEMA_CONTEXT_TABLES (512) DoS cap boundary, and a SQL-injection-
# shaped table name proving clean rejection rather than execution.
gate_10_dos_and_injection() {
  local many; many=$(printf "'t%s'," $(seq 1 513) | sed 's/,$//')
  local r; r=$("${PSQL[@]}" -c "SELECT fractal_schema_context(ARRAY[$many]);" 2>&1)
  grep <<< "$r" -q "exceeds the limit of 512" \
    && pass "10 dos_cap: 513 table names rejected" \
    || fail "10 dos_cap: expected PROGRAM_LIMIT_EXCEEDED, got: $r"

  local r2; r2=$("${PSQL[@]}" -c "SELECT fractal_schema_context(ARRAY['bt_customers''; DROP TABLE bt_orders; --']);" 2>&1)
  local n; n=$("${PSQL[@]}" -c "SELECT count(*) FROM bt_orders;" 2>&1)
  if [[ "$n" = "0" ]]; then
    pass "10 injection: SQL-injection-shaped table name did not execute (bt_orders intact)"
  else
    fail "10 injection: bt_orders row count changed (n=$n) — injection may have executed"
  fi
  grep <<< "$r2" -qE "not found or not visible|ERROR" \
    && pass "10 injection: injection-shaped table name cleanly rejected" \
    || fail "10 injection: unexpected result: $r2"
}

# Scout mode minimal smoke: a 3-island clustered corpus, population
# returned (not the pre-Scout 1-row stub), particles disperse across
# more than one island. Mirrors tests/test_scout.py's core assertions
# in the lightweight bash/SQL style so it runs in the fast/CI path.
gate_11_scout() {
  "${PSQL[@]}" -c "
     DROP TABLE IF EXISTS bt_scout_docs;
     CREATE TABLE bt_scout_docs (id int, emb_arr float8[]);
     INSERT INTO bt_scout_docs
       SELECT i, ARRAY[1.0,0.0,0.0]::float8[] FROM generate_series(1,20) i
       UNION ALL
       SELECT i, ARRAY[0.0,1.0,0.0]::float8[] FROM generate_series(21,40) i
       UNION ALL
       SELECT i, ARRAY[0.0,0.0,1.0]::float8[] FROM generate_series(41,60) i;
  " >/dev/null 2>&1

  local n; n=$("${PSQL[@]}" -c "
     SELECT count(*) FROM fractal_search_explore(
       'bt_scout_docs', 'emb_arr', ARRAY[1.0,0.0,0.0]::float8[],
       '{\"population_size\": 24, \"iterations\": 12}'::jsonb);" 2>&1)
  [[ "$n" = "24" ]] && pass "11 scout: returns full population (24 particles)" \
                   || fail "11 scout: expected 24 particles, got: $n"

  local islands; islands=$("${PSQL[@]}" -c "
     SELECT count(DISTINCT
       CASE WHEN p[1] > p[2] AND p[1] > p[3] THEN 0
            WHEN p[2] > p[1] AND p[2] > p[3] THEN 1
            ELSE 2 END)
     FROM fractal_search_explore(
       'bt_scout_docs', 'emb_arr', ARRAY[1.0,0.0,0.0]::float8[],
       '{\"population_size\": 24, \"iterations\": 12}'::jsonb) AS p;" 2>&1)
  [[ "${islands:-0}" -gt 1 ]] 2>/dev/null && pass "11 scout: particles disperse across >1 island" \
                                          || fail "11 scout: expected dispersion, got islands=$islands"

  "${PSQL[@]}" -c "DROP TABLE IF EXISTS bt_scout_docs;" >/dev/null 2>&1
}

# Deliberately-segfaulting plugin. No in-process fix can prevent this —
# the point is to CI-verify PostgreSQL's own crash-recovery contract:
# the triggering connection drops, the postmaster auto-restarts the
# cluster (restart_after_crash, on by default), and previously
# committed data survives intact.
gate_06_crash_recovery() {
  "${PSQL[@]}" -c "INSERT INTO bt_customers (name, status) VALUES ('canary', 'ok');" >/dev/null 2>&1
  pg_swap_plugin "$CRASH" || { fail "06 crash_recovery: plugin swap did not take effect"; return; }
  echo "SELECT 1" > /tmp/fractalsql_bt_sql.txt
  local r; r=$("${PSQL[@]}" -c "SELECT fractal_text_to_sql('q', ARRAY['bt_customers','bt_orders']);" 2>&1)
  grep <<< "$r" -qE "server closed the connection|could not connect" \
    && pass "06 crash_recovery: triggering connection dropped as expected" \
    || fail "06 crash_recovery: expected the connection to drop, got: $r"

  # Two concerns share this poll but must NOT share the same cutoff:
  # whether recovery counts as "fast enough" for the gate's own pass/fail
  # (the original `tries` budget), and whether the crash plugin gets
  # swapped back to $MOCK at all -- restoring it was previously gated
  # behind this same up==1-within-budget check, so a near-miss (cluster
  # comes back a few seconds late) left the deliberately-crashing plugin
  # active for every remaining gate in the run, cascading into unrelated-
  # looking failures far downstream. Poll for up to double the budget;
  # report pass/fail against the original window, but restore the plugin
  # as long as the cluster comes back at all within the extended one.
  local up=0 i tries=$(( 30 * TIMEOUT_MULT )) within_budget=0
  for i in $(seq 1 $(( tries * 2 ))); do
    "${PSQL[@]}" -c "SELECT 1;" >/dev/null 2>&1 && { up=1; [[ "$i" -le "$tries" ]] && within_budget=1; break; }
    sleep 0.5
  done
  [[ "$within_budget" -eq 1 ]] && pass "06 crash_recovery: cluster auto-restarted" \
                   || fail "06 crash_recovery: cluster did not come back within $(( tries / 2 ))s"

  if [[ "$up" -eq 1 ]]; then
    local n; n=$("${PSQL[@]}" -c "SELECT count(*) FROM bt_customers WHERE name = 'canary';" 2>&1)
    [[ "$n" = "1" ]] && pass "06 crash_recovery: prior data intact after recovery" \
                    || fail "06 crash_recovery: canary row missing after recovery (n=$n)"
    pg_swap_plugin "$MOCK"
  else
    fail "06 crash_recovery: cluster never came back -- remaining gates will run against the crash plugin"
  fi
}

# Concurrency/soak: SOAK_WORKERS concurrent backends x SOAK_ITERS mixed
# benign calls each (fractal_search / schema_context / text_to_sql),
# against the SAME shared cluster. Each backend is a separate OS
# process (no threading), so this isn't hunting for data races on
# fractalsql.c's static globals -- those are already per-process. It's
# checking for what concurrency actually CAN break here: connection/
# resource exhaustion, and any SPI/transaction-handling bug that only
# surfaces under overlapping backends. Bounded duration by design, not
# a multi-minute stress soak.
SOAK_WORKERS=20
SOAK_ITERS=15

gate_12_soak() {
  local outdir="/tmp/fractalsql_bt_soak_$$"
  rm -rf "$outdir"; mkdir -p "$outdir"
  echo "SELECT count(*) FROM bt_orders" > /tmp/fractalsql_bt_sql.txt

  local pids=() w
  for w in $(seq 1 "$SOAK_WORKERS"); do
    (
      local rc=0 i
      for i in $(seq 1 "$SOAK_ITERS"); do
        case $(( (w + i) % 3 )) in
          0) "${PSQL[@]}" -c "SELECT fractal_search(ARRAY[0.6,0.8]::float8[],20,20,2);" >/dev/null 2>&1 || rc=1 ;;
          1) "${PSQL[@]}" -c "SELECT fractal_schema_context(ARRAY['bt_customers','bt_orders']);" >/dev/null 2>&1 || rc=1 ;;
          2) "${PSQL[@]}" -c "SELECT fractal_text_to_sql('q', ARRAY['bt_customers','bt_orders']);" >/dev/null 2>&1 || rc=1 ;;
          *) ;;   # unreachable: (w+i) % 3 is always 0/1/2
        esac
      done
      echo "$rc" > "$outdir/worker_$w.rc"
    ) &
    pids+=("$!")
  done
  local p
  for p in "${pids[@]}"; do wait "$p"; done

  local failed_workers=0
  for w in $(seq 1 "$SOAK_WORKERS"); do
    [[ "$(cat "$outdir/worker_$w.rc" 2>/dev/null)" = "0" ]] || failed_workers=$((failed_workers + 1))
  done
  local total=$(( SOAK_WORKERS * SOAK_ITERS ))
  [[ "$failed_workers" -eq 0 ]] \
    && pass "12 soak: $SOAK_WORKERS workers x $SOAK_ITERS iterations ($total calls) all succeeded" \
    || fail "12 soak: $failed_workers/$SOAK_WORKERS workers had a failed call"

  "${PSQL[@]}" -c "SELECT 1;" >/dev/null 2>&1 \
    && pass "12 soak: cluster responsive after concurrent load" \
    || fail "12 soak: cluster unresponsive after concurrent load"

  rm -rf "$outdir"
}

# select_insert_update mode: fractalsql.text_to_sql_allowed_statements
# widens the allowlist from SELECT-only to SELECT/INSERT/UPDATE. Proves
# both halves of that: writes are now returned (not rejected) instead
# of executed (still just EXPLAINed, per t2s_check_explain), and DDL/
# DELETE remain rejected regardless -- the GUC only ever adds INSERT/
# UPDATE to the allowed set, never removes the DDL/DELETE block.
gate_13_siu_mode() {
  pg_set_guc fractalsql.text_to_sql_allowed_statements "'select_insert_update'" "select_insert_update" \
    || { fail "13 siu_mode: GUC did not take effect"; return; }

  t2s_expect "INSERT INTO bt_orders (customer_id, total) VALUES (1, 100)" "" "13 siu-insert-allowed"
  t2s_expect "UPDATE bt_orders SET total = 0"                             "" "13 siu-update-allowed"
  t2s_expect "DROP TABLE bt_orders"          "not permitted" "13 siu-ddl-still-rejected"
  t2s_expect "DELETE FROM bt_orders"         "not permitted" "13 siu-delete-still-rejected"

  local n; n=$("${PSQL[@]}" -c "SELECT count(*) FROM bt_orders;" 2>&1)
  [[ "$n" = "0" ]] && pass "13 siu_mode: INSERT/UPDATE never execute (bt_orders still empty)" \
                  || fail "13 siu_mode: row count=$n"

  pg_set_guc fractalsql.text_to_sql_allowed_statements "'select'" "select"
}

# Retry-with-feedback: max_attempts>1 with a plugin that returns a
# rejected statement on attempt 1 and a valid one on attempt 2. Covers
# the retry loop's prompt-rebuild branch (fractalsql.c, `last_sql !=
# NULL`) which every other gate leaves untouched (they all run at
# max_attempts=1, so the loop body only ever executes once).
gate_14_retry() {
  pg_set_guc fractalsql.text_to_sql_max_attempts 2 2 \
    || { fail "14 retry: GUC did not take effect"; return; }
  pg_swap_plugin "$RETRY" || { fail "14 retry: plugin swap did not take effect"; pg_set_guc fractalsql.text_to_sql_max_attempts 1 1; return; }

  local r; r=$("${PSQL[@]}" -c "SELECT fractal_text_to_sql('q', ARRAY['bt_customers','bt_orders']);" 2>&1)
  if grep <<< "$r" -qE "server closed the connection|could not connect"; then
    fail "14 retry: backend crashed -- $r"
  elif grep <<< "$r" -q "^SELECT 1"; then
    pass "14 retry: succeeded on 2nd attempt after 1st was rejected"
  else
    fail "14 retry: expected eventual success (SELECT 1), got: $r"
  fi

  local prompt; prompt=$(cat /tmp/fractalsql_bt_retry_prompt.txt 2>/dev/null)
  grep <<< "$prompt" -q "not permitted" \
    && pass "14 retry: attempt-1 rejection reason fed back into attempt-2 prompt" \
    || fail "14 retry: retry prompt missing feedback text: '$prompt'"

  local n; n=$("${PSQL[@]}" -c "SELECT count(*) FROM bt_orders;" 2>&1)
  [[ "$n" = "0" ]] && pass "14 retry: never-executes held across retries" || fail "14 retry: row count=$n"

  pg_set_guc fractalsql.text_to_sql_max_attempts 1 1
  pg_swap_plugin "$MOCK"
}

# fractal_embed() + the vectorizer, real dispatch through
# ensure_embed_ctx()/g_embed_ctx (the three-tier reasoning-context split
# -- see fractalsql.c's own header comment) using a canned-vector mock
# plugin, not just the "no plugin configured"/"no http_embed_url
# configured" precondition-error paths every other gate here leaves
# untouched. HTTP-level embedding-response parsing (data[0].embedding
# extraction, malformed-response handling) is covered separately in
# tests/test_vectorizer.py against the real vendored plugin -- this gate
# is about fractalsql-postgresql's OWN glue (dispatch, parse_embedding_
# array, the vectorizer's queue/trigger/write-back), matching every
# other gate's mock-plugin scope in this file.
gate_15_embed() {
  pg_set_guc fractalsql.http_embed_url "'http://unused/embeddings'" "http://unused/embeddings" \
    || { fail "15 embed: http_embed_url GUC did not take effect"; return; }
  pg_set_guc fractalsql.reasoning_plugin "'$EMBED'" "$EMBED" \
    || { fail "15 embed: plugin swap did not take effect"; pg_swap_plugin "$MOCK"; return; }

  local r; r=$("${PSQL[@]}" -c "SELECT fractal_embed('test input');" 2>&1)
  [[ "$r" = "{0.1,0.2,0.3}" ]] \
    && pass "15 embed: fractal_embed() returned the canned vector" \
    || fail "15 embed: fractal_embed() expected {0.1,0.2,0.3}, got: $r"

  local rnull; rnull=$("${PSQL[@]}" -c "SELECT fractal_embed(NULL);" 2>&1)
  grep <<< "$rnull" -q "must not be NULL" \
    && pass "15 embed: NULL input rejected cleanly" \
    || fail "15 embed: NULL input expected a clear rejection, got: $rnull"

  # Nonexistent plugin path -- exercises ensure_reasoning_tier_ctx's own
  # load-failure branch (distinct from "no plugin configured at all").
  pg_set_guc fractalsql.reasoning_plugin "'/tmp/fractalsql_bt_nonexistent.so'" "/tmp/fractalsql_bt_nonexistent.so" \
    || { fail "15 embed: bad-path GUC did not take effect"; pg_swap_plugin "$MOCK"; return; }
  local rbad; rbad=$("${PSQL[@]}" -c "SELECT fractal_embed('test input');" 2>&1)
  grep <<< "$rbad" -q "failed to load reasoning plugin" \
    && pass "15 embed: nonexistent plugin path rejected cleanly" \
    || fail "15 embed: nonexistent plugin path expected a clear rejection, got: $rbad"
  pg_set_guc fractalsql.reasoning_plugin "'$EMBED'" "$EMBED" \
    || { fail "15 embed: plugin swap back did not take effect"; pg_swap_plugin "$MOCK"; return; }

  # Evil embed: a plugin returning MAX_EMBED_DIM+1 (16385) floats must be
  # REJECTED, not silently truncated to a wrong-but-plausible 16384-
  # element vector -- a real bug in parse_embedding_array() fixed
  # alongside this test (the original loop condition stopped writing at
  # cap but still returned success). tests/evil_embed_plugin.c mirrors
  # gate 07's evil_lying_length_plugin.c for the embedding response path.
  pg_swap_plugin "$EVIL_EMBED" || { fail "15 embed: evil_embed plugin swap did not take effect"; pg_swap_plugin "$MOCK"; return; }
  local revil; revil=$("${PSQL[@]}" -c "SELECT fractal_embed('test input');" 2>&1)
  grep <<< "$revil" -q "could not parse embedding response" \
    && pass "15 embed: over-limit embedding array rejected, not silently truncated" \
    || fail "15 embed: expected a clean rejection, got: $revil"
  pg_set_guc fractalsql.reasoning_plugin "'$EMBED'" "$EMBED" \
    || { fail "15 embed: plugin swap back (post evil_embed) did not take effect"; pg_swap_plugin "$MOCK"; return; }

  "${PSQL[@]}" -c "DELETE FROM fractal_vectorizers WHERE source_table = 'bt_embed_docs';" >/dev/null 2>&1
  "${PSQL[@]}" -c "DROP TABLE IF EXISTS bt_embed_docs;" >/dev/null 2>&1
  "${PSQL[@]}" -c "CREATE TABLE bt_embed_docs (id serial PRIMARY KEY, body text NOT NULL, embedding float8[]);" >/dev/null 2>&1
  "${PSQL[@]}" -c "INSERT INTO bt_embed_docs (body) VALUES ('a'), ('b');" >/dev/null 2>&1

  # SQL-injection-shaped source_table, same pattern gate 10 already
  # proves for fractal_schema_context/fractal_search_explore, extended
  # here to the vectorizer's own dynamic SQL (CREATE TRIGGER/EXECUTE
  # with %I-quoted identifiers). Must fail cleanly via the ::regclass
  # cast (source_table doesn't resolve) before ever reaching format().
  local rinj; rinj=$("${PSQL[@]}" -c "SELECT fractal_vectorizer_create('bt_embed_docs''; DROP TABLE bt_embed_docs; --', 'body', 'embedding');" 2>&1)
  local ninj; ninj=$("${PSQL[@]}" -c "SELECT count(*) FROM bt_embed_docs;" 2>&1)
  if [[ "$ninj" = "2" ]]; then
    pass "15 embed: injection-shaped source_table did not execute (bt_embed_docs intact)"
  else
    fail "15 embed: bt_embed_docs row count changed (n=$ninj) — injection may have executed"
  fi
  grep <<< "$rinj" -qE "invalid name syntax|does not exist|ERROR" \
    && pass "15 embed: injection-shaped source_table cleanly rejected" \
    || fail "15 embed: unexpected result: $rinj"

  local vzid; vzid=$("${PSQL[@]}" -c "SELECT fractal_vectorizer_create('bt_embed_docs', 'body', 'embedding');" 2>&1)

  # Double-create: same (source_table, text_col, embedding_col) again
  # must fail with a clean, fractal_-prefixed message naming the
  # existing vectorizer id -- not a raw "duplicate key value violates
  # unique constraint ..." that leaks the constraint name and a
  # PL/pgSQL stack frame.
  local rdup; rdup=$("${PSQL[@]}" -c "SELECT fractal_vectorizer_create('bt_embed_docs', 'body', 'embedding');" 2>&1)
  grep <<< "$rdup" -q "already exists (id=$vzid)" \
    && pass "15 embed: double-create rejected with a clean, specific error" \
    || fail "15 embed: expected a clean double-create rejection naming id=$vzid, got: $rdup"
  local n; n=$("${PSQL[@]}" -c "SELECT fractal_vectorizer_process_queue();" 2>&1)
  [[ "$n" = "2" ]] && pass "15 embed: process_queue processed 2 backfilled rows" \
    || fail "15 embed: process_queue expected 2, got: $n"

  local embedded; embedded=$("${PSQL[@]}" -c "SELECT count(*) FROM bt_embed_docs WHERE embedding = '{0.1,0.2,0.3}';" 2>&1)
  [[ "$embedded" = "2" ]] && pass "15 embed: both rows got the real embedding written back" \
    || fail "15 embed: expected 2 rows with the embedding written back, got: $embedded"

  local status; status=$("${PSQL[@]}" -c "SELECT status FROM fractal_vectorizer_status WHERE vectorizer_id = $vzid;" 2>&1)
  [[ "$status" = "done" ]] && pass "15 embed: vectorizer status shows done, no failures" \
    || fail "15 embed: expected status 'done', got: $status"

  "${PSQL[@]}" -c "DELETE FROM fractal_vectorizers WHERE source_table = 'bt_embed_docs';" >/dev/null 2>&1
  "${PSQL[@]}" -c "DROP TABLE IF EXISTS bt_embed_docs;" >/dev/null 2>&1
  pg_swap_plugin "$MOCK"
}

# Vectorizer authz: two real properties, not assumed from reading the
# GRANTs added alongside this test --
#   1. A role that owns its OWN table can fully use the vectorizer on
#      it (create, backfill, trigger-driven auto-enqueue on a new
#      write) without any DBA-granted access to fractal_vectorizers/
#      fractal_vectorizer_queue -- requires those tables' PUBLIC grants
#      (see sql/fractalsql--1.0.sql) plus fractal_vectorizer_enqueue()
#      being SECURITY DEFINER; a real, found-this-session bug before
#      that fix was every non-owner-of-the-tracking-tables role's
#      INSERT into a vectorized table failing entirely (the trigger
#      itself errored on "permission denied for table
#      fractal_vectorizer_queue", rolling back the caller's own write).
#   2. A DIFFERENT role, with no SELECT on that table, calling
#      fractal_vectorizer_process_queue() (which processes the GLOBAL
#      queue, not just its own caller's vectorizers) must not be able
#      to read or embed that table's content -- Postgres's own
#      privilege system gates the dynamic EXECUTE SELECT inside
#      process_queue(), same class of boundary gate 08 already proves
#      for fractal_schema_context, applied here to the vectorizer.
gate_16_embed_authz() {
  "${PSQL[@]}" -c "
     DROP ROLE IF EXISTS bt_embed_owner;
     CREATE ROLE bt_embed_owner LOGIN;
     GRANT CREATE ON SCHEMA public TO bt_embed_owner;
     DROP ROLE IF EXISTS bt_embed_outsider;
     CREATE ROLE bt_embed_outsider LOGIN;
  " >/dev/null 2>&1

  local owner_psql=("$BIN/psql" -h "$SOCKDIR" -p "$PORT" -U bt_embed_owner -d postgres -X -tA)
  local outsider_psql=("$BIN/psql" -h "$SOCKDIR" -p "$PORT" -U bt_embed_outsider -d postgres -X -tA)

  "${owner_psql[@]}" -c "
     CREATE TABLE bt_embed_owned (id serial PRIMARY KEY, body text, embedding float8[]);
     INSERT INTO bt_embed_owned (body) VALUES ('owner data');
  " >/dev/null 2>&1

  local vzid; vzid=$("${owner_psql[@]}" -c "SELECT fractal_vectorizer_create('bt_embed_owned', 'body', 'embedding');" 2>&1)
  case "$vzid" in
    ''|*[!0-9]*) fail "16 embed_authz: owner role could not create its own vectorizer: $vzid" ;;
    *) pass "16 embed_authz: owner role created a vectorizer on its own table" ;;
  esac

  "${owner_psql[@]}" -c "INSERT INTO bt_embed_owned (body) VALUES ('second row, via trigger');" >/dev/null 2>&1
  local qn; qn=$("${owner_psql[@]}" -c "
     SELECT count(*) FROM fractal_vectorizer_queue q
     JOIN fractal_vectorizers v ON v.id = q.vectorizer_id
     WHERE v.source_table = 'bt_embed_owned' AND q.status = 'pending';" 2>&1)
  [[ "$qn" = "2" ]] \
    && pass "16 embed_authz: backfill + trigger-driven enqueue both succeeded for the owner (2 pending)" \
    || fail "16 embed_authz: expected 2 pending rows (1 backfilled + 1 via trigger), got: $qn"

  local rout; rout=$("${outsider_psql[@]}" -c "SELECT fractal_vectorizer_process_queue();" 2>&1)
  local statuses; statuses=$("${owner_psql[@]}" -c "
     SELECT string_agg(DISTINCT q.status, ',') FROM fractal_vectorizer_queue q
     JOIN fractal_vectorizers v ON v.id = q.vectorizer_id
     WHERE v.source_table = 'bt_embed_owned';" 2>&1)
  [[ "$statuses" = "failed" ]] \
    && pass "16 embed_authz: outsider's process_queue() call left both rows 'failed', not processed" \
    || fail "16 embed_authz: expected both rows 'failed' after the outsider's call, got statuses: $statuses"

  local errtext; errtext=$("${owner_psql[@]}" -c "
     SELECT last_error FROM fractal_vectorizer_status WHERE vectorizer_id = $vzid AND status = 'failed';" 2>&1)
  grep <<< "$errtext" -q "permission denied for table bt_embed_owned" \
    && pass "16 embed_authz: failure reason correctly names a permission error, not a data value" \
    || fail "16 embed_authz: expected a permission-denied error, got: $errtext"

  local leaked; leaked=$("${owner_psql[@]}" -c "SELECT embedding FROM bt_embed_owned WHERE embedding IS NOT NULL;" 2>&1)
  [[ -z "$leaked" ]] \
    && pass "16 embed_authz: no embedding was written by the unauthorized outsider's call" \
    || fail "16 embed_authz: an embedding was written despite the outsider lacking SELECT: $leaked"

  "${PSQL[@]}" -c "
     DELETE FROM fractal_vectorizers WHERE source_table = 'bt_embed_owned';
     DROP TABLE IF EXISTS bt_embed_owned;
     DROP ROLE IF EXISTS bt_embed_owner;
     DROP ROLE IF EXISTS bt_embed_outsider;
  " >/dev/null 2>&1
}

# Concurrent fractal_vectorizer_process_queue() calls against a SHARED
# queue, proving (not assuming) the "safe to call concurrently" claim
# both the code comment and docs/vectorizer-setup.md make for its
# SELECT ... FOR UPDATE SKIP LOCKED usage: every row processed exactly
# once, no row double-embedded, no row left behind, no worker error --
# mirrors gate 12's soak pattern (background subshells, one process per
# worker, no threading -- not hunting data races in fractalsql.c's
# statics, which are already per-process; this is checking Postgres's
# own row-locking behavior under real overlapping callers).
EMBED_SOAK_ROWS=100
EMBED_SOAK_WORKERS=10
EMBED_SOAK_BATCH=5

gate_17_embed_soak() {
  pg_set_guc fractalsql.http_embed_url "'http://unused/embeddings'" "http://unused/embeddings" \
    || { fail "17 embed_soak: http_embed_url GUC did not take effect"; return; }
  pg_swap_plugin "$EMBED" || { fail "17 embed_soak: plugin swap did not take effect"; return; }

  "${PSQL[@]}" -c "
     DELETE FROM fractal_vectorizers WHERE source_table = 'bt_embed_soak';
     DROP TABLE IF EXISTS bt_embed_soak;
     CREATE TABLE bt_embed_soak (id serial PRIMARY KEY, body text NOT NULL, embedding float8[]);
     INSERT INTO bt_embed_soak (body)
       SELECT 'row ' || i FROM generate_series(1, $EMBED_SOAK_ROWS) i;
  " >/dev/null 2>&1
  local vzid; vzid=$("${PSQL[@]}" -c "SELECT fractal_vectorizer_create('bt_embed_soak', 'body', 'embedding');" 2>&1)
  local queued; queued=$("${PSQL[@]}" -c "
     SELECT count(*) FROM fractal_vectorizer_queue WHERE vectorizer_id = $vzid AND status = 'pending';" 2>&1)
  if [[ "$queued" != "$EMBED_SOAK_ROWS" ]]; then
    fail "17 embed_soak: setup: expected $EMBED_SOAK_ROWS queued rows, got $queued"
    pg_swap_plugin "$MOCK"; return
  fi

  local outdir="/tmp/fractalsql_bt_embed_soak_$$"
  rm -rf "$outdir"; mkdir -p "$outdir"
  local pids=() w
  for w in $(seq 1 "$EMBED_SOAK_WORKERS"); do
    (
      local rc=0 total=0 i
      # Enough iterations per worker that, summed across all workers,
      # the queue is fully drained even in the worst-case scheduling
      # (workers finishing early once their share is exhausted just do
      # cheap zero-row calls for their remaining iterations).
      for i in $(seq 1 $(( EMBED_SOAK_ROWS / EMBED_SOAK_BATCH + 2 ))); do
        local n; n=$("${PSQL[@]}" -c "SELECT fractal_vectorizer_process_queue($EMBED_SOAK_BATCH);" 2>&1)
        case "$n" in
          ''|*[!0-9]*) rc=1 ;;
          *) total=$(( total + n )) ;;
        esac
      done
      echo "$rc $total" > "$outdir/worker_$w.rc"
    ) &
    pids+=("$!")
  done
  local p
  for p in "${pids[@]}"; do wait "$p"; done

  local failed_workers=0 sum_processed=0
  for w in $(seq 1 "$EMBED_SOAK_WORKERS"); do
    local line; line=$(cat "$outdir/worker_$w.rc" 2>/dev/null)
    local wrc wtotal; read -r wrc wtotal <<< "$line"
    [[ "$wrc" = "0" ]] || failed_workers=$((failed_workers + 1))
    sum_processed=$(( sum_processed + ${wtotal:-0} ))
  done
  rm -rf "$outdir"

  [[ "$failed_workers" -eq 0 ]] \
    && pass "17 embed_soak: $EMBED_SOAK_WORKERS concurrent workers, no call errored" \
    || fail "17 embed_soak: $failed_workers/$EMBED_SOAK_WORKERS workers had a failed call"

  [[ "$sum_processed" -eq "$EMBED_SOAK_ROWS" ]] \
    && pass "17 embed_soak: exactly $EMBED_SOAK_ROWS rows processed total (no double-count, none lost)" \
    || fail "17 embed_soak: expected $EMBED_SOAK_ROWS rows processed summed across workers, got $sum_processed"

  local done_n; done_n=$("${PSQL[@]}" -c "
     SELECT count(*) FROM fractal_vectorizer_queue WHERE vectorizer_id = $vzid AND status = 'done';" 2>&1)
  [[ "$done_n" = "$EMBED_SOAK_ROWS" ]] \
    && pass "17 embed_soak: all $EMBED_SOAK_ROWS queue rows are 'done', none stuck pending/processing" \
    || fail "17 embed_soak: expected $EMBED_SOAK_ROWS rows 'done', got $done_n"

  local embedded_n; embedded_n=$("${PSQL[@]}" -c "
     SELECT count(*) FROM bt_embed_soak WHERE embedding = '{0.1,0.2,0.3}';" 2>&1)
  [[ "$embedded_n" = "$EMBED_SOAK_ROWS" ]] \
    && pass "17 embed_soak: all $EMBED_SOAK_ROWS rows got the embedding written back exactly once" \
    || fail "17 embed_soak: expected $EMBED_SOAK_ROWS rows with the embedding, got $embedded_n"

  "${PSQL[@]}" -c "
     DELETE FROM fractal_vectorizers WHERE source_table = 'bt_embed_soak';
     DROP TABLE IF EXISTS bt_embed_soak;
  " >/dev/null 2>&1
  pg_swap_plugin "$MOCK"
}

# Real crash mid-process_queue(), via the same deliberately-segfaulting
# plugin gate 06 already uses. Proves what ACTUALLY happens, not what
# stale_after's own doc comment might suggest in isolation: fractal_
# vectorizer_process_queue() is one PL/pgSQL FUNCTION call, i.e. one
# transaction (EXCEPTION blocks are subtransaction SAVEPOINTs, not
# independent commits) -- a crash mid-call means NOTHING from that call
# was ever committed, so the row(s) it touched revert to whatever they
# were before the call (here, 'pending'), not left stuck in
# 'processing'. stale_after's reclaim exists for a DIFFERENT failure
# shape (a caller that durably committed 'processing' some other way,
# e.g. a future per-row-autonomous-transaction redesign) -- this gate
# exists so that distinction is verified, not assumed from reading the
# code. See docs/vectorizer-setup.md's "Design" section for the
# same point stated for operators.
gate_18_embed_crash() {
  pg_set_guc fractalsql.http_embed_url "'http://unused/embeddings'" "http://unused/embeddings" \
    || { fail "18 embed_crash: http_embed_url GUC did not take effect"; return; }

  "${PSQL[@]}" -c "
     DELETE FROM fractal_vectorizers WHERE source_table = 'bt_embed_crash';
     DROP TABLE IF EXISTS bt_embed_crash;
     CREATE TABLE bt_embed_crash (id serial PRIMARY KEY, body text NOT NULL, embedding float8[]);
     INSERT INTO bt_embed_crash (body) VALUES ('a'), ('b'), ('c');
  " >/dev/null 2>&1
  local vzid; vzid=$("${PSQL[@]}" -c "SELECT fractal_vectorizer_create('bt_embed_crash', 'body', 'embedding');" 2>&1)

  pg_swap_plugin "$CRASH" || { fail "18 embed_crash: plugin swap did not take effect"; return; }
  local r; r=$("${PSQL[@]}" -c "SELECT fractal_vectorizer_process_queue();" 2>&1)
  grep <<< "$r" -qE "server closed the connection|could not connect" \
    && pass "18 embed_crash: triggering connection dropped as expected" \
    || fail "18 embed_crash: expected the connection to drop, got: $r"

  # See gate_06_crash_recovery's comment on why pass/fail budget and
  # actual up-detection must not share the same cutoff -- restoring the
  # plugin at the end of this gate depends on `up`, and a near-miss here
  # previously left the crash plugin active for the rest of the run.
  local up=0 i tries=$(( 30 * TIMEOUT_MULT )) within_budget=0
  for i in $(seq 1 $(( tries * 2 ))); do
    "${PSQL[@]}" -c "SELECT 1;" >/dev/null 2>&1 && { up=1; [[ "$i" -le "$tries" ]] && within_budget=1; break; }
    sleep 0.5
  done
  [[ "$within_budget" -eq 1 ]] && pass "18 embed_crash: cluster auto-restarted" \
                   || fail "18 embed_crash: cluster did not come back within $(( tries / 2 ))s"
  if [[ "$up" -ne 1 ]]; then
    fail "18 embed_crash: cluster never came back -- remaining gates will run against the crash plugin"
    return
  fi

  # The real, empirically-checked claim this gate exists for: the crash
  # rolled back the WHOLE in-flight call, so all 3 rows are back to
  # 'pending' -- not stuck in 'processing' waiting on stale_after.
  local statuses; statuses=$("${PSQL[@]}" -c "
     SELECT string_agg(DISTINCT status, ',') FROM fractal_vectorizer_queue
     WHERE vectorizer_id = $vzid;" 2>&1)
  [[ "$statuses" = "pending" ]] \
    && pass "18 embed_crash: all 3 rows reverted to 'pending' after the crash (atomic rollback, not stuck 'processing')" \
    || fail "18 embed_crash: expected all rows 'pending' post-crash, got statuses: $statuses"

  # Recovery: a normal call afterward, with a working plugin, must
  # process the reverted rows normally -- no data lost, nothing
  # permanently wedged by the earlier crash.
  pg_swap_plugin "$EMBED" || { fail "18 embed_crash: plugin swap to EMBED did not take effect"; pg_swap_plugin "$MOCK"; return; }
  local n; n=$("${PSQL[@]}" -c "SELECT fractal_vectorizer_process_queue();" 2>&1)
  [[ "$n" = "3" ]] && pass "18 embed_crash: post-recovery call processed all 3 previously-crashed rows" \
                  || fail "18 embed_crash: expected 3 rows processed after recovery, got: $n"

  local done_n; done_n=$("${PSQL[@]}" -c "
     SELECT count(*) FROM bt_embed_crash WHERE embedding = '{0.1,0.2,0.3}';" 2>&1)
  [[ "$done_n" = "3" ]] && pass "18 embed_crash: all 3 rows correctly embedded after recovery" \
                       || fail "18 embed_crash: expected 3 embedded rows after recovery, got: $done_n"

  "${PSQL[@]}" -c "
     DELETE FROM fractal_vectorizers WHERE source_table = 'bt_embed_crash';
     DROP TABLE IF EXISTS bt_embed_crash;
  " >/dev/null 2>&1
  pg_swap_plugin "$MOCK"
}

# validate_sfs_params() bounds (fractal_search/fractal_search_debug/
# fractal_search_explore all funnel through the same function) were
# NEVER exercised anywhere in this gate suite before this test --
# gate 10 proves the equivalent DoS cap for fractal_schema_context
# (MAX_SCHEMA_CONTEXT_TABLES) but nothing did the same for SFS's own
# iterations/population_size/diffusion_factor/dim ceilings. Also closes
# the injection-shaped-identifier gap for fractal_search_explore
# specifically (gate 10 only ever covered fractal_schema_context for
# that class of test).
#
# MAX_QUERY_DIM (1M) turns out to be effectively dead code in practice:
# the core library's own FSQL_MAX_DIM ceiling is 16384, far below 1M, so
# it always rejects first for any realistic-but-large dim. This gate
# tests the REAL, reachable ceiling (16385) and notes the finding here
# rather than constructing a >1M-element array to reach validate_sfs_
# params' own (currently unreachable) check.
gate_19_sfs_bounds() {
  local r

  r=$("${PSQL[@]}" -c "SELECT fractal_search(ARRAY(SELECT 0.1 FROM generate_series(1,16385)));" 2>&1)
  grep <<< "$r" -qE "exceeds FSQL_MAX_DIM|out of range" \
    && pass "19 sfs_bounds: over-limit query dim (16385) rejected cleanly" \
    || fail "19 sfs_bounds: expected a clean dim-limit rejection, got: $r"

  r=$("${PSQL[@]}" -c "SELECT fractal_search(ARRAY[]::float8[]);" 2>&1)
  grep <<< "$r" -qE "1-D non-null|must be non-empty" \
    && pass "19 sfs_bounds: empty query array rejected cleanly" \
    || fail "19 sfs_bounds: expected a clean empty-array rejection, got: $r"

  r=$("${PSQL[@]}" -c "SELECT fractal_search(ARRAY[0.1,0.2]::float8[], 10001);" 2>&1)
  grep <<< "$r" -q "iterations 10001 out of range" \
    && pass "19 sfs_bounds: iterations over MAX_ITERATIONS (10000) rejected cleanly" \
    || fail "19 sfs_bounds: expected an iterations-limit rejection, got: $r"

  r=$("${PSQL[@]}" -c "SELECT fractal_search(ARRAY[0.1,0.2]::float8[], 10, 100001);" 2>&1)
  grep <<< "$r" -q "population_size 100001 out of range" \
    && pass "19 sfs_bounds: population_size over MAX_POPULATION_SIZE (100000) rejected cleanly" \
    || fail "19 sfs_bounds: expected a population_size-limit rejection, got: $r"

  r=$("${PSQL[@]}" -c "SELECT fractal_search(ARRAY[0.1,0.2]::float8[], 10, 20, 33);" 2>&1)
  grep <<< "$r" -q "diffusion_factor 33 out of range" \
    && pass "19 sfs_bounds: diffusion_factor over MAX_DIFFUSION_FACTOR (32) rejected cleanly" \
    || fail "19 sfs_bounds: expected a diffusion_factor-limit rejection, got: $r"

  # fractal_search_debug shares validate_sfs_params -- one spot check
  # (not the full sweep above) confirms the shared function is actually
  # being called from this entry point too, not just fractal_search.
  r=$("${PSQL[@]}" -c "SELECT fractal_search_debug(ARRAY[0.1,0.2]::float8[], 10, 20, 33);" 2>&1)
  grep <<< "$r" -q "diffusion_factor 33 out of range" \
    && pass "19 sfs_bounds: fractal_search_debug shares the same bounds check" \
    || fail "19 sfs_bounds: expected fractal_search_debug to reject diffusion_factor=33, got: $r"

  # Injection-shaped table_name into fractal_search_explore -- same
  # class of test gate 10 already gives fractal_schema_context, closing
  # the gap for search_explore specifically.
  local rinj; rinj=$("${PSQL[@]}" -c "SELECT * FROM fractal_search_explore('bt_orders''; DROP TABLE bt_orders; --', 'vec', ARRAY[0.1,0.2]::float8[]);" 2>&1)
  local n; n=$("${PSQL[@]}" -c "SELECT count(*) FROM bt_orders;" 2>&1)
  if [[ "$n" = "0" ]]; then
    pass "19 sfs_bounds: injection-shaped table_name into fractal_search_explore did not execute (bt_orders intact)"
  else
    fail "19 sfs_bounds: bt_orders row count changed (n=$n) — injection may have executed"
  fi
  grep <<< "$rinj" -qE "does not exist|ERROR" \
    && pass "19 sfs_bounds: injection-shaped table_name cleanly rejected" \
    || fail "19 sfs_bounds: unexpected result: $rinj"
}

# Closes 5 concrete API-surface coverage gaps found by a gap analysis
# against README's API table (each an explicit, existing code path --
# not speculative):
#   1. fractal_reason(): happy-path correctness was never checked --
#      every other gate touching it only asserts "didn't crash" /
#      "cleanly rejected a bad plugin", never "returned the right text".
#   2. fractal_reason(NULL): its own explicit PG_ARGISNULL(0) check
#      (fractal_reason isn't STRICT, unlike the search functions) had
#      zero coverage.
#   3. fractal_text_to_sql(NULL): same pattern, its own explicit
#      PG_ARGISNULL(0) check, zero coverage.
#   4. fractal_search_explore()'s bounds: it calls the same
#      validate_sfs_params() as fractal_search/_debug (confirmed by
#      reading the code), but nothing had ever proved that by actually
#      passing an over-limit value through its options jsonb -- exactly
#      the kind of "shares code, must be fine" assumption that hid the
#      build_schema_context_cstr() heap-use-after-free found this
#      session via ASan, not code review.
#   5. fractal_vectorizer_process_queue()'s stale_after reclaim: gate 18
#      already proved a crash can't produce a stuck 'processing' row in
#      the CURRENT implementation, but the reclaim UPDATE itself (the
#      WHERE processing_started_at < now() - stale_after clause) was
#      never independently exercised -- staged directly here, with a
#      negative control (a row still within the window) proving the
#      time comparison actually gates rather than reclaiming
#      unconditionally.
gate_20_api_func() {
  # --- 1: fractal_reason() happy path -------------------------------
  echo "gap-analysis-canary" > /tmp/fractalsql_bt_sql.txt
  local r1; r1=$("${PSQL[@]}" -c "SELECT fractal_reason('q');" 2>&1)
  local expect1; expect1=$(printf '```sql\ngap-analysis-canary\n```')
  [[ "$r1" = "$expect1" ]] \
    && pass "20 api_func: fractal_reason() returns the plugin's actual response" \
    || fail "20 api_func: fractal_reason() expected the fenced canary text, got: $r1"
  rm -f /tmp/fractalsql_bt_sql.txt

  # --- 2: fractal_reason(NULL) ---------------------------------------
  local r2; r2=$("${PSQL[@]}" -c "SELECT fractal_reason(NULL);" 2>&1)
  grep <<< "$r2" -q "query must not be NULL" \
    && pass "20 api_func: fractal_reason(NULL) rejected cleanly" \
    || fail "20 api_func: fractal_reason(NULL) expected a clear rejection, got: $r2"

  # --- 3: fractal_text_to_sql(NULL) -----------------------------------
  local r3; r3=$("${PSQL[@]}" -c "SELECT fractal_text_to_sql(NULL);" 2>&1)
  grep <<< "$r3" -q "question must not be NULL" \
    && pass "20 api_func: fractal_text_to_sql(NULL) rejected cleanly" \
    || fail "20 api_func: fractal_text_to_sql(NULL) expected a clear rejection, got: $r3"

  # --- 4: fractal_search_explore()'s own bounds -----------------------
  "${PSQL[@]}" -c "
     DROP TABLE IF EXISTS bt_explore_bounds;
     CREATE TABLE bt_explore_bounds (id int, emb float8[]);
     INSERT INTO bt_explore_bounds VALUES (1, ARRAY[0.1,0.2]::float8[]);
  " >/dev/null 2>&1
  local r4; r4=$("${PSQL[@]}" -c "
     SELECT * FROM fractal_search_explore('bt_explore_bounds', 'emb',
       ARRAY[0.1,0.2]::float8[], '{\"iterations\": 10001}'::jsonb);" 2>&1)
  grep <<< "$r4" -q "iterations 10001 out of range" \
    && pass "20 api_func: fractal_search_explore rejects an over-limit iterations option" \
    || fail "20 api_func: expected an iterations-limit rejection, got: $r4"

  local r4b; r4b=$("${PSQL[@]}" -c "
     SELECT * FROM fractal_search_explore('bt_explore_bounds', 'emb',
       ARRAY[0.1,0.2]::float8[], '{\"diffusion_factor\": 33}'::jsonb);" 2>&1)
  grep <<< "$r4b" -q "diffusion_factor 33 out of range" \
    && pass "20 api_func: fractal_search_explore rejects an over-limit diffusion_factor option" \
    || fail "20 api_func: expected a diffusion_factor-limit rejection, got: $r4b"
  "${PSQL[@]}" -c "DROP TABLE IF EXISTS bt_explore_bounds;" >/dev/null 2>&1

  # --- 5: fractal_vectorizer_process_queue()'s stale_after reclaim ----
  pg_set_guc fractalsql.http_embed_url "'http://unused/embeddings'" "http://unused/embeddings" \
    || { fail "20 api_func: http_embed_url GUC did not take effect"; return; }
  pg_swap_plugin "$EMBED" || { fail "20 api_func: plugin swap did not take effect"; pg_swap_plugin "$MOCK"; return; }

  "${PSQL[@]}" -c "
     DELETE FROM fractal_vectorizers WHERE source_table = 'bt_stale_reclaim';
     DROP TABLE IF EXISTS bt_stale_reclaim;
     CREATE TABLE bt_stale_reclaim (id serial PRIMARY KEY, body text NOT NULL, embedding float8[]);
     INSERT INTO bt_stale_reclaim (body) VALUES ('old-stuck'), ('recent-stuck');
  " >/dev/null 2>&1
  local vzid; vzid=$("${PSQL[@]}" -c "SELECT fractal_vectorizer_create('bt_stale_reclaim', 'body', 'embedding');" 2>&1)

  # old-stuck: claimed 1 hour ago, past the 5-minute stale_after below
  # -- must be reclaimed. recent-stuck: claimed 30 seconds ago, still
  # within it -- must be left alone (the negative control).
  "${PSQL[@]}" -c "
     UPDATE fractal_vectorizer_queue q
        SET status = 'processing', processing_started_at = now() - interval '1 hour'
       FROM bt_stale_reclaim t
      WHERE q.vectorizer_id = $vzid AND t.body = 'old-stuck' AND q.source_pk_value = t.id::text;
     UPDATE fractal_vectorizer_queue q
        SET status = 'processing', processing_started_at = now() - interval '30 seconds'
       FROM bt_stale_reclaim t
      WHERE q.vectorizer_id = $vzid AND t.body = 'recent-stuck' AND q.source_pk_value = t.id::text;
  " >/dev/null 2>&1

  "${PSQL[@]}" -c "SELECT fractal_vectorizer_process_queue(10, '5 minutes'::interval);" >/dev/null 2>&1

  local statuses; statuses=$("${PSQL[@]}" -c "
     SELECT t.body || '=' || q.status FROM fractal_vectorizer_queue q
     JOIN bt_stale_reclaim t ON t.id::text = q.source_pk_value
     WHERE q.vectorizer_id = $vzid ORDER BY t.body;" 2>&1)
  grep <<< "$statuses" -q "old-stuck=done" \
    && pass "20 api_func: a row stranded past stale_after was reclaimed and processed" \
    || fail "20 api_func: expected old-stuck=done, got: $statuses"
  grep <<< "$statuses" -q "recent-stuck=processing" \
    && pass "20 api_func: a row still within stale_after was left alone, not reclaimed" \
    || fail "20 api_func: expected recent-stuck=processing (untouched), got: $statuses"

  "${PSQL[@]}" -c "
     DELETE FROM fractal_vectorizers WHERE source_table = 'bt_stale_reclaim';
     DROP TABLE IF EXISTS bt_stale_reclaim;
  " >/dev/null 2>&1
  pg_swap_plugin "$MOCK" >/dev/null
}

# v2.x additions smoke gate -- HNSW/Diversify-era functions (dimension
# analysis, portfolio optimization, domain geometry, the named feature
# store, Diversify/feedback controls). Deliberately a smoke gate, not
# exhaustive unit coverage -- proves the SQL wiring end-to-end against
# the real .so, same scope/spirit as gate_02_smoke and gate_11_scout.
#
# Fixture note: fractal_dimension_boxcount / _vascular_network /
# _nerve_plexus_metric / _morphological_complexity all bottom out in
# box-counting, which needs enough points AND enough dynamic range of
# scales to produce >= 3 valid epsilon buckets -- too few points (or an
# exactly-regular lattice) silently fails that filter even for
# well-defined geometry. Point counts here (40/30/80) and the jitter on
# the nerve fixture are chosen to satisfy that filter.
gate_22_v2_functions() {
  # --- fixtures (generated once, deterministic seeds) -----------------
  local boxpts; boxpts=$(awk 'BEGIN{srand(42); out=""; for(i=1;i<=40;i++){x=i+rand()*0.01; y=i*0.5+rand()*0.01; if(i>1) out=out","; out=out x","y} print out}')
  # mapfile is bash 4.0+ only -- macOS (and macOS GitHub Actions runners)
  # ship bash 3.2.57 as /bin/bash and never upgrade it (frozen there over
  # the GPLv3 relicense), so build a plain array with a read loop instead
  # -- confirmed on a real 3.2.57 that mapfile is "command not found"
  # there, while this pattern works unchanged.
  local vasc=()
  while IFS= read -r vasc_line; do vasc+=("$vasc_line"); done < <(awk 'BEGIN{
    srand(1); n=30; nc=""; el=""; al="";
    for (i=0;i<n;i++) { x=i; y=rand()*0.01; z=rand()*0.01; xs[i]=x; ys[i]=y; zs[i]=z; if (i>0) nc=nc","; nc=nc x","y","z; }
    for (i=0;i<n-1;i++) { if (i>0) { el=el","; al=al","; } el=el i","(i+1); dx=xs[i+1]-xs[i]; dy=ys[i+1]-ys[i]; dz=zs[i+1]-zs[i]; d=sqrt(dx*dx+dy*dy+dz*dz); al=al d; }
    print nc; print el; print al;
  }')
  local vasc_nc="${vasc[0]}" vasc_el="${vasc[1]}" vasc_al="${vasc[2]}"
  local nerve=()
  while IFS= read -r nerve_line; do nerve+=("$nerve_line"); done < <(awk 'BEGIN{
    srand(2); n=80; nc=""; el="";
    for (i=0;i<n;i++) { x=i; y=(i%2==0?0:1)+rand()*0.01; if (i>0) nc=nc","; nc=nc x","y; }
    for (i=0;i<n-1;i++) { if (i>0) el=el","; el=el i","(i+1); }
    print nc; print el;
  }')
  local nerve_nc="${nerve[0]}" nerve_el="${nerve[1]}"

  # --- 1: dimension analysis -------------------------------------------
  local r1; r1=$("${PSQL[@]}" -c "
     SELECT fractal_dimension_dfa(
       (SELECT array_agg(sin(i / 3.0) + i * 0.001) FROM generate_series(1, 64) i));" 2>&1)
  grep <<< "$r1" -Eq '^[0-9]+\.[0-9]+$' \
    && pass "22 v2_functions: fractal_dimension_dfa returns a numeric exponent" \
    || fail "22 v2_functions: fractal_dimension_dfa expected a float8, got: $r1"

  local r1b; r1b=$("${PSQL[@]}" -c "SELECT fractal_dimension_dfa(ARRAY[1,2,3]::float8[]);" 2>&1)
  grep <<< "$r1b" -q "series needs >= 16 points" \
    && pass "22 v2_functions: fractal_dimension_dfa rejects a too-short series" \
    || fail "22 v2_functions: expected a too-short-series rejection, got: $r1b"

  local r2; r2=$("${PSQL[@]}" -c "SELECT fractal_dimension_boxcount(ARRAY[$boxpts]::float8[], 2);" 2>&1)
  grep <<< "$r2" -Eq '^[0-9]+\.[0-9]+$' \
    && pass "22 v2_functions: fractal_dimension_boxcount returns a numeric dimension" \
    || fail "22 v2_functions: fractal_dimension_boxcount expected a float8, got: $r2"

  local r3; r3=$("${PSQL[@]}" -c "
     SELECT fractal_dimension_drift(
       (SELECT array_agg(sin(i / 3.0) + i * 0.001) FROM generate_series(1, 200) i), 64);" 2>&1)
  grep <<< "$r3" -q '"drift"' \
    && pass "22 v2_functions: fractal_dimension_drift returns {drift, recent_alpha, baseline_alpha}" \
    || fail "22 v2_functions: fractal_dimension_drift expected a drift jsonb, got: $r3"

  # --- 2: portfolio optimization ---------------------------------------
  local r4; r4=$("${PSQL[@]}" -c "
     SELECT fractal_optimize_portfolio(
       ARRAY[0.08,0.12,0.10,0.15]::float8[],
       ARRAY[0.04,0.01,0.01,0.01, 0.01,0.06,0.01,0.01, 0.01,0.01,0.05,0.01, 0.01,0.01,0.01,0.09]::float8[],
       2, 12345);" 2>&1)
  grep <<< "$r4" -q '"sharpe"' \
    && pass "22 v2_functions: fractal_optimize_portfolio returns {sharpe, weights}" \
    || fail "22 v2_functions: fractal_optimize_portfolio expected a sharpe/weights jsonb, got: $r4"

  local r4b; r4b=$("${PSQL[@]}" -c "
     SELECT fractal_optimize_portfolio(ARRAY[0.1,0.1]::float8[], ARRAY[1.0]::float8[], 1, NULL);" 2>&1)
  grep <<< "$r4b" -q "cov length" \
    && pass "22 v2_functions: fractal_optimize_portfolio rejects a mismatched cov length" \
    || fail "22 v2_functions: expected a cov-length rejection, got: $r4b"

  # --- 3: domain-specific geometry --------------------------------------
  local r5; r5=$("${PSQL[@]}" -c "SELECT fractal_morphological_complexity(ARRAY[$boxpts]::float8[], 2);" 2>&1)
  grep <<< "$r5" -q '"lacunarity"' \
    && pass "22 v2_functions: fractal_morphological_complexity returns {dimension, lacunarity}" \
    || fail "22 v2_functions: fractal_morphological_complexity expected a dimension/lacunarity jsonb, got: $r5"

  local r6; r6=$("${PSQL[@]}" -c "
     SELECT fractal_vascular_network(ARRAY[$vasc_nc]::float8[], ARRAY[$vasc_el]::int4[], ARRAY[$vasc_al]::float8[]);" 2>&1)
  grep <<< "$r6" -q '"mean_tortuosity"' \
    && pass "22 v2_functions: fractal_vascular_network returns {mean_tortuosity, branch_density, fractal_dimension}" \
    || fail "22 v2_functions: fractal_vascular_network expected a tortuosity jsonb, got: $r6"

  local r7; r7=$("${PSQL[@]}" -c "
     SELECT fractal_nerve_plexus_metric(ARRAY[$nerve_nc]::float8[], 2, ARRAY[$nerve_el]::int4[]);" 2>&1)
  grep <<< "$r7" -q '"fiber_length_density"' \
    && pass "22 v2_functions: fractal_nerve_plexus_metric returns {fiber_length_density, branch_density, fractal_dimension}" \
    || fail "22 v2_functions: fractal_nerve_plexus_metric expected a fiber-density jsonb, got: $r7"

  # Tetrahedron: mesh IS its own convex hull, so gyrification_index must
  # be exactly 1.0 -- a clean deterministic check, not just "didn't error".
  local r8; r8=$("${PSQL[@]}" -c "
     SELECT fractal_cortical_folding(
       ARRAY[0,0,0, 1,0,0, 0,1,0, 0,0,1]::float8[],
       ARRAY[0,1,2, 0,1,3, 0,2,3, 1,2,3]::int4[]);" 2>&1)
  grep <<< "$r8" -q '"gyrification_index": 1.0000000000' \
    && pass "22 v2_functions: fractal_cortical_folding gives gyrification_index=1.0 for a tetrahedron (mesh == its own hull)" \
    || fail "22 v2_functions: expected gyrification_index=1.0 for a tetrahedron, got: $r8"

  # --- 4: named feature store (postgres-side, no core primitive) -------
  "${PSQL[@]}" -c "
     DELETE FROM fractalsql_feature_store WHERE doc_id IN (901,902,903,904);
     SELECT fractal_store_morphology(901, ARRAY[0.0,0.0,0.0]::float8[]);
     SELECT fractal_store_morphology(902, ARRAY[10.0,10.0,10.0]::float8[]);
     SELECT fractal_store_morphology(903, ARRAY[1.0,0.0,0.0]::float8[]);
     SELECT fractal_store_morphology(904, ARRAY[0.5,0.5,0.5]::float8[]);
  " >/dev/null 2>&1
  # upsert-overwrite: doc 901 moves far away, must drop out of a k=2 mine
  "${PSQL[@]}" -c "SELECT fractal_store_morphology(901, ARRAY[100.0,100.0,100.0]::float8[]);" >/dev/null 2>&1
  local r9; r9=$("${PSQL[@]}" -c "
     SELECT string_agg(doc_id::text, ',' ORDER BY distance)
     FROM fractal_mine_topology_negatives(ARRAY[0.0,0.0,0.0]::float8[], 2)
     WHERE doc_id IN (901,902,903,904);" 2>&1)
  [[ "$r9" = "904,903" ]] \
    && pass "22 v2_functions: fractal_mine_topology_negatives k-NN order + upsert-overwrite correct" \
    || fail "22 v2_functions: expected mine order 904,903 (901 overwritten far away), got: $r9"

  local r9b; r9b=$("${PSQL[@]}" -c "SELECT fractal_store_morphology(-1, ARRAY[1.0]::float8[]);" 2>&1)
  grep <<< "$r9b" -q "doc_id must be >= 0" \
    && pass "22 v2_functions: fractal_store_morphology rejects a negative doc_id" \
    || fail "22 v2_functions: expected a negative-doc_id rejection, got: $r9b"

  local r9c; r9c=$("${PSQL[@]}" -c "SELECT fractal_mine_topology_negatives(ARRAY[0.0]::float8[], 0);" 2>&1)
  grep <<< "$r9c" -q "k must be > 0" \
    && pass "22 v2_functions: fractal_mine_topology_negatives rejects k<=0" \
    || fail "22 v2_functions: expected a k<=0 rejection, got: $r9c"

  "${PSQL[@]}" -c "DELETE FROM fractalsql_feature_store WHERE doc_id IN (901,902,903,904);" >/dev/null 2>&1

  # --- 5: Diversify / feedback controls ---------------------------------
  "${PSQL[@]}" -c "SELECT fractal_diversify_enable();" >/dev/null 2>&1
  "${PSQL[@]}" -c "SELECT fractal_diversify_set_params(20, 0.1, 1.0, 0.5, 100, 50);" >/dev/null 2>&1
  local r10; r10=$("${PSQL[@]}" -c "SELECT fractal_explain_result();" 2>&1)
  grep <<< "$r10" -q '"diversify_enabled": true' \
    && pass "22 v2_functions: fractal_explain_result reflects diversify_enabled after enable" \
    || fail "22 v2_functions: expected diversify_enabled=true, got: $r10"

  "${PSQL[@]}" -c "SELECT fractal_feedback_report(0, 'negative', 100);" >/tmp/fractalsql_bt_v2_fb.log 2>&1
  grep -q "ERROR" /tmp/fractalsql_bt_v2_fb.log \
    && fail "22 v2_functions: fractal_feedback_report errored on a valid call: $(cat /tmp/fractalsql_bt_v2_fb.log)" \
    || pass "22 v2_functions: fractal_feedback_report accepted a valid negative-engagement report"

  local r11; r11=$("${PSQL[@]}" -c "SELECT fractal_feedback_report(0, 'bogus', NULL);" 2>&1)
  grep <<< "$r11" -q "kind must be one of" \
    && pass "22 v2_functions: fractal_feedback_report rejects an invalid kind" \
    || fail "22 v2_functions: expected an invalid-kind rejection, got: $r11"

  "${PSQL[@]}" -c "SELECT fractal_diversify_disable();" >/dev/null 2>&1
  rm -f /tmp/fractalsql_bt_v2_fb.log

  # --- 6: table-backed top-k telemetry search + thin compositions -----
  "${PSQL[@]}" -c "
     DROP TABLE IF EXISTS bt_telemetry_docs;
     CREATE TABLE bt_telemetry_docs (id serial PRIMARY KEY, emb float8[]);
     INSERT INTO bt_telemetry_docs (emb) VALUES
       (ARRAY[1.0,0.0,0.0]::float8[]),
       (ARRAY[0.0,1.0,0.0]::float8[]),
       (ARRAY[0.9,0.1,0.0]::float8[]),
       (ARRAY[0.0,0.0,1.0]::float8[]),
       (ARRAY[0.5,0.5,0.0]::float8[]);
  " >/dev/null 2>&1

  local r12; r12=$("${PSQL[@]}" -c "
     SELECT doc_id, distance FROM fractal_search_telemetry(
       'bt_telemetry_docs', 'emb', ARRAY[1.0,0.0,0.0]::float8[], 2);" 2>&1)
  grep <<< "$r12" -q "^0|0$" \
    && pass "22 v2_functions: fractal_search_telemetry finds the exact match at distance 0" \
    || fail "22 v2_functions: expected doc_id=0 dist=0 first, got: $r12"

  local r13; r13=$("${PSQL[@]}" -c "
     SELECT doc_id FROM fractal_hybrid_clinical_search(
       'bt_telemetry_docs', 'emb', ARRAY[0.0,1.0,0.0]::float8[],
       ARRAY[1,3,4]::int8[], 3) ORDER BY distance;" 2>&1)
  [[ "$r13" = "$(printf '1\n4\n3')" ]] \
    && pass "22 v2_functions: fractal_hybrid_clinical_search restricts to the cohort and returns real doc_ids" \
    || fail "22 v2_functions: expected doc_ids 1,4,3 in that order, got: $r13"

  local r14; r14=$("${PSQL[@]}" -c "
     SELECT fractal_hybrid_clinical_search(
       'bt_telemetry_docs', 'emb', ARRAY[0.0,1.0,0.0]::float8[],
       ARRAY[999]::int8[], 1);" 2>&1)
  grep <<< "$r14" -q "cohort matched no rows" \
    && pass "22 v2_functions: fractal_hybrid_clinical_search rejects a cohort matching zero rows" \
    || fail "22 v2_functions: expected a no-rows-matched rejection, got: $r14"

  local r15; r15=$("${PSQL[@]}" -c "
     SELECT doc_id, distance FROM fractal_search_trajectory(
       'bt_telemetry_docs', 'emb', ARRAY[0.0,0.0,0.0]::float8[],
       ARRAY[1.0,0.0,0.0]::float8[], 1);" 2>&1)
  grep <<< "$r15" -q "^0|0$" \
    && pass "22 v2_functions: fractal_search_trajectory searches near the delta vector" \
    || fail "22 v2_functions: expected doc_id=0 dist=0 for a [1,0,0] delta, got: $r15"

  "${PSQL[@]}" -c "
     DROP TABLE IF EXISTS bt_combined_docs;
     CREATE TABLE bt_combined_docs (id serial PRIMARY KEY, emb float8[]);
     INSERT INTO bt_combined_docs (emb) VALUES
       (ARRAY[1.0,0.0, 0.0,0.0]::float8[]),
       (ARRAY[0.0,0.0, 1.0,0.0]::float8[]);
  " >/dev/null 2>&1
  local r16; r16=$("${PSQL[@]}" -c "
     SELECT doc_id, distance FROM fractal_cross_modal_search(
       'bt_combined_docs', 'emb', ARRAY[1.0,0.0]::float8[],
       ARRAY[1.0,0.0]::float8[], 1.0, 1);" 2>&1)
  grep <<< "$r16" -q "^0|0$" \
    && pass "22 v2_functions: fractal_cross_modal_search at alpha=1.0 favors the morphology-only row" \
    || fail "22 v2_functions: expected doc_id=0 dist=0 at alpha=1.0, got: $r16"

  local r17; r17=$("${PSQL[@]}" -c "
     SELECT fractal_cross_modal_search(
       'bt_combined_docs', 'emb', ARRAY[1.0,0.0]::float8[],
       ARRAY[1.0,0.0]::float8[], 1.5, 1);" 2>&1)
  grep <<< "$r17" -q "alpha_weight must be in" \
    && pass "22 v2_functions: fractal_cross_modal_search rejects an out-of-range alpha_weight" \
    || fail "22 v2_functions: expected an alpha_weight rejection, got: $r17"

  "${PSQL[@]}" -c "DROP TABLE IF EXISTS bt_telemetry_docs, bt_combined_docs;" >/dev/null 2>&1
}

# fractalsql_agents dependent-extension smoke gate -- the two parameterized
# PL/pgSQL agent engines (fractal_agent_anomaly_triage, fractal_agent_allocate)
# shipped in fractalsql_agents/. Deliberately a smoke gate, same scope/spirit
# as gate 22: proves the engine compositions run end-to-end against the real .so
# + the real C primitives they wrap (fractal_dimension_drift, fractal_reason,
# fractal_optimize_portfolio). The engines' LLM step is fed by the gate-20 mock
# reasoning canary so it is deterministic without a live endpoint: the drift and
# optimizer steps are real C (deterministic); the reason step returns the
# canary. The engines themselves are loaded by pg_setup's agents-SQL slice (no
# MODULE_PATHNAME, pure PL/pgSQL). Mirrors build_test.ps1's Gate23Agents.
gate_23_agents() {
  # The engines call fractal_reason; the mock reasoning plugin (the resting
  # $MOCK state) returns /tmp/fractalsql_bt_sql.txt's content as the response.
  # Set the same canary gate 20 uses, so the engines' triage_summary / rationale
  # carry it. pg_swap_plugin "$MOCK" guarantees the mock is active even if gate
  # 23 is run standalone (without gate 20 before it).
  pg_swap_plugin "$MOCK" >/dev/null
  echo "gap-analysis-canary" > /tmp/fractalsql_bt_sql.txt

  # --- fixture: a drifting metric series for one host -----------------
  # Same step-up shape as demo/demo-vertical-agentic-ops-devops.sql: baseline ~50 for
  # the first 48 rows then a +30 step-up, 96 points, so fractal_dimension_drift's
  # 32-point recent window has a real regime change to detect (window=16 is too
  # small for DFA on the recent window -- see the demo's own note). A second
  # host makes the host filter meaningful.
  "${PSQL[@]}" -c "
     DROP TABLE IF EXISTS bt_agents_logs;
     CREATE TABLE bt_agents_logs (metric float8, ts timestamptz, host text);
     INSERT INTO bt_agents_logs (metric, ts, host)
     SELECT 50.0 + (gs % 8)::float8 * 1.3 + CASE WHEN gs > 48 THEN 30.0 ELSE 0.0 END,
            now() - (96 - gs) * interval '1 second', 'host-1'
       FROM generate_series(1,96) gs;
     INSERT INTO bt_agents_logs VALUES (10, now(), 'host-2'),
                                        (11, now() + interval '1 min', 'host-2');" >/dev/null 2>&1

  # --- 1: fractal_agent_anomaly_triage happy path ---------------------
  # threat_score is the REAL drift exponent (fractal_dimension_drift ran);
  # triage_summary is the REAL reason step (canary proves fractal_reason ran).
  local r1; r1=$("${PSQL[@]}" -c "
     SELECT threat_score FROM fractal_agent_anomaly_triage(
       'bt_agents_logs','metric','ts','host','host-1',32);" 2>&1)
  grep <<< "$r1" -Eq '^-?[0-9]+(\.[0-9]+)?$' \
    && pass "23 agents: anomaly_triage threat_score is a real computed drift float" \
    || fail "23 agents: expected a numeric threat_score, got: $r1"

  local r1b; r1b=$("${PSQL[@]}" -c "
     SELECT triage_summary FROM fractal_agent_anomaly_triage(
       'bt_agents_logs','metric','ts','host','host-1',32);" 2>&1)
  grep <<< "$r1b" -q 'gap-analysis-canary' \
    && pass "23 agents: anomaly_triage composes drift -> reason (reason step ran)" \
    || fail "23 agents: expected the reasoning canary in triage_summary, got: $r1b"

  # --- 2: anomaly_triage empty-series guard ---------------------------
  local r2; r2=$("${PSQL[@]}" -c "
     SELECT * FROM fractal_agent_anomaly_triage(
       'bt_agents_logs','metric','ts','host','no-such-host',32);" 2>&1)
  grep <<< "$r2" -q 'no rows in' \
    && pass "23 agents: anomaly_triage raises a clean ERROR when the filter matches no rows" \
    || fail "23 agents: expected a no-rows ERROR, got: $r2"

  # --- 3: fractal_agent_allocate happy path --------------------------
  # allocation is the REAL optimizer jsonb {sharpe, weights}; sharpe is the REAL
  # risk-adjusted return extracted from it (replaces the demo's 0.042 literal);
  # rationale is the REAL reason step (canary).
  local r3; r3=$("${PSQL[@]}" -c "
     SELECT allocation FROM fractal_agent_allocate(
       ARRAY[0.05,0.1]::float8[], ARRAY[1.0,0.0,0.0,1.0]::float8[], 1, '{}'::text);" 2>&1)
  grep <<< "$r3" -q '"sharpe"' \
    && pass "23 agents: allocate composes optimize_portfolio -> reason (real optimizer jsonb with sharpe)" \
    || fail "23 agents: expected a sharpe-bearing allocation jsonb, got: $r3"

  local r3b; r3b=$("${PSQL[@]}" -c "
     SELECT rationale FROM fractal_agent_allocate(
       ARRAY[0.05,0.1]::float8[], ARRAY[1.0,0.0,0.0,1.0]::float8[], 1, '{}'::text);" 2>&1)
  grep <<< "$r3b" -q 'gap-analysis-canary' \
    && pass "23 agents: allocate rationale is the real reason step output (canary)" \
    || fail "23 agents: expected the reasoning canary in rationale, got: $r3b"

  # --- 4: allocate cov-length rejection -------------------------------
  # The engine must surface fractal_optimize_portfolio's clean 'cov length'
  # ERROR unchanged, not swallow it.
  local r4; r4=$("${PSQL[@]}" -c "
     SELECT * FROM fractal_agent_allocate(
       ARRAY[0.1,0.1]::float8[], ARRAY[1.0]::float8[], 1, NULL::text);" 2>&1)
  grep <<< "$r4" -q 'cov length' \
    && pass "23 agents: allocate surfaces the optimizer's clean cov-length rejection" \
    || fail "23 agents: expected a cov-length rejection, got: $r4"

  # --- 5: fractal_agent_route_task happy path -------------------------
  # routed_to is the REAL nearest capability (telemetry ran + doc_id resolved
  # to the named id); confidence is real, derived from the nearest distance
  # (1/(1+d)); rationale is the REAL reason step (canary).
  "${PSQL[@]}" -c "
     DROP TABLE IF EXISTS bt_agents_caps;
     CREATE TABLE bt_agents_caps (capability_name text, emb float8[]);
     INSERT INTO bt_agents_caps VALUES ('cap-a', ARRAY[0.1,0.2,0.3]), ('cap-b', ARRAY[0.9,0.8,0.7]);" >/dev/null 2>&1
  local r5; r5=$("${PSQL[@]}" -c "
     SELECT routed_to FROM fractal_agent_route_task(
       ARRAY[0.1,0.2,0.3]::float8[], 'bt_agents_caps','emb','capability_name', 1000);" 2>&1)
  grep <<< "$r5" -q '^cap-a$' \
    && pass "23 agents: route_task returns the real nearest capability name (telemetry + doc_id resolution)" \
    || fail "23 agents: expected routed_to=cap-a, got: $r5"

  local r5b; r5b=$("${PSQL[@]}" -c "
     SELECT confidence FROM fractal_agent_route_task(
       ARRAY[0.1,0.2,0.3]::float8[], 'bt_agents_caps','emb','capability_name', 1000);" 2>&1)
  grep <<< "$r5b" -Eq '^[0-9]+(\.[0-9]+)?$' \
    && pass "23 agents: route_task confidence is a real float derived from the nearest distance" \
    || fail "23 agents: expected a numeric confidence, got: $r5b"

  local r5c; r5c=$("${PSQL[@]}" -c "
     SELECT rationale FROM fractal_agent_route_task(
       ARRAY[0.1,0.2,0.3]::float8[], 'bt_agents_caps','emb','capability_name', 1000);" 2>&1)
  grep <<< "$r5c" -q 'gap-analysis-canary' \
    && pass "23 agents: route_task composes telemetry -> reason (reason step ran)" \
    || fail "23 agents: expected the reasoning canary in rationale, got: $r5c"

  # --- 6: route_task empty-capability-table guard ---------------------
  "${PSQL[@]}" -c "DELETE FROM bt_agents_caps;" >/dev/null 2>&1
  local r6; r6=$("${PSQL[@]}" -c "
     SELECT * FROM fractal_agent_route_task(
       ARRAY[0.1,0.2,0.3]::float8[], 'bt_agents_caps','emb','capability_name', 1000);" 2>&1)
  grep <<< "$r6" -q 'no capability rows' \
    && pass "23 agents: route_task raises a clean ERROR when the capability table is empty" \
    || fail "23 agents: expected a no-capability-rows ERROR, got: $r6"

  # --- 7: fractal_agent_outlier_intercept intercept + allow -----------
  # Bad states point along the x-axis. Cosine distance ignores magnitude, so
  # the "far" probe must differ in DIRECTION (orthogonal y-axis), not just
  # magnitude -- [0.1,0.1,0.1] vs [0.9,0.9,0.9] would be distance 0 (parallel).
  "${PSQL[@]}" -c "
     DROP TABLE IF EXISTS bt_agents_badstates;
     CREATE TABLE bt_agents_badstates (emb float8[]);
     INSERT INTO bt_agents_badstates VALUES (ARRAY[1,0,0]), (ARRAY[0.9,0.1,0.0]);" >/dev/null 2>&1
  local r7; r7=$("${PSQL[@]}" -c "
     SELECT intercepted FROM fractal_agent_outlier_intercept(
       ARRAY[1,0,0]::float8[], 'bt_agents_badstates','emb', 0.5);" 2>&1)
  grep <<< "$r7" -q '^t$' \
    && pass "23 agents: outlier_intercept intercepts a state within the threshold (real distance 0 < 0.5)" \
    || fail "23 agents: expected intercepted=t for a near state, got: $r7"

  local r7b; r7b=$("${PSQL[@]}" -c "
     SELECT intercepted FROM fractal_agent_outlier_intercept(
       ARRAY[0,1,0]::float8[], 'bt_agents_badstates','emb', 0.5);" 2>&1)
  grep <<< "$r7b" -q '^f$' \
    && pass "23 agents: outlier_intercept allows an orthogonal state (real cosine distance 1 > 0.5)" \
    || fail "23 agents: expected intercepted=f for an orthogonal state, got: $r7b"

  local r7c; r7c=$("${PSQL[@]}" -c "
     SELECT reason FROM fractal_agent_outlier_intercept(
       ARRAY[1,0,0]::float8[], 'bt_agents_badstates','emb', 0.5);" 2>&1)
  grep <<< "$r7c" -q 'gap-analysis-canary' \
    && pass "23 agents: outlier_intercept reason is the real reason step output (canary)" \
    || fail "23 agents: expected the reasoning canary in reason, got: $r7c"

  # --- 8: fractal_agent_recall_hybrid happy path + guard --------------
  # Real session_ids + real content from the fixture (NOT the stub's
  # generate_series 1-5 / 'recalled memory snippet N'); the cohort
  # (customer_id filter) excludes cust-b's session. Pure retrieval -- no
  # LLM step, so no canary here, fully real C.
  "${PSQL[@]}" -c "
     DROP TABLE IF EXISTS bt_agents_mem;
     CREATE TABLE bt_agents_mem (session_id bigint, customer_id text, state_vector float8[], content text);
     INSERT INTO bt_agents_mem VALUES
       (1001, 'cust-a', ARRAY[0.1,0.2,0.3], 'resolved churn via loyalty upgrade'),
       (1002, 'cust-a', ARRAY[0.15,0.25,0.35], 'offered retention discount'),
       (1003, 'cust-b', ARRAY[0.9,0.8,0.7], 'escalated to human agent');" >/dev/null 2>&1
  local r8; r8=$("${PSQL[@]}" -c "
     SELECT mem_id FROM fractal_agent_recall_hybrid(
       'bt_agents_mem','state_vector', ARRAY[0.1,0.2,0.3]::float8[],
       'customer_id','cust-a', 5, 'session_id','content') LIMIT 1;" 2>&1)
  grep <<< "$r8" -q '^1001$' \
    && pass "23 agents: recall_hybrid returns the real nearest session_id (not the stub's generate_series 1-5)" \
    || fail "23 agents: expected mem_id=1001, got: $r8"

  local r8b; r8b=$("${PSQL[@]}" -c "
     SELECT content FROM fractal_agent_recall_hybrid(
       'bt_agents_mem','state_vector', ARRAY[0.1,0.2,0.3]::float8[],
       'customer_id','cust-a', 5, 'session_id','content') LIMIT 1;" 2>&1)
  grep <<< "$r8b" -q 'resolved churn via loyalty upgrade' \
    && pass "23 agents: recall_hybrid returns the real row content (not the stub's canned snippet)" \
    || fail "23 agents: expected the real content, got: $r8b"

  local r8c; r8c=$("${PSQL[@]}" -c "
     SELECT * FROM fractal_agent_recall_hybrid(
       'bt_agents_mem','state_vector', ARRAY[0.1,0.2,0.3]::float8[],
       'customer_id','no-such-cust', 5, 'session_id','content');" 2>&1)
  grep <<< "$r8c" -q 'filter matched no rows' \
    && pass "23 agents: recall_hybrid raises a clean ERROR when the filter matches no rows" \
    || fail "23 agents: expected a filter-matched-no-rows ERROR, got: $r8c"

  # --- 9: fractal_agent_recommend_diverse happy path ------------------
  # Real catalog ids + real scores (NOT the stub's generate_series 1..k /
  # 0.95 - i*0.01). Diversify is enabled as a session side effect; no
  # feedback has been reported so repulsion is a no-op and telemetry returns
  # the plain nearest first (id 10, distance 0 -> score 1). Pure retrieval.
  "${PSQL[@]}" -c "
     DROP TABLE IF EXISTS bt_agents_catalog;
     CREATE TABLE bt_agents_catalog (id bigint, emb float8[]);
     INSERT INTO bt_agents_catalog VALUES (10, ARRAY[0.1,0.2,0.3]), (20, ARRAY[0.9,0.8,0.7]), (30, ARRAY[0.5,0.5,0.5]);" >/dev/null 2>&1
  local r9; r9=$("${PSQL[@]}" -c "
     SELECT item_id FROM fractal_agent_recommend_diverse(
       'bt_agents_catalog','emb', ARRAY[0.1,0.2,0.3]::float8[], 3, 'id') LIMIT 1;" 2>&1)
  grep <<< "$r9" -q '^10$' \
    && pass "23 agents: recommend_diverse returns the real nearest catalog id (not the stub's generate_series 1..k)" \
    || fail "23 agents: expected item_id=10, got: $r9"

  local r9b; r9b=$("${PSQL[@]}" -c "
     SELECT score FROM fractal_agent_recommend_diverse(
       'bt_agents_catalog','emb', ARRAY[0.1,0.2,0.3]::float8[], 3, 'id') LIMIT 1;" 2>&1)
  grep <<< "$r9b" -Eq '^[0-9]+(\.[0-9]+)?$' \
    && pass "23 agents: recommend_diverse score is a real float (1 - cosine distance), not the stub's canned 0.95-i*0.01" \
    || fail "23 agents: expected a numeric score, got: $r9b"

  # ====================================================================
  # Stage 4 engines G-O (9 new). The 8 cognition engines (G,H,J,K,L,M,N,O)
  # reuse the gate-20 mock canary set above, so their rationale/analysis
  # columns carry it; feedback_audit (I) is pure analytics (no LLM, no
  # canary). Real C primitives feed the analytics columns; the canary proves
  # the reason step ran. Mirrors build_test.ps1's Gate23Agents.
  # ====================================================================

  # --- 10: fractal_agent_data_analyst happy path ----------------------
  # Composes fractal_sql_agent (NL->SQL->execute, auto_execute=true) ->
  # fractal_reason. With the mock canary the generated_sql IS the canary
  # (the mock LLM); auto_execute's subtransaction catches the canary-as-SQL
  # syntax error into a real execution_failed result_json, proving the
  # execute step ran; analysis is the real reason step (canary).
  "${PSQL[@]}" -c "
     DROP TABLE IF EXISTS bt_agents_data;
     CREATE TABLE bt_agents_data (id int PRIMARY KEY, val float8);
     INSERT INTO bt_agents_data VALUES (1,10.5),(2,20.5);" >/dev/null 2>&1
  local r10; r10=$("${PSQL[@]}" -c "
     SELECT generated_sql FROM fractal_agent_data_analyst(
       'sum of val', ARRAY['bt_agents_data'], 2);" 2>&1)
  grep <<< "$r10" -q 'gap-analysis-canary' \
    && pass "23 agents: data_analyst composes sql_agent (generated_sql is the real LLM step, canary)" \
    || fail "23 agents: expected the canary in generated_sql, got: $r10"
  local r10b; r10b=$("${PSQL[@]}" -c "
     SELECT result_json::text FROM fractal_agent_data_analyst(
       'sum of val', ARRAY['bt_agents_data'], 2);" 2>&1)
  grep <<< "$r10b" -q '"status"' \
    && pass "23 agents: data_analyst result_json is a real jsonb (auto_execute subtransaction ran)" \
    || fail "23 agents: expected a status-bearing result_json, got: $r10b"
  local r10c; r10c=$("${PSQL[@]}" -c "
     SELECT analysis FROM fractal_agent_data_analyst(
       'sum of val', ARRAY['bt_agents_data'], 2);" 2>&1)
  grep <<< "$r10c" -q 'gap-analysis-canary' \
    && pass "23 agents: data_analyst composes sql_agent -> reason (analysis is the real reason step, canary)" \
    || fail "23 agents: expected the canary in analysis, got: $r10c"

  # --- 11: fractal_agent_patient_deterioration_triage happy + guard ----
  # nearest_cohort_id is the REAL hybrid_clinical_search nearest resolved via
  # ctid; cohort_distance/drift_distance are real; rationale is the reason
  # step (canary). cohort_doc_ids built from age>65 AND condition='sepsis'
  # (the two-predicate case recall_hybrid cannot express).
  "${PSQL[@]}" -c "
     DROP TABLE IF EXISTS bt_agents_patients;
     CREATE TABLE bt_agents_patients (id int PRIMARY KEY, age int, condition text, vitals float8[]);
     INSERT INTO bt_agents_patients VALUES
       (1,70,'sepsis',ARRAY[0.9,-0.8,0.7,0.6]),
       (2,30,'sepsis',ARRAY[0.1,0.1,0.1,0.1]),
       (3,72,'flu',  ARRAY[0.2,0.2,0.2,0.2]),
       (4,80,'sepsis',ARRAY[0.85,-0.75,0.65,0.55]);" >/dev/null 2>&1
  local r11; r11=$("${PSQL[@]}" -c "
     SELECT nearest_cohort_id FROM fractal_agent_patient_deterioration_triage(
       'bt_agents_patients','vitals', ARRAY[0.9,-0.8,0.7,0.6]::float8[],
       ARRAY[0.1,0.1,0.1,0.1]::float8[], ARRAY[0.95,-0.85,0.75,0.65]::float8[],
       (SELECT array_agg(doc_id ORDER BY doc_id) FROM
          (SELECT row_number() OVER (ORDER BY ctid)-1 AS doc_id
             FROM bt_agents_patients WHERE age>65 AND condition='sepsis') x),
       5, 'id');" 2>&1)
  grep <<< "$r11" -Eq '^[0-9]+$' \
    && pass "23 agents: patient_deterioration_triage returns the real nearest cohort id (hybrid search + ctid resolution)" \
    || fail "23 agents: expected a numeric nearest_cohort_id, got: $r11"
  local r11m; r11m=$("${PSQL[@]}" -c "
     SELECT jsonb_array_length(cohort_matches) FROM fractal_agent_patient_deterioration_triage(
       'bt_agents_patients','vitals', ARRAY[0.9,-0.8,0.7,0.6]::float8[],
       ARRAY[0.1,0.1,0.1,0.1]::float8[], ARRAY[0.95,-0.85,0.75,0.65]::float8[],
       (SELECT array_agg(doc_id ORDER BY doc_id) FROM
          (SELECT row_number() OVER (ORDER BY ctid)-1 AS doc_id
             FROM bt_agents_patients WHERE age>65 AND condition='sepsis') x),
       5, 'id');" 2>&1)
  [[ "$r11m" = "2" ]] \
    && pass "23 agents: patient_deterioration_triage cohort_matches now honors k (got 2 of 2 qualifying rows)" \
    || fail "23 agents: expected cohort_matches length 2, got: $r11m"
  local r11b; r11b=$("${PSQL[@]}" -c "
     SELECT rationale FROM fractal_agent_patient_deterioration_triage(
       'bt_agents_patients','vitals', ARRAY[0.9,-0.8,0.7,0.6]::float8[],
       ARRAY[0.1,0.1,0.1,0.1]::float8[], ARRAY[0.95,-0.85,0.75,0.65]::float8[],
       (SELECT array_agg(doc_id ORDER BY doc_id) FROM
          (SELECT row_number() OVER (ORDER BY ctid)-1 AS doc_id
             FROM bt_agents_patients WHERE age>65 AND condition='sepsis') x),
       5, 'id');" 2>&1)
  grep <<< "$r11b" -q 'gap-analysis-canary' \
    && pass "23 agents: patient_deterioration_triage composes hybrid+trajectory -> reason (canary)" \
    || fail "23 agents: expected the canary in rationale, got: $r11b"
  "${PSQL[@]}" -c "DELETE FROM bt_agents_patients;" >/dev/null 2>&1
  local r11c; r11c=$("${PSQL[@]}" -c "
     SELECT * FROM fractal_agent_patient_deterioration_triage(
       'bt_agents_patients','vitals', ARRAY[0.9,-0.8,0.7,0.6]::float8[],
       ARRAY[0.1,0.1,0.1,0.1]::float8[], ARRAY[0.95,-0.85,0.75,0.65]::float8[],
       NULL, 5, 'id');" 2>&1)
  grep <<< "$r11c" -q 'no patient rows' \
    && pass "23 agents: patient_deterioration_triage raises a clean ERROR when the patient table is empty" \
    || fail "23 agents: expected a no-patient-rows ERROR, got: $r11c"

  # --- 12: fractal_agent_feedback_audit happy + guard ------------------
  # Pure analytics (NO LLM, no canary): enables diversify, warms the D_q
  # window from the warmup table, isolates the target, reads back a real
  # diversity_quotient (NOT NaN -- the warmup populated the window) + the
  # real session diagnostics jsonb. Self-disables diversify.
  "${PSQL[@]}" -c "
     DROP TABLE IF EXISTS bt_agents_fcatalog, bt_agents_fwarmup;
     CREATE TABLE bt_agents_fcatalog (id bigint PRIMARY KEY, emb float8[]);
     INSERT INTO bt_agents_fcatalog SELECT gs, ARRAY[random()*2-1, random()*2-1, random()*2-1] FROM generate_series(1,20) gs;
     CREATE TABLE bt_agents_fwarmup (center float8[]);
     INSERT INTO bt_agents_fwarmup SELECT ARRAY[random()*2-1, random()*2-1, random()*2-1] FROM generate_series(1,8);" >/dev/null 2>&1
  local r12; r12=$("${PSQL[@]}" -c "
     SELECT diversity_quotient::text FROM fractal_agent_feedback_audit(
       'bt_agents_fcatalog','emb', ARRAY[0.5,0.5,0.5]::float8[],
       'bt_agents_fwarmup','center', 8, 3);" 2>&1)
  grep <<< "$r12" -Eq '^[0-9]+(\.[0-9]+)?$' \
    && pass "23 agents: feedback_audit diversity_quotient is a real float (warmup populated the D_q window, not NaN)" \
    || fail "23 agents: expected a numeric diversity_quotient, got: $r12"
  local r12b; r12b=$("${PSQL[@]}" -c "
     SELECT (explanation IS NOT NULL)::text FROM fractal_agent_feedback_audit(
       'bt_agents_fcatalog','emb', ARRAY[0.5,0.5,0.5]::float8[],
       'bt_agents_fwarmup','center', 8, 3);" 2>&1)
  grep <<< "$r12b" -q '^true$' \
    && pass "23 agents: feedback_audit returns the real session diagnostics jsonb" \
    || fail "23 agents: expected a non-null explanation, got: $r12b"
  "${PSQL[@]}" -c "DELETE FROM bt_agents_fcatalog;" >/dev/null 2>&1
  local r12c; r12c=$("${PSQL[@]}" -c "
     SELECT * FROM fractal_agent_feedback_audit(
       'bt_agents_fcatalog','emb', ARRAY[0.5,0.5,0.5]::float8[],
       'bt_agents_fwarmup','center', 8, 3);" 2>&1)
  grep <<< "$r12c" -q 'no catalog rows' \
    && pass "23 agents: feedback_audit raises a clean ERROR when the catalog is empty" \
    || fail "23 agents: expected a no-catalog-rows ERROR, got: $r12c"

  # --- 13: fractal_agent_schedule_workload happy + guard ---------------
  # assigned_node is the REAL nearest node (fractal_search refinement +
  # telemetry + ctid resolution); confidence = 1/(1+d) is real; rationale
  # is the reason step (canary).
  "${PSQL[@]}" -c "
     DROP TABLE IF EXISTS bt_agents_nodes;
     CREATE TABLE bt_agents_nodes (id int PRIMARY KEY, capability float8[]);
     INSERT INTO bt_agents_nodes VALUES
       (1,ARRAY[0.9,0.1,0.0,0.0,0.0]),
       (2,ARRAY[0.0,0.0,0.9,0.1,0.0]),
       (3,ARRAY[0.1,0.0,0.0,0.0,0.9]);" >/dev/null 2>&1
  local r13; r13=$("${PSQL[@]}" -c "
     SELECT assigned_node FROM fractal_agent_schedule_workload(
       ARRAY[0.8,0.1,0.0,0.0,0.1]::float8[], 'bt_agents_nodes','capability','id', 30, 50, 5);" 2>&1)
  grep <<< "$r13" -Eq '^[0-9]+$' \
    && pass "23 agents: schedule_workload returns the real nearest node (fractal_search + telemetry + ctid)" \
    || fail "23 agents: expected a numeric assigned_node, got: $r13"
  local r13b; r13b=$("${PSQL[@]}" -c "
     SELECT rationale FROM fractal_agent_schedule_workload(
       ARRAY[0.8,0.1,0.0,0.0,0.1]::float8[], 'bt_agents_nodes','capability','id', 30, 50, 5);" 2>&1)
  grep <<< "$r13b" -q 'gap-analysis-canary' \
    && pass "23 agents: schedule_workload composes search+telemetry -> reason (canary)" \
    || fail "23 agents: expected the canary in rationale, got: $r13b"
  "${PSQL[@]}" -c "DELETE FROM bt_agents_nodes;" >/dev/null 2>&1
  local r13c; r13c=$("${PSQL[@]}" -c "
     SELECT * FROM fractal_agent_schedule_workload(
       ARRAY[0.8,0.1,0.0,0.0,0.1]::float8[], 'bt_agents_nodes','capability','id', 30, 50, 5);" 2>&1)
  grep <<< "$r13c" -q 'no node rows' \
    && pass "23 agents: schedule_workload raises a clean ERROR when the node table is empty" \
    || fail "23 agents: expected a no-node-rows ERROR, got: $r13c"

  # --- 14: fractal_agent_rebalance_sibling happy + guard ---------------
  # sharpe is the REAL optimizer output; weights is the real jsonb;
  # nearest_alloc_id is the real trajectory-search nearest resolved via
  # ctid; rationale is the reason step (canary).
  "${PSQL[@]}" -c "
     DROP TABLE IF EXISTS bt_agents_alloc;
     CREATE TABLE bt_agents_alloc (id bigint PRIMARY KEY, alloc float8[]);
     INSERT INTO bt_agents_alloc VALUES
       (1,ARRAY[0.25,0.25,0.25,0.25]),
       (2,ARRAY[0.4,0.3,0.2,0.1]),
       (3,ARRAY[0.1,0.2,0.3,0.4]);" >/dev/null 2>&1
  local r14; r14=$("${PSQL[@]}" -c "
     SELECT sharpe::text FROM fractal_agent_rebalance_sibling(
       ARRAY[0.05,0.10,0.15,0.20]::float8[],
       ARRAY[0.04,0.0,0.0,0.0, 0.0,0.09,0.0,0.0, 0.0,0.0,0.16,0.0, 0.0,0.0,0.0,0.25]::float8[],
       4, 'bt_agents_alloc','alloc', ARRAY[0.25,0.25,0.25,0.25]::float8[], NULL, 5, 'id');" 2>&1)
  grep <<< "$r14" -Eq '^-?[0-9]+(\.[0-9]+)?$' \
    && pass "23 agents: rebalance_sibling sharpe is the real optimizer output" \
    || fail "23 agents: expected a numeric sharpe, got: $r14"
  local r14b; r14b=$("${PSQL[@]}" -c "
     SELECT nearest_alloc_id FROM fractal_agent_rebalance_sibling(
       ARRAY[0.05,0.10,0.15,0.20]::float8[],
       ARRAY[0.04,0.0,0.0,0.0, 0.0,0.09,0.0,0.0, 0.0,0.0,0.16,0.0, 0.0,0.0,0.0,0.25]::float8[],
       4, 'bt_agents_alloc','alloc', ARRAY[0.25,0.25,0.25,0.25]::float8[], NULL, 5, 'id');" 2>&1)
  grep <<< "$r14b" -Eq '^[0-9]+$' \
    && pass "23 agents: rebalance_sibling nearest_alloc_id is the real trajectory nearest (ctid resolution)" \
    || fail "23 agents: expected a numeric nearest_alloc_id, got: $r14b"
  local r14c; r14c=$("${PSQL[@]}" -c "
     SELECT rationale FROM fractal_agent_rebalance_sibling(
       ARRAY[0.05,0.10,0.15,0.20]::float8[],
       ARRAY[0.04,0.0,0.0,0.0, 0.0,0.09,0.0,0.0, 0.0,0.0,0.16,0.0, 0.0,0.0,0.0,0.25]::float8[],
       4, 'bt_agents_alloc','alloc', ARRAY[0.25,0.25,0.25,0.25]::float8[], NULL, 5, 'id');" 2>&1)
  grep <<< "$r14c" -q 'gap-analysis-canary' \
    && pass "23 agents: rebalance_sibling composes optimize+trajectory -> reason (canary)" \
    || fail "23 agents: expected the canary in rationale, got: $r14c"
  "${PSQL[@]}" -c "DELETE FROM bt_agents_alloc;" >/dev/null 2>&1
  local r14d; r14d=$("${PSQL[@]}" -c "
     SELECT * FROM fractal_agent_rebalance_sibling(
       ARRAY[0.05,0.10,0.15,0.20]::float8[],
       ARRAY[0.04,0.0,0.0,0.0, 0.0,0.09,0.0,0.0, 0.0,0.0,0.16,0.0, 0.0,0.0,0.0,0.25]::float8[],
       4, 'bt_agents_alloc','alloc', ARRAY[0.25,0.25,0.25,0.25]::float8[], NULL, 5, 'id');" 2>&1)
  grep <<< "$r14d" -q 'no allocation rows' \
    && pass "23 agents: rebalance_sibling raises a clean ERROR when the allocation table is empty" \
    || fail "23 agents: expected a no-allocation-rows ERROR, got: $r14d"

  # --- 15: fractal_agent_detour_classify happy + guard -----------------
  # nearest_fleet_id is the REAL trajectory-search nearest; trace_complexity
  # is the REAL box-counting dimension of the GPS trace; rationale is the
  # reason step (canary).
  "${PSQL[@]}" -c "
     DROP TABLE IF EXISTS bt_agents_vehicles;
     CREATE TABLE bt_agents_vehicles (id int PRIMARY KEY, baseline float8[], current float8[]);
     INSERT INTO bt_agents_vehicles SELECT gs, ARRAY[b1,b2,b3,b4], ARRAY[b1+0.05,b2+0.05,b3+0.05,b4+0.05]
       FROM generate_series(1,8) gs,
            LATERAL (SELECT random()*2-1 a, random()*2-1 b, random()*2-1 c, random()*2-1 d) bl(b1,b2,b3,b4);
     UPDATE bt_agents_vehicles SET current = ARRAY[(baseline::float8[])[1]-0.7,(baseline::float8[])[2]+0.6,(baseline::float8[])[3]+0.5,(baseline::float8[])[4]-0.4] WHERE id=1;" >/dev/null 2>&1
  local r15; r15=$("${PSQL[@]}" -c "
     SELECT trace_complexity::text FROM fractal_agent_detour_classify(
       'bt_agents_vehicles','current',
       (SELECT baseline::float8[] FROM bt_agents_vehicles WHERE id=1),
       (SELECT current::float8[] FROM bt_agents_vehicles WHERE id=1),
       (SELECT array_agg(cum ORDER BY t, ord) FROM (
          SELECT t, ord, sum(step) OVER (PARTITION BY ord ORDER BY t) AS cum
          FROM generate_series(1,100) t
          CROSS JOIN LATERAL (VALUES (1,(random()-0.5)*0.3),(2,(random()-0.5)*0.3)) AS s(ord,step)
        ) c),
       5, 'id', 2);" 2>&1)
  grep <<< "$r15" -Eq '^[0-9]+(\.[0-9]+)?$' \
    && pass "23 agents: detour_classify trace_complexity is the real box-counting dimension of the GPS trace" \
    || fail "23 agents: expected a numeric trace_complexity, got: $r15"
  local r15b; r15b=$("${PSQL[@]}" -c "
     SELECT rationale FROM fractal_agent_detour_classify(
       'bt_agents_vehicles','current',
       (SELECT baseline::float8[] FROM bt_agents_vehicles WHERE id=1),
       (SELECT current::float8[] FROM bt_agents_vehicles WHERE id=1),
       (SELECT array_agg(cum ORDER BY t, ord) FROM (
          SELECT t, ord, sum(step) OVER (PARTITION BY ord ORDER BY t) AS cum
          FROM generate_series(1,100) t
          CROSS JOIN LATERAL (VALUES (1,(random()-0.5)*0.3),(2,(random()-0.5)*0.3)) AS s(ord,step)
        ) c),
       5, 'id', 2);" 2>&1)
  grep <<< "$r15b" -q 'gap-analysis-canary' \
    && pass "23 agents: detour_classify composes trajectory+boxcount -> reason (canary)" \
    || fail "23 agents: expected the canary in rationale, got: $r15b"
  "${PSQL[@]}" -c "DELETE FROM bt_agents_vehicles;" >/dev/null 2>&1
  local r15c; r15c=$("${PSQL[@]}" -c "
     SELECT * FROM fractal_agent_detour_classify(
       'bt_agents_vehicles','current',
       ARRAY[0.1,0.1,0.1,0.1]::float8[], ARRAY[0.2,0.2,0.2,0.2]::float8[],
       ARRAY[0,0,0,0]::float8[], 5, 'id', 2);" 2>&1)
  grep <<< "$r15c" -q 'no vehicle rows' \
    && pass "23 agents: detour_classify raises a clean ERROR when the vehicle table is empty" \
    || fail "23 agents: expected a no-vehicle-rows ERROR, got: $r15c"

  # --- 16: fractal_agent_track_anomaly happy + guard -------------------
  # nearest_fleet_id is the REAL trajectory nearest; dfa_exponent is the REAL
  # DFA exponent of the heading series (may be -1, still numeric); rationale
  # is the reason step (canary).
  "${PSQL[@]}" -c "
     DROP TABLE IF EXISTS bt_agents_tracks;
     CREATE TABLE bt_agents_tracks (id int PRIMARY KEY, baseline float8[], current float8[]);
     INSERT INTO bt_agents_tracks SELECT gs, ARRAY[b1,b2,b3,b4], ARRAY[b1+0.04,b2+0.04,b3+0.04,b4+0.04]
       FROM generate_series(1,8) gs,
            LATERAL (SELECT random()*2-1 a, random()*2-1 b, random()*2-1 c, random()*2-1 d) bl(b1,b2,b3,b4);
     UPDATE bt_agents_tracks SET current = ARRAY[(baseline::float8[])[1]+0.6,(baseline::float8[])[2]-0.5,(baseline::float8[])[3]-0.9,(baseline::float8[])[4]+0.8] WHERE id=1;" >/dev/null 2>&1
  local r16; r16=$("${PSQL[@]}" -c "
     SELECT dfa_exponent::text FROM fractal_agent_track_anomaly(
       'bt_agents_tracks','current',
       (SELECT baseline::float8[] FROM bt_agents_tracks WHERE id=1),
       (SELECT current::float8[] FROM bt_agents_tracks WHERE id=1),
       (SELECT array_agg(cum ORDER BY t) FROM (
          SELECT t, sum(step) OVER (ORDER BY t) AS cum
          FROM (SELECT t, (random()-0.5)*(CASE WHEN t BETWEEN 40 AND 60 THEN 0.35 ELSE 0.03 END) AS step
                  FROM generate_series(1,120) t) s
        ) c),
       5, 'id');" 2>&1)
  grep <<< "$r16" -Eq '^-?[0-9]+(\.[0-9]+)?$' \
    && pass "23 agents: track_anomaly dfa_exponent is the real DFA exponent of the heading series" \
    || fail "23 agents: expected a numeric dfa_exponent, got: $r16"
  local r16b; r16b=$("${PSQL[@]}" -c "
     SELECT rationale FROM fractal_agent_track_anomaly(
       'bt_agents_tracks','current',
       (SELECT baseline::float8[] FROM bt_agents_tracks WHERE id=1),
       (SELECT current::float8[] FROM bt_agents_tracks WHERE id=1),
       (SELECT array_agg(cum ORDER BY t) FROM (
          SELECT t, sum(step) OVER (ORDER BY t) AS cum
          FROM (SELECT t, (random()-0.5)*(CASE WHEN t BETWEEN 40 AND 60 THEN 0.35 ELSE 0.03 END) AS step
                  FROM generate_series(1,120) t) s
        ) c),
       5, 'id');" 2>&1)
  grep <<< "$r16b" -q 'gap-analysis-canary' \
    && pass "23 agents: track_anomaly composes trajectory+dfa -> reason (canary)" \
    || fail "23 agents: expected the canary in rationale, got: $r16b"
  "${PSQL[@]}" -c "DELETE FROM bt_agents_tracks;" >/dev/null 2>&1
  local r16c; r16c=$("${PSQL[@]}" -c "
     SELECT * FROM fractal_agent_track_anomaly(
       'bt_agents_tracks','current',
       ARRAY[0.1,0.1,0.1,0.1]::float8[], ARRAY[0.2,0.2,0.2,0.2]::float8[],
       ARRAY[0,0,0]::float8[], 5, 'id');" 2>&1)
  grep <<< "$r16c" -q 'no track rows' \
    && pass "23 agents: track_anomaly raises a clean ERROR when the track table is empty" \
    || fail "23 agents: expected a no-track-rows ERROR, got: $r16c"

  # --- 17: fractal_agent_network_coverage_alert happy + NULL guard -----
  # morph_dimension + lacunarity are the REAL morphological_complexity output
  # (needs >= ~256 points -- use a 20x20 grid, matching the smart-cities
  # demo); drift_detected is the REAL |drift|>threshold over a step-up
  # series (true); rationale is the reason step (canary).
  local r17; r17=$("${PSQL[@]}" -c "
     SELECT morph_dimension::text FROM fractal_agent_network_coverage_alert(
       (SELECT array_agg(v ORDER BY id, ord) FROM (
          SELECT r*20+c AS id, ord, v FROM generate_series(0,19) r
          CROSS JOIN generate_series(0,19) c
          CROSS JOIN LATERAL unnest(ARRAY[r+(random()-0.5)*0.3, c+(random()-0.5)*0.3]) WITH ORDINALITY AS u(v,ord)
        ) g),
       (SELECT array_agg(v ORDER BY t) FROM (
          SELECT t, CASE WHEN t<48 THEN 4.0+1.5*sin(t*0.31)+(random()-0.5)*0.8
                         ELSE 4.0+3.0*sin(t*1.4)+(random()-0.5)*0.4 END AS v
          FROM generate_series(1,96) t) s),
       2, 48, 0.5);" 2>&1)
  grep <<< "$r17" -Eq '^[0-9]+(\.[0-9]+)?$' \
    && pass "23 agents: network_coverage_alert morph_dimension is the real morphological complexity" \
    || fail "23 agents: expected a numeric morph_dimension, got: $r17"
  local r17b; r17b=$("${PSQL[@]}" -c "
     SELECT drift_detected::text FROM fractal_agent_network_coverage_alert(
       (SELECT array_agg(v ORDER BY id, ord) FROM (
          SELECT r*20+c AS id, ord, v FROM generate_series(0,19) r
          CROSS JOIN generate_series(0,19) c
          CROSS JOIN LATERAL unnest(ARRAY[r+(random()-0.5)*0.3, c+(random()-0.5)*0.3]) WITH ORDINALITY AS u(v,ord)
        ) g),
       (SELECT array_agg(v ORDER BY t) FROM (
          SELECT t, CASE WHEN t<48 THEN 4.0+1.5*sin(t*0.31)+(random()-0.5)*0.8
                         ELSE 4.0+3.0*sin(t*1.4)+(random()-0.5)*0.4 END AS v
          FROM generate_series(1,96) t) s),
       2, 48, 0.5);" 2>&1)
  grep <<< "$r17b" -q '^true$' \
    && pass "23 agents: network_coverage_alert drift_detected=true for a real regime-change series (|drift|>0.5)" \
    || fail "23 agents: expected drift_detected=t, got: $r17b"
  local r17c; r17c=$("${PSQL[@]}" -c "
     SELECT rationale FROM fractal_agent_network_coverage_alert(
       (SELECT array_agg(v ORDER BY id, ord) FROM (
          SELECT r*20+c AS id, ord, v FROM generate_series(0,19) r
          CROSS JOIN generate_series(0,19) c
          CROSS JOIN LATERAL unnest(ARRAY[r+(random()-0.5)*0.3, c+(random()-0.5)*0.3]) WITH ORDINALITY AS u(v,ord)
        ) g),
       (SELECT array_agg(v ORDER BY t) FROM (
          SELECT t, CASE WHEN t<48 THEN 4.0+1.5*sin(t*0.31)+(random()-0.5)*0.8
                         ELSE 4.0+3.0*sin(t*1.4)+(random()-0.5)*0.4 END AS v
          FROM generate_series(1,96) t) s),
       2, 48, 0.5);" 2>&1)
  grep <<< "$r17c" -q 'gap-analysis-canary' \
    && pass "23 agents: network_coverage_alert composes morph+drift -> reason (canary)" \
    || fail "23 agents: expected the canary in rationale, got: $r17c"
  local r17d; r17d=$("${PSQL[@]}" -c "
     SELECT * FROM fractal_agent_network_coverage_alert(
       NULL::float8[], ARRAY[1,2,3]::float8[], 2, 48, 0.5);" 2>&1)
  grep <<< "$r17d" -q 'point_cloud and drift_series are required' \
    && pass "23 agents: network_coverage_alert raises a clean ERROR when point_cloud/drift_series is NULL" \
    || fail "23 agents: expected a required-args ERROR, got: $r17d"

  # --- 18: fractal_agent_regime_triage happy + NULL guard --------------
  # dfa_exponent is the REAL DFA exponent; drift_detected is the REAL
  # |drift|>threshold (true for the step-up series); recent/baseline alphas
  # are real; rationale is the reason step (canary).
  local r18; r18=$("${PSQL[@]}" -c "
     SELECT dfa_exponent::text FROM fractal_agent_regime_triage(
       (SELECT array_agg(v ORDER BY t) FROM (
          SELECT t, CASE WHEN t<48 THEN 4.0+1.5*sin(t*0.31)+(random()-0.5)*0.8
                         ELSE 4.0+3.0*sin(t*1.4)+(random()-0.5)*0.4 END AS v
          FROM generate_series(1,96) t) s),
       64, 0.5);" 2>&1)
  grep <<< "$r18" -Eq '^-?[0-9]+(\.[0-9]+)?$' \
    && pass "23 agents: regime_triage dfa_exponent is the real DFA exponent" \
    || fail "23 agents: expected a numeric dfa_exponent, got: $r18"
  local r18b; r18b=$("${PSQL[@]}" -c "
     SELECT drift_detected::text FROM fractal_agent_regime_triage(
       (SELECT array_agg(v ORDER BY t) FROM (
          SELECT t, CASE WHEN t<48 THEN 4.0+1.5*sin(t*0.31)+(random()-0.5)*0.8
                         ELSE 4.0+3.0*sin(t*1.4)+(random()-0.5)*0.4 END AS v
          FROM generate_series(1,96) t) s),
       64, 0.5);" 2>&1)
  grep <<< "$r18b" -q '^true$' \
    && pass "23 agents: regime_triage drift_detected=true for a real regime-change series (|drift|>0.5)" \
    || fail "23 agents: expected drift_detected=t, got: $r18b"
  local r18c; r18c=$("${PSQL[@]}" -c "
     SELECT rationale FROM fractal_agent_regime_triage(
       (SELECT array_agg(v ORDER BY t) FROM (
          SELECT t, CASE WHEN t<48 THEN 4.0+1.5*sin(t*0.31)+(random()-0.5)*0.8
                         ELSE 4.0+3.0*sin(t*1.4)+(random()-0.5)*0.4 END AS v
          FROM generate_series(1,96) t) s),
       64, 0.5);" 2>&1)
  grep <<< "$r18c" -q 'gap-analysis-canary' \
    && pass "23 agents: regime_triage composes dfa+drift -> reason (canary)" \
    || fail "23 agents: expected the canary in rationale, got: $r18c"
  local r18d; r18d=$("${PSQL[@]}" -c "
     SELECT * FROM fractal_agent_regime_triage(NULL::float8[], 64, 0.5);" 2>&1)
  grep <<< "$r18d" -q 'series is required' \
    && pass "23 agents: regime_triage raises a clean ERROR when series is NULL" \
    || fail "23 agents: expected a series-required ERROR, got: $r18d"

  # Restore session state: diversify was enabled by recommend_diverse and
  # feedback_audit (feedback_audit self-disables, but belt-and-suspenders).
  "${PSQL[@]}" -c "SELECT fractal_diversify_disable();" >/dev/null 2>&1

  "${PSQL[@]}" -c "DROP TABLE IF EXISTS bt_agents_caps, bt_agents_badstates, bt_agents_mem, bt_agents_catalog;" >/dev/null 2>&1
  "${PSQL[@]}" -c "DROP TABLE IF EXISTS bt_agents_logs;" >/dev/null 2>&1
  "${PSQL[@]}" -c "DROP TABLE IF EXISTS bt_agents_data, bt_agents_patients, bt_agents_fcatalog, bt_agents_fwarmup, bt_agents_nodes, bt_agents_alloc, bt_agents_vehicles, bt_agents_tracks;" >/dev/null 2>&1
  rm -f /tmp/fractalsql_bt_sql.txt
}

# FUZZ only -- not in DEFAULT or QUICK, run via --fuzz. No live cluster
# needed: builds + briefly runs libFuzzer drivers against the three
# hand-rolled parsers this repo has that read externally-influenceable
# text into a fixed-size buffer (src/fractalsql_parse.c -- factored out
# of src/fractalsql.c specifically so these can be linked standalone,
# without postgres.h/a running backend; see that file's own header
# comment). fsql_parse_embedding_array is the highest-priority target:
# it parses fractal_embed()'s raw response from whatever embedding
# endpoint fractalsql.http_embed_url points at, i.e. genuinely
# attacker-controlled bytes if that endpoint is malicious or merely
# buggy. The other two (fsql_extract_best_point, fsql_extract_population)
# parse the vendored core's own result JSON -- lower external-adversary
# risk, included as defense-in-depth for the same hand-rolled-strtod-
# scan class of bug.
#
# This is a SMOKE run (FSQL_FUZZ_TIME seconds per target, default 30),
# not a real fuzzing campaign -- it exists to catch a regression before
# push. Run a real multi-hour campaign locally (same binaries, higher
# -max_total_time) before relying on this gate to have found everything.
gate_21_fuzz_smoke() {
  local cc="${FSQL_FUZZ_CC:-}"
  if [[ -z "$cc" ]]; then
    for candidate in clang-18 clang-17 clang-16 clang-15 clang; do
      if command -v "$candidate" >/dev/null 2>&1; then cc="$candidate"; break; fi
    done
  fi
  if [[ -z "$cc" ]] || ! command -v "$cc" >/dev/null 2>&1; then
    skip "21 fuzz_smoke (no clang found -- set FSQL_FUZZ_CC to a libFuzzer-capable clang)"
    return
  fi
  # The clang resolved above might not actually have libFuzzer support
  # (e.g. a bare `clang` shadowed by an unrelated toolchain's shim) --
  # verify with a trivial compile before trusting it for the real
  # targets, rather than failing confusingly three functions down.
  local probe_src probe_bin
  probe_src="$(mktemp /tmp/fractalsql_bt_fuzzprobe_XXXXXX.c)"
  probe_bin="${probe_src%.c}"
  printf 'int LLVMFuzzerTestOneInput(const unsigned char*d,unsigned long n){(void)d;(void)n;return 0;}\n' > "$probe_src"
  if ! "$cc" -fsanitize=fuzzer "$probe_src" -o "$probe_bin" >/dev/null 2>&1; then
    rm -f "$probe_src" "$probe_bin"
    skip "21 fuzz_smoke ($cc lacks -fsanitize=fuzzer support -- set FSQL_FUZZ_CC)"
    return
  fi
  rm -f "$probe_src" "$probe_bin"

  local fuzz_time="${FSQL_FUZZ_TIME:-30}"
  mkdir -p /tmp/fractalsql_bt_fuzz

  local target
  for target in parse_embedding_array extract_best_point extract_population; do
    local bin="/tmp/fractalsql_bt_fuzz/fuzz_$target"
    local buildlog="/tmp/fractalsql_bt_fuzz_${target}_build.log"
    if ! "$cc" -std=c99 -O1 -g -fsanitize=fuzzer,address -fno-sanitize-recover=address \
        -Isrc \
        src/fractalsql_parse.c "tests/fuzz/fuzz_${target}.c" \
        -o "$bin" >"$buildlog" 2>&1; then
      fail "21 fuzz_smoke: $target — build failed, see $buildlog"
      continue
    fi

    local runlog="/tmp/fractalsql_bt_fuzz_${target}_run.log"
    if ASAN_OPTIONS=detect_leaks=0 "$bin" -max_total_time="$fuzz_time" -print_final_stats=1 \
        "tests/fuzz/corpus_${target}/" >"$runlog" 2>&1; then
      local execs; execs=$(grep -o "number_of_executed_units: [0-9]*" "$runlog" | grep -o "[0-9]*")
      pass "21 fuzz_smoke: $target — ${fuzz_time}s clean (${execs:-?} execs, no crash)"
    else
      fail "21 fuzz_smoke: $target — crash/hang found, see $runlog (repro: $bin <crash-file>)"
    fi
    rm -f "$bin"
  done
}

# --- run one major through a gate set ---------------------------------
gate_24_enterprise() {
  # QTL ledger + CISO audit -- runtime-gated behind the enterprise core
  # library. Self-skips on a community-only checkout (no enterprise
  # library vendored in include/). When the library IS present, exercises
  # the full wiring: dlopen + dlsym of fsql_ledger_*/fsql_audit_unpack, the
  # Postgres-backed storage VFS round-trip (flush -> fractalsql_ledger ->
  # audit_unpack), and the dormant-path error when the library is absent.
  local ent_so
  ent_so=$(ls include/*/libfractalsql-enterprise-sovereign-c.so include/*/libfractalsql-enterprise-sovereign-c.dylib 2>/dev/null | head -1)
  if [[ -z "$ent_so" ]]; then
    skip "24 enterprise: skipped (community edition; no libfractalsql-enterprise-sovereign-c.* in include/)"
    return
  fi
  local abs
  abs=$(cd "$(dirname "$ent_so")" && pwd)/$(basename "$ent_so")

  # Phase E below calls agents that invoke fractal_reason -- make sure the
  # mock plugin is active regardless of whether gate 23 ran first (this
  # gate must be standalone-runnable, same rationale as gate 23's swap).
  pg_swap_plugin "$MOCK" >/dev/null

  # fractalsql.enterprise_lib is PGC_SIGHUP: set it via ALTER SYSTEM +
  # reload, then poll until a fresh backend observes the new value (a
  # bare SET cannot change a SIGHUP GUC in-session, and pg_reload_conf()
  # returns before the postmaster has re-read config).
  local v
  set_ent_guc() {
    local val="$1" want="$1"
    "${PSQL[@]}" -c "ALTER SYSTEM SET fractalsql.enterprise_lib = '$val';" >/dev/null 2>&1
    "${PSQL[@]}" -c "SELECT pg_reload_conf();" >/dev/null 2>&1
    for _ in 1 2 3 4 5 6 7 8 9 10; do
      v=$("${PSQL[@]}" -tA -c "SHOW fractalsql.enterprise_lib;" 2>/dev/null)
      [[ "$v" = "$want" ]] && return
      sleep 0.3
    done
  }

  # Phase A: enterprise library present -- the surface activates.
  set_ent_guc "$abs"
  if [[ "$v" != "$abs" ]]; then
    fail "24 enterprise: could not apply fractalsql.enterprise_lib (reload did not take effect; got '$v')"
    return
  fi
  local ra
  ra=$("${PSQL[@]}" -c "
    SELECT fractal_ledger_flush();
    SELECT fractal_ledger_truth_count() AS truth, fractal_ledger_shadow_count() AS shadow;
    SELECT fractal_ledger_load();
    SELECT fractal_ledger_compact();
    SELECT fractal_ledger_reset_soft();
    SELECT fractal_ledger_reset_hard();
    SELECT fractal_audit_unpack(blob)::text AS audit
      FROM fractalsql_ledger WHERE kind = 1;" 2>&1)
  grep <<< "$ra" -q "ERROR:" \
    && fail "24 enterprise: ledger/audit errored with the enterprise library present: $ra" \
    || pass "24 enterprise: ledger flush/load/compact/reset/counts work with the enterprise library"
  grep <<< "$ra" -q "\[\]" \
    && pass "24 enterprise: fractal_audit_unpack decoded the persisted QTL blob end-to-end (storage VFS round-trip)" \
    || fail "24 enterprise: audit_unpack did not return the flushed QTL jsonb (got: $ra)"

  # Phase B: point the GUC at a missing path -- the surface goes dormant,
  # equivalent to removing the .so. Fresh backend -> dlopen fails -> the
  # documented 'enterprise tier not loaded' error.
  set_ent_guc "/nonexistent/fractalsql-enterprise-absent.so"
  local rb
  rb=$("${PSQL[@]}" -c "SELECT fractal_ledger_flush();" 2>&1)
  grep <<< "$rb" -q "enterprise tier not loaded" \
    && pass "24 enterprise: ledger functions return 'enterprise tier not loaded' when the library is absent" \
    || fail "24 enterprise: expected 'enterprise tier not loaded' when absent, got: $rb"

  # Phase C: fractal_optimize_portfolio_multimodal -- dormant error while
  # absent, real multi-candidate result once the library is back.
  local rc_dormant
  rc_dormant=$("${PSQL[@]}" -c "SELECT fractal_optimize_portfolio_multimodal(ARRAY[0.1,0.05,0.08]::float8[], ARRAY[0.04,0.01,0.01, 0.01,0.03,0.01, 0.01,0.01,0.05]::float8[], 2);" 2>&1)
  grep <<< "$rc_dormant" -q "enterprise tier not loaded" \
    && pass "24 enterprise: portfolio_multimodal returns 'enterprise tier not loaded' when the library is absent" \
    || fail "24 enterprise: expected 'enterprise tier not loaded' for portfolio_multimodal when absent, got: $rc_dormant"

  set_ent_guc "$abs"
  local rc_active
  rc_active=$("${PSQL[@]}" -tA -c "SELECT fractal_optimize_portfolio_multimodal(ARRAY[0.1,0.05,0.08]::float8[], ARRAY[0.04,0.01,0.01, 0.01,0.03,0.01, 0.01,0.01,0.05]::float8[], 2, 4)->>'n_found';" 2>/dev/null)
  case "$rc_active" in
    [1-9]|[1-9][0-9])
      pass "24 enterprise: portfolio_multimodal returns real candidates (n_found=$rc_active) with the library present" ;;
    *)
      fail "24 enterprise: expected a positive n_found from portfolio_multimodal, got: $rc_active" ;;
  esac

  # Phase D: fractal_audit_log / fractal_ledger_verify(2) -- the general
  # decision-audit chain (kind=2, independent of kind=1's QTL chain).
  # Library still active from Phase C.
  "${PSQL[@]}" -c "DELETE FROM fractalsql_ledger WHERE kind = 2;" >/dev/null 2>&1
  local rd_write
  rd_write=$("${PSQL[@]}" -c "SELECT fractal_audit_log('test_entry', '{\"note\":\"gate24\"}'::jsonb);" 2>&1)
  grep <<< "$rd_write" -q "ERROR:" \
    && fail "24 enterprise: fractal_audit_log errored with the library present: $rd_write" \
    || pass "24 enterprise: fractal_audit_log writes to the audit chain (kind=2) with the library present"

  local rd_verify
  rd_verify=$("${PSQL[@]}" -tA -c "SELECT fractal_ledger_verify(2)->>'ok';" 2>/dev/null)
  [[ "$rd_verify" = "true" ]] \
    && pass "24 enterprise: fractal_ledger_verify(2) confirms the audit chain is clean" \
    || fail "24 enterprise: expected fractal_ledger_verify(2) ok=true, got: $rd_verify"

  # fractal_optimize_portfolio (single-best) also logs to the audit chain
  # when enterprise is active -- confirm a NEW kind=2 row appears.
  local rd_before rd_after
  rd_before=$("${PSQL[@]}" -tA -c "SELECT count(*) FROM fractalsql_ledger WHERE kind = 2;" 2>/dev/null)
  "${PSQL[@]}" -c "SELECT fractal_optimize_portfolio(ARRAY[0.1,0.05,0.08]::float8[], ARRAY[0.04,0.01,0.01, 0.01,0.03,0.01, 0.01,0.01,0.05]::float8[], 2);" >/dev/null 2>&1
  rd_after=$("${PSQL[@]}" -tA -c "SELECT count(*) FROM fractalsql_ledger WHERE kind = 2;" 2>/dev/null)
  if [[ "${rd_after:-0}" -gt "${rd_before:-0}" ]] 2>/dev/null; then
    pass "24 enterprise: fractal_optimize_portfolio logs a provenance record to the audit chain when enterprise is active"
  else
    fail "24 enterprise: expected a new kind=2 row after fractal_optimize_portfolio, before=$rd_before after=$rd_after"
  fi

  # Dormant: fractal_audit_log errors cleanly; fractal_optimize_portfolio
  # (a community feature) keeps working regardless -- this is the whole
  # point of the best-effort binding.
  set_ent_guc "/nonexistent/fractalsql-enterprise-absent.so"
  local rd_dormant
  rd_dormant=$("${PSQL[@]}" -c "SELECT fractal_audit_log('test_entry', '{}'::jsonb);" 2>&1)
  grep <<< "$rd_dormant" -q "enterprise tier not loaded" \
    && pass "24 enterprise: fractal_audit_log returns 'enterprise tier not loaded' when the library is absent" \
    || fail "24 enterprise: expected 'enterprise tier not loaded' for fractal_audit_log when absent, got: $rd_dormant"

  local rd_portfolio_still_works
  rd_portfolio_still_works=$("${PSQL[@]}" -c "SELECT fractal_optimize_portfolio(ARRAY[0.1,0.05,0.08]::float8[], ARRAY[0.04,0.01,0.01, 0.01,0.03,0.01, 0.01,0.01,0.05]::float8[], 2);" 2>&1)
  grep <<< "$rd_portfolio_still_works" -q "ERROR:" \
    && fail "24 enterprise: fractal_optimize_portfolio broke on community (no enterprise lib): $rd_portfolio_still_works" \
    || pass "24 enterprise: fractal_optimize_portfolio (community feature) keeps working with the enterprise library absent"

  # Phase E: representative sample of the newly-wired agent bindings --
  # confirm each writes a correctly-typed kind=2 row when enterprise is
  # active. Gate 23 already proves all 11 candidates behave identically
  # (best-effort no-op) on community; this proves the enterprise side of
  # the same bindings actually fires.
  set_ent_guc "$abs"
  latest_audit_type() {
    "${PSQL[@]}" -tA -c "
      SELECT convert_from(blob, 'UTF8')::jsonb->>'type'
        FROM fractalsql_ledger WHERE kind = 2
        ORDER BY id DESC LIMIT 1;" 2>/dev/null
  }

  "${PSQL[@]}" -c "
     DROP TABLE IF EXISTS bt_gate24_history;
     CREATE TABLE bt_gate24_history (id int PRIMARY KEY, emb float8[]);
     INSERT INTO bt_gate24_history VALUES (1, ARRAY[0.1,0.2,0.3]);" >/dev/null 2>&1
  "${PSQL[@]}" -c "
     SELECT * FROM fractal_agent_outlier_intercept(
       ARRAY[0.1,0.2,0.3]::float8[], 'bt_gate24_history', 'emb', 0.5);" >/dev/null 2>&1
  [[ "$(latest_audit_type)" = "agent_outlier_intercept" ]] \
    && pass "24 enterprise: fractal_agent_outlier_intercept logs a provenance record to the audit chain" \
    || fail "24 enterprise: expected agent_outlier_intercept in the latest kind=2 row"

  "${PSQL[@]}" -c "
     DROP TABLE IF EXISTS bt_gate24_data;
     CREATE TABLE bt_gate24_data (id int PRIMARY KEY, val float8);
     INSERT INTO bt_gate24_data VALUES (1,10.5),(2,20.5);" >/dev/null 2>&1
  "${PSQL[@]}" -c "
     SELECT * FROM fractal_agent_data_analyst(
       'sum of val', ARRAY['bt_gate24_data'], 2);" >/dev/null 2>&1
  [[ "$(latest_audit_type)" = "agent_data_analyst" ]] \
    && pass "24 enterprise: fractal_agent_data_analyst logs a provenance record to the audit chain" \
    || fail "24 enterprise: expected agent_data_analyst in the latest kind=2 row"

  # fractal_agent_diverse_portfolios (enterprise-only gap-fix binding) --
  # both the C-side portfolio_optimize_multimodal entry and the agent-level
  # entry must land (same double-logging pattern as allocate/rebalance).
  "${PSQL[@]}" -c "
     SELECT * FROM fractal_agent_diverse_portfolios(
       ARRAY[0.1,0.05,0.08]::float8[],
       ARRAY[0.04,0.01,0.01, 0.01,0.03,0.01, 0.01,0.01,0.05]::float8[], 2, 4);" >/dev/null 2>&1
  local rd_diverse_types
  rd_diverse_types=$("${PSQL[@]}" -tA -c "
    SELECT convert_from(blob, 'UTF8')::jsonb->>'type'
      FROM fractalsql_ledger WHERE kind = 2
      ORDER BY id DESC LIMIT 2;" 2>/dev/null)
  grep <<< "$rd_diverse_types" -q "agent_diverse_portfolios" \
    && grep <<< "$rd_diverse_types" -q "portfolio_optimize_multimodal" \
    && pass "24 enterprise: fractal_agent_diverse_portfolios + fractal_optimize_portfolio_multimodal both log (double-logging, gap-fix binding)" \
    || fail "24 enterprise: expected both agent_diverse_portfolios and portfolio_optimize_multimodal in the last 2 kind=2 rows, got: $rd_diverse_types"

  # Reset the GUC so it does not leak into later gates on a reused cluster.
  set_ent_guc ""
}

gate_25_enterprise_stress() {
  # Enterprise QTL ledger under stress + tamper-evidence + concurrency.
  # Self-skips on a community-only checkout (same detection as gate 24).
  # Gate 24 covers the basic active/dormant wiring; this gate exercises the
  # ledger at its capacity bound, under repeated churn, against a corrupted
  # blob, and under concurrent + cross-backend access.
  local ent_so
  ent_so=$(ls include/*/libfractalsql-enterprise-sovereign-c.so include/*/libfractalsql-enterprise-sovereign-c.dylib 2>/dev/null | head -1)
  if [[ -z "$ent_so" ]]; then
    skip "25 enterprise-stress: skipped (community edition; no libfractalsql-enterprise-sovereign-c.* in include/)"
    return
  fi
  local abs
  abs=$(cd "$(dirname "$ent_so")" && pwd)/$(basename "$ent_so")

  # PGC_SIGHUP GUC -- same apply-and-poll helper as gate 24.
  local v
  set_ent_guc() {
    local val="$1" want="$1"
    "${PSQL[@]}" -c "ALTER SYSTEM SET fractalsql.enterprise_lib = '$val';" >/dev/null 2>&1
    "${PSQL[@]}" -c "SELECT pg_reload_conf();" >/dev/null 2>&1
    for _ in 1 2 3 4 5 6 7 8 9 10; do
      v=$("${PSQL[@]}" -tA -c "SHOW fractalsql.enterprise_lib;" 2>/dev/null)
      [[ "$v" = "$want" ]] && return
      sleep 0.3
    done
  }

  set_ent_guc "$abs"
  if [[ "$v" != "$abs" ]]; then
    fail "25 enterprise-stress: could not apply fractalsql.enterprise_lib (got '$v')"
    set_ent_guc ""
    return
  fi

  # Clean slate for the gate.
  "${PSQL[@]}" -c "DROP TABLE IF EXISTS fractalsql_ledger;" >/dev/null 2>&1

  # ---- Phase A: stress -- fill-to-cap (64 truth + 64 shadow = 128) + churn.
  # Truth/Shadow each cap at 64 (FSQL_TRUTH/SHADOW_DEFAULT_CAP); beyond that
  # the lowest-weight entry is evicted. 64+64 with disjoint doc_ids encodes
  # all 128 (no QTL dedup). Churn = 10 reset+reseed+flush+load cycles.
  local ra
  ra=$("${PSQL[@]}" 2>&1 <<'SQL'
SELECT fractal_diversify_enable();
DO $$
DECLARE i int; c int; tc bigint; sc bigint; ev int; audit jsonb;
BEGIN
  PERFORM fractal_ledger_reset_hard();
  FOR i IN 1..64 LOOP PERFORM fractal_feedback_report(i, 'positive'); END LOOP;
  FOR i IN 65..128 LOOP PERFORM fractal_feedback_report(i, 'negative'); END LOOP;
  SELECT fractal_ledger_truth_count()  INTO tc;
  SELECT fractal_ledger_shadow_count() INTO sc;
  PERFORM fractal_ledger_flush();
  SELECT fractal_audit_unpack(blob) INTO audit FROM fractalsql_ledger WHERE kind = 1 ORDER BY id DESC LIMIT 1;
  ev := jsonb_array_length(audit);
  IF tc <> 64 OR sc <> 64 OR ev <> 128 THEN
    RAISE EXCEPTION 'A fill mismatch: truth=% shadow=% events=%', tc, sc, ev;
  END IF;
  FOR c IN 1..10 LOOP
    PERFORM fractal_ledger_reset_hard();
    FOR i IN 1..64  LOOP PERFORM fractal_feedback_report(i + 1000*c, 'positive'); END LOOP;
    FOR i IN 65..128 LOOP PERFORM fractal_feedback_report(i + 1000*c, 'negative'); END LOOP;
    PERFORM fractal_ledger_flush();
    PERFORM fractal_ledger_load();
  END LOOP;
  SELECT fractal_ledger_truth_count()  INTO tc;
  SELECT fractal_ledger_shadow_count() INTO sc;
  SELECT fractal_audit_unpack(blob) INTO audit FROM fractalsql_ledger WHERE kind = 1 ORDER BY id DESC LIMIT 1;
  ev := jsonb_array_length(audit);
  IF tc <> 64 OR sc <> 64 OR ev <> 128 THEN
    RAISE EXCEPTION 'A churn mismatch: truth=% shadow=% events=%', tc, sc, ev;
  END IF;
END $$;
SQL
)
  if grep <<< "$ra" -q "ERROR:"; then
    fail "25 enterprise-stress Phase A: fill-to-cap/churn errored: $ra"
  else
    pass "25 enterprise-stress Phase A: fill-to-cap (64+64=128) + 10 flush/load churn cycles, audit round-trips 128 events"
  fi

  # ---- Phase B: tamper-evidence (structural). Truncate the persisted QTL
  # blob below the 24-byte header and assert load rejects it. NOTE: the QTL
  # format carries no CRC/MAC and ledger_seal_ledger is a no-op, so this is
  # STRUCTURAL tamper-evidence only -- a targeted payload byte-flip is NOT
  # caught. The gate asserts the structural case and documents the gap.
  "${PSQL[@]}" -c "DROP TABLE IF EXISTS fractalsql_ledger;" >/dev/null 2>&1
  local rb
  rb=$("${PSQL[@]}" 2>&1 <<'SQL'
SELECT fractal_diversify_enable();
SELECT fractal_ledger_reset_hard();
SELECT fractal_feedback_report(1, 'positive');
SELECT fractal_feedback_report(2, 'negative');
SELECT fractal_ledger_flush();
UPDATE fractalsql_ledger SET blob = substring(blob from 1 for 5) WHERE id = (SELECT max(id) FROM fractalsql_ledger WHERE kind = 1);
SELECT fractal_ledger_load();
SQL
)
  # B-full's entry_hash covers the blob unconditionally (no key required),
  # so this UPDATE is now caught by ledger_verify_latest()'s chain-hash
  # check BEFORE the core's own structural decode ever runs -- a strictly
  # earlier, and now always-active, layer of the same tamper-evidence.
  # Accept either message: the core's structural rejection is still the
  # fallback for anything that somehow gets past the chain-hash check.
  if grep <<< "$rb" -q "ERROR:" && grep <<< "$rb" -qE "fsql_ledger_load|ledger chain verification failed"; then
    pass "25 enterprise-stress Phase B: structural tamper (truncated QTL blob) rejected by load"
  else
    fail "25 enterprise-stress Phase B: expected load to reject a truncated blob, got: $rb"
  fi

  # ---- Phase C: concurrency.
  # (a) Cross-session persistence: seed+flush in one backend, load+count in
  #     a FRESH backend; counts must match (proves the table-backed VFS is
  #     backend-independent, not in-memory only).
  # (b) 8 concurrent backends each seed one event + flush. Under B-full's
  #     append-only chain this correctly produces MULTIPLE rows (B-lite's
  #     UPSERT collapsed concurrent flushes into one; that behavior is
  #     gone by design). The invariant now is that the chain stays a
  #     single unforked line despite the concurrency -- ledger_write_entry's
  #     advisory xact lock (keyed on kind) serializes the "read head, link,
  #     insert" sequence -- and the latest blob still decodes cleanly.
  "${PSQL[@]}" -c "DROP TABLE IF EXISTS fractalsql_ledger;" >/dev/null 2>&1
  # NOTE: seed+flush MUST run as -c/-c/-c... within a SINGLE psql
  # invocation (one backend, one g_ctx) -- each separate "${PSQL[@]}" -c
  # call below would otherwise open its own connection/backend, so the
  # in-memory truth/shadow ledgers from one call would never be visible
  # to the next and fractal_ledger_flush() would persist an EMPTY
  # ledger (the cross-session load then correctly reports 0|0, which
  # silently masked this rather than erroring).
  "${PSQL[@]}" \
    -c "SELECT fractal_diversify_enable();" \
    -c "SELECT fractal_ledger_reset_hard();" \
    -c "SELECT fractal_feedback_report(g, 'positive') FROM generate_series(1,10) g;" \
    -c "SELECT fractal_feedback_report(g, 'negative') FROM generate_series(11,20) g;" \
    -c "SELECT fractal_ledger_flush();" >/dev/null 2>&1
  local cross
  cross=$("${PSQL[@]}" -c "SELECT fractal_ledger_load(); SELECT fractal_ledger_truth_count() AS t, fractal_ledger_shadow_count() AS s;" 2>&1)
  if grep <<< "$cross" -q "10|10"; then
    pass "25 enterprise-stress Phase C(a): cross-session persistence -- fresh backend loaded 10/10 from the persisted blob"
  else
    fail "25 enterprise-stress Phase C(a): expected 10|10 after cross-session load, got: $cross"
  fi

  # 8 concurrent workers, each: seed one event + flush. Fresh chain (drop
  # first) so the row count is self-contained regardless of what earlier
  # phases left behind; pre-flush one row before the workers start so they
  # write to an EXISTING chain, avoiding the concurrent CREATE TABLE IF NOT
  # EXISTS race on pg_class. feedback_report inserts unconditionally, so
  # workers need not re-enable diversify. Invariant: 9 rows total (1
  # pre-flush + 8 concurrent), the chain verifies as a single unforked
  # line, and the latest blob decodes.
  "${PSQL[@]}" -c "DROP TABLE IF EXISTS fractalsql_ledger;" >/dev/null 2>&1
  "${PSQL[@]}" -c "SELECT fractal_diversify_enable(); SELECT fractal_feedback_report(0, 'positive'); SELECT fractal_ledger_flush();" >/dev/null 2>&1
  local w
  for w in 1 2 3 4 5 6 7 8; do
    "${PSQL[@]}" -c "SELECT fractal_feedback_report($w, 'positive'); SELECT fractal_ledger_flush();" >/dev/null 2>&1 &
  done
  wait
  local rows verify_full verify_ok latest_decode
  rows=$("${PSQL[@]}" -tA -c "SELECT count(*) FROM fractalsql_ledger WHERE kind = 1;" 2>/dev/null)
  verify_full=$("${PSQL[@]}" -tA -c "SELECT fractal_ledger_verify()::text;" 2>/dev/null)
  verify_ok=$("${PSQL[@]}" -tA -c "SELECT fractal_ledger_verify()->>'ok';" 2>/dev/null)
  latest_decode=$("${PSQL[@]}" -c "SELECT fractal_audit_unpack(blob)::text FROM fractalsql_ledger WHERE kind = 1 ORDER BY id DESC LIMIT 1;" 2>&1)
  if [[ "$rows" = "9" ]] && [[ "$verify_ok" = "true" ]] && ! grep <<< "$latest_decode" -q "ERROR:"; then
    pass "25 enterprise-stress Phase C(b): 8 concurrent flushes -> 9 append-only rows, chain verifies as one unforked line, latest blob decodes"
  else
    fail "25 enterprise-stress Phase C(b): expected 9 linked rows + clean decode after parallel flush, got rows=$rows verify=$verify_full decode=$latest_decode"
  fi

  # ---- Phase D: MAC-authenticated tamper-evidence (enterprise_ledger_key).
  # Phases A-C ran with the key UNSET (structural path). D sets the key
  # (PGC_SUSET -> SET per-session, no reload): flush tags the blob with
  # HMAC-SHA256 (assert length(mac)=32), load verifies; a middle payload
  # byte-flip (length + count preserved -> structural check blind to it) is
  # rejected by the MAC; re-flush re-tags and load verifies clean. This is
  # B-lite: the MAC lives in the open extension at the storage seam; the
  # enterprise core is unchanged and is never handed tampered bytes.
  "${PSQL[@]}" -c "DROP TABLE IF EXISTS fractalsql_ledger;" >/dev/null 2>&1
  local rd
  rd=$("${PSQL[@]}" 2>&1 <<'SQL'
SET fractalsql.enterprise_ledger_key = 'gate25-mac-key';
DO $$
DECLARE mac_len int;
BEGIN
  PERFORM fractal_diversify_enable();
  PERFORM fractal_ledger_reset_hard();
  PERFORM fractal_feedback_report(1, 'positive');
  PERFORM fractal_ledger_flush();
  SELECT length(mac) INTO mac_len FROM fractalsql_ledger WHERE kind = 1 ORDER BY id DESC LIMIT 1;
  IF mac_len IS NULL OR mac_len <> 32 THEN
    RAISE EXCEPTION 'D tag mismatch: mac length = % (expected 32)', mac_len;
  END IF;
  PERFORM fractal_ledger_load();                 -- MAC verifies -> ok
  -- tamper: flip a middle payload byte the structural check cannot see
  UPDATE fractalsql_ledger
     SET blob = set_byte(blob, length(blob) / 2, 254)
   WHERE id = (SELECT max(id) FROM fractalsql_ledger WHERE kind = 1);
  BEGIN
    PERFORM fractal_ledger_load();
    RAISE EXCEPTION 'D tamper NOT detected: load accepted a byte-flipped blob';
  EXCEPTION
    WHEN internal_error THEN
      RAISE NOTICE 'D tamper detected by HMAC (byte-flip rejected)';
  END;
  -- recovery: re-flush re-tags; load verifies clean
  PERFORM fractal_ledger_reset_hard();
  PERFORM fractal_feedback_report(1, 'positive');
  PERFORM fractal_ledger_flush();
  PERFORM fractal_ledger_load();
EXCEPTION
  WHEN object_not_in_prerequisite_state THEN
    RAISE EXCEPTION 'D enterprise not loaded';
END $$;
RESET fractalsql.enterprise_ledger_key;
SQL
)
  if grep <<< "$rd" -q "D tamper detected by HMAC"; then
    pass "25 enterprise-stress Phase D: HMAC MAC tags blob (32B), rejects a structural-blind byte-flip, re-flush re-tags cleanly"
  else
    fail "25 enterprise-stress Phase D: MAC path did not behave as expected: $rd"
  fi

  # ---- Phase E: B-full append-only chain -- multi-row verify, a MIDDLE-row
  # tamper that fractal_ledger_load()'s O(1) tip-only check cannot see but
  # fractal_ledger_verify()'s full O(n) walk catches, and a deleted-row gap.
  # NOTE (documented limitation, not tested here): a chain can prove nothing
  # in the MIDDLE was altered/removed, but it cannot prove nothing was
  # truncated off the very END -- there is nothing after the last surviving
  # row to notice its absence. That needs an external anchor (e.g. publishing
  # the head hash somewhere independent), out of scope here.
  "${PSQL[@]}" -c "DROP TABLE IF EXISTS fractalsql_ledger;" >/dev/null 2>&1
  local re
  re=$("${PSQL[@]}" 2>&1 <<'SQL'
DO $$
DECLARE v jsonb;
BEGIN
  PERFORM fractal_diversify_enable();
  PERFORM fractal_ledger_reset_hard();
  PERFORM fractal_feedback_report(1, 'positive'); PERFORM fractal_ledger_flush();
  PERFORM fractal_ledger_reset_hard();
  PERFORM fractal_feedback_report(2, 'positive'); PERFORM fractal_ledger_flush();
  PERFORM fractal_ledger_reset_hard();
  PERFORM fractal_feedback_report(3, 'positive'); PERFORM fractal_ledger_flush();

  SELECT fractal_ledger_verify() INTO v;
  IF NOT (v->>'ok')::boolean OR (v->>'rows_verified')::int <> 3 THEN
    RAISE EXCEPTION 'E chain mismatch after 3 flushes: %', v;
  END IF;
  RAISE NOTICE 'E verify: 3/3 rows clean after 3 flushes';

  -- Tamper a MIDDLE row (id=2), not the latest (id=3).
  UPDATE fractalsql_ledger SET blob = set_byte(blob, 0, 254) WHERE id = 2;

  -- load() only checks the tip (id=3) -- still succeeds. Documents the
  -- intentional O(1) scope boundary.
  PERFORM fractal_ledger_load();
  RAISE NOTICE 'E load: still passes after a MIDDLE-row tamper (O(1) tip-only scope)';

  -- the full walk done by verify() catches it.
  SELECT fractal_ledger_verify() INTO v;
  IF (v->>'ok')::boolean OR (v->>'first_failure_id')::int <> 2 THEN
    RAISE EXCEPTION 'E verify() did not catch the middle-row tamper: %', v;
  END IF;
  RAISE NOTICE 'E verify: caught middle-row tamper at id=2 (%)', v->>'reason';
END $$;
SQL
)
  if grep <<< "$re" -q "E verify: 3/3 rows clean" \
     && grep <<< "$re" -q "E load: still passes" \
     && grep <<< "$re" -q "E verify: caught middle-row tamper"; then
    pass "25 enterprise-stress Phase E: B-full chain -- multi-row verify, middle-row tamper undetected by load but caught by verify()"
  else
    fail "25 enterprise-stress Phase E: B-full chain checks did not behave as expected: $re"
  fi

  # Phase E continued: deleting a MIDDLE row leaves a visible id-sequence gap.
  "${PSQL[@]}" -c "DROP TABLE IF EXISTS fractalsql_ledger;" >/dev/null 2>&1
  local rg
  rg=$("${PSQL[@]}" 2>&1 <<'SQL'
DO $$
DECLARE v jsonb;
BEGIN
  PERFORM fractal_diversify_enable();
  PERFORM fractal_ledger_reset_hard();
  PERFORM fractal_feedback_report(1, 'positive'); PERFORM fractal_ledger_flush();
  PERFORM fractal_ledger_reset_hard();
  PERFORM fractal_feedback_report(2, 'positive'); PERFORM fractal_ledger_flush();
  PERFORM fractal_ledger_reset_hard();
  PERFORM fractal_feedback_report(3, 'positive'); PERFORM fractal_ledger_flush();

  DELETE FROM fractalsql_ledger WHERE id = 2;

  SELECT fractal_ledger_verify() INTO v;
  IF (v->>'ok')::boolean OR (v->>'reason' NOT LIKE '%gap%') THEN
    RAISE EXCEPTION 'E deletion gap not detected: %', v;
  END IF;
  RAISE NOTICE 'E verify: caught deletion gap (%)', v->>'reason';
END $$;
SQL
)
  if grep <<< "$rg" -q "E verify: caught deletion gap"; then
    pass "25 enterprise-stress Phase E: deleting a middle row leaves a visible id-sequence gap, caught by verify()"
  else
    fail "25 enterprise-stress Phase E: deletion gap detection did not behave as expected: $rg"
  fi

  # Phase E continued: migrating an existing B-lite-shaped table (kind PK,
  # no id/prev_hash/entry_hash) -- expect a NOTICE and a clean fresh chain,
  # not an error. Nothing worth preserving from that shape (last-writer-wins,
  # no real history), so this is an intentional reset, not data loss.
  "${PSQL[@]}" -c "DROP TABLE IF EXISTS fractalsql_ledger;" >/dev/null 2>&1
  "${PSQL[@]}" -c "
    CREATE TABLE fractalsql_ledger (
      kind    integer PRIMARY KEY,
      blob    bytea   NOT NULL,
      mac     bytea,
      sealed  boolean NOT NULL DEFAULT false,
      updated timestamptz NOT NULL DEFAULT now()
    );
    INSERT INTO fractalsql_ledger (kind, blob) VALUES (1, '\x00'::bytea);
  " >/dev/null 2>&1
  local rm
  rm=$("${PSQL[@]}" -c "SELECT fractal_diversify_enable(); SELECT fractal_ledger_reset_hard(); SELECT fractal_feedback_report(1, 'positive'); SELECT fractal_ledger_flush();" 2>&1)
  local rm_verify
  rm_verify=$("${PSQL[@]}" -c "SELECT fractal_ledger_verify();" 2>&1)
  if grep <<< "$rm" -q "migrating fractalsql_ledger from the single-row snapshot schema" \
     && grep <<< "$rm_verify" -q '"ok": *true'; then
    pass "25 enterprise-stress Phase E: single-row-snapshot -> append-only-chain schema migration -- NOTICE fires, fresh chain verifies clean"
  else
    fail "25 enterprise-stress Phase E: migration did not behave as expected: flush=$rm verify=$rm_verify"
  fi

  # Reset the GUC so it does not leak into later gates on a reused cluster.
  set_ent_guc ""
}

gate_26_enterprise_signature() {
  # Detached Ed25519 signature verification for the enterprise .so
  # (fractalsql.enterprise_require_signature). Self-skips on a
  # community-only checkout, same detection as gates 24/25.
  #
  # This gate deliberately does NOT test the "valid signature, actually
  # verifies" happy path -- that requires the matching private key, which
  # is FractalSQLabs's release-process secret and does not belong in this
  # repo or its test fixtures (a checked-in test key would misrepresent
  # key custody). That path was validated manually against a throwaway
  # keypair during development -- gate 24 passing with a real matching
  # .sig staged alongside the .so is the evidence (see fractalsql.c's
  # FSQL_ENTERPRISE_PUBKEY comment). What's tested here needs no key at
  # all: a missing .sig (soft unless require=on) and an invalid .sig
  # (always hard-refused, regardless of require).
  local ent_so
  ent_so=$(ls include/*/libfractalsql-enterprise-sovereign-c.so include/*/libfractalsql-enterprise-sovereign-c.dylib 2>/dev/null | head -1)
  if [[ -z "$ent_so" ]]; then
    skip "26 enterprise-signature: skipped (community edition; no libfractalsql-enterprise-sovereign-c.* in include/)"
    return
  fi
  local abs sig_path
  abs=$(cd "$(dirname "$ent_so")" && pwd)/$(basename "$ent_so")
  sig_path="${abs}.sig"
  rm -f "$sig_path"

  local v
  set_ent_guc() {
    local val="$1" want="$1"
    "${PSQL[@]}" -c "ALTER SYSTEM SET fractalsql.enterprise_lib = '$val';" >/dev/null 2>&1
    "${PSQL[@]}" -c "SELECT pg_reload_conf();" >/dev/null 2>&1
    for _ in 1 2 3 4 5 6 7 8 9 10; do
      v=$("${PSQL[@]}" -tA -c "SHOW fractalsql.enterprise_lib;" 2>/dev/null)
      [[ "$v" = "$want" ]] && return
      sleep 0.3
    done
  }
  set_require() {
    local rval="$1" want_r="$1" vr
    "${PSQL[@]}" -c "ALTER SYSTEM SET fractalsql.enterprise_require_signature = $rval;" >/dev/null 2>&1
    "${PSQL[@]}" -c "SELECT pg_reload_conf();" >/dev/null 2>&1
    for _ in 1 2 3 4 5 6 7 8 9 10; do
      vr=$("${PSQL[@]}" -tA -c "SHOW fractalsql.enterprise_require_signature;" 2>/dev/null)
      [[ "$vr" = "$want_r" ]] && return
      sleep 0.3
    done
  }

  set_ent_guc "$abs"
  if [[ "$v" != "$abs" ]]; then
    fail "26 enterprise-signature: could not apply fractalsql.enterprise_lib (got '$v')"
    return
  fi

  # ---- Case A: no .sig, require=off (default) -- soft: WARNING logged,
  # library still loads and works.
  set_require "off"
  local ra
  ra=$("${PSQL[@]}" -c "SELECT fractal_ledger_reset_hard();" 2>&1)
  if grep <<< "$ra" -q "no signature found for enterprise library" \
     && ! grep <<< "$ra" -q "enterprise tier not loaded"; then
    pass "26 enterprise-signature Case A: missing .sig + require=off -- WARNS but still loads"
  else
    fail "26 enterprise-signature Case A: expected a WARN-and-load, got: $ra"
  fi

  # ---- Case B: no .sig, require=on -- hard: refused.
  set_require "on"
  local rb
  rb=$("${PSQL[@]}" -c "SELECT fractal_ledger_reset_hard();" 2>&1)
  if grep <<< "$rb" -q "no signature found for enterprise library" \
     && grep <<< "$rb" -q "enterprise tier not loaded"; then
    pass "26 enterprise-signature Case B: missing .sig + require=on -- refused"
  else
    fail "26 enterprise-signature Case B: expected a hard refusal, got: $rb"
  fi

  # ---- Case C: invalid/garbage .sig (64 random bytes, matches no key) --
  # always refused, even with require=off.
  set_require "off"
  head -c 64 /dev/urandom > "$sig_path"
  local rc
  rc=$("${PSQL[@]}" -c "SELECT fractal_ledger_reset_hard();" 2>&1)
  if grep <<< "$rc" -q "failed signature verification" \
     && grep <<< "$rc" -q "enterprise tier not loaded"; then
    pass "26 enterprise-signature Case C: invalid .sig -- always refused regardless of require setting"
  else
    fail "26 enterprise-signature Case C: expected a hard refusal on invalid signature, got: $rc"
  fi
  rm -f "$sig_path"

  # Reset the GUCs so they do not leak into later gates on a reused cluster.
  set_require "off"
  set_ent_guc ""
}

# Reasoning-effort (THINK) GUC passthrough -- fractalsql.http_think/
# http_think_provider/http_native_url/http_num_ctx reach the plugin's
# process environment correctly (Case A/B), and never leak into
# fractal_embed()'s tier even when set (Case C, proving
# ensure_embed_ctx()'s explicit unsetenv() calls actually work). Each
# case uses a fresh "${PSQL[@]}" -c invocation deliberately -- a new
# backend process per call, so g_reason_loaded/g_embed_loaded (per-
# backend statics) start false and ensure_*_ctx() actually re-applies
# the current GUC values instead of short-circuiting on an earlier
# call's cached load.
gate_27_think() {
  pg_swap_plugin "$THINK" || { fail "27 think: plugin swap did not take effect"; return; }
  local dump=/tmp/fractalsql_bt_think_dump.txt

  # Case A: all four unset -- byte-identical to pre-v1.4.0 behavior.
  pg_set_guc fractalsql.http_think "''" "" || { fail "27 think: reset http_think"; pg_swap_plugin "$MOCK"; return; }
  pg_set_guc fractalsql.http_think_provider "''" "" || { fail "27 think: reset http_think_provider"; pg_swap_plugin "$MOCK"; return; }
  pg_set_guc fractalsql.http_native_url "''" "" || { fail "27 think: reset http_native_url"; pg_swap_plugin "$MOCK"; return; }
  pg_set_guc fractalsql.http_num_ctx 0 0 || { fail "27 think: reset http_num_ctx"; pg_swap_plugin "$MOCK"; return; }
  rm -f "$dump"
  "${PSQL[@]}" -c "SELECT fractal_reason('q');" >/dev/null 2>&1
  local a; a=$(cat "$dump" 2>/dev/null)
  if grep <<< "$a" -q "^THINK=(unset)$" && grep <<< "$a" -q "^THINK_PROVIDER=(unset)$" \
     && grep <<< "$a" -q "^NATIVE_URL=(unset)$" && grep <<< "$a" -q "^NUM_CTX=(unset)$"; then
    pass "27 think Case A: all four GUCs unset -> no THINK-related env var reaches the plugin"
  else
    fail "27 think Case A: expected all four (unset), got: $a"
  fi

  # Case B: set all four -- each reaches the plugin's environment via
  # fractal_reason() (ensure_reason_ctx()'s apply_think_env()).
  pg_set_guc fractalsql.http_think "'medium'" "medium" || { fail "27 think: set http_think"; pg_swap_plugin "$MOCK"; return; }
  pg_set_guc fractalsql.http_think_provider "'ollama'" "ollama" || { fail "27 think: set http_think_provider"; pg_swap_plugin "$MOCK"; return; }
  pg_set_guc fractalsql.http_native_url "'http://127.0.0.1:9/native'" "http://127.0.0.1:9/native" \
    || { fail "27 think: set http_native_url"; pg_swap_plugin "$MOCK"; return; }
  pg_set_guc fractalsql.http_num_ctx 8192 8192 || { fail "27 think: set http_num_ctx"; pg_swap_plugin "$MOCK"; return; }
  rm -f "$dump"
  "${PSQL[@]}" -c "SELECT fractal_reason('q');" >/dev/null 2>&1
  local b; b=$(cat "$dump" 2>/dev/null)
  if grep <<< "$b" -q "^THINK=medium$" && grep <<< "$b" -q "^THINK_PROVIDER=ollama$" \
     && grep <<< "$b" -q "^NATIVE_URL=http://127.0.0.1:9/native$" && grep <<< "$b" -q "^NUM_CTX=8192$"; then
    pass "27 think Case B: all four GUCs reach the plugin via fractal_reason()"
  else
    fail "27 think Case B: expected THINK=medium/THINK_PROVIDER=ollama/NATIVE_URL=http://127.0.0.1:9/native/NUM_CTX=8192, got: $b"
  fi

  # Case C: fractal_text_to_sql()'s GENERATE step forwards the same four
  # (apply_think_env() is shared between ensure_reason_ctx() and
  # ensure_text_to_sql_ctx()) -- the mock's canned "OK" response isn't
  # a fenced SQL block, so this call is expected to error; only the
  # dump file (written before that error, at format_prompt() time) is
  # under test here.
  rm -f "$dump"
  "${PSQL[@]}" -c "SELECT fractal_text_to_sql('q', ARRAY['bt_customers']);" >/dev/null 2>&1
  local c; c=$(cat "$dump" 2>/dev/null)
  if grep <<< "$c" -q "^THINK=medium$" && grep <<< "$c" -q "^THINK_PROVIDER=ollama$"; then
    pass "27 think Case C: fractal_text_to_sql()'s GENERATE step also forwards THINK/THINK_PROVIDER"
  else
    fail "27 think Case C: expected THINK=medium/THINK_PROVIDER=ollama from the GENERATE step, got: $c"
  fi

  # Case D: fractal_embed() never sees THINK vars even with the GUCs
  # still set from Case B/C -- proves ensure_embed_ctx()'s explicit
  # unsetenv() calls, not just "embed happens not to set them".
  pg_set_guc fractalsql.http_embed_url "'http://unused/embeddings'" "http://unused/embeddings" \
    || { fail "27 think Case D: http_embed_url GUC did not take effect"; pg_swap_plugin "$MOCK"; return; }
  rm -f "$dump"
  "${PSQL[@]}" -c "SELECT fractal_embed('test input');" >/dev/null 2>&1
  local d; d=$(cat "$dump" 2>/dev/null)
  if grep <<< "$d" -q "^THINK=(unset)$" && grep <<< "$d" -q "^THINK_PROVIDER=(unset)$" \
     && grep <<< "$d" -q "^NATIVE_URL=(unset)$" && grep <<< "$d" -q "^NUM_CTX=(unset)$"; then
    pass "27 think Case D: fractal_embed() never sees THINK vars, even with the GUCs still set"
  else
    fail "27 think Case D: expected all four (unset) in the embed tier, got: $d"
  fi

  # Reset the GUCs so they do not leak into later gates on a reused cluster.
  pg_set_guc fractalsql.http_think "''" ""
  pg_set_guc fractalsql.http_think_provider "''" ""
  pg_set_guc fractalsql.http_native_url "''" ""
  pg_set_guc fractalsql.http_num_ctx 0 0
  pg_swap_plugin "$MOCK"
}

run_major() {
  local v="$1"; shift
  local gates=("$@")
  printf "== PG%s ==\n" "$v"
  # gate 01 (build) and gate 21 (fuzz smoke) always run standalone (no
  # cluster) -- gate 21 links the pure-C parsers directly, no postgres
  # backend involved at all.
  for g in "${gates[@]}"; do [[ "$g" = "01" ]] && gate_01_build "$v"; done
  for g in "${gates[@]}"; do [[ "$g" = "21" ]] && gate_21_fuzz_smoke; done
  # gates 02-20 need a live cluster
  local need_db=0
  for g in "${gates[@]}"; do
    case "$g" in
      02|03|04|05|06|07|08|09|10|11|12|13|14|15|16|17|18|19|20|22|23|24|25|26|27) need_db=1 ;;
      *) ;;   # 01/21 run standalone above, no DB needed -- intentional no-op
    esac
  done
  if [[ "$need_db" -eq 1 ]]; then
    pg_setup "$v"; local rc=$?
    if [[ "$rc" -eq 1 ]]; then skip "PG$v runtime gates (server binaries absent)"; return; fi
    if [[ "$rc" -eq 3 ]]; then return; fi   # pg_setup already printed its own skip() message
    if [[ "$rc" -ne 0 ]]; then fail "PG$v cluster setup"; return; fi
    # gate 03 creates bt_customers/bt_orders; several later gates
    # (04, 05, 07, 08, 10) depend on that fixture already existing, so
    # ensure it exists even if 03 wasn't explicitly requested.
    local have_03=0
    for g in "${gates[@]}"; do [[ "$g" = "03" ]] && have_03=1; done
    [[ "$have_03" -eq 0 ]] && gate_03_schema_context >/dev/null
    for g in "${gates[@]}"; do
      case "$g" in
        02) gate_02_smoke ;;
        03) gate_03_schema_context ;;
        04) gate_04_text_to_sql ;;
        05) gate_05_evil_overread ;;
        06) gate_06_crash_recovery ;;
        07) gate_07_evil_lying_length ;;
        08) gate_08_authz ;;
        09) gate_09_guc_superuser ;;
        10) gate_10_dos_and_injection ;;
        11) gate_11_scout ;;
        12) gate_12_soak ;;
        13) gate_13_siu_mode ;;
        14) gate_14_retry ;;
        15) gate_15_embed ;;
        16) gate_16_embed_authz ;;
        17) gate_17_embed_soak ;;
        18) gate_18_embed_crash ;;
        19) gate_19_sfs_bounds ;;
        20) gate_20_api_func ;;
        22) gate_22_v2_functions ;;
        23) gate_23_agents ;;
        24) gate_24_enterprise ;;
        25) gate_25_enterprise_stress ;;
        26) gate_26_enterprise_signature ;;
        27) gate_27_think ;;
        *) ;;   # 01/21 already ran standalone above, no-op here by design
      esac
    done
    pg_teardown
  fi
}

# --- dispatch ---------------------------------------------------------
if [[ -n "$ONE_GATE" ]]; then
  run_major "$PG_MAJOR" "$ONE_GATE"
elif [[ "$MODE" = "quick" ]]; then
  run_major "$PG_MAJOR" "${QUICK_GATES[@]}"
elif [[ "$MODE" = "cross" ]]; then
  for v in 14 15 16 17 18; do run_major "$v" "${DEFAULT_GATES[@]}"; done
elif [[ "$MODE" = "fuzz" ]]; then
  run_major "$PG_MAJOR" "${FUZZ_GATES[@]}"
else
  run_major "$PG_MAJOR" "${DEFAULT_GATES[@]}"
fi

[[ "$COVERAGE" -eq 1 ]] && run_coverage_report

echo ""
if [[ "$FAILED" -eq 0 ]]; then printf "${G}build_test: PASS${Z}\n"; exit 0
else printf "${R}build_test: FAIL${Z}\n"; exit 1; fi
