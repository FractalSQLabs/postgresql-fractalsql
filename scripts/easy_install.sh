#!/bin/bash
#
# scripts/easy_install.sh
#
# The "easy button" for FractalSQL. One command gets you from a bare
# Linux or macOS box to a running install with reasoning configured.
#
# Usage (fresh machine, nothing installed yet):
#   curl -fsSL https://github.com/FractalSQLabs/fractalsql-postgresql/releases/latest/download/easy_install.sh | bash
#
# Usage (package already installed via apt/dnf/tarball yourself):
#   ./easy_install.sh              # detects it, skips straight to the wizard
#
# Flags (all optional. Anything you omit gets asked interactively):
#   --pg <major>              target PG major when several are installed
#   --port <port>              override the auto-detected port, if it guessed wrong
#   --provider ollama|openai-compatible|skip
#   --url <chat-completions-url>       --model <name>
#   --embed-url <url>                  --embed-model <name>
#   --token <token>            (prefer leaving this to the masked prompt)
#   --think <off|low|medium|high|...>  --think-provider <ollama|openai|...>
#   --yes                      pre-confirm every prompt (needed for CI/non-tty)
#   --no-install               don't offer to install a missing package
#   --dry-run                  print what would happen, change nothing
#   --force-reinstall          allow DROP+CREATE EXTENSION on a version mismatch
#   --uninstall                reverse everything this script can set up
#   --version <X.Y.Z>          package version to install (default: this script's own)
#   -h, --help
#
# Env vars:
#   PG_BINDIR                 same override build_test.sh already uses: when
#                              set and non-empty, use this bin dir directly
#                              (e.g. PG_BINDIR=/opt/homebrew/opt/postgresql@17/bin)
#                              and skip auto-detection entirely.
#
# No telemetry. This script never reports usage, provider choice, or
# success/failure anywhere. That's deliberate, matching FractalSQL's own
# "sovereign reasoning" positioning: your infra choices stay yours.
#
# Design notes:
#   - Runs fine piped from curl. Every prompt reads from /dev/tty directly,
#     not stdin, since stdin is the pipe's source in `curl ... | bash`.
#   - Never DROP EXTENSION without --force-reinstall (protects against a
#     stale/foreign extension of the same name colliding with this one).
#   - Re-running the wizard (no --force-reinstall) is the normal way to
#     change providers or models. It only overwrites GUC values and reloads.

set -euo pipefail

# --- version -----------------------------------------------------------
# Stamped in by release.yml at build time (the placeholder below is
# replaced with the tag version before this file is uploaded as a release
# asset). Falls back to reading src/fractalsql.c directly when run from a
# repo checkout during development (matches scripts/package-darwin.sh's
# own VERSION-sourcing pattern), so this script works untouched both as a
# release asset and as a dev/test tool.
FSQL_VERSION="@@FSQL_VERSION@@"
if [[ "${FSQL_VERSION}" == "@@FSQL_VERSION@@" ]]; then
    HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    if [[ -f "${HERE}/../src/fractalsql.c" ]]; then
        FSQL_VERSION="$(sed -n 's/^#define FSQL_VERSION "\(.*\)"$/\1/p' "${HERE}/../src/fractalsql.c")"
    fi
fi

REPO="FractalSQLabs/fractalsql-postgresql"

# --- output helpers ------------------------------------------------------
if [[ -t 1 ]]; then G="\033[32m"; R="\033[31m"; Y="\033[33m"; B="\033[1m"; Z="\033[0m"; else G=""; R=""; Y=""; B=""; Z=""; fi
log()  { printf "${B}==>${Z} %s\n" "$1"; }
ok()   { printf "  ${G}✓${Z} %s\n" "$1"; }
warn() { printf "  ${Y}!${Z} %s\n" "$1" >&2; }
err()  { printf "  ${R}✗${Z} %s\n" "$1" >&2; }
die()  { err "$1"; exit 1; }

# --- /dev/tty-aware prompting --------------------------------------------
# `curl ... | bash` makes stdin the pipe, not the terminal. Reading a
# prompt from stdin in that mode either blocks forever or silently
# consumes script bytes as "input." Reading from /dev/tty directly
# sidesteps this (same trick rustup's installer uses). If there is no tty
# at all, a real non-interactive context like CI, every prompt requires
# its answer to already be known via a flag or --yes.
YES=0
NO_INSTALL=0
DRY_RUN=0
FORCE_REINSTALL=0
UNINSTALL=0
INSTALL_VERSION="${FSQL_VERSION}"
PG_MAJOR_ARG=""
PORT_ARG=""
PROVIDER=""
HTTP_URL=""
HTTP_MODEL=""
HTTP_TOKEN=""
HTTP_EMBED_URL=""
HTTP_EMBED_MODEL=""
HTTP_THINK=""
HTTP_THINK_PROVIDER=""

have_tty() { [[ -e /dev/tty ]]; }

confirm() {  # confirm "question" -> 0=yes 1=no
    local question="$1"
    [[ "${YES}" -eq 1 ]] && { ok "${question} -> yes (--yes)"; return 0; }
    if ! have_tty; then
        die "'${question}' needs an answer but there's no terminal to ask (running non-interactively). Pass --yes, or the specific flag for what you're trying to set."
    fi
    local reply
    read -r -p "${question} [Y/n] " reply < /dev/tty || true
    [[ -z "${reply}" || "${reply}" =~ ^[Yy] ]]
}

prompt() {  # prompt "question" "default" -> echoes the answer
    local question="$1" default="${2:-}" reply
    if ! have_tty; then
        [[ -n "${default}" ]] && { echo "${default}"; return; }
        die "'${question}' needs an answer but there's no terminal to ask (running non-interactively). Pass the corresponding flag."
    fi
    if [[ -n "${default}" ]]; then
        read -r -p "${question} [${default}]: " reply < /dev/tty || true
        echo "${reply:-${default}}"
    else
        read -r -p "${question}: " reply < /dev/tty || true
        echo "${reply}"
    fi
}

prompt_secret() {  # prompt_secret "question" -> echoes the answer, never displayed
    local question="$1" reply
    if ! have_tty; then
        die "'${question}' needs an answer but there's no terminal to ask (running non-interactively). Pass --token."
    fi
    read -r -s -p "${question}: " reply < /dev/tty || true
    echo >&2
    echo "${reply}"
}

# --- arg parsing -----------------------------------------------------------
usage() { sed -n '2,46p' "$0" | sed 's/^# \{0,1\}//'; exit 0; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --pg)               PG_MAJOR_ARG="$2"; shift 2 ;;
        --port)                PORT_ARG="$2"; shift 2 ;;
        --provider)          PROVIDER="$2"; shift 2 ;;
        --url)                HTTP_URL="$2"; shift 2 ;;
        --model)            HTTP_MODEL="$2"; shift 2 ;;
        --token)            HTTP_TOKEN="$2"; shift 2 ;;
        --embed-url)     HTTP_EMBED_URL="$2"; shift 2 ;;
        --embed-model) HTTP_EMBED_MODEL="$2"; shift 2 ;;
        --think)              HTTP_THINK="$2"; shift 2 ;;
        --think-provider) HTTP_THINK_PROVIDER="$2"; shift 2 ;;
        --version)      INSTALL_VERSION="$2"; shift 2 ;;
        --yes)               YES=1; shift ;;
        --no-install)  NO_INSTALL=1; shift ;;
        --dry-run)        DRY_RUN=1; shift ;;
        --force-reinstall) FORCE_REINSTALL=1; shift ;;
        --uninstall)     UNINSTALL=1; shift ;;
        -h|--help)       usage ;;
        *) die "unknown flag: $1 (see --help)" ;;
    esac
done

[[ -n "${INSTALL_VERSION}" ]] || die "could not determine a version to install. Pass --version X.Y.Z"

# --- OS / PG detection -----------------------------------------------------
OS_FAMILY=""   # debian | rhel | darwin
PKG_MGR=""     # dnf | yum | zypper (only set when OS_FAMILY=rhel)
ARCH_UNAME="$(uname -m)"
case "${ARCH_UNAME}" in
    x86_64|amd64) ARCH_DEB="amd64"; ARCH_DARWIN="x86_64" ;;
    arm64|aarch64) ARCH_DEB="arm64"; ARCH_DARWIN="arm64" ;;
    *) die "unsupported architecture: ${ARCH_UNAME}" ;;
esac

detect_os() {
    case "$(uname -s)" in
        Darwin) OS_FAMILY="darwin" ;;
        Linux)
            # apt-get covers Debian and Ubuntu (both use the same
            # postgresql-common / pg_lsclusters tooling and the same
            # /usr/lib/postgresql/<major>/ layout, confirmed by
            # install-test.yml's own debian-install job, which runs
            # against ubuntu:24.04). dnf/yum/zypper all resolve to the
            # SAME OS_FAMILY here: RHEL, Rocky, Alma, Fedora, and SUSE
            # (verified against a real openSUSE Leap 15.6 + PGDG-SUSE-repo
            # container) all use PGDG's identical /usr/pgsql-<major>/
            # layout, the same postgresql<major>-server package name, and
            # the same postgresql-<major>.service unit. The one real
            # difference is the install command itself (PKG_MGR below):
            # zypper enforces signature checks on local RPMs by default
            # and needs --no-gpg-checks for our unsigned package; dnf/yum
            # don't.
            if command -v apt-get >/dev/null 2>&1; then OS_FAMILY="debian"
            elif command -v dnf >/dev/null 2>&1; then OS_FAMILY="rhel"; PKG_MGR="dnf"
            elif command -v yum >/dev/null 2>&1; then OS_FAMILY="rhel"; PKG_MGR="yum"
            elif command -v zypper >/dev/null 2>&1; then OS_FAMILY="rhel"; PKG_MGR="zypper"
            else
                die "unsupported Linux distro (need apt-get, dnf, yum, or zypper; Alpine isn't packaged yet)"
            fi
            ;;
        *) die "unsupported OS: $(uname -s). This script covers Linux and macOS. See easy_install.ps1 for Windows." ;;
    esac
}

# Each detected install is recorded as "major:port:pg_config_path".
declare -a PG_INSTALLS=()

# Best-effort real port lookup for layouts with no pg_lsclusters
# equivalent (RHEL/PGDG, and every macOS install method). Reads the
# `port` setting out of that install's own postgresql.conf, using each
# layout's known data-directory convention. Falls back to PostgreSQL's
# own compiled-in default (5432) when the data directory or its config
# can't be found or read. This is a best guess, not a guarantee, which
# is why --port exists as a manual override.
detect_port_for() {
    local major="$1" pgdata conf line
    for pgdata in \
        "/var/lib/pgsql/${major}/data" \
        "/Library/PostgreSQL/${major}/data" \
        "/opt/homebrew/var/postgresql@${major}" \
        "/usr/local/var/postgresql@${major}"
    do
        conf="${pgdata}/postgresql.conf"
        [[ -f "${conf}" ]] || continue
        line="$(grep -E '^[[:space:]]*port[[:space:]]*=' "${conf}" 2>/dev/null | tail -1)"
        if [[ "${line}" =~ port[[:space:]]*=[[:space:]]*\'?([0-9]+) ]]; then
            echo "${BASH_REMATCH[1]}"
            return
        fi
    done
    echo 5432
}

detect_pg_installs() {
    PG_INSTALLS=()
    # Same override convention as build_test.sh's own pg_bindir(): when
    # PG_BINDIR is set and non-empty, trust it completely and skip
    # auto-detection. An empty PG_BINDIR (e.g. PG_BINDIR="") behaves the
    # same as leaving it unset, matching build_test.sh's [[ -n ... ]] test.
    if [[ -n "${PG_BINDIR:-}" ]]; then
        local pgc="${PG_BINDIR}/pg_config" ver
        [[ -x "${pgc}" ]] || die "PG_BINDIR is set to '${PG_BINDIR}' but ${pgc} isn't executable"
        ver="$("${pgc}" --version | sed -E 's/^PostgreSQL ([0-9]+).*/\1/')"
        PG_INSTALLS+=("${ver}:$(detect_port_for "${ver}"):${pgc}")
        return
    fi
    if [[ "${OS_FAMILY}" == "debian" ]] && command -v pg_lsclusters >/dev/null 2>&1; then
        # Debian/Ubuntu can run several major versions side by side as
        # separate "clusters" on separate ports. pg_lsclusters is the
        # authoritative source for what's actually running.
        while read -r ver _ port _; do
            [[ -x "/usr/lib/postgresql/${ver}/bin/pg_config" ]] || continue
            PG_INSTALLS+=("${ver}:${port}:/usr/lib/postgresql/${ver}/bin/pg_config")
        done < <(pg_lsclusters --no-header 2>/dev/null)
    else
        # RHEL/PGDG and macOS: scan pg_config on PATH plus every install
        # layout we know about. macOS in particular has three common
        # ones with different defaults: Homebrew (postgresql@NN), the
        # EDB one-click installer (the one postgresql.org itself points
        # to, default /Library/PostgreSQL/<major>), and Postgres.app.
        # scripts/macos/install.sh already documents supporting all three;
        # this just needs to find them first.
        local candidates=() c
        command -v pg_config >/dev/null 2>&1 && candidates+=("$(command -v pg_config)")
        for c in /usr/pgsql-*/bin/pg_config \
                 /opt/homebrew/opt/postgresql@*/bin/pg_config \
                 /usr/local/opt/postgresql@*/bin/pg_config \
                 /Library/PostgreSQL/*/bin/pg_config \
                 /Applications/Postgres.app/Contents/Versions/*/bin/pg_config \
                 /opt/local/lib/postgresql*/bin/pg_config; do
            [[ -x "$c" ]] && candidates+=("$c")
        done
        local seen="" pgc ver
        for pgc in "${candidates[@]}"; do
            ver="$("${pgc}" --version | sed -E 's/^PostgreSQL ([0-9]+).*/\1/')"
            [[ "${seen}" == *" ${ver} "* ]] && continue
            seen="${seen} ${ver} "
            PG_INSTALLS+=("${ver}:$(detect_port_for "${ver}"):${pgc}")
        done
    fi
    [[ "${#PG_INSTALLS[@]}" -gt 0 ]] || die "no PostgreSQL installation found (checked pg_lsclusters, pg_config on PATH, and common install paths)"
}

TARGET_MAJOR=""; TARGET_PORT=""; TARGET_PG_CONFIG=""

select_pg_target() {
    if [[ -n "${PG_MAJOR_ARG}" ]]; then
        local entry
        for entry in "${PG_INSTALLS[@]}"; do
            if [[ "${entry%%:*}" == "${PG_MAJOR_ARG}" ]]; then
                TARGET_MAJOR="${entry%%:*}"; TARGET_PORT="$(echo "${entry}" | cut -d: -f2)"; TARGET_PG_CONFIG="$(echo "${entry}" | cut -d: -f3)"
                return
            fi
        done
        die "PG major ${PG_MAJOR_ARG} not found among detected installs (${PG_INSTALLS[*]})"
    fi
    if [[ "${#PG_INSTALLS[@]}" -eq 1 ]]; then
        local entry="${PG_INSTALLS[0]}"
        TARGET_MAJOR="${entry%%:*}"; TARGET_PORT="$(echo "${entry}" | cut -d: -f2)"; TARGET_PG_CONFIG="$(echo "${entry}" | cut -d: -f3)"
        return
    fi
    log "Found multiple PostgreSQL installs:"
    local i=1 entry
    for entry in "${PG_INSTALLS[@]}"; do
        printf "  %d) PG%s (port %s)\n" "$i" "${entry%%:*}" "$(echo "${entry}" | cut -d: -f2)"
        i=$((i+1))
    done
    local choice
    choice="$(prompt "Which one? (1-${#PG_INSTALLS[@]}, or a PG major like 17)" "")"
    if [[ "${choice}" =~ ^[0-9]+$ ]] && [[ "${choice}" -ge 1 ]] && [[ "${choice}" -le "${#PG_INSTALLS[@]}" ]]; then
        local entry="${PG_INSTALLS[$((choice-1))]}"
        TARGET_MAJOR="${entry%%:*}"; TARGET_PORT="$(echo "${entry}" | cut -d: -f2)"; TARGET_PG_CONFIG="$(echo "${entry}" | cut -d: -f3)"
    else
        PG_MAJOR_ARG="${choice}"
        select_pg_target
    fi
}

# --- psql plumbing -----------------------------------------------------
# Uses the psql binary for THIS specific PG major, not whatever happens
# to be on PATH. A machine with several PG majors installed would
# otherwise silently run the wrong client.
#
# Connection: try the invoking user directly first (peer auth via the
# unix socket, the common case on Homebrew and Postgres.app). Fall back
# to `sudo -u postgres` (the Debian and RHEL packaged default).
PSQL_AS=()
resolve_psql_as() {
    local bin; bin="$(dirname "${TARGET_PG_CONFIG}")/psql"
    [[ -x "${bin}" ]] || die "psql not found next to ${TARGET_PG_CONFIG}"
    if "${bin}" -p "${TARGET_PORT}" -d postgres -Atc 'SELECT 1;' >/dev/null 2>&1; then
        PSQL_AS=("${bin}" -p "${TARGET_PORT}" -d postgres)
    elif command -v sudo >/dev/null 2>&1 && sudo -u postgres "${bin}" -p "${TARGET_PORT}" -d postgres -Atc 'SELECT 1;' >/dev/null 2>&1; then
        PSQL_AS=(sudo -u postgres "${bin}" -p "${TARGET_PORT}" -d postgres)
    else
        die "can't connect to PG${TARGET_MAJOR} on port ${TARGET_PORT}, either directly or via 'sudo -u postgres'. Check the cluster is running."
    fi
}

is_installed() {
    local extdir; extdir="$("${TARGET_PG_CONFIG}" --sharedir)/extension"
    [[ -f "${extdir}/fractalsql.control" ]]
}

# --- Phase B: install the package (default-on, confirmed) ------------------
phase_b_install() {
    if is_installed; then return; fi
    if [[ "${NO_INSTALL}" -eq 1 ]]; then
        die "FractalSQL isn't installed for PG${TARGET_MAJOR}. Grab the matching package from https://github.com/${REPO}/releases and install it, then re-run this script (or drop --no-install)."
    fi
    confirm "FractalSQL isn't installed for PG${TARGET_MAJOR} yet. Install it now?" \
        || die "Nothing to do without installing the package first. Re-run without --no-install, or install it yourself from https://github.com/${REPO}/releases."

    local asset_base="https://github.com/${REPO}/releases/download/v${INSTALL_VERSION}"
    # Global, not local: an EXIT trap runs after set -e has already
    # unwound out of this function on a failing command below, at which
    # point a `local` variable here would no longer exist and `set -u`
    # would reject the trap's own reference to it as unbound.
    TMP_DIR="$(mktemp -d)"
    trap 'rm -rf "${TMP_DIR}"' EXIT

    case "${OS_FAMILY}" in
        debian)
            local asset="postgresql-${TARGET_MAJOR}-fractalsql-${ARCH_DEB}.deb"
            log "Downloading ${asset}..."
            curl -fsSL "${asset_base}/${asset}" -o "${TMP_DIR}/${asset}"
            log "sudo apt-get install -y ${TMP_DIR}/${asset}"
            [[ "${DRY_RUN}" -eq 1 ]] || sudo apt-get install -y "${TMP_DIR}/${asset}"
            ;;
        rhel)
            local asset="postgresql-${TARGET_MAJOR}-fractalsql-${ARCH_DEB}.rpm"
            log "Downloading ${asset}..."
            curl -fsSL "${asset_base}/${asset}" -o "${TMP_DIR}/${asset}"
            if [[ "${PKG_MGR}" == "zypper" ]]; then
                # zypper enforces signature checks by default, even for a
                # locally-supplied file; dnf/yum don't. --no-gpg-checks is
                # zypper's equivalent of dnf's implicit local-file
                # leniency, confirmed against a real SUSE install.
                log "sudo zypper --non-interactive --no-gpg-checks install ${TMP_DIR}/${asset}"
                [[ "${DRY_RUN}" -eq 1 ]] || sudo zypper --non-interactive --no-gpg-checks install "${TMP_DIR}/${asset}"
            else
                log "sudo ${PKG_MGR} install -y ${TMP_DIR}/${asset}"
                [[ "${DRY_RUN}" -eq 1 ]] || sudo "${PKG_MGR}" install -y "${TMP_DIR}/${asset}"
            fi
            ;;
        darwin)
            local asset="fractalsql-postgresql-${INSTALL_VERSION}-pg${TARGET_MAJOR}-darwin-${ARCH_DARWIN}.tar.gz"
            log "Downloading ${asset}..."
            curl -fsSL "${asset_base}/${asset}" -o "${TMP_DIR}/${asset}"
            tar xzf "${TMP_DIR}/${asset}" -C "${TMP_DIR}"
            local dir="${TMP_DIR}/${asset%.tar.gz}"
            log "Running the bundled scripts/macos/install.sh (reused, not reimplemented)..."
            [[ "${DRY_RUN}" -eq 1 ]] || PG_CONFIG="${TARGET_PG_CONFIG}" "${dir}/install.sh"
            ;;
    esac
    ok "Package installed for PG${TARGET_MAJOR}."
}

# --- Phase C: the wizard -----------------------------------------------
# Doubles any single quote in a value before it goes inside a SQL string
# literal. Values here come from user input (a URL, a model name, a
# token), and a literal quote in one of them would otherwise break the
# ALTER SYSTEM SET statement's syntax.
sqlq() { printf '%s' "${1//\'/\'\'}"; }
guc_set() { PSQL_ARGS+=(-c "ALTER SYSTEM SET fractalsql.$1 = $2"); }
guc_reset_all() {
    local g
    for g in reasoning_plugin http_url http_token http_model http_allow_plaintext \
             http_embed_url http_embed_model http_think http_think_provider \
             http_native_url http_num_ctx; do
        PSQL_ARGS+=(-c "ALTER SYSTEM RESET fractalsql.${g}")
    done
}

# A cold-loading local model (for example, pulling a 13.8GB gpt-oss:20b
# into memory or VRAM for the first time) can take minutes to answer.
# That's longer than the reasoning-http plugin's default
# CURLOPT_TIMEOUT_MS and slowloris window.
#
# These are process env vars, not fractalsql.* GUCs. They're read once
# at plugin init, so ALTER SYSTEM SET can't touch them and a real
# restart is needed. The values here match docker-compose.yml's own
# FSQL_REASONING_HTTP_TIMEOUT_MS=330000 and _LOW_SPEED_SECS=300, and
# docs/reasoning-setup.md's "Handling Constrained Hardware" section.
#
# Only offered for the Ollama provider. A cloud endpoint doesn't
# cold-load a model on your hardware.
offer_cold_start_timeout() {
    confirm "Local models can be slow to answer the first time while they load into memory or VRAM. Raise the reasoning HTTP timeout to handle that? This needs a PostgreSQL restart, which drops active connections, not just a reload." \
        || return 0

    local timeout_ms=330000 low_speed_secs=300

    # postgres already owns its own Debian cluster (it can pg_ctlcluster
    # its own cluster directly, same as the plain "start" call elsewhere
    # in this script), so root or postgres skip sudo there. systemd on
    # RHEL has no such exception -- only root can touch it.
    local as_root=0 as_postgres=0
    [[ "$(id -u)" -eq 0 ]] && as_root=1
    [[ "$(id -un)" == "postgres" ]] && as_postgres=1
    local skip_sudo_debian=0 skip_sudo_rhel=0
    [[ "${as_root}" -eq 1 || "${as_postgres}" -eq 1 ]] && skip_sudo_debian=1
    [[ "${as_root}" -eq 1 ]] && skip_sudo_rhel=1
    priv() {
        local skip="$1"; shift
        if [[ "${skip}" -eq 1 ]]; then
            "$@"
        else
            command -v sudo >/dev/null 2>&1 \
                || die "this needs root privileges but 'sudo' isn't installed and you're not root. Install sudo, or re-run as root."
            sudo "$@"
        fi
    }

    case "${OS_FAMILY}" in
        debian)
            local envfile="/etc/postgresql/${TARGET_MAJOR}/main/environment"
            if [[ ! -f "${envfile}" ]]; then
                warn "expected ${envfile} not found. Skipping (unusual Debian PG layout?)"
                return 0
            fi
            log "Writing to ${envfile}:"
            echo "  FSQL_REASONING_HTTP_TIMEOUT_MS = '${timeout_ms}'"
            echo "  FSQL_REASONING_HTTP_LOW_SPEED_SECS = '${low_speed_secs}'"
            if [[ "${DRY_RUN}" -eq 1 ]]; then
                log "(--dry-run: not actually writing or restarting)"
                return 0
            fi
            local debian_restart_cmd="pg_ctlcluster ${TARGET_MAJOR} main restart"
            [[ "${skip_sudo_debian}" -eq 1 ]] || debian_restart_cmd="sudo ${debian_restart_cmd}"
            priv "${skip_sudo_debian}" sed -i '/^FSQL_REASONING_HTTP_TIMEOUT_MS/d;/^FSQL_REASONING_HTTP_LOW_SPEED_SECS/d' "${envfile}"
            printf "FSQL_REASONING_HTTP_TIMEOUT_MS = '%s'\nFSQL_REASONING_HTTP_LOW_SPEED_SECS = '%s'\n" \
                "${timeout_ms}" "${low_speed_secs}" | priv "${skip_sudo_debian}" tee -a "${envfile}" >/dev/null
            log "${debian_restart_cmd}"
            if confirm "Restart PG${TARGET_MAJOR} now to apply it?"; then
                priv "${skip_sudo_debian}" pg_ctlcluster "${TARGET_MAJOR}" main restart
                ok "PG${TARGET_MAJOR} restarted with a longer reasoning timeout."
            else
                warn "Not restarted. The longer timeout won't take effect until you run: ${debian_restart_cmd}"
            fi
            ;;
        rhel)
            local dropin_dir="/etc/systemd/system/postgresql-${TARGET_MAJOR}.service.d"
            local dropin="${dropin_dir}/fractalsql-env.conf"
            log "Writing to ${dropin}:"
            echo "  Environment=FSQL_REASONING_HTTP_TIMEOUT_MS=${timeout_ms}"
            echo "  Environment=FSQL_REASONING_HTTP_LOW_SPEED_SECS=${low_speed_secs}"
            if [[ "${DRY_RUN}" -eq 1 ]]; then
                log "(--dry-run: not actually writing or restarting)"
                return 0
            fi
            local rhel_restart_cmd="systemctl restart postgresql-${TARGET_MAJOR}"
            [[ "${skip_sudo_rhel}" -eq 1 ]] || rhel_restart_cmd="sudo ${rhel_restart_cmd}"
            priv "${skip_sudo_rhel}" mkdir -p "${dropin_dir}"
            printf '[Service]\nEnvironment=FSQL_REASONING_HTTP_TIMEOUT_MS=%s\nEnvironment=FSQL_REASONING_HTTP_LOW_SPEED_SECS=%s\n' \
                "${timeout_ms}" "${low_speed_secs}" | priv "${skip_sudo_rhel}" tee "${dropin}" >/dev/null
            priv "${skip_sudo_rhel}" systemctl daemon-reload
            log "${rhel_restart_cmd}"
            if confirm "Restart PG${TARGET_MAJOR} now to apply it?"; then
                priv "${skip_sudo_rhel}" systemctl restart "postgresql-${TARGET_MAJOR}"
                ok "PG${TARGET_MAJOR} restarted with a longer reasoning timeout."
            else
                warn "Not restarted. The longer timeout won't take effect until you run: ${rhel_restart_cmd}"
            fi
            ;;
        darwin)
            warn "macOS (launchd) needs this set by hand. See docs/reasoning-setup.md's 'Handling Constrained Hardware' section for the brew services and launchctl steps. Not automated here."
            ;;
    esac
}

phase_c_wizard() {
    resolve_psql_as

    log "Activating the extension in database 'postgres' on PG${TARGET_MAJOR}..."
    local extver stale=0
    extver="$("${PSQL_AS[@]}" -Atc "SELECT extversion FROM pg_extension WHERE extname='fractalsql';" 2>/dev/null || true)"
    if [[ -n "${extver}" ]]; then
        if [[ "${extver}" != "1.0" ]]; then
            stale=1
        else
            # extversion alone can't detect staleness: this project's SQL
            # extension version is permanently fixed at 1.0 (the real
            # version lives in fractal_version() itself), so a
            # same-version-but-older-content install, for example one
            # left over from working on this repo directly before this
            # script existed, sails right past an extversion check.
            # CREATE EXTENSION IF NOT EXISTS would then silently no-op
            # against it, leaving stale catalog objects that are missing
            # fractal_version(). Check for the function directly instead.
            local has_fn
            has_fn="$("${PSQL_AS[@]}" -Atc "SELECT 1 FROM pg_proc WHERE proname = 'fractal_version';" 2>/dev/null || true)"
            [[ -n "${has_fn}" ]] || stale=1
        fi
    fi
    if [[ "${stale}" -eq 1 ]]; then
        if [[ "${FORCE_REINSTALL}" -ne 1 ]]; then
            die "fractalsql is already CREATE EXTENSION'd here but looks stale or foreign (version '${extver}', fractal_version() missing or unexpected). Re-run with --force-reinstall to drop and recreate it fresh, only after checking nothing depends on it (see docs/reasoning-setup.md)."
        fi
        warn "Dropping existing fractalsql extension (--force-reinstall)..."
        [[ "${DRY_RUN}" -eq 1 ]] || "${PSQL_AS[@]}" -c "DROP EXTENSION IF EXISTS fractalsql_agents, fractalsql;"
    fi
    [[ "${DRY_RUN}" -eq 1 ]] || "${PSQL_AS[@]}" \
        -c "CREATE EXTENSION IF NOT EXISTS fractalsql;" \
        -c "CREATE EXTENSION IF NOT EXISTS fractalsql_agents;"
    ok "fractalsql + fractalsql_agents extensions active."

    if [[ -z "${PROVIDER}" ]]; then
        log "Reasoning provider:"
        echo "  1) Local Ollama"
        echo "  2) Cloud / OpenAI-compatible endpoint"
        echo "  3) Skip: search-only install, configure reasoning later"
        local choice; choice="$(prompt "Choice" "1")"
        case "${choice}" in
            1) PROVIDER="ollama" ;;
            2) PROVIDER="openai-compatible" ;;
            *) PROVIDER="skip" ;;
        esac
    fi

    local pkglibdir; pkglibdir="$("${TARGET_PG_CONFIG}" --pkglibdir)"
    local plugin_so="${pkglibdir}/fractalsql-reasoning-http.so"

    # Forces _PG_init() to register the fractalsql.* GUCs in THIS session
    # before ALTER SYSTEM SET can see them. Mirrors the same fix already
    # used in .github/workflows/install-test.yml.
    PSQL_ARGS=(-c "SELECT fractal_version();")
    case "${PROVIDER}" in
        ollama)
            HTTP_URL="${HTTP_URL:-$(prompt "Ollama chat URL" "http://localhost:11434/v1/chat/completions")}"
            HTTP_MODEL="${HTTP_MODEL:-$(prompt "Model" "gpt-oss:20b")}"
            HTTP_EMBED_URL="${HTTP_EMBED_URL:-$(prompt "Ollama embeddings URL" "http://localhost:11434/v1/embeddings")}"
            HTTP_EMBED_MODEL="${HTTP_EMBED_MODEL:-$(prompt "Embedding model" "nomic-embed-text")}"
            HTTP_THINK="${HTTP_THINK:-off}"
            HTTP_THINK_PROVIDER="${HTTP_THINK_PROVIDER:-ollama}"
            guc_set reasoning_plugin "'$(sqlq "${plugin_so}")'"
            guc_set http_url "'$(sqlq "${HTTP_URL}")'"
            guc_set http_allow_plaintext "on"
            guc_set http_model "'$(sqlq "${HTTP_MODEL}")'"
            guc_set http_embed_url "'$(sqlq "${HTTP_EMBED_URL}")'"
            guc_set http_embed_model "'$(sqlq "${HTTP_EMBED_MODEL}")'"
            guc_set http_think "'$(sqlq "${HTTP_THINK}")'"
            guc_set http_think_provider "'$(sqlq "${HTTP_THINK_PROVIDER}")'"
            ;;
        openai-compatible)
            HTTP_URL="${HTTP_URL:-$(prompt "Chat completions URL" "")}"
            [[ -n "${HTTP_URL}" ]] || die "a URL is required for a cloud/OpenAI-compatible endpoint"
            HTTP_MODEL="${HTTP_MODEL:-$(prompt "Model" "gpt-4o-mini")}"
            [[ -n "${HTTP_TOKEN}" ]] || HTTP_TOKEN="$(prompt_secret "API token (masked, never logged)")"
            guc_set reasoning_plugin "'$(sqlq "${plugin_so}")'"
            guc_set http_url "'$(sqlq "${HTTP_URL}")'"
            guc_set http_token "'$(sqlq "${HTTP_TOKEN}")'"
            guc_set http_model "'$(sqlq "${HTTP_MODEL}")'"
            if [[ "${HTTP_URL}" != https://* ]]; then
                warn "That URL isn't https://. That's fine for localhost or a private LAN, but risky for anything else. Not blocking, just flagging it."
            fi
            ;;
        skip)
            log "Skipping reasoning config. Search functions like fractal_search and fractal_search_explore work with no model."
            ;;
        *) die "unknown --provider '${PROVIDER}' (expected ollama, openai-compatible, or skip)" ;;
    esac

    if [[ "${PROVIDER}" != "skip" ]]; then
        log "About to set:"
        local a
        for a in "${PSQL_ARGS[@]}"; do
            [[ "$a" == "-c" ]] && continue
            [[ "$a" == *http_token* ]] && { echo "  ALTER SYSTEM SET fractalsql.http_token = '***'"; continue; }
            echo "  $a"
        done
        confirm "Apply this configuration and reload?" || die "Aborted. Nothing was changed."
        PSQL_ARGS+=(-c "SELECT pg_reload_conf();")
        if [[ "${DRY_RUN}" -eq 1 ]]; then
            log "(--dry-run: not actually applying)"
        else
            "${PSQL_AS[@]}" "${PSQL_ARGS[@]}" >/dev/null
            ok "Reasoning configured and reloaded."
        fi
    fi

    [[ "${PROVIDER}" == "ollama" ]] && offer_cold_start_timeout

    if [[ "${DRY_RUN}" -ne 1 ]]; then
        local ed ver
        ed="$("${PSQL_AS[@]}" -Atc 'SELECT fractal_edition();')"
        ver="$("${PSQL_AS[@]}" -Atc 'SELECT fractal_version();')"
        ok "fractal_edition() = ${ed}, fractal_version() = ${ver}"
        if [[ "${ver}" != "${INSTALL_VERSION}" ]]; then
            # DROP+CREATE (even with --force-reinstall) only touches the
            # SQL catalog objects. It registers whatever .so is already
            # on disk, it doesn't replace it. A mismatch here means the
            # installed files are stale, not something this step can
            # fix on its own.
            warn "That's not ${INSTALL_VERSION}, the version this script expected. The installed files themselves are out of date. Reinstall the current package from https://github.com/${REPO}/releases over this PG${TARGET_MAJOR} install to actually update the .so, then re-run this script."
        fi
        if [[ "${PROVIDER}" != "skip" ]] && confirm "Run a live reasoning smoke test (SELECT fractal_reason('say ok'))? A cloud endpoint may incur cost, and a cold local model can take several minutes the first time."; then
            local reply; reply="$("${PSQL_AS[@]}" -Atc "SELECT fractal_reason('say ok');" 2>&1 || true)"
            echo "  ${reply}" | head -5
            if [[ "${reply}" == *ERROR* ]]; then
                warn "That failed. If it looks like a timeout on a slow/cold local model, re-run and accept the cold-start timeout offer above, or see docs/reasoning-setup.md's 'Handling Constrained Hardware' section."
            fi
        fi
    fi

    printf "\n${G}You're set up.${Z} Where next:\n"
    cat <<'EOF'
  - docs/starter-kits.md: industry-specific runnable examples
  - docs/api-agency.md: the 16 built-in agents, full reference
  - docs/composition-guide.md: build your own agent
  - Re-run this script anytime to switch providers or models. It's
    safe, it just overwrites the GUCs above and reloads.
EOF
}

# --- --uninstall ---------------------------------------------------------
uninstall_flow() {
    resolve_psql_as
    log "This will reset all fractalsql.* reasoning GUCs on PG${TARGET_MAJOR}."
    PSQL_ARGS=(-c "SELECT fractal_version();")
    guc_reset_all
    PSQL_ARGS+=(-c "SELECT pg_reload_conf();")
    if confirm "Reset reasoning config now?"; then
        if [[ "${DRY_RUN}" -eq 1 ]]; then
            log "(--dry-run: not actually resetting)"
        else
            "${PSQL_AS[@]}" "${PSQL_ARGS[@]}" >/dev/null
            ok "Reasoning GUCs reset."
        fi
    fi

    if confirm "Also DROP EXTENSION fractalsql_agents, fractalsql (deletes any dependent objects too)?"; then
        if [[ "${DRY_RUN}" -eq 1 ]]; then
            log "(--dry-run: not actually dropping)"
        else
            "${PSQL_AS[@]}" -c "DROP EXTENSION IF EXISTS fractalsql_agents, fractalsql;"
            ok "Extensions dropped."
        fi
    fi

    case "${OS_FAMILY}" in
        debian) echo "  To remove the package: sudo apt remove postgresql-${TARGET_MAJOR}-fractalsql" ;;
        rhel)
            if [[ "${PKG_MGR}" == "zypper" ]]; then
                echo "  To remove the package: sudo zypper remove postgresql-${TARGET_MAJOR}-fractalsql"
            else
                echo "  To remove the package: sudo ${PKG_MGR} remove postgresql-${TARGET_MAJOR}-fractalsql"
            fi
            ;;
        darwin) echo "  To remove the files: rm \$($TARGET_PG_CONFIG --pkglibdir)/fractalsql* \$($TARGET_PG_CONFIG --sharedir)/extension/fractalsql*" ;;
    esac
}

# --- main ------------------------------------------------------------------
main() {
    detect_os
    detect_pg_installs
    select_pg_target
    [[ -n "${PORT_ARG}" ]] && TARGET_PORT="${PORT_ARG}"
    log "Targeting PostgreSQL ${TARGET_MAJOR} (port ${TARGET_PORT})"

    if [[ "${UNINSTALL}" -eq 1 ]]; then
        uninstall_flow
        exit 0
    fi

    phase_b_install
    phase_c_wizard
}

main "$@"
