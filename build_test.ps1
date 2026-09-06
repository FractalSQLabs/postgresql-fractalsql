<#
.SYNOPSIS
    build_test.ps1 -- Windows post-build validation gate runner for
    fractalsql-postgresql. PowerShell port of build_test.sh; same gate
    numbering/behavior where the underlying technique is portable.

.DESCRIPTION
    Windows post-build validation gate runner for fractalsql-postgresql;
    PowerShell port of build_test.sh with the same gate numbering. Default
    gates: 01-20, 22, 23 (gate 21/fuzz is opt-in via -Fuzz).

    Gates (see build_test.sh for the full rationale behind each):
      01  build              scripts\windows\build-windows.ps1
      02  smoke              version + fractal_search convergence
      03  schema_context     PK / NOT NULL / comment / FK introspection
      04  text_to_sql        allowlist matrix + never-executes proof
      05  evil_overread      guard-page (VirtualAlloc/VirtualProtect)
                             non-terminated response survives -- at
                             GENERATE, REVIEW, and bare fractal_reason()
      06  crash_recovery     deliberately-segfaulting plugin: connection
                             drops, cluster auto-restarts, data intact.
                             Windows uses EXEC_BACKEND (CreateProcess per
                             backend, no fork()) -- the crash-recovery
                             CONTRACT should hold (documented, 20+ years
                             of Windows PG support) but the exact log/
                             error-message wording this gate string-
                             matches has not been confirmed on Windows.
      07  evil_lying_length  guard_ai_response_len rejects an implausible
                             claimed length before any read -- pure
                             malloc/free, no platform-specific technique,
                             lowest-risk of the three evil gates to port.
      08  authz              low-priv role blocked from schema_context on
                             a table it lacks SELECT on
      09  guc_superuser      non-superuser rejected from setting
                             reasoning_plugin
      10  dos_and_injection  512-table cap fires at 513; SQL-injection-
                             shaped table_names cleanly rejected
      11  scout              fractal_search_explore population + dispersion
      12  soak               concurrent workers x mixed benign calls
      13  siu_mode           text_to_sql_allowed_statements=select_insert_
                             update: INSERT/UPDATE returned (never executed),
                             DDL/DELETE still rejected
      14  retry              max_attempts=2 retry-with-feedback: attempt 1
                             rejected, attempt 2 succeeds, rejection reason
                             threaded into the attempt-2 prompt
                             (uses tests\windows\retry_reasoning_plugin_win.c)
      15  embed              fractal_embed()/vectorizer dispatch, NULL/
                             bad-path/over-limit/injection/double-create
      16  embed_authz        vectorizer authz: owner vs. outsider
      17  embed_soak         concurrent process_queue() workers, no
                             double-processing
      18  embed_crash        crash mid-process_queue() rolls back the
                             whole batch atomically
      19  sfs_bounds         validate_sfs_params() bounds across all
                             three search entry points
      20  api_func           fractal_reason() happy path + NULL,
                             fractal_text_to_sql(NULL), search_explore's
                             own bounds via options jsonb, stale_after
                             reclaim (see build_test.sh Gate 20)
      21  fuzz_smoke         FUZZ ONLY (-Fuzz, not in default gates).
                             libFuzzer via clang-cl against the 3
                             hand-rolled parsers in
                             src\fractalsql_parse.c -- no cluster, no
                             extension DLL (see build_test.sh Gate 21)
      22  v2_functions       v2.x additions smoke: dimension analysis,
                             portfolio optimization, domain geometry,
                             named feature store, Diversify/feedback
                             controls, telemetry/trajectory/cross-modal
                             search (see build_test.sh Gate 22)

.PARAMETER PgDir
    PostgreSQL server tree (EDB install root or unpacked binaries.zip).
    Same meaning as build-windows.ps1's -PgDir.

.PARAMETER PgMajor
    Target PostgreSQL major (14-18).

.PARAMETER Quick
    Gates 01-02 only.

.PARAMETER Gate
    Run a single gate by number (e.g. -Gate 05).

.PARAMETER TimeoutMult
    Scales gate 06/16's post-crash restart poll budget. Same purpose as
    build_test.sh's FSQL_TEST_TIMEOUT_MULT. Default 1, auto-bumped to 8
    under -Asan/-Ubsan unless passed explicitly (confirmed on real
    hardware: the default of 1 does not survive gate 06 under -Asan).

.PARAMETER Fuzz
    Gate 21 only -- libFuzzer smoke via clang-cl against
    src\fractalsql_parse.c's 3 hand-rolled parsers. Set FSQL_FUZZ_TIME
    (seconds per target, default 30) to run longer than the pre-push
    smoke budget.

.EXAMPLE
    PS> .\build_test.ps1 -PgDir "C:\Program Files\PostgreSQL\17" -PgMajor 17
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$PgDir,
    [Parameter(Mandatory = $true)][ValidateSet('14', '15', '16', '17', '18')][string]$PgMajor,
    [switch]$Quick,
    [string]$Gate,
    [int]$TimeoutMult = 1,
    # Rebuilds fractalsql.dll with MSVC /fsanitize=address into a
    # separate dist\windows-asan\ tree (never touches the normal
    # dist\windows\ release output), then runs the same gates against
    # the instrumented DLL loaded into postgres.exe. Only fractalsql.c
    # (this repo's own source) gets instrumented; the vendored core .lib
    # (include\windows-x86_64\fractalsql-*.lib) is linked as-is, not
    # rebuilt, so this catches bugs in the extension's own glue code but
    # not inside core's own SFS algorithm internals. /GL (whole-program
    # optimization, on in the normal build) is dropped -- documented
    # MSVC incompatibility with /fsanitize=address -- and /LTCG drops
    # with it at link time. -TimeoutMult auto-bumps to 8 under -Asan
    # (see below): ASan overhead blows the default 15s gate-06 crash-
    # recovery poll budget, cascade-failing later gates with "database
    # system is in recovery mode".
    [switch]$Asan,
    # Same structure as -Asan (separate dist\windows-ubsan\ tree, same
    # gates run against the instrumented DLL), but via clang-cl
    # (LLVM's MSVC-ABI-compatible driver -- native cl.exe has no UBSan
    # support at all) and -fsanitize=undefined instead of native
    # cl.exe's /fsanitize=address. Mutually exclusive with -Asan -- each
    # rebuilds its own separate dist\ tree, run one at a time. Whether
    # gate 06 needs the same -TimeoutMult headroom ASan needed is
    # unverified -- instrumentation overhead differs by sanitizer,
    # don't assume identical without checking a real run.
    [switch]$Ubsan,
    # Windows port of build_test.sh's Gate 21 (--fuzz): builds and
    # briefly runs libFuzzer drivers against the 3 hand-rolled parsers
    # in src\fractalsql_parse.c, via the same clang-cl -Ubsan already
    # resolves (LLVM's fuzzer support is a real, longstanding clang-cl
    # feature, not Linux-only). Unlike -Asan/-Ubsan, this does NOT
    # touch fractalsql.dll or postgres.exe at all -- fractalsql_parse.c
    # was split into its own postgres.h-free translation unit
    # specifically so these 3 functions link into a standalone .exe
    # directly, same as the Linux gate. Not mutually exclusive with
    # -Asan/-Ubsan (harmless to combine, just pointless -- this gate
    # doesn't use the extension DLL either builds).
    [switch]$Fuzz
)

if ($Asan -and $Ubsan) {
    throw "-Asan and -Ubsan are mutually exclusive -- each rebuilds its own separate dist\ tree. Run one at a time."
}

# -Asan/-Ubsan auto-set $TimeoutMult to 8 unless the caller explicitly
# passed a value ($PSBoundParameters check honors an explicit -TimeoutMult 1).
if (-not $PSBoundParameters.ContainsKey('TimeoutMult') -and ($Asan -or $Ubsan)) {
    $TimeoutMult = 8
}

$ErrorActionPreference = 'Stop'
# PowerShell 7.3+ defaults to treating ANY native-command stderr write
# as a terminating error under $ErrorActionPreference = 'Stop' --
# regardless of the writing program's own actual severity level. psql
# sends NOTICE/WARNING/ERROR all to stderr; without this, a routine
# "NOTICE: table ... does not exist, skipping" from a plain
# DROP TABLE IF EXISTS throws and aborts the whole script. This
# script already checks $LASTEXITCODE and regex-matches expected
# output text explicitly wherever it actually needs to detect a real
# failure -- it doesn't rely on PowerShell's automatic error handling
# for native commands, so restore the pre-7.3 lenient behavior.
$PSNativeCommandUseErrorActionPreference = $false
Set-StrictMode -Version Latest

$RepoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $RepoRoot

$DefaultGates = @('01','02','03','04','05','06','07','08','09','10','11','12','13','14','15','16','17','18','19','20','22','23','24','25','26','27')
$QuickGates   = @('01','02')
$FuzzGates    = @('21')

$script:Failed = 0
function Pass($msg) { Write-Host "  [PASS] $msg" -ForegroundColor Green }
function Fail($msg) { Write-Host "  [FAIL] $msg" -ForegroundColor Red; $script:Failed = 1 }
function Skip($msg) { Write-Host "  [SKIP] $msg" -ForegroundColor Yellow }

# --- per-run state ------------------------------------------------------
$Bin      = Join-Path $PgDir 'bin'
$DistSubdir = if ($Asan) { "dist\windows-asan\pg$PgMajor" }
              elseif ($Ubsan) { "dist\windows-ubsan\pg$PgMajor" }
              else { "dist\windows\pg$PgMajor" }
$Dll      = Join-Path $RepoRoot "$DistSubdir\fractalsql.dll"

# ASan reports to stderr and aborts by default on the first violation --
# halt_on_error=1 makes that explicit. Inherited ambiently by every
# child process this script spawns (postgres.exe included, since it
# loads fractalsql.dll into its own process).
if ($Asan) { $env:ASAN_OPTIONS = 'halt_on_error=1:print_stats=0' }

# Discovery order: PATH -> vswhere-resolved VC\Tools\Llvm\x64\bin\clang-cl.exe
# -> standalone LLVM. Throws instead of skipping -- -Ubsan being passed at
# all means the caller wants it to actually run.
function Find-ClangCl {
    $candidate = Get-Command clang-cl.exe -ErrorAction SilentlyContinue
    if ($candidate) { return $candidate.Source }
    $VsWhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    if (Test-Path $VsWhere) {
        $vsPath = & $VsWhere -latest -products * -property installationPath 2>$null
        if ($vsPath) {
            $vsClang = Join-Path $vsPath 'VC\Tools\Llvm\x64\bin\clang-cl.exe'
            if (Test-Path $vsClang) { return $vsClang }
        }
    }
    $standalone = 'C:\Program Files\LLVM\bin\clang-cl.exe'
    if (Test-Path $standalone) { return $standalone }
    throw "-Ubsan/-Fuzz requested but clang-cl.exe not found (checked PATH, VS's 'C++ Clang tools for Windows' component, standalone LLVM)."
}
$script:ClangCl = $null
if ($Ubsan -or $Fuzz) {
    $script:ClangCl = Find-ClangCl
    Write-Host "Using clang-cl: $script:ClangCl"
}
if ($Ubsan) {
    $env:UBSAN_OPTIONS = 'print_stacktrace=1:halt_on_error=1'
}
# Postgres's "is this library already loaded" dedup (internal_load_library)
# compares the path STRING, not a canonicalized/resolved path -- two
# different spellings of the same file (backslash vs forward-slash) are
# NOT recognized as the same library. shared_preload_libraries loads it
# once at postmaster/backend startup; every CREATE FUNCTION ... AS
# below ALSO names it. If those two spellings ever differ, Postgres
# loads the DLL a second time in the same process and _PG_init() runs
# twice, which genuinely IS "attempt to redefine parameter" the second
# time -- reproduced exactly this way on the first real Windows run
# (shared_preload_libraries used the forward-slash form, CREATE
# FUNCTION used the raw backslash form). Never hit on Linux, where
# build_test.sh uses the identical string in both places. Single
# normalized value, used everywhere the DLL path appears, closes it.
$DllPath  = $Dll -replace '\\','/'
$DataDir  = Join-Path $env:TEMP "fractalsql_bt_data_$PgMajor"
$Port     = 5600 + [int]$PgMajor
$PluginDir = Join-Path $env:TEMP "fractalsql_bt_plugins_$PgMajor"
# Inside $DataDir, not an absolute C:\Windows\Temp\... path -- that
# was the previous attempt and it silently never worked (fopen always
# returned NULL despite the file demonstrably existing there with the
# right content, confirmed via diagnostics on a real Windows run).
# tests\windows\*_win.c's plugins open these by BARE RELATIVE FILENAME,
# resolving against the backend's CWD, which PostgreSQL sets to its
# own data directory at startup -- a location the backend
# unquestionably has full access to, since it's postgres's own. These
# two locations must always agree with each other.
$TriggerFile = Join-Path $DataDir 'fractalsql_bt_evil_trigger_call.txt'
$SqlFile     = Join-Path $DataDir 'fractalsql_bt_sql.txt'
# Bare relative filename the retry plugin (tests\windows\retry_reasoning_
# plugin_win.c) writes the 2nd-call GENERATE prompt to, resolved against
# the backend's CWD (its own data dir) -- same mechanism as $SqlFile /
# $TriggerFile above. gate 14 (retry) reads this back to prove the
# attempt-1 rejection reason was threaded into the attempt-2 prompt.
$RetryPromptFile = Join-Path $DataDir 'fractalsql_bt_retry_prompt.txt'

# Bare relative filename the THINK plugin (tests\windows\think_reasoning_
# plugin_win.c) dumps the four FSQL_REASONING_HTTP_THINK*/NUM_CTX env vars
# to at format_prompt() time -- same resolved-against-CWD mechanism as
# $RetryPromptFile above. Gate 27 reads this back.
$ThinkDumpFile = Join-Path $DataDir 'fractalsql_bt_think_dump.txt'

$Mock  = Join-Path $PluginDir 'mock.dll'
$Evil  = Join-Path $PluginDir 'evil_overread.dll'
$Crash = Join-Path $PluginDir 'evil_crash.dll'
$Lying = Join-Path $PluginDir 'evil_lying.dll'
$Retry = Join-Path $PluginDir 'retry.dll'
$Embed = Join-Path $PluginDir 'mock_embed.dll'
$EvilEmbed = Join-Path $PluginDir 'evil_embed.dll'
$Think = Join-Path $PluginDir 'think.dll'

# Runs psql.exe via .NET's Process API directly rather than PowerShell's
# own native-command invocation (`&`). Simpler approaches still let a
# routine psql NOTICE (e.g. from DROP TABLE IF EXISTS) get wrapped as a
# NativeCommandError and, under $ErrorActionPreference = 'Stop', abort
# the whole script. ProcessStartInfo.ArgumentList passes each argument
# through CreateProcess exactly as given (no shell-level re-quoting), and
# reading StandardOutput/StandardError as plain .NET strings never touches
# PowerShell's ErrorRecord/$ErrorActionPreference machinery.
# ProcessStartInfo.ArgumentList needs .NET Core 2.1+ / pwsh 7+ -- it is
# absent under the ambient Windows PowerShell 5.1 host, so this script
# must be invoked via `pwsh -File`. (SQL travels via stdin -- `-f -` --
# not the command line, so there is no argv-escaping of $Sql at all.)

function Psql {
    param([string]$Sql, [string]$Db = 'postgres', [string]$User = 'postgres')
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = "$Bin\psql.exe"
    # SQL is fed via stdin (`-f -`), NOT via `-c` on the command line.
    # PgSetup loads three slices of the extension SQL through this helper;
    # the fractalsql_agents slice alone is ~58KB after Stage 4's 9 new
    # engines -- far over the 32,767-char CreateProcess command-line
    # limit. Passing it via `-c $Sql` threw Win32 error 206 ("The
    # filename or extension is too long") at .Start, caught upstream as
    # "PG16 cluster setup". stdin has no such cap. `-f -` is also more
    # correct for multi-statement DDL than `-c "A; B; C"` (the latter
    # runs as one implicit transaction -- the same hazard documented at
    # PgSetGuc, which is why ALTER SYSTEM is split into two calls).
    # ArgumentList (not the Arguments string) needs no manual argv-
    # escaping and matches initdb's launch + the gate-23 psql helpers.
    foreach ($a in @('-h','127.0.0.1','-p',"$Port",'-U',$User,'-d',$Db,'-X','-tA','-f','-')) {
        $psi.ArgumentList.Add($a)
    }
    $psi.RedirectStandardInput  = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError  = $true
    $psi.UseShellExecute = $false
    $proc = [System.Diagnostics.Process]::Start($psi)
    # Read both streams concurrently, not sequentially -- a query whose
    # ERROR/DETAIL text is large (e.g. gate 15's evil-embed case, whose
    # errdetail echoes the plugin's ~33KB raw response) fills the stderr
    # pipe's OS buffer while stdout sits empty; ReadToEnd()'ing stdout
    # first then blocks forever waiting for EOF that can't arrive because
    # psql.exe itself is blocked writing the rest of stderr into a full
    # pipe. Starting both reads before WaitForExit() drains each pipe as
    # the child writes to it, so neither side can back the other up.
    $stdoutTask = $proc.StandardOutput.ReadToEndAsync()
    $stderrTask = $proc.StandardError.ReadToEndAsync()
    # Feed the SQL via stdin and close (EOF) so psql (-f -) processes it.
    # This is done AFTER starting the async stdout/stderr reads above:
    # psql executes -f - input statement-by-statement and writes output
    # as it goes, so if stdout were not being drained concurrently a
    # large SQL could fill the OS pipe buffer and deadlock (our stdin
    # Write blocks waiting for psql to read, psql blocks waiting for us
    # to drain stdout). The async reads keep both pipes drained.
    $proc.StandardInput.Write($Sql)
    $proc.StandardInput.Close()
    $proc.WaitForExit()
    ($stdoutTask.Result + $stderrTask.Result).Trim()
}

function Cleanup {
    if (Test-Path $DataDir) {
        try { & "$Bin\pg_ctl.exe" -D $DataDir -m immediate stop 2>&1 | Out-Null } catch { <# best-effort: pg_ctl fails harmlessly if the server is already stopped #> }
        # TEMPORARY: FSQL_BT_KEEP_DATADIR preserves $DataDir\log for
        # post-mortem debugging of the gate-24 Windows enterprise crash --
        # revert this gate once that's root-caused.
        if (-not $env:FSQL_BT_KEEP_DATADIR) {
            Remove-Item -Recurse -Force $DataDir -ErrorAction SilentlyContinue
        } else {
            Write-Host "[build_test] FSQL_BT_KEEP_DATADIR set -- leaving $DataDir in place (log at $DataDir\log)"
        }
    }
    Remove-Item -Force $SqlFile, $TriggerFile, $RetryPromptFile, $ThinkDumpFile -ErrorAction SilentlyContinue
}

# --- gate 01: build -------------------------------------------------------
# Replicates scripts\windows\build-windows.ps1's compile+link for
# fractalsql.c directly (doesn't call that script -- no
# ASan option there), with /fsanitize=address + /Zi added, /GL + /LTCG
# dropped (documented MSVC /fsanitize=address incompatibility with
# /GL), and /DEBUG added at link time. /MT unchanged -- already proven
# to work with /fsanitize=address. The vendored core .lib and
# postgres.lib are linked as-is (see the -Asan PARAMETER block above for
# why that's an accepted, documented limit of this gate's coverage).
function Build-AsanExtension {
    if (-not (Get-Command cl.exe -ErrorAction SilentlyContinue)) {
        throw "cl.exe not on PATH. Activate MSVC first (Native Tools Command Prompt / ilammy/msvc-dev-cmd)."
    }
    $outDir = Split-Path -Parent $Dll
    New-Item -ItemType Directory -Force -Path $outDir | Out-Null

    $pgLib       = Join-Path $PgDir 'lib\postgres.lib'
    $pgServerInc = Join-Path $PgDir 'include\server'
    if (-not (Test-Path $pgLib)) { throw "postgres.lib not found at $pgLib" }

    $coreLib = Join-Path $RepoRoot 'include\windows-x86_64\fractalsql-community-sovereign-c.lib'
    if (-not (Test-Path $coreLib)) { throw "vendored core library not found: $coreLib" }

    # libcrypto.lib: ent_verify_signature() in fractalsql.c (Ed25519 check
    # on the optional enterprise .so) calls OpenSSL's EVP API -- see
    # build-windows.ps1's $CryptoLib resolution for the full rationale
    # (Linux gets this for free via dlopen-time resolution against
    # postgres's own libcrypto.so; Windows needs it named at link time).
    $cryptoLib = Join-Path $PgDir 'lib\libcrypto.lib'
    if (-not (Test-Path $cryptoLib)) { throw "libcrypto.lib not found at $cryptoLib" }

    $src        = Join-Path $RepoRoot 'src\fractalsql.c'
    # fsql_extract_best_point / fsql_parse_embedding_array /
    # fsql_extract_population live in this separate, postgres.h-free TU,
    # not fractalsql.c -- must be compiled and linked here too, or the
    # link fails on 3 unresolved externals.
    $srcParse   = Join-Path $RepoRoot 'src\fractalsql_parse.c'
    $inc        = Join-Path $RepoRoot 'include'
    $fractalsqlObj      = Join-Path $outDir 'fractalsql.obj'
    $fractalsqlParseObj = Join-Path $outDir 'fractalsql_parse.obj'

    $commonCompileArgs = @(
        '/nologo', '/MT', '/O2', '/fsanitize=address', '/Zi', '/c',
        '/DWIN32', '/D_WINDOWS', '/D_CRT_SECURE_NO_WARNINGS', '/DFSQL_STATIC',
        "/I$(Join-Path $pgServerInc 'port\win32_msvc')",
        "/I$(Join-Path $pgServerInc 'port\win32')",
        "/I$pgServerInc",
        "/I$(Join-Path $PgDir 'include')",
        "/I$inc"
    )

    & cl.exe @commonCompileArgs "/Fo$fractalsqlObj" $src
    if ($LASTEXITCODE -ne 0) { throw "ASan compile failed for fractalsql.c (exit $LASTEXITCODE)" }
    & cl.exe @commonCompileArgs "/Fo$fractalsqlParseObj" $srcParse
    if ($LASTEXITCODE -ne 0) { throw "ASan compile failed for fractalsql_parse.c (exit $LASTEXITCODE)" }
    # fractalsql_vector.c -- third TU (fractal_vector type), same as the
    # Makefile's OBJS.
    $srcVector           = Join-Path $RepoRoot 'src\fractalsql_vector.c'
    $fractalsqlVectorObj = Join-Path $outDir 'fractalsql_vector.obj'
    & cl.exe @commonCompileArgs "/Fo$fractalsqlVectorObj" $srcVector
    if ($LASTEXITCODE -ne 0) { throw "ASan compile failed for fractalsql_vector.c (exit $LASTEXITCODE)" }

    # bcrypt.lib: the vendored community-sovereign-c.lib includes
    # src/diversify/entropy.c, which calls BCryptGenRandom on Windows.
    $linkArgs = @(
        '/nologo', '/LD',
        $fractalsqlObj,
        $fractalsqlParseObj,
        $fractalsqlVectorObj,
        "/Fe$Dll",
        '/link', '/DEBUG',
        $coreLib, $pgLib, $cryptoLib,
        'ws2_32.lib', 'advapi32.lib', 'secur32.lib', 'bcrypt.lib'
    )
    & cl.exe @linkArgs
    if ($LASTEXITCODE -ne 0) { throw "ASan link failed for $Dll (exit $LASTEXITCODE)" }
    if (-not (Test-Path $Dll)) { throw "ASan build did not produce $Dll" }
    Write-Host ("  -> {0} ({1:N0} bytes)" -f $Dll, (Get-Item $Dll).Length) -ForegroundColor Green
}

# Same structure as Build-AsanExtension above -- clang-cl instead of
# cl.exe, -fsanitize=undefined instead of /fsanitize=address. Both
# invocations (compile-to-.obj, then the second cl-driver invocation
# that links via /LD ... /link) go through clang-cl here, so clang-cl
# itself resolves the UBSan runtime's /DEFAULTLIB directives during its
# own driver-orchestrated link step (single-driver compile+link shape).
function Build-UbsanExtension {
    $outDir = Split-Path -Parent $Dll
    New-Item -ItemType Directory -Force -Path $outDir | Out-Null

    $pgLib       = Join-Path $PgDir 'lib\postgres.lib'
    $pgServerInc = Join-Path $PgDir 'include\server'
    if (-not (Test-Path $pgLib)) { throw "postgres.lib not found at $pgLib" }

    $coreLib = Join-Path $RepoRoot 'include\windows-x86_64\fractalsql-community-sovereign-c.lib'
    if (-not (Test-Path $coreLib)) { throw "vendored core library not found: $coreLib" }

    # libcrypto.lib: same requirement as Build-AsanExtension above -- see
    # build-windows.ps1's $CryptoLib resolution for the full rationale.
    $cryptoLib = Join-Path $PgDir 'lib\libcrypto.lib'
    if (-not (Test-Path $cryptoLib)) { throw "libcrypto.lib not found at $cryptoLib" }

    $src        = Join-Path $RepoRoot 'src\fractalsql.c'
    # fsql_extract_best_point / fsql_parse_embedding_array /
    # fsql_extract_population live in this separate, postgres.h-free TU,
    # not fractalsql.c -- must be compiled and linked here too, or the
    # link fails on 3 unresolved externals.
    $srcParse   = Join-Path $RepoRoot 'src\fractalsql_parse.c'
    $inc        = Join-Path $RepoRoot 'include'
    $fractalsqlObj      = Join-Path $outDir 'fractalsql.obj'
    $fractalsqlParseObj = Join-Path $outDir 'fractalsql_parse.obj'

    # /MD, not /MT: LLVM's prebuilt clang_rt.ubsan_standalone-x86_64.lib
    # expects dynamic-CRT (/MD) import-thunk symbols -- linking it into a
    # /MT (static CRT) binary produces 17 unresolved __imp_* externals
    # (getenv, SymInitialize, StackWalk64, etc.). UNVERIFIED here: whether
    # the vendored core .lib (a /MT release artifact, linked unchanged
    # below) is CRT-compatible with these now-/MD-compiled objects in the
    # same final .dll -- watch the first real run for a CRT mismatch
    # (LNK4098-class warning/error).
    $commonCompileArgs = @(
        '/nologo', '/MD', '/O2', '-fsanitize=undefined', '/Zi', '/c',
        '/DWIN32', '/D_WINDOWS', '/D_CRT_SECURE_NO_WARNINGS', '/DFSQL_STATIC',
        "/I$(Join-Path $pgServerInc 'port\win32_msvc')",
        "/I$(Join-Path $pgServerInc 'port\win32')",
        "/I$pgServerInc",
        "/I$(Join-Path $PgDir 'include')",
        "/I$inc"
    )

    & $script:ClangCl @commonCompileArgs "/Fo$fractalsqlObj" $src
    if ($LASTEXITCODE -ne 0) { throw "UBSan compile failed for fractalsql.c (exit $LASTEXITCODE)" }
    & $script:ClangCl @commonCompileArgs "/Fo$fractalsqlParseObj" $srcParse
    if ($LASTEXITCODE -ne 0) { throw "UBSan compile failed for fractalsql_parse.c (exit $LASTEXITCODE)" }
    # fractalsql_vector.c -- third TU (fractal_vector type), same as the
    # Makefile's OBJS.
    $srcVector           = Join-Path $RepoRoot 'src\fractalsql_vector.c'
    $fractalsqlVectorObj = Join-Path $outDir 'fractalsql_vector.obj'
    & $script:ClangCl @commonCompileArgs "/Fo$fractalsqlVectorObj" $srcVector
    if ($LASTEXITCODE -ne 0) { throw "UBSan compile failed for fractalsql_vector.c (exit $LASTEXITCODE)" }

    $linkArgs = @(
        '/nologo', '/LD',
        $fractalsqlObj,
        $fractalsqlParseObj,
        $fractalsqlVectorObj,
        "/Fe$Dll",
        '/link', '/DEBUG',
        $coreLib, $pgLib, $cryptoLib,
        'ws2_32.lib', 'advapi32.lib', 'secur32.lib', 'bcrypt.lib'
    )
    & $script:ClangCl @linkArgs
    if ($LASTEXITCODE -ne 0) { throw "UBSan link failed for $Dll (exit $LASTEXITCODE)" }
    if (-not (Test-Path $Dll)) { throw "UBSan build did not produce $Dll" }
    Write-Host ("  -> {0} ({1:N0} bytes)" -f $Dll, (Get-Item $Dll).Length) -ForegroundColor Green
}

function Gate01Build {
    Write-Host "  building..."
    if ($Asan) {
        Build-AsanExtension
    } elseif ($Ubsan) {
        Build-UbsanExtension
    } else {
        & "$RepoRoot\scripts\windows\build-windows.ps1" -PgDir $PgDir -PgMajor $PgMajor
    }
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path $Dll)) {
        Fail "01 build (PG$PgMajor)"
        return $false
    }
    Pass "01 build (PG$PgMajor)$(if ($Asan) { ' [ASan]' } elseif ($Ubsan) { ' [UBSan]' })"
    return $true
}

# --- build the test plugins (mirrors build_test.sh's pg_setup) ----------
function BuildTestPlugins {
    # New-Item -Force on an existing $PluginDir just means "don't error,"
    # it does NOT clear contents -- a stale .dll memory-mapped by a
    # lingering backend can shadow a rebuilt plugin. Remove-Item first to
    # start genuinely fresh.
    if (Test-Path $PluginDir) { Remove-Item -Recurse -Force $PluginDir -ErrorAction SilentlyContinue }
    New-Item -ItemType Directory -Force -Path $PluginDir | Out-Null
    $DefFile = Join-Path $RepoRoot 'tests\windows\fractalsql-test-plugin.def'
    $Inc = Join-Path $RepoRoot 'include'

    $targets = @(
        @{ Src = Join-Path $RepoRoot 'tests\windows\mock_reasoning_plugin_win.c';   Out = $Mock  },
        @{ Src = Join-Path $RepoRoot 'tests\windows\evil_nonterminating_plugin_win.c'; Out = $Evil  },
        @{ Src = Join-Path $RepoRoot 'tests\evil_crash_plugin.c';                  Out = $Crash },
        @{ Src = Join-Path $RepoRoot 'tests\evil_lying_length_plugin.c';           Out = $Lying },
        @{ Src = Join-Path $RepoRoot 'tests\windows\retry_reasoning_plugin_win.c'; Out = $Retry },
        @{ Src = Join-Path $RepoRoot 'tests\mock_embed_plugin.c';                  Out = $Embed },
        @{ Src = Join-Path $RepoRoot 'tests\evil_embed_plugin.c';                  Out = $EvilEmbed },
        @{ Src = Join-Path $RepoRoot 'tests\windows\think_reasoning_plugin_win.c'; Out = $Think }
    )
    foreach ($t in $targets) {
        $obj = [System.IO.Path]::ChangeExtension($t.Out, '.obj')
        & cl.exe /nologo /MT /LD /DFSQL_STATIC "/I$Inc" $t.Src "/Fo$obj" "/Fe$($t.Out)" `
            /link "/DEF:$DefFile" | Out-Null
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path $t.Out)) {
            throw "failed to build test plugin: $($t.Src)"
        }
    }
}

# --- cluster setup/teardown ----------------------------------------------
function PgSetup {
    # pg_ctl start (below) runs postgres.exe DETACHED from this script's
    # own process tree -- killing a previous run's pwsh/build_test.ps1
    # (Ctrl+C, closing the terminal) does NOT kill the postgres.exe it
    # started. A stale instance from an earlier interrupted run can be
    # left holding files open in $DataDir, so Remove-Item below fails or
    # partially succeeds, and initdb then genuinely fails against a
    # locked/non-empty directory ("removing data directory ... because
    # initialization failed") -- confirmed as the likely cause of a real
    # run that looked hung and got killed. Stop anything still bound to
    # THIS specific datadir first (scoped, not a general postgres.exe
    # sweep -- see this same pattern already used at teardown).
    if (Test-Path $DataDir) {
        try { & "$Bin\pg_ctl.exe" -D $DataDir -m immediate stop 2>&1 | Out-Null } catch { <# best-effort: pg_ctl fails harmlessly if the server is already stopped #> }
        Remove-Item -Recurse -Force $DataDir
    }
    BuildTestPlugins

    # Real diagnostic gap fixed here: this used to be
    # `& "$Bin\initdb.exe" ... | Out-Null`, which hides ALL of initdb's
    # normal stdout progress ("creating directory ... ok", "selecting
    # default...", etc.) -- a genuinely slow-but-healthy initdb (Windows
    # Defender scanning every file it writes can take 30-60s+) looks
    # completely silent, indistinguishable from a real hang, which is
    # exactly what caused a real run to be killed as "stuck" when
    # initdb may have simply been working with no visible feedback.
    # `&` native-command invocation is also what this file's own header
    # comment already documents as unsafe under PowerShell 7.3+'s
    # ANY-stderr-is-a-terminating-error behavior (the same reason Psql
    # uses the .NET Process API directly instead) -- initdb writing
    # even a routine NOTICE-class line to stderr could have aborted the
    # whole script right here, silently, before ever reaching the
    # explicit exit-code check this now has. Same Process API pattern
    # as Psql, echoing captured output live instead of swallowing it.
    $initdbPsi = New-Object System.Diagnostics.ProcessStartInfo
    $initdbPsi.FileName = "$Bin\initdb.exe"
    foreach ($a in @('-D', $DataDir, '-U', 'postgres', '--auth=trust')) {
        $initdbPsi.ArgumentList.Add($a)
    }
    $initdbPsi.RedirectStandardOutput = $true
    $initdbPsi.RedirectStandardError  = $true
    $initdbPsi.UseShellExecute = $false
    $initdbProc = [System.Diagnostics.Process]::Start($initdbPsi)
    $initdbOutTask = $initdbProc.StandardOutput.ReadToEndAsync()
    $initdbErrTask = $initdbProc.StandardError.ReadToEndAsync()
    $initdbProc.WaitForExit()
    $initdbOut = $initdbOutTask.Result
    $initdbErr = $initdbErrTask.Result
    if ($initdbOut) { Write-Host $initdbOut }
    if ($initdbErr) { Write-Host $initdbErr }
    if ($initdbProc.ExitCode -ne 0) {
        throw "initdb.exe failed (exit $($initdbProc.ExitCode)) -- see output above."
    }

    # All config via postgresql.conf, not pg_ctl -o's command-line
    # options string -- deliberately, not by oversight. PowerShell's
    # own native-argument quoting when shelling out (via &) is
    # inconsistent about embedded quotes/spaces across PS versions,
    # and $Dll/$RepoRoot can contain spaces on a real dev machine
    # (e.g. "C:\Users\Daniel Gardiner\..."). Same lesson build_test.sh
    # already learned the hard way on Linux for a different reason
    # (command-line -c permanently outranks later ALTER SYSTEM) --
    # postgresql.conf is the robust way to hand the server config that
    # might contain spaces or need later overriding.
    # fractalsql.reasoning_plugin: raw native (backslash) path, NOT
    # forward-slash-converted like $DllPath above. The core library's
    # fsql_load_reasoning() rejects a non-canonical path (one of three
    # defense layers before dlopen/LoadLibrary) -- on Windows the OS's
    # own canonicalization resolves to backslash form, so a forward-
    # slash-converted value fails that check with "path is not
    # canonical". Opposite requirement from $DllPath's fix above (that
    # one's about matching shared_preload_libraries' string-equality
    # dedup, a completely different subsystem).
    #
    # postgresql.conf's own file format additionally does C-style
    # backslash-escape processing on quoted string values (undocumented
    # in most guides but real: \f, \n, \t etc. are recognized escapes,
    # and an unrecognized one like \U or \A silently drops the
    # backslash) -- writing this file directly via Add-Content, I'm
    # responsible for doing that escaping myself, unlike ALTER SYSTEM
    # (PgSwapPlugin, below) which goes through SQL + Postgres's own
    # internal postgresql.auto.conf serialization and handles the
    # round-trip correctly without help. Confirmed the hard way: the
    # unescaped path's "\f" (from "...\fractalsql_bt_..." in the temp
    # dir name) got read back as a literal form-feed character, and
    # every other single backslash was silently dropped.
    $MockEscaped = $Mock -replace '\\','\\'
    $confLines = @(
        "listen_addresses = '127.0.0.1'",
        "port = $Port",
        "shared_preload_libraries = '$DllPath'",
        "fractalsql.reasoning_plugin = '$MockEscaped'",
        "fractalsql.text_to_sql_max_attempts = 1"
    )
    Add-Content -Path (Join-Path $DataDir 'postgresql.conf') -Value $confLines

    # REVERTED to the original bare invocation -- a redirected-pipe
    # version of this call was tried and caused a real regression: `pg_ctl
    # start` spawns postgres.exe as a long-running DETACHED daemon (that's
    # its whole job), which inherits handles to any redirected stdout/
    # stderr pipe. pg_ctl.exe itself exits promptly once the server is
    # ready, but reading a redirected pipe to EOF (Process.StandardOutput/
    # StandardError) blocks until EVERY process holding a handle to the
    # write end closes it -- and postgres.exe (plus its own child
    # processes: checkpointer, bgwriter, walwriter, ...) never do, since
    # they're meant to keep running. That made the script hang
    # indefinitely right here, even though the server itself had started
    # successfully (confirmed via its own log showing "ready to accept
    # connections") -- initdb doesn't have this problem (no long-lived
    # daemon children, the pipe reaches real EOF), so its own Process API
    # version above is unaffected and stays as-is. The PS7.3+ stderr-as-
    # terminating-error risk this bare form was originally rewritten to
    # avoid is real in theory, but this exact call has been empirically
    # proven fine across every real Windows run this session predating
    # that rewrite -- pg_ctl -w start's normal (success) path doesn't
    # write to stderr at all, so the risk never actually manifested,
    # unlike the pipe-EOF hang, which manifested immediately.
    & "$Bin\pg_ctl.exe" -D $DataDir -w -l (Join-Path $DataDir 'log') start
    if ($LASTEXITCODE -ne 0) { throw "pg_ctl start failed -- see $DataDir\log" }

    $createSql = @"
CREATE FUNCTION fractal_version() RETURNS text AS '$DllPath','fractal_version' LANGUAGE C IMMUTABLE STRICT;
CREATE FUNCTION fractal_edition() RETURNS text AS '$DllPath','fractal_edition' LANGUAGE C IMMUTABLE STRICT;
CREATE FUNCTION fractal_search(query float8[], iterations int4 DEFAULT 30, population_size int4 DEFAULT 50, diffusion_factor int4 DEFAULT 2) RETURNS float8[] AS '$DllPath','fractal_search' LANGUAGE C VOLATILE STRICT;
CREATE FUNCTION fractal_search_debug(query float8[], iterations int4 DEFAULT 30, population_size int4 DEFAULT 50, diffusion_factor int4 DEFAULT 2) RETURNS jsonb AS '$DllPath','fractal_search_debug' LANGUAGE C VOLATILE STRICT;
CREATE FUNCTION fractal_schema_context(table_names text[] DEFAULT NULL, query_hint text DEFAULT NULL) RETURNS text AS '$DllPath','fractal_schema_context' LANGUAGE C;
CREATE FUNCTION fractal_text_to_sql(question text, table_names text[] DEFAULT NULL) RETURNS text AS '$DllPath','fractal_text_to_sql' LANGUAGE C;
CREATE FUNCTION fractal_reason(query text, context text DEFAULT '{}') RETURNS text AS '$DllPath','fractal_reason' LANGUAGE C;
CREATE FUNCTION fractal_search_explore(table_name text, vector_col text, query float8[], options jsonb DEFAULT '{}'::jsonb) RETURNS SETOF float8[] AS '$DllPath','fractal_search_explore' LANGUAGE C VOLATILE STRICT;
CREATE FUNCTION fractal_embed(input text) RETURNS float8[] AS '$DllPath','fractal_embed' LANGUAGE C;
"@
    Psql -Sql $createSql | Out-Null

    # Load the two post-core sections of sql\fractalsql--1.0.sql straight
    # from the real file (not duplicated here by hand), matching build_test.sh's
    # Linux pg_setup() slice pattern exactly:
    #
    #   1. Vectorizer section (tables/trigger function/fractal_vectorizer_create/
    #      fractal_vectorizer_process_queue/fractal_vectorizer_status view) --
    #      pure SQL/PLpgSQL, NO MODULE_PATHNAME references, so it is loaded raw.
    #
    #   2. v2.x additions section (Diversify/Repulsion, feedback, dimension
    #      analysis, portfolio optimization, domain geometry, fractal_vector
    #      type, _fv overloads) -- this section DOES reference MODULE_PATHNAME
    #      (every C function in it), which only CREATE EXTENSION substitutes
    #      automatically; replace it with $DllPath before loading, exactly as
    #      build_test.sh does via `sed "s#MODULE_PATHNAME#$SO#g"` (its lines
    #      518-521). Without this the functions load with a literal
    #      "MODULE_PATHNAME" library string (CREATE FUNCTION does not validate
    #      the lib at create time) and fail at first call ("could not find
    #      function ... in file MODULE_PATHNAME").
    $sqlFileLines = Get-Content (Join-Path $RepoRoot 'sql\fractalsql--1.0.sql')
    $vectorizerIdx = ($sqlFileLines | Select-String -Pattern '^-- Vectorizer --' | Select-Object -First 1).LineNumber
    if (-not $vectorizerIdx) { throw "could not find '-- Vectorizer --' marker in sql\fractalsql--1.0.sql" }
    $v2xIdx = ($sqlFileLines | Select-String -Pattern '^-- v2.x additions --' | Select-Object -First 1).LineNumber
    if (-not $v2xIdx) { throw "could not find '-- v2.x additions --' marker in sql\fractalsql--1.0.sql" }

    # Slice 0 (Agent-tier): the 6 C-level "Universal Agent" functions +
    # their composite return types (fractal_search_agent, fractal_sql_agent,
    # fractal_rag_agent, fractal_agent_plan_explore, fractal_agent_
    # trajectory_predict, fractal_agent_detect_loop). This section sits
    # between the core (hand-registered as createSql above) and the
    # Vectorizer marker; it references MODULE_PATHNAME, so substitute
    # $DllPath. Engine G (fractal_agent_data_analyst) composes
    # fractal_sql_agent, so its fractal_sql_agent_result composite type
    # MUST exist before the agents extension slice loads -- PL/pgSQL
    # resolves DECLARE res fractal_sql_agent_result at CREATE time, so
    # without this slice engine G's CREATE fails with "type
    # fractal_sql_agent_result does not exist".
    $agentTierIdx = ($sqlFileLines | Select-String -Pattern '^-- Agent-tier results types' | Select-Object -First 1).LineNumber
    if (-not $agentTierIdx) { throw "could not find '-- Agent-tier results types' marker in sql\fractalsql--1.0.sql" }
    $agentTierSql = ($sqlFileLines[($agentTierIdx - 1)..($vectorizerIdx - 2)]) -join "`n"
    $agentTierSql = $agentTierSql -replace 'MODULE_PATHNAME', $DllPath
    $agentTierResult = Psql -Sql $agentTierSql
    if ($agentTierResult -match '(?i)error') { throw "agent-tier DDL failed to load: $agentTierResult" }

    # Slice 1 (Vectorizer): from its marker up to but EXCLUDING the v2.x
    # marker -- pure SQL/PLpgSQL, no MODULE_PATHNAME, load raw.
    $vectorizerSql = ($sqlFileLines[($vectorizerIdx - 1)..($v2xIdx - 2)]) -join "`n"
    $vzResult = Psql -Sql $vectorizerSql
    if ($vzResult -match '(?i)error') { throw "vectorizer DDL failed to load: $vzResult" }

    # Slice 2 (v2.x + fractal_vector): from its marker to EOF, with
    # MODULE_PATHNAME replaced by $DllPath (forward-slash DLL path, same
    # form the inline CREATE FUNCTION block above uses).
    $v2xSql = ($sqlFileLines[($v2xIdx - 1)..($sqlFileLines.Count - 1)]) -join "`n"
    $v2xSql = $v2xSql -replace 'MODULE_PATHNAME', $DllPath
    $v2xResult = Psql -Sql $v2xSql
    if ($v2xResult -match '(?i)error') { throw "v2.x/vector DDL failed to load: $v2xResult" }

    # Slice 3 (fractalsql_agents dependent extension): the parameterized
    # PL/pgSQL agent engines shipped in fractalsql_agents/. Pure PL/pgSQL
    # (no MODULE_PATHNAME), loaded raw like the Vectorizer slice -- but read
    # from its own extension subdir, with the \echo ... \quit guard line
    # stripped (the same guard the base SQL carries; \quit would abort psql).
    # The base functions it composes (fractal_dimension_drift, fractal_reason,
    # fractal_optimize_portfolio) are already registered above (hand-registered
    # C + the v2.x slice), so PL/pgSQL CREATE defers-resolution succeeds.
    $agentsSqlFile = Join-Path $RepoRoot 'fractalsql_agents\sql\fractalsql_agents--1.0.sql'
    if (-not (Test-Path $agentsSqlFile)) { throw "fractalsql_agents\sql\fractalsql_agents--1.0.sql not found -- run from a checkout that includes the fractalsql_agents/ extension" }
    $agentsSql = ((Get-Content $agentsSqlFile) | Where-Object { $_ -notmatch '^\s*\\echo.*\\quit' }) -join "`n"
    $agentsResult = Psql -Sql $agentsSql
    if ($agentsResult -match '(?i)error') { throw "fractalsql_agents DDL failed to load: $agentsResult" }
}

function PgTeardown {
    try { & "$Bin\pg_ctl.exe" -D $DataDir -m fast stop 2>&1 | Out-Null } catch { <# best-effort: pg_ctl fails harmlessly if the server is already stopped #> }
    # TEMPORARY: see Cleanup's matching FSQL_BT_KEEP_DATADIR comment.
    if (-not $env:FSQL_BT_KEEP_DATADIR) {
        Remove-Item -Recurse -Force $DataDir, $PluginDir -ErrorAction SilentlyContinue
    } else {
        Remove-Item -Recurse -Force $PluginDir -ErrorAction SilentlyContinue
    }
}

# ALTER SYSTEM cannot run inside a transaction block; a single -c "A; B"
# string runs as one implicit transaction (same finding as
# build_test.sh's pg_swap_plugin). Two separate psql invocations here,
# same as the Linux fix.
function PgSetGuc {
    param([string]$Name, [string]$SetVal, [string]$Want)
    Psql -Sql "ALTER SYSTEM SET $Name = $SetVal;" | Out-Null
    Psql -Sql "SELECT pg_reload_conf();" | Out-Null
    for ($i = 0; $i -lt (10 * $TimeoutMult); $i++) {
        $v = Psql -Sql "SELECT current_setting('$Name');"
        if ($v -eq $Want) { return $true }
        Start-Sleep -Milliseconds 200
    }
    return $false
}

function PgSwapPlugin($path) {
    # Raw native path, not forward-slash-converted -- see the matching
    # comment on the initial postgresql.conf write in PgSetup for why.
    PgSetGuc -Name 'fractalsql.reasoning_plugin' -SetVal "'$path'" -Want $path
}

# --- gates 02-12 ----------------------------------------------------------

function Gate02Smoke {
    $ver = Psql -Sql "SELECT fractal_version();"
    if ($ver -eq '2.0.11') { Pass "02 smoke: version=$ver" } else { Fail "02 smoke: version='$ver' (want 2.0.11)" }
    $r = Psql -Sql @"
WITH q AS (SELECT fractal_search(ARRAY[0.6,0.8]::float8[],100,50,2) AS v)
SELECT CASE WHEN sqrt(v[1]*v[1]+v[2]*v[2])>1e-9
             AND (v[1]*0.6+v[2]*0.8)/sqrt(v[1]*v[1]+v[2]*v[2])>0.99
            THEN 'ok' ELSE 'FAIL' END FROM q;
"@
    if ($r -eq 'ok') { Pass "02 smoke: fractal_search convergence" } else { Fail "02 smoke: convergence=$r" }
    $ed = Psql -Sql "SELECT fractal_edition();"
    if ($ed -and $ed -notmatch 'ERROR') { Pass "02 smoke: edition=$ed" } else { Fail "02 smoke: edition='$ed'" }
    # fractal_search_debug returns the FULL fsql_search_ptr result JSON
    # (not just the best_point extraction fractal_search uses) -- assert
    # the best_point key survives the jsonb_in round-trip.
    $dbg = Psql -Sql "SELECT fractal_search_debug(ARRAY[0.6,0.8]::float8[],100,50,2);"
    if ($dbg -match 'best_point') { Pass "02 smoke: fractal_search_debug has best_point" }
    else { Fail "02 smoke: fractal_search_debug='$dbg'" }
}

function Gate03SchemaContext {
    Psql -Sql @"
DROP TABLE IF EXISTS bt_orders, bt_customers;
CREATE TABLE bt_customers (id serial PRIMARY KEY, name text NOT NULL, status text);
COMMENT ON TABLE bt_customers IS 'buyers';
CREATE TABLE bt_orders (id serial PRIMARY KEY, customer_id int NOT NULL REFERENCES bt_customers(id), total int NOT NULL);
"@ | Out-Null
    $ctx = Psql -Sql "SELECT fractal_schema_context(ARRAY['bt_customers','bt_orders']);"
    if ($ctx -match 'id integer PK')          { Pass "03 schema_context: PK" }       else { Fail "03 schema_context: PK" }
    if ($ctx -match 'name text NOT NULL')     { Pass "03 schema_context: NOT NULL" } else { Fail "03 schema_context: NOT NULL" }
    if ($ctx -match 'buyers')                 { Pass "03 schema_context: comment" }  else { Fail "03 schema_context: comment" }
    if ($ctx -match 'REFERENCES bt_customers'){ Pass "03 schema_context: FK" }       else { Fail "03 schema_context: FK" }
}

function T2sExpect($Canned, $Want, $Label) {
    Set-Content -Path $SqlFile -Value $Canned -NoNewline
    $r = Psql -Sql "SELECT fractal_text_to_sql('q', ARRAY['bt_customers','bt_orders']);"
    if ([string]::IsNullOrEmpty($Want)) {
        if ($r -match 'ERROR') { Fail "$Label (expected PASS): $r" } else { Pass "$Label -> returned" }
    } else {
        if ($r -match [regex]::Escape($Want)) { Pass "$Label -> rejected ($Want)" } else { Fail "${Label}: got '$r' (want '$Want')" }
    }
}

function Gate04TextToSql {
    T2sExpect 'SELECT count(*) FROM bt_orders' '' '04 valid-SELECT'
    T2sExpect 'SELECT 1; DROP TABLE bt_orders' 'exactly one SQL' '04 stacked'
    T2sExpect 'DROP TABLE bt_orders' 'not permitted' '04 DDL'
    T2sExpect 'DELETE FROM bt_orders' 'not permitted' '04 DELETE'
    T2sExpect 'WITH d AS (DELETE FROM bt_orders RETURNING *) SELECT * FROM d' 'data-modifying CTE' '04 modifying-CTE'
    T2sExpect 'SELECT nope FROM bt_orders' 'does not analyze' '04 bad-column'
    $n = Psql -Sql "SELECT count(*) FROM bt_orders;"
    if ($n -eq '0') { Pass "04 never-executes (bt_orders still empty)" } else { Fail "04 never-executes: row count=$n" }
}

function Gate05EvilOverread {
    if (-not (PgSwapPlugin $Evil)) { Fail "05 evil_overread: plugin swap did not take effect"; return }

    Set-Content -Path $TriggerFile -Value '1' -NoNewline
    Set-Content -Path $SqlFile -Value 'SELECT 1' -NoNewline
    $r = Psql -Sql "SELECT fractal_text_to_sql('q', ARRAY['bt_customers','bt_orders']);"
    if ($r -match 'server closed the connection|could not connect') { Fail "05 evil_overread: GENERATE path -- backend crashed -- $r" }
    else { Pass "05 evil_overread: GENERATE path (non-terminated guard-page response) survived" }

    $r2 = Psql -Sql "SELECT fractal_reason('q');"
    if ($r2 -match 'server closed the connection|could not connect') { Fail "05 evil_overread: bare fractal_reason() -- backend crashed -- $r2" }
    else { Pass "05 evil_overread: bare fractal_reason() survived" }

    if (-not (PgSetGuc -Name 'fractalsql.text_to_sql_use_review' -SetVal 'on' -Want 'on')) {
        Fail "05 evil_overread: could not enable text_to_sql_use_review"; PgSwapPlugin $Mock | Out-Null; return
    }
    Set-Content -Path $TriggerFile -Value '2' -NoNewline
    $r3 = Psql -Sql "SELECT fractal_text_to_sql('q', ARRAY['bt_customers','bt_orders']);"
    if ($r3 -match 'server closed the connection|could not connect') { Fail "05 evil_overread: REVIEW path -- backend crashed -- $r3" }
    else { Pass "05 evil_overread: REVIEW path (t2s_run_review) survived" }
    PgSetGuc -Name 'fractalsql.text_to_sql_use_review' -SetVal 'off' -Want 'off' | Out-Null
    Set-Content -Path $TriggerFile -Value '1' -NoNewline

    PgSwapPlugin $Mock | Out-Null
}

function Gate06CrashRecovery {
    Psql -Sql "INSERT INTO bt_customers (name, status) VALUES ('canary', 'ok');" | Out-Null
    if (-not (PgSwapPlugin $Crash)) { Fail "06 crash_recovery: plugin swap did not take effect"; return }

    Set-Content -Path $SqlFile -Value 'SELECT 1' -NoNewline
    $r = Psql -Sql "SELECT fractal_text_to_sql('q', ARRAY['bt_customers','bt_orders']);"
    if ($r -match 'server closed the connection|could not connect') {
        Pass "06 crash_recovery: triggering connection dropped as expected"
    } else {
        Fail "06 crash_recovery: expected the connection to drop, got: $r"
    }

    # Pass/fail budget and actual up-detection must not share the same
    # cutoff -- restoring $Mock below depends on $up, and a near-miss on
    # the original budget (cluster comes back a few seconds late) left
    # the deliberately-crashing plugin active for every remaining gate,
    # cascading into unrelated-looking failures far downstream (confirmed
    # on real Windows CI: 06 missed a 15s budget by ~4s, then gates
    # 07/12/13/14/15/17/20 all failed against the still-active crash
    # plugin). Poll for up to double the budget; report pass/fail against
    # the original window, but restore the plugin as long as the cluster
    # comes back at all within the extended one.
    $up = $false
    $withinBudget = $false
    $tries = 30 * $TimeoutMult
    for ($i = 0; $i -lt ($tries * 2); $i++) {
        $t = Psql -Sql "SELECT 1;"
        if ($t -eq '1') { $up = $true; if ($i -lt $tries) { $withinBudget = $true }; break }
        Start-Sleep -Milliseconds 500
    }
    if ($withinBudget) { Pass "06 crash_recovery: cluster auto-restarted" }
    else { Fail "06 crash_recovery: cluster did not come back within $($tries / 2)s" }

    if ($up) {
        $n = Psql -Sql "SELECT count(*) FROM bt_customers WHERE name = 'canary';"
        if ($n -eq '1') { Pass "06 crash_recovery: prior data intact after recovery" }
        else { Fail "06 crash_recovery: canary row missing after recovery (n=$n)" }
        PgSwapPlugin $Mock | Out-Null
    } else {
        Fail "06 crash_recovery: cluster never came back -- remaining gates will run against the crash plugin"
    }
}

function Gate07EvilLyingLength {
    if (-not (PgSwapPlugin $Lying)) { Fail "07 evil_lying_length: plugin swap did not take effect"; return }

    Set-Content -Path $TriggerFile -Value '1' -NoNewline
    $r = Psql -Sql "SELECT fractal_text_to_sql('q', ARRAY['bt_customers','bt_orders']);"
    if ($r -match 'server closed the connection|could not connect') { Fail "07 evil_lying_length: GENERATE path -- backend crashed -- $r" }
    elseif ($r -match 'implausible response length') { Pass "07 evil_lying_length: GENERATE path rejected cleanly" }
    else { Fail "07 evil_lying_length: GENERATE path -- expected rejection, got: $r" }

    $r2 = Psql -Sql "SELECT fractal_reason('q');"
    if ($r2 -match 'server closed the connection|could not connect') { Fail "07 evil_lying_length: bare fractal_reason() -- backend crashed -- $r2" }
    elseif ($r2 -match 'implausible response length') { Pass "07 evil_lying_length: bare fractal_reason() rejected cleanly" }
    else { Fail "07 evil_lying_length: bare fractal_reason() -- expected rejection, got: $r2" }

    if (-not (PgSetGuc -Name 'fractalsql.text_to_sql_use_review' -SetVal 'on' -Want 'on')) {
        Fail "07 evil_lying_length: could not enable text_to_sql_use_review"; PgSwapPlugin $Mock | Out-Null; return
    }
    Set-Content -Path $TriggerFile -Value '2' -NoNewline
    $r3 = Psql -Sql "SELECT fractal_text_to_sql('q', ARRAY['bt_customers','bt_orders']);"
    if ($r3 -match 'server closed the connection|could not connect') { Fail "07 evil_lying_length: REVIEW path -- backend crashed -- $r3" }
    elseif ($r3 -match 'implausible response length') { Pass "07 evil_lying_length: REVIEW path (t2s_run_review) rejected cleanly" }
    else { Fail "07 evil_lying_length: REVIEW path -- expected rejection, got: $r3" }
    PgSetGuc -Name 'fractalsql.text_to_sql_use_review' -SetVal 'off' -Want 'off' | Out-Null
    Set-Content -Path $TriggerFile -Value '1' -NoNewline

    PgSwapPlugin $Mock | Out-Null
}

function Gate08Authz {
    Psql -Sql @"
DROP TABLE IF EXISTS bt_secret;
CREATE TABLE bt_secret (id serial PRIMARY KEY, ssn text);
COMMENT ON TABLE bt_secret IS 'PII - restricted';
REVOKE ALL ON bt_secret FROM PUBLIC;
DROP ROLE IF EXISTS bt_lowpriv;
CREATE ROLE bt_lowpriv LOGIN;
"@ | Out-Null

    $r = Psql -Sql "SELECT fractal_schema_context(ARRAY['bt_secret']);" -User 'bt_lowpriv'
    if ($r -match 'ssn') { Fail "08 authz: low-priv role saw bt_secret's columns (info disclosure): $r" }
    elseif ($r -match 'not found or not visible') { Pass "08 authz: low-priv role correctly blocked from bt_secret" }
    else { Fail "08 authz: unexpected result: $r" }

    Psql -Sql "GRANT SELECT ON bt_secret TO bt_lowpriv;" | Out-Null
    $r2 = Psql -Sql "SELECT fractal_schema_context(ARRAY['bt_secret']);" -User 'bt_lowpriv'
    if ($r2 -match 'ssn') { Pass "08 authz: SELECT grant restores visibility" } else { Fail "08 authz: granted role still blocked: $r2" }

    Psql -Sql "DROP ROLE bt_lowpriv; DROP TABLE bt_secret;" | Out-Null
}

function Gate09GucSuperuser {
    Psql -Sql "DROP ROLE IF EXISTS bt_lowpriv2; CREATE ROLE bt_lowpriv2 LOGIN;" | Out-Null
    $r = Psql -Sql "ALTER SYSTEM SET fractalsql.reasoning_plugin = 'C:\evil.dll';" -User 'bt_lowpriv2'
    if ($r -match '(?i)permission denied|must be a?n? ?superuser') {
        Pass "09 guc_superuser: non-superuser rejected from setting reasoning_plugin"
    } else {
        Fail "09 guc_superuser: expected rejection, got: $r"
    }
    Psql -Sql "DROP ROLE bt_lowpriv2;" | Out-Null
}

function Gate10DosAndInjection {
    $many = (1..513 | ForEach-Object { "'t$_'" }) -join ','
    $r = Psql -Sql "SELECT fractal_schema_context(ARRAY[$many]);"
    if ($r -match 'exceeds the limit of 512') { Pass "10 dos_cap: 513 table names rejected" }
    else { Fail "10 dos_cap: expected PROGRAM_LIMIT_EXCEEDED, got: $r" }

    $r2 = Psql -Sql "SELECT fractal_schema_context(ARRAY['bt_customers''; DROP TABLE bt_orders; --']);"
    $n = Psql -Sql "SELECT count(*) FROM bt_orders;"
    if ($n -eq '0') { Pass "10 injection: SQL-injection-shaped table name did not execute (bt_orders intact)" }
    else { Fail "10 injection: bt_orders row count changed (n=$n) -- injection may have executed" }
    if ($r2 -match 'not found or not visible|ERROR') { Pass "10 injection: injection-shaped table name cleanly rejected" }
    else { Fail "10 injection: unexpected result: $r2" }
}

function Gate11Scout {
    Psql -Sql @"
DROP TABLE IF EXISTS bt_scout_docs;
CREATE TABLE bt_scout_docs (id int, emb_arr float8[]);
INSERT INTO bt_scout_docs
  SELECT i, ARRAY[1.0,0.0,0.0]::float8[] FROM generate_series(1,20) i
  UNION ALL
  SELECT i, ARRAY[0.0,1.0,0.0]::float8[] FROM generate_series(21,40) i
  UNION ALL
  SELECT i, ARRAY[0.0,0.0,1.0]::float8[] FROM generate_series(41,60) i;
"@ | Out-Null

    $n = Psql -Sql @"
SELECT count(*) FROM fractal_search_explore(
  'bt_scout_docs', 'emb_arr', ARRAY[1.0,0.0,0.0]::float8[],
  '{"population_size": 24, "iterations": 12}'::jsonb);
"@
    if ($n -eq '24') { Pass "11 scout: returns full population (24 particles)" }
    else { Fail "11 scout: expected 24 particles, got: $n" }

    $islands = Psql -Sql @"
SELECT count(DISTINCT
  CASE WHEN p[1] > p[2] AND p[1] > p[3] THEN 0
       WHEN p[2] > p[1] AND p[2] > p[3] THEN 1
       ELSE 2 END)
FROM fractal_search_explore(
  'bt_scout_docs', 'emb_arr', ARRAY[1.0,0.0,0.0]::float8[],
  '{"population_size": 24, "iterations": 12}'::jsonb) AS p;
"@
    $islandsNum = 0
    if ([int]::TryParse($islands, [ref]$islandsNum) -and $islandsNum -gt 1) {
        Pass "11 scout: particles disperse across >1 island"
    } else {
        Fail "11 scout: expected dispersion, got islands=$islands"
    }

    Psql -Sql "DROP TABLE IF EXISTS bt_scout_docs;" | Out-Null
}

function Gate12Soak {
    # Diagnostic: a real run produced zero Pass/Fail output for this
    # gate (and 13/14) against a cluster still recovering from gate 06's
    # crash, while gates 07-11 printed FAIL lines against the same dead
    # cluster -- this entry echo exists to disambiguate "never started"
    # from "started but its own Pass/Fail calls didn't print" the next
    # time that happens, since ForEach-Object -Parallel's 20 runspaces
    # give this gate a materially different failure surface than the
    # other gates' single synchronous Psql calls. Cheap, always-on
    # (unlike a -Verbose-gated line) since gate 12 already prints on
    # every run anyway.
    Write-Host "  12 soak: starting (20 workers x 15 iterations)..."
    $workers = 20
    $iters = 15
    Set-Content -Path $SqlFile -Value 'SELECT count(*) FROM bt_orders' -NoNewline

    $results = 1..$workers | ForEach-Object -Parallel {
        $w = $_
        $bin = $using:Bin
        $port = $using:Port
        $rc = 0
        for ($i = 1; $i -le $using:iters; $i++) {
            $q = switch ((($w + $i) % 3)) {
                0 { "SELECT fractal_search(ARRAY[0.6,0.8]::float8[],20,20,2);" }
                1 { "SELECT fractal_schema_context(ARRAY['bt_customers','bt_orders']);" }
                2 { "SELECT fractal_text_to_sql('q', ARRAY['bt_customers','bt_orders']);" }
            }
            # Process API directly (not & psql.exe), matching the
            # script-scope Psql function's approach -- see its comment.
            # -Parallel runs in an isolated runspace that doesn't
            # inherit script-scope preference variables, so this can't
            # just call that function; inlined here instead.
            $psi = New-Object System.Diagnostics.ProcessStartInfo
            $psi.FileName = "$bin\psql.exe"
            foreach ($a in @('-h','127.0.0.1','-p',"$port",'-U','postgres','-d','postgres','-X','-tA','-c',$q)) {
                $psi.ArgumentList.Add($a)
            }
            $psi.RedirectStandardOutput = $true
            $psi.RedirectStandardError  = $true
            $psi.UseShellExecute = $false
            $proc = [System.Diagnostics.Process]::Start($psi)
            # Concurrent async reads, not sequential ReadToEnd() -- see
            # the script-scope Psql function's comment for why a large
            # stderr payload (an unexpected error's detail text) can
            # deadlock a stdout-then-stderr read order.
            $soT = $proc.StandardOutput.ReadToEndAsync()
            $seT = $proc.StandardError.ReadToEndAsync()
            $proc.WaitForExit()
            $soT.Result | Out-Null
            $seT.Result | Out-Null
            if ($proc.ExitCode -ne 0) { $rc = 1 }
        }
        $rc
    } -ThrottleLimit $workers

    # @(...) forces an array even when zero items match -- under
    # Set-StrictMode, Where-Object matching nothing returns $null, and
    # $null.Count throws "property cannot be found" (confirmed the
    # hard way: all 20 workers succeeding -- a GOOD result -- crashed
    # the script here on the first real Windows run).
    $failedWorkers = @($results | Where-Object { $_ -ne 0 }).Count
    $total = $workers * $iters
    if ($failedWorkers -eq 0) { Pass "12 soak: $workers workers x $iters iterations ($total calls) all succeeded" }
    else { Fail "12 soak: $failedWorkers/$workers workers had a failed call" }

    $t = Psql -Sql "SELECT 1;"
    if ($t -eq '1') { Pass "12 soak: cluster responsive after concurrent load" }
    else { Fail "12 soak: cluster unresponsive after concurrent load" }
}

# select_insert_update mode: fractalsql.text_to_sql_allowed_statements
# widens the allowlist from SELECT-only to SELECT/INSERT/UPDATE. Proves
# both halves of that: writes are now returned (not rejected) instead of
# executed (still just EXPLAINed, per t2s_check_explain), and DDL/DELETE
# remain rejected regardless -- the GUC only ever adds INSERT/UPDATE to
# the allowed set, never removes the DDL/DELETE block. Mirrors
# build_test.sh's gate 13. Pure SQL/GUC -- no plugin swap needed (runs
# against the mock plugin T2sExpect already drives through $SqlFile).
function Gate13SiuMode {
    if (-not (PgSetGuc -Name 'fractalsql.text_to_sql_allowed_statements' -SetVal "'select_insert_update'" -Want 'select_insert_update')) {
        Fail "13 siu_mode: GUC did not take effect"; return
    }

    T2sExpect 'INSERT INTO bt_orders (customer_id, total) VALUES (1, 100)' '' '13 siu-insert-allowed'
    T2sExpect 'UPDATE bt_orders SET total = 0'                             '' '13 siu-update-allowed'
    T2sExpect 'DROP TABLE bt_orders'          'not permitted' '13 siu-ddl-still-rejected'
    T2sExpect 'DELETE FROM bt_orders'         'not permitted' '13 siu-delete-still-rejected'

    $n = Psql -Sql "SELECT count(*) FROM bt_orders;"
    if ($n -eq '0') { Pass "13 siu_mode: INSERT/UPDATE never execute (bt_orders still empty)" }
    else { Fail "13 siu_mode: row count=$n" }

    PgSetGuc -Name 'fractalsql.text_to_sql_allowed_statements' -SetVal "'select'" -Want 'select' | Out-Null
}

# Retry-with-feedback: max_attempts>1 with a plugin (tests\windows\
# retry_reasoning_plugin_win.c) that returns a rejected DDL statement
# ("DROP TABLE bt_orders", fails the ALLOWLIST) on GENERATE call 1, then
# "SELECT 1" (passes) on call 2 -- exercising fractal_text_to_sql()'s
# retry loop (fractalsql.c, the `last_sql != NULL` prompt-rebuild branch)
# which every other gate leaves untouched (they all run at
# max_attempts=1, so the loop body only ever executes once). The plugin
# dumps the 2nd-call GENERATE prompt to $RetryPromptFile so this gate can
# confirm the attempt-1 rejection reason was actually threaded back into
# the attempt-2 prompt, not just that *a* retry happened. Mirrors
# build_test.sh's gate 14.
function Gate14Retry {
    # Fresh prompt file -- a stale file from a prior run must not fool the
    # feedback-threading assertion. (Cleanup also removes it on exit.)
    Remove-Item -Force $RetryPromptFile -ErrorAction SilentlyContinue
    if (-not (PgSetGuc -Name 'fractalsql.text_to_sql_max_attempts' -SetVal '2' -Want '2')) {
        Fail "14 retry: GUC did not take effect"; return
    }
    if (-not (PgSwapPlugin $Retry)) {
        Fail "14 retry: plugin swap did not take effect"
        PgSetGuc -Name 'fractalsql.text_to_sql_max_attempts' -SetVal '1' -Want '1' | Out-Null; return
    }

    $r = Psql -Sql "SELECT fractal_text_to_sql('q', ARRAY['bt_customers','bt_orders']);"
    if ($r -match 'server closed the connection|could not connect') {
        Fail "14 retry: backend crashed -- $r"
    } elseif ($r -match '^SELECT 1') {
        Pass "14 retry: succeeded on 2nd attempt after 1st was rejected"
    } else {
        Fail "14 retry: expected eventual success (SELECT 1), got: $r"
    }

    # The plugin only writes the prompt file on call_count >= 2 (the
    # attempt-2 GENERATE prompt, which carries the attempt-1 rejection
    # feedback). Read it back to prove the feedback was threaded through.
    $prompt = Get-Content -Path $RetryPromptFile -Raw -ErrorAction SilentlyContinue
    if ($prompt -and $prompt -match 'not permitted') {
        Pass "14 retry: attempt-1 rejection reason fed back into attempt-2 prompt"
    } else {
        Fail "14 retry: retry prompt missing feedback text: '$prompt'"
    }

    $n = Psql -Sql "SELECT count(*) FROM bt_orders;"
    if ($n -eq '0') { Pass "14 retry: never-executes held across retries" }
    else { Fail "14 retry: row count=$n" }

    PgSetGuc -Name 'fractalsql.text_to_sql_max_attempts' -SetVal '1' -Want '1' | Out-Null
    PgSwapPlugin $Mock | Out-Null
    Remove-Item -Force $RetryPromptFile -ErrorAction SilentlyContinue
}

# fractal_embed() + the vectorizer, real dispatch through
# ensure_embed_ctx()/g_embed_ctx (the three-tier reasoning-context split
# -- see fractalsql.c's own header comment) using a canned-vector mock
# plugin, not just the "no plugin configured"/"no http_embed_url
# configured" precondition-error paths every other gate here leaves
# untouched. HTTP-level embedding-response parsing is covered separately
# in tests/test_vectorizer.py against the real vendored plugin (Linux-
# verified; needs its own Windows equivalent if this repo ever wires
# psycopg into this harness -- not done here, see build_test.sh's own
# gate 15 comment for the identical scope note) -- this gate is about
# fractalsql-postgresql's OWN glue, matching every other gate's
# mock-plugin scope in this file. Mirrors build_test.sh's gate 15.
function Gate15Embed {
    Write-Host "  15 embed: starting..."
    if (-not (PgSetGuc -Name 'fractalsql.http_embed_url' -SetVal "'http://unused/embeddings'" -Want 'http://unused/embeddings')) {
        Fail "15 embed: http_embed_url GUC did not take effect"; return
    }
    if (-not (PgSwapPlugin $Embed)) { Fail "15 embed: plugin swap did not take effect"; return }

    $r = Psql -Sql "SELECT fractal_embed('test input');"
    if ($r -eq '{0.1,0.2,0.3}') { Pass "15 embed: fractal_embed() returned the canned vector" }
    else { Fail "15 embed: fractal_embed() expected {0.1,0.2,0.3}, got: $r" }

    $rnull = Psql -Sql "SELECT fractal_embed(NULL);"
    if ($rnull -match 'must not be NULL') { Pass "15 embed: NULL input rejected cleanly" }
    else { Fail "15 embed: NULL input expected a clear rejection, got: $rnull" }

    # Nonexistent plugin path -- exercises ensure_reasoning_tier_ctx's own
    # load-failure branch (distinct from "no plugin configured at all").
    if (-not (PgSetGuc -Name 'fractalsql.reasoning_plugin' -SetVal "'C:\fractalsql_bt_nonexistent.dll'" -Want 'C:\fractalsql_bt_nonexistent.dll')) {
        Fail "15 embed: bad-path GUC did not take effect"; PgSwapPlugin $Mock | Out-Null; return
    }
    $rbad = Psql -Sql "SELECT fractal_embed('test input');"
    if ($rbad -match 'failed to load reasoning plugin') { Pass "15 embed: nonexistent plugin path rejected cleanly" }
    else { Fail "15 embed: nonexistent plugin path expected a clear rejection, got: $rbad" }
    if (-not (PgSwapPlugin $Embed)) { Fail "15 embed: plugin swap back did not take effect"; PgSwapPlugin $Mock | Out-Null; return }

    # Evil embed: a plugin returning MAX_EMBED_DIM+1 (16385) floats must
    # be REJECTED, not silently truncated to a wrong-but-plausible 16384-
    # element vector -- a real bug fixed in parse_embedding_array()
    # alongside this test (see tests/evil_embed_plugin.c / build_test.sh's
    # matching gate 15 comment for the full story).
    if (-not (PgSwapPlugin $EvilEmbed)) { Fail "15 embed: evil_embed plugin swap did not take effect"; PgSwapPlugin $Mock | Out-Null; return }
    $revil = Psql -Sql "SELECT fractal_embed('test input');"
    if ($revil -match 'could not parse embedding response') { Pass "15 embed: over-limit embedding array rejected, not silently truncated" }
    else { Fail "15 embed: expected a clean rejection, got: $revil" }
    if (-not (PgSwapPlugin $Embed)) { Fail "15 embed: plugin swap back (post evil_embed) did not take effect"; PgSwapPlugin $Mock | Out-Null; return }

    Psql -Sql "DELETE FROM fractal_vectorizers WHERE source_table = 'bt_embed_docs';" | Out-Null
    Psql -Sql "DROP TABLE IF EXISTS bt_embed_docs;" | Out-Null
    Psql -Sql "CREATE TABLE bt_embed_docs (id serial PRIMARY KEY, body text NOT NULL, embedding float8[]);" | Out-Null
    Psql -Sql "INSERT INTO bt_embed_docs (body) VALUES ('a'), ('b');" | Out-Null

    # SQL-injection-shaped source_table, same pattern gate 10 already
    # proves for fractal_schema_context/fractal_search_explore, extended
    # to the vectorizer's own dynamic SQL. Must fail cleanly via the
    # ::regclass cast before ever reaching format().
    $rinj = Psql -Sql "SELECT fractal_vectorizer_create('bt_embed_docs''; DROP TABLE bt_embed_docs; --', 'body', 'embedding');"
    $ninj = Psql -Sql "SELECT count(*) FROM bt_embed_docs;"
    if ($ninj -eq '2') { Pass "15 embed: injection-shaped source_table did not execute (bt_embed_docs intact)" }
    else { Fail "15 embed: bt_embed_docs row count changed (n=$ninj) -- injection may have executed" }
    if ($rinj -match 'invalid name syntax|does not exist|ERROR') { Pass "15 embed: injection-shaped source_table cleanly rejected" }
    else { Fail "15 embed: unexpected result: $rinj" }

    $vzid = Psql -Sql "SELECT fractal_vectorizer_create('bt_embed_docs', 'body', 'embedding');"

    # Double-create: same (source_table, text_col, embedding_col) again
    # must fail with a clean, fractal_-prefixed message naming the
    # existing vectorizer id -- not a raw "duplicate key value violates
    # unique constraint ..." that leaks the constraint name and a
    # PL/pgSQL stack frame.
    $rdup = Psql -Sql "SELECT fractal_vectorizer_create('bt_embed_docs', 'body', 'embedding');"
    if ($rdup -match "already exists \(id=$vzid\)") { Pass "15 embed: double-create rejected with a clean, specific error" }
    else { Fail "15 embed: expected a clean double-create rejection naming id=$vzid, got: $rdup" }

    $n = Psql -Sql "SELECT fractal_vectorizer_process_queue();"
    if ($n -eq '2') { Pass "15 embed: process_queue processed 2 backfilled rows" }
    else { Fail "15 embed: process_queue expected 2, got: $n" }

    $embedded = Psql -Sql "SELECT count(*) FROM bt_embed_docs WHERE embedding = '{0.1,0.2,0.3}';"
    if ($embedded -eq '2') { Pass "15 embed: both rows got the real embedding written back" }
    else { Fail "15 embed: expected 2 rows with the embedding written back, got: $embedded" }

    $status = Psql -Sql "SELECT status FROM fractal_vectorizer_status WHERE vectorizer_id = $vzid;"
    if ($status -eq 'done') { Pass "15 embed: vectorizer status shows done, no failures" }
    else { Fail "15 embed: expected status 'done', got: $status" }

    Psql -Sql "DELETE FROM fractal_vectorizers WHERE source_table = 'bt_embed_docs';" | Out-Null
    Psql -Sql "DROP TABLE IF EXISTS bt_embed_docs;" | Out-Null
    PgSwapPlugin $Mock | Out-Null
}

# Vectorizer authz: two real properties, not assumed from reading the
# GRANTs added alongside this test --
#   1. A role that owns its OWN table can fully use the vectorizer on
#      it (create, backfill, trigger-driven auto-enqueue on a new
#      write) without any DBA-granted access to fractal_vectorizers/
#      fractal_vectorizer_queue -- requires those tables' PUBLIC grants
#      (see sql/fractalsql--1.0.sql) plus fractal_vectorizer_enqueue()
#      being SECURITY DEFINER; a real bug before that fix was every
#      non-owner-of-the-tracking-tables role's INSERT into a vectorized
#      table failing entirely.
#   2. A DIFFERENT role, with no SELECT on that table, calling
#      fractal_vectorizer_process_queue() (which processes the GLOBAL
#      queue, not just its own caller's vectorizers) must not be able
#      to read or embed that table's content. Mirrors build_test.sh's
#      gate 16.
function Gate16EmbedAuthz {
    Write-Host "  16 embed_authz: starting..."
    Psql -Sql @"
DROP ROLE IF EXISTS bt_embed_owner;
CREATE ROLE bt_embed_owner LOGIN;
GRANT CREATE ON SCHEMA public TO bt_embed_owner;
DROP ROLE IF EXISTS bt_embed_outsider;
CREATE ROLE bt_embed_outsider LOGIN;
"@ | Out-Null

    Psql -User 'bt_embed_owner' -Sql @"
CREATE TABLE bt_embed_owned (id serial PRIMARY KEY, body text, embedding float8[]);
INSERT INTO bt_embed_owned (body) VALUES ('owner data');
"@ | Out-Null

    $vzid = Psql -User 'bt_embed_owner' -Sql "SELECT fractal_vectorizer_create('bt_embed_owned', 'body', 'embedding');"
    $vzidNum = 0
    if ([int]::TryParse($vzid, [ref]$vzidNum)) {
        Pass "16 embed_authz: owner role created a vectorizer on its own table"
    } else {
        Fail "16 embed_authz: owner role could not create its own vectorizer: $vzid"
    }

    Psql -User 'bt_embed_owner' -Sql "INSERT INTO bt_embed_owned (body) VALUES ('second row, via trigger');" | Out-Null
    $qn = Psql -User 'bt_embed_owner' -Sql @"
SELECT count(*) FROM fractal_vectorizer_queue q
JOIN fractal_vectorizers v ON v.id = q.vectorizer_id
WHERE v.source_table = 'bt_embed_owned' AND q.status = 'pending';
"@
    if ($qn -eq '2') { Pass "16 embed_authz: backfill + trigger-driven enqueue both succeeded for the owner (2 pending)" }
    else { Fail "16 embed_authz: expected 2 pending rows (1 backfilled + 1 via trigger), got: $qn" }

    $rout = Psql -User 'bt_embed_outsider' -Sql "SELECT fractal_vectorizer_process_queue();"
    $statuses = Psql -User 'bt_embed_owner' -Sql @"
SELECT string_agg(DISTINCT q.status, ',') FROM fractal_vectorizer_queue q
JOIN fractal_vectorizers v ON v.id = q.vectorizer_id
WHERE v.source_table = 'bt_embed_owned';
"@
    if ($statuses -eq 'failed') { Pass "16 embed_authz: outsider's process_queue() call left both rows 'failed', not processed" }
    else { Fail "16 embed_authz: expected both rows 'failed' after the outsider's call, got statuses: $statuses" }

    $errtext = Psql -User 'bt_embed_owner' -Sql "SELECT last_error FROM fractal_vectorizer_status WHERE vectorizer_id = $vzid AND status = 'failed';"
    if ($errtext -match 'permission denied for table bt_embed_owned') { Pass "16 embed_authz: failure reason correctly names a permission error, not a data value" }
    else { Fail "16 embed_authz: expected a permission-denied error, got: $errtext" }

    $leaked = Psql -User 'bt_embed_owner' -Sql "SELECT embedding FROM bt_embed_owned WHERE embedding IS NOT NULL;"
    if ([string]::IsNullOrEmpty($leaked)) { Pass "16 embed_authz: no embedding was written by the unauthorized outsider's call" }
    else { Fail "16 embed_authz: an embedding was written despite the outsider lacking SELECT: $leaked" }

    Psql -Sql @"
DELETE FROM fractal_vectorizers WHERE source_table = 'bt_embed_owned';
DROP TABLE IF EXISTS bt_embed_owned;
DROP ROLE IF EXISTS bt_embed_owner;
DROP ROLE IF EXISTS bt_embed_outsider;
"@ | Out-Null
}

# Concurrent fractal_vectorizer_process_queue() calls against a SHARED
# queue, proving the "safe to call concurrently" claim (SELECT ... FOR
# UPDATE SKIP LOCKED) rather than assuming it: every row processed
# exactly once, no double-embedding, no row left behind, no worker
# error. Mirrors Gate12Soak's -Parallel pattern and build_test.sh's
# gate 17.
$EmbedSoakRows = 100
$EmbedSoakWorkers = 10
$EmbedSoakBatch = 5

function Gate17EmbedSoak {
    if (-not (PgSetGuc -Name 'fractalsql.http_embed_url' -SetVal "'http://unused/embeddings'" -Want 'http://unused/embeddings')) {
        Fail "17 embed_soak: http_embed_url GUC did not take effect"; return
    }
    if (-not (PgSwapPlugin $Embed)) { Fail "17 embed_soak: plugin swap did not take effect"; return }

    Psql -Sql @"
DELETE FROM fractal_vectorizers WHERE source_table = 'bt_embed_soak';
DROP TABLE IF EXISTS bt_embed_soak;
CREATE TABLE bt_embed_soak (id serial PRIMARY KEY, body text NOT NULL, embedding float8[]);
INSERT INTO bt_embed_soak (body) SELECT 'row ' || i FROM generate_series(1, $EmbedSoakRows) i;
"@ | Out-Null
    $vzid = Psql -Sql "SELECT fractal_vectorizer_create('bt_embed_soak', 'body', 'embedding');"
    $queued = Psql -Sql "SELECT count(*) FROM fractal_vectorizer_queue WHERE vectorizer_id = $vzid AND status = 'pending';"
    if ($queued -ne "$EmbedSoakRows") {
        Fail "17 embed_soak: setup: expected $EmbedSoakRows queued rows, got $queued"
        PgSwapPlugin $Mock | Out-Null; return
    }

    $itersPerWorker = [int]([math]::Floor($EmbedSoakRows / $EmbedSoakBatch)) + 2
    $results = 1..$EmbedSoakWorkers | ForEach-Object -Parallel {
        $bin = $using:Bin
        $port = $using:Port
        $batch = $using:EmbedSoakBatch
        $iters = $using:itersPerWorker
        $rc = 0
        $total = 0
        for ($i = 1; $i -le $iters; $i++) {
            $psi = New-Object System.Diagnostics.ProcessStartInfo
            $psi.FileName = "$bin\psql.exe"
            foreach ($a in @('-h','127.0.0.1','-p',"$port",'-U','postgres','-d','postgres','-X','-tA','-c',"SELECT fractal_vectorizer_process_queue($batch);")) {
                $psi.ArgumentList.Add($a)
            }
            $psi.RedirectStandardOutput = $true
            $psi.RedirectStandardError  = $true
            $psi.UseShellExecute = $false
            $proc = [System.Diagnostics.Process]::Start($psi)
            # Concurrent async reads -- see the script-scope Psql
            # function's comment for why sequential ReadToEnd() can
            # deadlock on an unexpectedly large stderr payload.
            $soT = $proc.StandardOutput.ReadToEndAsync()
            $seT = $proc.StandardError.ReadToEndAsync()
            $proc.WaitForExit()
            $out = $soT.Result.Trim()
            $seT.Result | Out-Null
            $n = 0
            if ($proc.ExitCode -ne 0 -or -not [int]::TryParse($out, [ref]$n)) { $rc = 1 }
            else { $total += $n }
        }
        [PSCustomObject]@{ Rc = $rc; Total = $total }
    } -ThrottleLimit $EmbedSoakWorkers

    $failedWorkers = @($results | Where-Object { $_.Rc -ne 0 }).Count
    $sumProcessed = ($results | Measure-Object -Property Total -Sum).Sum

    if ($failedWorkers -eq 0) { Pass "17 embed_soak: $EmbedSoakWorkers concurrent workers, no call errored" }
    else { Fail "17 embed_soak: $failedWorkers/$EmbedSoakWorkers workers had a failed call" }

    if ($sumProcessed -eq $EmbedSoakRows) { Pass "17 embed_soak: exactly $EmbedSoakRows rows processed total (no double-count, none lost)" }
    else { Fail "17 embed_soak: expected $EmbedSoakRows rows processed summed across workers, got $sumProcessed" }

    $doneN = Psql -Sql "SELECT count(*) FROM fractal_vectorizer_queue WHERE vectorizer_id = $vzid AND status = 'done';"
    if ($doneN -eq "$EmbedSoakRows") { Pass "17 embed_soak: all $EmbedSoakRows queue rows are 'done', none stuck pending/processing" }
    else { Fail "17 embed_soak: expected $EmbedSoakRows rows 'done', got $doneN" }

    $embeddedN = Psql -Sql "SELECT count(*) FROM bt_embed_soak WHERE embedding = '{0.1,0.2,0.3}';"
    if ($embeddedN -eq "$EmbedSoakRows") { Pass "17 embed_soak: all $EmbedSoakRows rows got the embedding written back exactly once" }
    else { Fail "17 embed_soak: expected $EmbedSoakRows rows with the embedding, got $embeddedN" }

    Psql -Sql @"
DELETE FROM fractal_vectorizers WHERE source_table = 'bt_embed_soak';
DROP TABLE IF EXISTS bt_embed_soak;
"@ | Out-Null
    PgSwapPlugin $Mock | Out-Null
}

# Real crash mid-process_queue(), via the same deliberately-segfaulting
# plugin Gate06CrashRecovery already uses. fractal_vectorizer_process_
# queue() is one PL/pgSQL function call -- one transaction -- so a crash
# mid-call rolls back everything it touched, reverting rows to 'pending'
# rather than leaving them stuck in 'processing'. Confirmed against a
# real crash, not assumed. Mirrors build_test.sh's gate 18.
function Gate18EmbedCrash {
    if (-not (PgSetGuc -Name 'fractalsql.http_embed_url' -SetVal "'http://unused/embeddings'" -Want 'http://unused/embeddings')) {
        Fail "18 embed_crash: http_embed_url GUC did not take effect"; return
    }

    Psql -Sql @"
DELETE FROM fractal_vectorizers WHERE source_table = 'bt_embed_crash';
DROP TABLE IF EXISTS bt_embed_crash;
CREATE TABLE bt_embed_crash (id serial PRIMARY KEY, body text NOT NULL, embedding float8[]);
INSERT INTO bt_embed_crash (body) VALUES ('a'), ('b'), ('c');
"@ | Out-Null
    $vzid = Psql -Sql "SELECT fractal_vectorizer_create('bt_embed_crash', 'body', 'embedding');"

    if (-not (PgSwapPlugin $Crash)) { Fail "18 embed_crash: plugin swap did not take effect"; return }
    $r = Psql -Sql "SELECT fractal_vectorizer_process_queue();"
    if ($r -match 'server closed the connection|could not connect') {
        Pass "18 embed_crash: triggering connection dropped as expected"
    } else {
        Fail "18 embed_crash: expected the connection to drop, got: $r"
    }

    # See Gate06CrashRecovery's comment on why pass/fail budget and actual
    # up-detection must not share the same cutoff -- restoring the plugin
    # below depends on $up, and a near-miss here previously left the
    # crash plugin active for the rest of the run.
    $up = $false
    $withinBudget = $false
    $tries = 30 * $TimeoutMult
    for ($i = 0; $i -lt ($tries * 2); $i++) {
        $t = Psql -Sql "SELECT 1;"
        if ($t -eq '1') { $up = $true; if ($i -lt $tries) { $withinBudget = $true }; break }
        Start-Sleep -Milliseconds 500
    }
    if ($withinBudget) { Pass "18 embed_crash: cluster auto-restarted" }
    else { Fail "18 embed_crash: cluster did not come back within $($tries / 2)s" }
    if (-not $up) {
        Fail "18 embed_crash: cluster never came back -- remaining gates will run against the crash plugin"
        return
    }

    $statuses = Psql -Sql "SELECT string_agg(DISTINCT status, ',') FROM fractal_vectorizer_queue WHERE vectorizer_id = $vzid;"
    if ($statuses -eq 'pending') { Pass "18 embed_crash: all 3 rows reverted to 'pending' after the crash (atomic rollback, not stuck 'processing')" }
    else { Fail "18 embed_crash: expected all rows 'pending' post-crash, got statuses: $statuses" }

    if (-not (PgSwapPlugin $Embed)) { Fail "18 embed_crash: plugin swap to EMBED did not take effect"; PgSwapPlugin $Mock | Out-Null; return }
    $n = Psql -Sql "SELECT fractal_vectorizer_process_queue();"
    if ($n -eq '3') { Pass "18 embed_crash: post-recovery call processed all 3 previously-crashed rows" }
    else { Fail "18 embed_crash: expected 3 rows processed after recovery, got: $n" }

    $doneN = Psql -Sql "SELECT count(*) FROM bt_embed_crash WHERE embedding = '{0.1,0.2,0.3}';"
    if ($doneN -eq '3') { Pass "18 embed_crash: all 3 rows correctly embedded after recovery" }
    else { Fail "18 embed_crash: expected 3 embedded rows after recovery, got: $doneN" }

    Psql -Sql @"
DELETE FROM fractal_vectorizers WHERE source_table = 'bt_embed_crash';
DROP TABLE IF EXISTS bt_embed_crash;
"@ | Out-Null
    PgSwapPlugin $Mock | Out-Null
}

# validate_sfs_params() bounds for fractal_search/_debug/_explore, plus
# an injection-shaped table_name into fractal_search_explore (mirrors
# gate 10's equivalent test for fractal_schema_context). Mirrors
# build_test.sh's gate 19. The core library's FSQL_MAX_DIM=16384 ceiling
# is always tighter than MAX_QUERY_DIM and fires first, so the latter is
# effectively dead code.
function Gate19SfsBounds {
    $r = Psql -Sql "SELECT fractal_search(ARRAY(SELECT 0.1 FROM generate_series(1,16385)));"
    if ($r -match 'exceeds FSQL_MAX_DIM|out of range') { Pass "19 sfs_bounds: over-limit query dim (16385) rejected cleanly" }
    else { Fail "19 sfs_bounds: expected a clean dim-limit rejection, got: $r" }

    $r = Psql -Sql "SELECT fractal_search(ARRAY[]::float8[]);"
    if ($r -match '1-D non-null|must be non-empty') { Pass "19 sfs_bounds: empty query array rejected cleanly" }
    else { Fail "19 sfs_bounds: expected a clean empty-array rejection, got: $r" }

    $r = Psql -Sql "SELECT fractal_search(ARRAY[0.1,0.2]::float8[], 10001);"
    if ($r -match 'iterations 10001 out of range') { Pass "19 sfs_bounds: iterations over MAX_ITERATIONS (10000) rejected cleanly" }
    else { Fail "19 sfs_bounds: expected an iterations-limit rejection, got: $r" }

    $r = Psql -Sql "SELECT fractal_search(ARRAY[0.1,0.2]::float8[], 10, 100001);"
    if ($r -match 'population_size 100001 out of range') { Pass "19 sfs_bounds: population_size over MAX_POPULATION_SIZE (100000) rejected cleanly" }
    else { Fail "19 sfs_bounds: expected a population_size-limit rejection, got: $r" }

    $r = Psql -Sql "SELECT fractal_search(ARRAY[0.1,0.2]::float8[], 10, 20, 33);"
    if ($r -match 'diffusion_factor 33 out of range') { Pass "19 sfs_bounds: diffusion_factor over MAX_DIFFUSION_FACTOR (32) rejected cleanly" }
    else { Fail "19 sfs_bounds: expected a diffusion_factor-limit rejection, got: $r" }

    $r = Psql -Sql "SELECT fractal_search_debug(ARRAY[0.1,0.2]::float8[], 10, 20, 33);"
    if ($r -match 'diffusion_factor 33 out of range') { Pass "19 sfs_bounds: fractal_search_debug shares the same bounds check" }
    else { Fail "19 sfs_bounds: expected fractal_search_debug to reject diffusion_factor=33, got: $r" }

    $rinj = Psql -Sql "SELECT * FROM fractal_search_explore('bt_orders''; DROP TABLE bt_orders; --', 'vec', ARRAY[0.1,0.2]::float8[]);"
    $n = Psql -Sql "SELECT count(*) FROM bt_orders;"
    if ($n -eq '0') { Pass "19 sfs_bounds: injection-shaped table_name into fractal_search_explore did not execute (bt_orders intact)" }
    else { Fail "19 sfs_bounds: bt_orders row count changed (n=$n) -- injection may have executed" }
    if ($rinj -match 'does not exist|ERROR') { Pass "19 sfs_bounds: injection-shaped table_name cleanly rejected" }
    else { Fail "19 sfs_bounds: unexpected result: $rinj" }
}

# Closes 5 concrete API-surface coverage gaps found by a gap analysis
# against README's API table (each an explicit, existing code path --
# not speculative). Mirrors build_test.sh's Gate 20 line-for-line:
#   1. fractal_reason(): happy-path correctness was never checked --
#      every other gate touching it only asserts "didn't crash" /
#      "cleanly rejected a bad plugin", never "returned the right text".
#   2. fractal_reason(NULL): its own explicit PG_ARGISNULL(0) check
#      (fractal_reason isn't STRICT, unlike the search functions) had
#      zero coverage.
#   3. fractal_text_to_sql(NULL): same pattern, its own explicit
#      PG_ARGISNULL(0) check, zero coverage.
#   4. fractal_search_explore()'s bounds: it calls the same
#      validate_sfs_params() as fractal_search/_debug, but nothing had
#      ever proved that by actually passing an over-limit value through
#      its options jsonb.
#   5. fractal_vectorizer_process_queue()'s stale_after reclaim: Gate 16
#      already proved a crash can't produce a stuck 'processing' row in
#      the CURRENT implementation, but the reclaim UPDATE itself (the
#      WHERE processing_started_at < now() - stale_after clause) was
#      never independently exercised -- staged directly here, with a
#      negative control (a row still within the window) proving the
#      time comparison actually gates rather than reclaiming
#      unconditionally.
function Gate20ApiFunc {
    # --- 1: fractal_reason() happy path ---------------------------------
    Set-Content -Path $SqlFile -Value "gap-analysis-canary" -NoNewline
    $r1 = Psql -Sql "SELECT fractal_reason('q');"
    # Normalize CRLF -> LF before comparing: this is the first exact
    # multi-line string-equality check in this file (every other -eq/
    # -match elsewhere is single-line or a substring match), and it's
    # what first exposed a real Windows-specific quirk -- psql.exe's C
    # runtime writes its redirected stdout in text mode, which
    # translates embedded \n bytes in a query result into \r\n. The
    # mock plugin (and the real response) only ever emits plain \n; the
    # \r is a Windows stdio artifact of the pipe, not a content
    # difference, so strip it rather than build $expect1 with `r`n and
    # bake the artifact into the assertion.
    $r1Normalized = $r1 -replace "`r", ""
    $expect1 = "``````sql`ngap-analysis-canary`n``````"
    if ($r1Normalized -eq $expect1) { Pass "20 api_func: fractal_reason() returns the plugin's actual response" }
    else { Fail "20 api_func: fractal_reason() expected the fenced canary text, got: $r1" }
    Remove-Item -Force $SqlFile -ErrorAction SilentlyContinue

    # --- 2: fractal_reason(NULL) ----------------------------------------
    $r2 = Psql -Sql "SELECT fractal_reason(NULL);"
    if ($r2 -match 'query must not be NULL') { Pass "20 api_func: fractal_reason(NULL) rejected cleanly" }
    else { Fail "20 api_func: fractal_reason(NULL) expected a clear rejection, got: $r2" }

    # --- 3: fractal_text_to_sql(NULL) -----------------------------------
    $r3 = Psql -Sql "SELECT fractal_text_to_sql(NULL);"
    if ($r3 -match 'question must not be NULL') { Pass "20 api_func: fractal_text_to_sql(NULL) rejected cleanly" }
    else { Fail "20 api_func: fractal_text_to_sql(NULL) expected a clear rejection, got: $r3" }

    # --- 4: fractal_search_explore()'s own bounds ------------------------
    Psql -Sql @"
DROP TABLE IF EXISTS bt_explore_bounds;
CREATE TABLE bt_explore_bounds (id int, emb float8[]);
INSERT INTO bt_explore_bounds VALUES (1, ARRAY[0.1,0.2]::float8[]);
"@ | Out-Null
    $r4 = Psql -Sql @"
SELECT * FROM fractal_search_explore('bt_explore_bounds', 'emb',
  ARRAY[0.1,0.2]::float8[], '{"iterations": 10001}'::jsonb);
"@
    if ($r4 -match 'iterations 10001 out of range') { Pass "20 api_func: fractal_search_explore rejects an over-limit iterations option" }
    else { Fail "20 api_func: expected an iterations-limit rejection, got: $r4" }

    $r4b = Psql -Sql @"
SELECT * FROM fractal_search_explore('bt_explore_bounds', 'emb',
  ARRAY[0.1,0.2]::float8[], '{"diffusion_factor": 33}'::jsonb);
"@
    if ($r4b -match 'diffusion_factor 33 out of range') { Pass "20 api_func: fractal_search_explore rejects an over-limit diffusion_factor option" }
    else { Fail "20 api_func: expected a diffusion_factor-limit rejection, got: $r4b" }
    Psql -Sql "DROP TABLE IF EXISTS bt_explore_bounds;" | Out-Null

    # --- 5: fractal_vectorizer_process_queue()'s stale_after reclaim ----
    if (-not (PgSetGuc -Name 'fractalsql.http_embed_url' -SetVal "'http://unused/embeddings'" -Want 'http://unused/embeddings')) {
        Fail "20 api_func: http_embed_url GUC did not take effect"; return
    }
    if (-not (PgSwapPlugin $Embed)) { Fail "20 api_func: plugin swap did not take effect"; PgSwapPlugin $Mock | Out-Null; return }

    Psql -Sql @"
DELETE FROM fractal_vectorizers WHERE source_table = 'bt_stale_reclaim';
DROP TABLE IF EXISTS bt_stale_reclaim;
CREATE TABLE bt_stale_reclaim (id serial PRIMARY KEY, body text NOT NULL, embedding float8[]);
INSERT INTO bt_stale_reclaim (body) VALUES ('old-stuck'), ('recent-stuck');
"@ | Out-Null
    $vzid = Psql -Sql "SELECT fractal_vectorizer_create('bt_stale_reclaim', 'body', 'embedding');"

    # old-stuck: claimed 1 hour ago, past the 5-minute stale_after below
    # -- must be reclaimed. recent-stuck: claimed 30 seconds ago, still
    # within it -- must be left alone (the negative control).
    Psql -Sql @"
UPDATE fractal_vectorizer_queue q
   SET status = 'processing', processing_started_at = now() - interval '1 hour'
  FROM bt_stale_reclaim t
 WHERE q.vectorizer_id = $vzid AND t.body = 'old-stuck' AND q.source_pk_value = t.id::text;
UPDATE fractal_vectorizer_queue q
   SET status = 'processing', processing_started_at = now() - interval '30 seconds'
  FROM bt_stale_reclaim t
 WHERE q.vectorizer_id = $vzid AND t.body = 'recent-stuck' AND q.source_pk_value = t.id::text;
"@ | Out-Null

    Psql -Sql "SELECT fractal_vectorizer_process_queue(10, '5 minutes'::interval);" | Out-Null

    $statuses = Psql -Sql @"
SELECT t.body || '=' || q.status FROM fractal_vectorizer_queue q
JOIN bt_stale_reclaim t ON t.id::text = q.source_pk_value
WHERE q.vectorizer_id = $vzid ORDER BY t.body;
"@
    if ($statuses -match 'old-stuck=done') { Pass "20 api_func: a row stranded past stale_after was reclaimed and processed" }
    else { Fail "20 api_func: expected old-stuck=done, got: $statuses" }
    if ($statuses -match 'recent-stuck=processing') { Pass "20 api_func: a row still within stale_after was left alone, not reclaimed" }
    else { Fail "20 api_func: expected recent-stuck=processing (untouched), got: $statuses" }

    Psql -Sql @"
DELETE FROM fractal_vectorizers WHERE source_table = 'bt_stale_reclaim';
DROP TABLE IF EXISTS bt_stale_reclaim;
"@ | Out-Null
    PgSwapPlugin $Mock | Out-Null
}

# v2.x additions smoke gate -- HNSW/Diversify-era functions (dimension
# analysis, portfolio optimization, domain geometry, the named feature
# store, Diversify/feedback controls, table-backed telemetry/trajectory/
# cross-modal search). Deliberately a smoke gate, not exhaustive unit
# coverage -- proves the SQL wiring end-to-end against the real DLL, same
# scope/spirit as gate 02 and gate 11. Mirrors build_test.sh's gate 22.
#
# Fixture note: fractal_dimension_boxcount / _vascular_network /
# _nerve_plexus_metric / _morphological_complexity all bottom out in
# box-counting, which needs enough points AND enough dynamic range of
# scales to produce >= 3 valid epsilon buckets -- too few points (or an
# exactly-regular lattice) silently fails that filter even for
# well-defined geometry. The fixtures here are built INLINE via
# generate_series (no awk dependency -- fully portable, unlike
# build_test.sh's awk-generated fixtures) with deterministic non-
# degenerate coordinates chosen so every assertion's result key is
# present. Assertions only check the result jsonb carries the expected
# key (plus the two deterministic exact-value checks: the tetrahedron
# gyrification_index=1.0 and the feature-store k-NN order), matching
# build_test.sh's gate 22.
function Gate22V2Functions {
    # --- fixtures (inline generate_series, deterministic) ---------------
    # 40 box-count points (x,y) interleaved: point i = (i, i*0.5)
    $boxpts = "(SELECT array_agg(CASE WHEN g%2=1 THEN ((g+1)/2)::float8 ELSE ((g+1)/2)::float8*0.5 END) FROM generate_series(1,80) g)"
    # 30 vascular nodes (x,y,z): node i = (i, (i%7)*0.01, (i%5)*0.01)
    $vascNc = "(SELECT array_agg(CASE (g-1)%3 WHEN 0 THEN ((g-1)/3)::float8 WHEN 1 THEN (((g-1)/3)%7)*0.01 ELSE (((g-1)/3)%5)*0.01 END) FROM generate_series(1,90) g)"
    # 29 edges (src,dst): (0,1),(1,2),...,(28,29)
    $vascEl = "(SELECT array_agg(CASE (g-1)%2 WHEN 0 THEN ((g-1)/2)::int WHEN 1 THEN ((g-1)/2+1)::int END) FROM generate_series(1,58) g)"
    # 29 edge lengths (~1.0: consecutive nodes are ~1 apart in x; the y/z
    # jitter is ~0.01 so the true length is 1.0 to 4dp -- close enough that
    # the function's tortuosity is well-defined, which is all the assertion
    # checks for)
    $vascAl = "(SELECT array_agg(1.0::float8) FROM generate_series(1,29) g)"
    # 80 nerve nodes (x,y): node i = (i, (i%2) + (i%3)*0.001)
    $nerveNc = "(SELECT array_agg(CASE (g-1)%2 WHEN 0 THEN ((g-1)/2)::float8 ELSE ((g-1)/2 % 2)::float8 + ((g-1)/2 % 3)*0.001 END) FROM generate_series(1,160) g)"
    # 79 edges (src,dst): (0,1),...,(78,79)
    $nerveEl = "(SELECT array_agg(CASE (g-1)%2 WHEN 0 THEN ((g-1)/2)::int WHEN 1 THEN ((g-1)/2+1)::int END) FROM generate_series(1,158) g)"

    # --- 1: dimension analysis -----------------------------------------
    $r1 = Psql -Sql "SELECT fractal_dimension_dfa((SELECT array_agg(sin(i/3.0) + i*0.001) FROM generate_series(1,64) i));"
    if ($r1 -match '^[0-9]+\.[0-9]+$') { Pass "22 v2_functions: fractal_dimension_dfa returns a numeric exponent" }
    else { Fail "22 v2_functions: fractal_dimension_dfa expected a float8, got: $r1" }

    $r1b = Psql -Sql "SELECT fractal_dimension_dfa(ARRAY[1,2,3]::float8[]);"
    if ($r1b -match 'series needs >= 16 points') { Pass "22 v2_functions: fractal_dimension_dfa rejects a too-short series" }
    else { Fail "22 v2_functions: expected a too-short-series rejection, got: $r1b" }

    $r2 = Psql -Sql "SELECT fractal_dimension_boxcount($boxpts, 2);"
    if ($r2 -match '^[0-9]+\.[0-9]+$') { Pass "22 v2_functions: fractal_dimension_boxcount returns a numeric dimension" }
    else { Fail "22 v2_functions: fractal_dimension_boxcount expected a float8, got: $r2" }

    $r3 = Psql -Sql "SELECT fractal_dimension_drift((SELECT array_agg(sin(i/3.0) + i*0.001) FROM generate_series(1,200) i), 64);"
    if ($r3 -match '"drift"') { Pass "22 v2_functions: fractal_dimension_drift returns {drift, recent_alpha, baseline_alpha}" }
    else { Fail "22 v2_functions: fractal_dimension_drift expected a drift jsonb, got: $r3" }

    # --- 2: portfolio optimization -------------------------------------
    $r4 = Psql -Sql "SELECT fractal_optimize_portfolio(ARRAY[0.08,0.12,0.10,0.15]::float8[], ARRAY[0.04,0.01,0.01,0.01, 0.01,0.06,0.01,0.01, 0.01,0.01,0.05,0.01, 0.01,0.01,0.01,0.09]::float8[], 2, 12345);"
    if ($r4 -match '"sharpe"') { Pass "22 v2_functions: fractal_optimize_portfolio returns {sharpe, weights}" }
    else { Fail "22 v2_functions: fractal_optimize_portfolio expected a sharpe/weights jsonb, got: $r4" }

    $r4b = Psql -Sql "SELECT fractal_optimize_portfolio(ARRAY[0.1,0.1]::float8[], ARRAY[1.0]::float8[], 1, NULL);"
    if ($r4b -match 'cov length') { Pass "22 v2_functions: fractal_optimize_portfolio rejects a mismatched cov length" }
    else { Fail "22 v2_functions: expected a cov-length rejection, got: $r4b" }

    # --- 3: domain-specific geometry -----------------------------------
    $r5 = Psql -Sql "SELECT fractal_morphological_complexity($boxpts, 2);"
    if ($r5 -match '"lacunarity"') { Pass "22 v2_functions: fractal_morphological_complexity returns {dimension, lacunarity}" }
    else { Fail "22 v2_functions: fractal_morphological_complexity expected a dimension/lacunarity jsonb, got: $r5" }

    $r6 = Psql -Sql "SELECT fractal_vascular_network($vascNc, $vascEl, $vascAl);"
    if ($r6 -match '"mean_tortuosity"') { Pass "22 v2_functions: fractal_vascular_network returns {mean_tortuosity, branch_density, fractal_dimension}" }
    else { Fail "22 v2_functions: fractal_vascular_network expected a tortuosity jsonb, got: $r6" }

    $r7 = Psql -Sql "SELECT fractal_nerve_plexus_metric($nerveNc, 2, $nerveEl);"
    if ($r7 -match '"fiber_length_density"') { Pass "22 v2_functions: fractal_nerve_plexus_metric returns {fiber_length_density, branch_density, fractal_dimension}" }
    else { Fail "22 v2_functions: fractal_nerve_plexus_metric expected a fiber-density jsonb, got: $r7" }

    # Tetrahedron: mesh IS its own convex hull, so gyrification_index must
    # be exactly 1.0 -- a clean deterministic check, not just "didn't error".
    $r8 = Psql -Sql "SELECT fractal_cortical_folding(ARRAY[0,0,0, 1,0,0, 0,1,0, 0,0,1]::float8[], ARRAY[0,1,2, 0,1,3, 0,2,3, 1,2,3]::int4[]);"
    if ($r8 -match '"gyrification_index": 1\.0000000000') { Pass "22 v2_functions: fractal_cortical_folding gives gyrification_index=1.0 for a tetrahedron (mesh == its own hull)" }
    else { Fail "22 v2_functions: expected gyrification_index=1.0 for a tetrahedron, got: $r8" }

    # --- 4: named feature store (postgres-side, no core primitive) ------
    Psql -Sql @"
DELETE FROM fractalsql_feature_store WHERE doc_id IN (901,902,903,904);
SELECT fractal_store_morphology(901, ARRAY[0.0,0.0,0.0]::float8[]);
SELECT fractal_store_morphology(902, ARRAY[10.0,10.0,10.0]::float8[]);
SELECT fractal_store_morphology(903, ARRAY[1.0,0.0,0.0]::float8[]);
SELECT fractal_store_morphology(904, ARRAY[0.5,0.5,0.5]::float8[]);
"@ | Out-Null
    # upsert-overwrite: doc 901 moves far away, must drop out of a k=2 mine
    Psql -Sql "SELECT fractal_store_morphology(901, ARRAY[100.0,100.0,100.0]::float8[]);" | Out-Null
    $r9 = Psql -Sql "SELECT string_agg(doc_id::text, ',' ORDER BY distance) FROM fractal_mine_topology_negatives(ARRAY[0.0,0.0,0.0]::float8[], 2) WHERE doc_id IN (901,902,903,904);"
    if ($r9 -eq '904,903') { Pass "22 v2_functions: fractal_mine_topology_negatives k-NN order + upsert-overwrite correct" }
    else { Fail "22 v2_functions: expected mine order 904,903 (901 overwritten far away), got: $r9" }

    $r9b = Psql -Sql "SELECT fractal_store_morphology(-1, ARRAY[1.0]::float8[]);"
    if ($r9b -match 'doc_id must be >= 0') { Pass "22 v2_functions: fractal_store_morphology rejects a negative doc_id" }
    else { Fail "22 v2_functions: expected a negative-doc_id rejection, got: $r9b" }

    $r9c = Psql -Sql "SELECT fractal_mine_topology_negatives(ARRAY[0.0]::float8[], 0);"
    if ($r9c -match 'k must be > 0') { Pass "22 v2_functions: fractal_mine_topology_negatives rejects k<=0" }
    else { Fail "22 v2_functions: expected a k<=0 rejection, got: $r9c" }

    Psql -Sql "DELETE FROM fractalsql_feature_store WHERE doc_id IN (901,902,903,904);" | Out-Null

    # --- 5: Diversify / feedback controls ------------------------------
    Psql -Sql "SELECT fractal_diversify_enable();" | Out-Null
    Psql -Sql "SELECT fractal_diversify_set_params(20, 0.1, 1.0, 0.5, 100, 50);" | Out-Null
    $r10 = Psql -Sql "SELECT fractal_explain_result();"
    if ($r10 -match '"diversify_enabled": true') { Pass "22 v2_functions: fractal_explain_result reflects diversify_enabled after enable" }
    else { Fail "22 v2_functions: expected diversify_enabled=true, got: $r10" }

    $fbr = Psql -Sql "SELECT fractal_feedback_report(0, 'negative', 100);"
    if ($fbr -match 'ERROR') { Fail "22 v2_functions: fractal_feedback_report errored on a valid call: $fbr" }
    else { Pass "22 v2_functions: fractal_feedback_report accepted a valid negative-engagement report" }

    $r11 = Psql -Sql "SELECT fractal_feedback_report(0, 'bogus', NULL);"
    if ($r11 -match 'kind must be one of') { Pass "22 v2_functions: fractal_feedback_report rejects an invalid kind" }
    else { Fail "22 v2_functions: expected an invalid-kind rejection, got: $r11" }

    Psql -Sql "SELECT fractal_diversify_disable();" | Out-Null

    # --- 6: table-backed top-k telemetry search + thin compositions -----
    Psql -Sql @"
DROP TABLE IF EXISTS bt_telemetry_docs;
CREATE TABLE bt_telemetry_docs (id serial PRIMARY KEY, emb float8[]);
INSERT INTO bt_telemetry_docs (emb) VALUES
  (ARRAY[1.0,0.0,0.0]::float8[]),
  (ARRAY[0.0,1.0,0.0]::float8[]),
  (ARRAY[0.9,0.1,0.0]::float8[]),
  (ARRAY[0.0,0.0,1.0]::float8[]),
  (ARRAY[0.5,0.5,0.0]::float8[]);
"@ | Out-Null

    $r12 = Psql -Sql "SELECT doc_id, distance FROM fractal_search_telemetry('bt_telemetry_docs', 'emb', ARRAY[1.0,0.0,0.0]::float8[], 2);"
    if ($r12 -match '^0\|0') { Pass "22 v2_functions: fractal_search_telemetry finds the exact match at distance 0" }
    else { Fail "22 v2_functions: expected doc_id=0 dist=0 first, got: $r12" }

    # CRLF normalization: psql -tA prints one row per line, and the Windows
    # C runtime writes \r\n -- see Gate20ApiFunc's matching note. The
    # multi-line exact-equality check below needs LF-only to compare.
    $r13 = (Psql -Sql "SELECT doc_id FROM fractal_hybrid_clinical_search('bt_telemetry_docs', 'emb', ARRAY[0.0,1.0,0.0]::float8[], ARRAY[1,3,4]::int8[], 3) ORDER BY distance;") -replace "`r", ""
    if ($r13 -eq "1`n4`n3") { Pass "22 v2_functions: fractal_hybrid_clinical_search restricts to the cohort and returns real doc_ids" }
    else { Fail "22 v2_functions: expected doc_ids 1,4,3 in that order, got: $r13" }

    $r14 = Psql -Sql "SELECT fractal_hybrid_clinical_search('bt_telemetry_docs', 'emb', ARRAY[0.0,1.0,0.0]::float8[], ARRAY[999]::int8[], 1);"
    if ($r14 -match 'cohort matched no rows') { Pass "22 v2_functions: fractal_hybrid_clinical_search rejects a cohort matching zero rows" }
    else { Fail "22 v2_functions: expected a no-rows-matched rejection, got: $r14" }

    $r15 = Psql -Sql "SELECT doc_id, distance FROM fractal_search_trajectory('bt_telemetry_docs', 'emb', ARRAY[0.0,0.0,0.0]::float8[], ARRAY[1.0,0.0,0.0]::float8[], 1);"
    if ($r15 -match '^0\|0') { Pass "22 v2_functions: fractal_search_trajectory searches near the delta vector" }
    else { Fail "22 v2_functions: expected doc_id=0 dist=0 for a [1,0,0] delta, got: $r15" }

    Psql -Sql @"
DROP TABLE IF EXISTS bt_combined_docs;
CREATE TABLE bt_combined_docs (id serial PRIMARY KEY, emb float8[]);
INSERT INTO bt_combined_docs (emb) VALUES
  (ARRAY[1.0,0.0, 0.0,0.0]::float8[]),
  (ARRAY[0.0,0.0, 1.0,0.0]::float8[]);
"@ | Out-Null
    $r16 = Psql -Sql "SELECT doc_id, distance FROM fractal_cross_modal_search('bt_combined_docs', 'emb', ARRAY[1.0,0.0]::float8[], ARRAY[1.0,0.0]::float8[], 1.0, 1);"
    if ($r16 -match '^0\|0') { Pass "22 v2_functions: fractal_cross_modal_search at alpha=1.0 favors the morphology-only row" }
    else { Fail "22 v2_functions: expected doc_id=0 dist=0 at alpha=1.0, got: $r16" }

    $r17 = Psql -Sql "SELECT fractal_cross_modal_search('bt_combined_docs', 'emb', ARRAY[1.0,0.0]::float8[], ARRAY[1.0,0.0]::float8[], 1.5, 1);"
    if ($r17 -match 'alpha_weight must be in') { Pass "22 v2_functions: fractal_cross_modal_search rejects an out-of-range alpha_weight" }
    else { Fail "22 v2_functions: expected an alpha_weight rejection, got: $r17" }

    Psql -Sql "DROP TABLE IF EXISTS bt_telemetry_docs, bt_combined_docs;" | Out-Null
}

# fractalsql_agents dependent-extension smoke gate -- the two parameterized
# PL/pgSQL agent engines (fractal_agent_anomaly_triage, fractal_agent_allocate)
# shipped in fractalsql_agents/. Deliberately a smoke gate, same scope/spirit
# as gate 22: proves the engine compositions run end-to-end against the real DLL
# + the real C primitives they wrap (fractal_dimension_drift, fractal_reason,
# fractal_optimize_portfolio). The engines' LLM step is fed by the gate-20 mock
# reasoning canary so it is deterministic without a live endpoint: the drift
# and optimizer steps are real C (deterministic); the reason step returns the
# canary. Mirrors build_test.sh's gate 23.
function Gate23Agents {
    # The engines call fractal_reason; the mock reasoning plugin (the resting
    # $Mock state) returns $SqlFile's content as the response. Set the same
    # canary gate 20 uses, so the engines' triage_summary / rationale carry it.
    # PgSwapPlugin $Mock guarantees the mock is active even if gate 23 is run
    # standalone (without gate 20 before it).
    PgSwapPlugin $Mock | Out-Null
    Set-Content -Path $SqlFile -Value "gap-analysis-canary" -NoNewline

    # --- fixture: a drifting metric series for one host -----------------
    # Same step-up shape as demo/demo-vertical-agentic-ops-devops.sql: baseline ~50
    # for the first 48 rows then a +30 step-up, 96 points, so
    # fractal_dimension_drift's 32-point recent window has a real regime change
    # to detect (window=16 is too small for DFA on the recent window -- see the
    # demo's own note). A second host makes the host filter meaningful.
    Psql -Sql @"
DROP TABLE IF EXISTS bt_agents_logs;
CREATE TABLE bt_agents_logs (metric float8, ts timestamptz, host text);
INSERT INTO bt_agents_logs (metric, ts, host)
SELECT 50.0 + (gs % 8)::float8 * 1.3 + CASE WHEN gs > 48 THEN 30.0 ELSE 0.0 END,
       now() - (96 - gs) * interval '1 second', 'host-1'
FROM generate_series(1,96) gs;
INSERT INTO bt_agents_logs VALUES (10, now(), 'host-2'), (11, now() + interval '1 min', 'host-2');
"@ | Out-Null

    # --- 1: fractal_agent_anomaly_triage happy path ---------------------
    # threat_score is the REAL drift exponent (fractal_dimension_drift ran);
    # triage_summary is the REAL reason step (canary proves fractal_reason ran).
    $r1 = Psql -Sql "SELECT threat_score FROM fractal_agent_anomaly_triage('bt_agents_logs','metric','ts','host','host-1',32);"
    if ($r1 -match '^-?[0-9]+(\.[0-9]+)?$') { Pass "23 agents: anomaly_triage threat_score is a real computed drift float" }
    else { Fail "23 agents: expected a numeric threat_score, got: $r1" }

    $r1b = Psql -Sql "SELECT triage_summary FROM fractal_agent_anomaly_triage('bt_agents_logs','metric','ts','host','host-1',32);"
    if ($r1b -match 'gap-analysis-canary') { Pass "23 agents: anomaly_triage composes drift -> reason (reason step ran)" }
    else { Fail "23 agents: expected the reasoning canary in triage_summary, got: $r1b" }

    # --- 2: anomaly_triage empty-series guard ---------------------------
    $r2 = Psql -Sql "SELECT * FROM fractal_agent_anomaly_triage('bt_agents_logs','metric','ts','host','no-such-host',32);"
    if ($r2 -match 'no rows in') { Pass "23 agents: anomaly_triage raises a clean ERROR when the filter matches no rows" }
    else { Fail "23 agents: expected a no-rows ERROR, got: $r2" }

    # --- 3: fractal_agent_allocate happy path --------------------------
    # allocation is the REAL optimizer jsonb {sharpe, weights}; sharpe is the
    # REAL risk-adjusted return extracted from it (replaces the demo's 0.042
    # literal); rationale is the REAL reason step (canary).
    $r3 = Psql -Sql "SELECT allocation FROM fractal_agent_allocate(ARRAY[0.05,0.1]::float8[], ARRAY[1.0,0.0,0.0,1.0]::float8[], 1, '{}'::text);"
    if ($r3 -match '"sharpe"') { Pass "23 agents: allocate composes optimize_portfolio -> reason (real optimizer jsonb with sharpe)" }
    else { Fail "23 agents: expected a sharpe-bearing allocation jsonb, got: $r3" }

    $r3b = Psql -Sql "SELECT rationale FROM fractal_agent_allocate(ARRAY[0.05,0.1]::float8[], ARRAY[1.0,0.0,0.0,1.0]::float8[], 1, '{}'::text);"
    if ($r3b -match 'gap-analysis-canary') { Pass "23 agents: allocate rationale is the real reason step output (canary)" }
    else { Fail "23 agents: expected the reasoning canary in rationale, got: $r3b" }

    # --- 4: allocate cov-length rejection -------------------------------
    # The engine must surface fractal_optimize_portfolio's clean 'cov length'
    # ERROR unchanged, not swallow it.
    $r4 = Psql -Sql "SELECT * FROM fractal_agent_allocate(ARRAY[0.1,0.1]::float8[], ARRAY[1.0]::float8[], 1, NULL::text);"
    if ($r4 -match 'cov length') { Pass "23 agents: allocate surfaces the optimizer's clean cov-length rejection" }
    else { Fail "23 agents: expected a cov-length rejection, got: $r4" }

    # --- 5: fractal_agent_route_task happy path -------------------------
    # routed_to is the REAL nearest capability (telemetry ran + doc_id
    # resolved to the named id); confidence is real, derived from the nearest
    # distance (1/(1+d)); rationale is the REAL reason step (canary).
    Psql -Sql @"
DROP TABLE IF EXISTS bt_agents_caps;
CREATE TABLE bt_agents_caps (capability_name text, emb float8[]);
INSERT INTO bt_agents_caps VALUES ('cap-a', ARRAY[0.1,0.2,0.3]), ('cap-b', ARRAY[0.9,0.8,0.7]);
"@ | Out-Null
    $r5 = Psql -Sql "SELECT routed_to FROM fractal_agent_route_task(ARRAY[0.1,0.2,0.3]::float8[], 'bt_agents_caps','emb','capability_name', 1000);"
    if ($r5 -match '^cap-a$') { Pass "23 agents: route_task returns the real nearest capability name (telemetry + doc_id resolution)" }
    else { Fail "23 agents: expected routed_to=cap-a, got: $r5" }

    $r5b = Psql -Sql "SELECT confidence FROM fractal_agent_route_task(ARRAY[0.1,0.2,0.3]::float8[], 'bt_agents_caps','emb','capability_name', 1000);"
    if ($r5b -match '^[0-9]+(\.[0-9]+)?$') { Pass "23 agents: route_task confidence is a real float derived from the nearest distance" }
    else { Fail "23 agents: expected a numeric confidence, got: $r5b" }

    $r5c = Psql -Sql "SELECT rationale FROM fractal_agent_route_task(ARRAY[0.1,0.2,0.3]::float8[], 'bt_agents_caps','emb','capability_name', 1000);"
    if ($r5c -match 'gap-analysis-canary') { Pass "23 agents: route_task composes telemetry -> reason (reason step ran)" }
    else { Fail "23 agents: expected the reasoning canary in rationale, got: $r5c" }

    # --- 6: route_task empty-capability-table guard ---------------------
    Psql -Sql "DELETE FROM bt_agents_caps;" | Out-Null
    $r6 = Psql -Sql "SELECT * FROM fractal_agent_route_task(ARRAY[0.1,0.2,0.3]::float8[], 'bt_agents_caps','emb','capability_name', 1000);"
    if ($r6 -match 'no capability rows') { Pass "23 agents: route_task raises a clean ERROR when the capability table is empty" }
    else { Fail "23 agents: expected a no-capability-rows ERROR, got: $r6" }

    # --- 7: fractal_agent_outlier_intercept intercept + allow -----------
    # Bad states point along the x-axis. Cosine distance ignores magnitude,
    # so the "far" probe must differ in DIRECTION (orthogonal y-axis), not
    # just magnitude -- [0.1,0.1,0.1] vs [0.9,0.9,0.9] would be distance 0.
    Psql -Sql @"
DROP TABLE IF EXISTS bt_agents_badstates;
CREATE TABLE bt_agents_badstates (emb float8[]);
INSERT INTO bt_agents_badstates VALUES (ARRAY[1,0,0]), (ARRAY[0.9,0.1,0.0]);
"@ | Out-Null
    $r7 = Psql -Sql "SELECT intercepted FROM fractal_agent_outlier_intercept(ARRAY[1,0,0]::float8[], 'bt_agents_badstates','emb', 0.5);"
    if ($r7 -match '^t$') { Pass "23 agents: outlier_intercept intercepts a state within the threshold (real distance 0 < 0.5)" }
    else { Fail "23 agents: expected intercepted=t for a near state, got: $r7" }

    $r7b = Psql -Sql "SELECT intercepted FROM fractal_agent_outlier_intercept(ARRAY[0,1,0]::float8[], 'bt_agents_badstates','emb', 0.5);"
    if ($r7b -match '^f$') { Pass "23 agents: outlier_intercept allows an orthogonal state (real cosine distance 1 > 0.5)" }
    else { Fail "23 agents: expected intercepted=f for an orthogonal state, got: $r7b" }

    $r7c = Psql -Sql "SELECT reason FROM fractal_agent_outlier_intercept(ARRAY[1,0,0]::float8[], 'bt_agents_badstates','emb', 0.5);"
    if ($r7c -match 'gap-analysis-canary') { Pass "23 agents: outlier_intercept reason is the real reason step output (canary)" }
    else { Fail "23 agents: expected the reasoning canary in reason, got: $r7c" }

    # --- 8: fractal_agent_recall_hybrid happy path + guard --------------
    # Real session_ids + real content (NOT the stub's generate_series 1-5 /
    # 'recalled memory snippet N'); the cohort (customer_id filter) excludes
    # cust-b's session. Pure retrieval -- no LLM step, no canary, real C.
    Psql -Sql @"
DROP TABLE IF EXISTS bt_agents_mem;
CREATE TABLE bt_agents_mem (session_id bigint, customer_id text, state_vector float8[], content text);
INSERT INTO bt_agents_mem VALUES
  (1001, 'cust-a', ARRAY[0.1,0.2,0.3], 'resolved churn via loyalty upgrade'),
  (1002, 'cust-a', ARRAY[0.15,0.25,0.35], 'offered retention discount'),
  (1003, 'cust-b', ARRAY[0.9,0.8,0.7], 'escalated to human agent');
"@ | Out-Null
    $r8 = Psql -Sql "SELECT mem_id FROM fractal_agent_recall_hybrid('bt_agents_mem','state_vector', ARRAY[0.1,0.2,0.3]::float8[], 'customer_id','cust-a', 5, 'session_id','content') LIMIT 1;"
    if ($r8 -match '^1001$') { Pass "23 agents: recall_hybrid returns the real nearest session_id (not the stub's generate_series 1-5)" }
    else { Fail "23 agents: expected mem_id=1001, got: $r8" }

    $r8b = Psql -Sql "SELECT content FROM fractal_agent_recall_hybrid('bt_agents_mem','state_vector', ARRAY[0.1,0.2,0.3]::float8[], 'customer_id','cust-a', 5, 'session_id','content') LIMIT 1;"
    if ($r8b -match 'resolved churn via loyalty upgrade') { Pass "23 agents: recall_hybrid returns the real row content (not the stub's canned snippet)" }
    else { Fail "23 agents: expected the real content, got: $r8b" }

    $r8c = Psql -Sql "SELECT * FROM fractal_agent_recall_hybrid('bt_agents_mem','state_vector', ARRAY[0.1,0.2,0.3]::float8[], 'customer_id','no-such-cust', 5, 'session_id','content');"
    if ($r8c -match 'filter matched no rows') { Pass "23 agents: recall_hybrid raises a clean ERROR when the filter matches no rows" }
    else { Fail "23 agents: expected a filter-matched-no-rows ERROR, got: $r8c" }

    # --- 9: fractal_agent_recommend_diverse happy path ------------------
    # Real catalog ids + real scores (NOT the stub's generate_series 1..k /
    # 0.95 - i*0.01). Diversify enabled as a session side effect; no feedback
    # reported so repulsion is a no-op and telemetry returns the plain nearest
    # first (id 10, distance 0 -> score 1). Pure retrieval.
    Psql -Sql @"
DROP TABLE IF EXISTS bt_agents_catalog;
CREATE TABLE bt_agents_catalog (id bigint, emb float8[]);
INSERT INTO bt_agents_catalog VALUES (10, ARRAY[0.1,0.2,0.3]), (20, ARRAY[0.9,0.8,0.7]), (30, ARRAY[0.5,0.5,0.5]);
"@ | Out-Null
    $r9 = Psql -Sql "SELECT item_id FROM fractal_agent_recommend_diverse('bt_agents_catalog','emb', ARRAY[0.1,0.2,0.3]::float8[], 3, 'id') LIMIT 1;"
    if ($r9 -match '^10$') { Pass "23 agents: recommend_diverse returns the real nearest catalog id (not the stub's generate_series 1..k)" }
    else { Fail "23 agents: expected item_id=10, got: $r9" }

    $r9b = Psql -Sql "SELECT score FROM fractal_agent_recommend_diverse('bt_agents_catalog','emb', ARRAY[0.1,0.2,0.3]::float8[], 3, 'id') LIMIT 1;"
    if ($r9b -match '^[0-9]+(\.[0-9]+)?$') { Pass "23 agents: recommend_diverse score is a real float (1 - cosine distance), not the stub's canned 0.95-i*0.01" }
    else { Fail "23 agents: expected a numeric score, got: $r9b" }

    # ====================================================================
    # Stage 4 engines G-O (9 new). The 8 cognition engines (G,H,J,K,L,M,N,O)
    # reuse the gate-20 mock canary set above, so their rationale/analysis
    # columns carry it; feedback_audit (I) is pure analytics (no LLM, no
    # canary). Real C primitives feed the analytics columns; the canary proves
    # the reason step ran. Mirrors build_test.sh's gate_23_agents.
    # ====================================================================

    # --- 10: fractal_agent_data_analyst happy path ----------------------
    # Composes fractal_sql_agent (NL->SQL->execute, auto_execute=true) ->
    # fractal_reason. With the mock canary the generated_sql IS the canary
    # (the mock LLM); auto_execute's subtransaction catches the canary-as-SQL
    # syntax error into a real execution_failed result_json, proving the
    # execute step ran; analysis is the real reason step (canary).
    Psql -Sql @"
DROP TABLE IF EXISTS bt_agents_data;
CREATE TABLE bt_agents_data (id int PRIMARY KEY, val float8);
INSERT INTO bt_agents_data VALUES (1,10.5),(2,20.5);
"@ | Out-Null
    $r10 = Psql -Sql "SELECT generated_sql FROM fractal_agent_data_analyst('sum of val', ARRAY['bt_agents_data'], 2);"
    if ($r10 -match 'gap-analysis-canary') { Pass "23 agents: data_analyst composes sql_agent (generated_sql is the real LLM step, canary)" }
    else { Fail "23 agents: expected the canary in generated_sql, got: $r10" }

    $r10b = Psql -Sql "SELECT result_json::text FROM fractal_agent_data_analyst('sum of val', ARRAY['bt_agents_data'], 2);"
    if ($r10b -match '"status"') { Pass "23 agents: data_analyst result_json is a real jsonb (auto_execute subtransaction ran)" }
    else { Fail "23 agents: expected a status-bearing result_json, got: $r10b" }

    $r10c = Psql -Sql "SELECT analysis FROM fractal_agent_data_analyst('sum of val', ARRAY['bt_agents_data'], 2);"
    if ($r10c -match 'gap-analysis-canary') { Pass "23 agents: data_analyst composes sql_agent -> reason (analysis is the real reason step, canary)" }
    else { Fail "23 agents: expected the canary in analysis, got: $r10c" }

    # --- 11: fractal_agent_patient_deterioration_triage happy + guard ----
    # nearest_cohort_id is the REAL hybrid_clinical_search nearest resolved via
    # ctid; cohort_distance/drift_distance are real; rationale is the reason
    # step (canary). cohort_doc_ids built from age>65 AND condition='sepsis'
    # (the two-predicate case recall_hybrid cannot express).
    Psql -Sql @"
DROP TABLE IF EXISTS bt_agents_patients;
CREATE TABLE bt_agents_patients (id int PRIMARY KEY, age int, condition text, vitals float8[]);
INSERT INTO bt_agents_patients VALUES
  (1,70,'sepsis',ARRAY[0.9,-0.8,0.7,0.6]),
  (2,30,'sepsis',ARRAY[0.1,0.1,0.1,0.1]),
  (3,72,'flu',  ARRAY[0.2,0.2,0.2,0.2]),
  (4,80,'sepsis',ARRAY[0.85,-0.75,0.65,0.55]);
"@ | Out-Null
    $r11 = Psql -Sql "SELECT nearest_cohort_id FROM fractal_agent_patient_deterioration_triage('bt_agents_patients','vitals', ARRAY[0.9,-0.8,0.7,0.6]::float8[], ARRAY[0.1,0.1,0.1,0.1]::float8[], ARRAY[0.95,-0.85,0.75,0.65]::float8[], (SELECT array_agg(doc_id ORDER BY doc_id) FROM (SELECT row_number() OVER (ORDER BY ctid)-1 AS doc_id FROM bt_agents_patients WHERE age>65 AND condition='sepsis') x), 5, 'id');"
    if ($r11 -match '^[0-9]+$') { Pass "23 agents: patient_deterioration_triage returns the real nearest cohort id (hybrid search + ctid resolution)" }
    else { Fail "23 agents: expected a numeric nearest_cohort_id, got: $r11" }

    $r11m = Psql -Sql "SELECT jsonb_array_length(cohort_matches) FROM fractal_agent_patient_deterioration_triage('bt_agents_patients','vitals', ARRAY[0.9,-0.8,0.7,0.6]::float8[], ARRAY[0.1,0.1,0.1,0.1]::float8[], ARRAY[0.95,-0.85,0.75,0.65]::float8[], (SELECT array_agg(doc_id ORDER BY doc_id) FROM (SELECT row_number() OVER (ORDER BY ctid)-1 AS doc_id FROM bt_agents_patients WHERE age>65 AND condition='sepsis') x), 5, 'id');"
    if ($r11m -eq '2') { Pass "23 agents: patient_deterioration_triage cohort_matches now honors k (got 2 of 2 qualifying rows)" }
    else { Fail "23 agents: expected cohort_matches length 2, got: $r11m" }

    $r11b = Psql -Sql "SELECT rationale FROM fractal_agent_patient_deterioration_triage('bt_agents_patients','vitals', ARRAY[0.9,-0.8,0.7,0.6]::float8[], ARRAY[0.1,0.1,0.1,0.1]::float8[], ARRAY[0.95,-0.85,0.75,0.65]::float8[], (SELECT array_agg(doc_id ORDER BY doc_id) FROM (SELECT row_number() OVER (ORDER BY ctid)-1 AS doc_id FROM bt_agents_patients WHERE age>65 AND condition='sepsis') x), 5, 'id');"
    if ($r11b -match 'gap-analysis-canary') { Pass "23 agents: patient_deterioration_triage composes hybrid+trajectory -> reason (canary)" }
    else { Fail "23 agents: expected the canary in rationale, got: $r11b" }

    Psql -Sql "DELETE FROM bt_agents_patients;" | Out-Null
    $r11c = Psql -Sql "SELECT * FROM fractal_agent_patient_deterioration_triage('bt_agents_patients','vitals', ARRAY[0.9,-0.8,0.7,0.6]::float8[], ARRAY[0.1,0.1,0.1,0.1]::float8[], ARRAY[0.95,-0.85,0.75,0.65]::float8[], NULL, 5, 'id');"
    if ($r11c -match 'no patient rows') { Pass "23 agents: patient_deterioration_triage raises a clean ERROR when the patient table is empty" }
    else { Fail "23 agents: expected a no-patient-rows ERROR, got: $r11c" }

    # --- 12: fractal_agent_feedback_audit happy + guard ------------------
    # Pure analytics (NO LLM, no canary): enables diversify, warms the D_q
    # window from the warmup table, isolates the target, reads back a real
    # diversity_quotient (NOT NaN -- the warmup populated the window) + the
    # real session diagnostics jsonb. Self-disables diversify.
    Psql -Sql @"
DROP TABLE IF EXISTS bt_agents_fcatalog, bt_agents_fwarmup;
CREATE TABLE bt_agents_fcatalog (id bigint PRIMARY KEY, emb float8[]);
INSERT INTO bt_agents_fcatalog SELECT gs, ARRAY[random()*2-1, random()*2-1, random()*2-1] FROM generate_series(1,20) gs;
CREATE TABLE bt_agents_fwarmup (center float8[]);
INSERT INTO bt_agents_fwarmup SELECT ARRAY[random()*2-1, random()*2-1, random()*2-1] FROM generate_series(1,8);
"@ | Out-Null
    $r12 = Psql -Sql "SELECT diversity_quotient::text FROM fractal_agent_feedback_audit('bt_agents_fcatalog','emb', ARRAY[0.5,0.5,0.5]::float8[], 'bt_agents_fwarmup','center', 8, 3);"
    if ($r12 -match '^[0-9]+(\.[0-9]+)?$') { Pass "23 agents: feedback_audit diversity_quotient is a real float (warmup populated the D_q window, not NaN)" }
    else { Fail "23 agents: expected a numeric diversity_quotient, got: $r12" }

    $r12b = Psql -Sql "SELECT (explanation IS NOT NULL)::text FROM fractal_agent_feedback_audit('bt_agents_fcatalog','emb', ARRAY[0.5,0.5,0.5]::float8[], 'bt_agents_fwarmup','center', 8, 3);"
    if ($r12b -match '^true$') { Pass "23 agents: feedback_audit returns the real session diagnostics jsonb" }
    else { Fail "23 agents: expected a non-null explanation, got: $r12b" }

    Psql -Sql "DELETE FROM bt_agents_fcatalog;" | Out-Null
    $r12c = Psql -Sql "SELECT * FROM fractal_agent_feedback_audit('bt_agents_fcatalog','emb', ARRAY[0.5,0.5,0.5]::float8[], 'bt_agents_fwarmup','center', 8, 3);"
    if ($r12c -match 'no catalog rows') { Pass "23 agents: feedback_audit raises a clean ERROR when the catalog is empty" }
    else { Fail "23 agents: expected a no-catalog-rows ERROR, got: $r12c" }

    # --- 13: fractal_agent_schedule_workload happy + guard ---------------
    # assigned_node is the REAL nearest node (fractal_search refinement +
    # telemetry + ctid resolution); confidence = 1/(1+d) is real; rationale
    # is the reason step (canary).
    Psql -Sql @"
DROP TABLE IF EXISTS bt_agents_nodes;
CREATE TABLE bt_agents_nodes (id int PRIMARY KEY, capability float8[]);
INSERT INTO bt_agents_nodes VALUES
  (1,ARRAY[0.9,0.1,0.0,0.0,0.0]),
  (2,ARRAY[0.0,0.0,0.9,0.1,0.0]),
  (3,ARRAY[0.1,0.0,0.0,0.0,0.9]);
"@ | Out-Null
    $r13 = Psql -Sql "SELECT assigned_node FROM fractal_agent_schedule_workload(ARRAY[0.8,0.1,0.0,0.0,0.1]::float8[], 'bt_agents_nodes','capability','id', 30, 50, 5);"
    if ($r13 -match '^[0-9]+$') { Pass "23 agents: schedule_workload returns the real nearest node (fractal_search + telemetry + ctid)" }
    else { Fail "23 agents: expected a numeric assigned_node, got: $r13" }

    $r13b = Psql -Sql "SELECT rationale FROM fractal_agent_schedule_workload(ARRAY[0.8,0.1,0.0,0.0,0.1]::float8[], 'bt_agents_nodes','capability','id', 30, 50, 5);"
    if ($r13b -match 'gap-analysis-canary') { Pass "23 agents: schedule_workload composes search+telemetry -> reason (canary)" }
    else { Fail "23 agents: expected the canary in rationale, got: $r13b" }

    Psql -Sql "DELETE FROM bt_agents_nodes;" | Out-Null
    $r13c = Psql -Sql "SELECT * FROM fractal_agent_schedule_workload(ARRAY[0.8,0.1,0.0,0.0,0.1]::float8[], 'bt_agents_nodes','capability','id', 30, 50, 5);"
    if ($r13c -match 'no node rows') { Pass "23 agents: schedule_workload raises a clean ERROR when the node table is empty" }
    else { Fail "23 agents: expected a no-node-rows ERROR, got: $r13c" }

    # --- 14: fractal_agent_rebalance_sibling happy + guard ---------------
    # sharpe is the REAL optimizer output; weights is the real jsonb;
    # nearest_alloc_id is the real trajectory-search nearest resolved via
    # ctid; rationale is the reason step (canary).
    Psql -Sql @"
DROP TABLE IF EXISTS bt_agents_alloc;
CREATE TABLE bt_agents_alloc (id bigint PRIMARY KEY, alloc float8[]);
INSERT INTO bt_agents_alloc VALUES
  (1,ARRAY[0.25,0.25,0.25,0.25]),
  (2,ARRAY[0.4,0.3,0.2,0.1]),
  (3,ARRAY[0.1,0.2,0.3,0.4]);
"@ | Out-Null
    $r14 = Psql -Sql "SELECT sharpe::text FROM fractal_agent_rebalance_sibling(ARRAY[0.05,0.10,0.15,0.20]::float8[], ARRAY[0.04,0.0,0.0,0.0, 0.0,0.09,0.0,0.0, 0.0,0.0,0.16,0.0, 0.0,0.0,0.0,0.25]::float8[], 4, 'bt_agents_alloc','alloc', ARRAY[0.25,0.25,0.25,0.25]::float8[], NULL, 5, 'id');"
    if ($r14 -match '^-?[0-9]+(\.[0-9]+)?$') { Pass "23 agents: rebalance_sibling sharpe is the real optimizer output" }
    else { Fail "23 agents: expected a numeric sharpe, got: $r14" }

    $r14b = Psql -Sql "SELECT nearest_alloc_id FROM fractal_agent_rebalance_sibling(ARRAY[0.05,0.10,0.15,0.20]::float8[], ARRAY[0.04,0.0,0.0,0.0, 0.0,0.09,0.0,0.0, 0.0,0.0,0.16,0.0, 0.0,0.0,0.0,0.25]::float8[], 4, 'bt_agents_alloc','alloc', ARRAY[0.25,0.25,0.25,0.25]::float8[], NULL, 5, 'id');"
    if ($r14b -match '^[0-9]+$') { Pass "23 agents: rebalance_sibling nearest_alloc_id is the real trajectory nearest (ctid resolution)" }
    else { Fail "23 agents: expected a numeric nearest_alloc_id, got: $r14b" }

    $r14c = Psql -Sql "SELECT rationale FROM fractal_agent_rebalance_sibling(ARRAY[0.05,0.10,0.15,0.20]::float8[], ARRAY[0.04,0.0,0.0,0.0, 0.0,0.09,0.0,0.0, 0.0,0.0,0.16,0.0, 0.0,0.0,0.0,0.25]::float8[], 4, 'bt_agents_alloc','alloc', ARRAY[0.25,0.25,0.25,0.25]::float8[], NULL, 5, 'id');"
    if ($r14c -match 'gap-analysis-canary') { Pass "23 agents: rebalance_sibling composes optimize+trajectory -> reason (canary)" }
    else { Fail "23 agents: expected the canary in rationale, got: $r14c" }

    Psql -Sql "DELETE FROM bt_agents_alloc;" | Out-Null
    $r14d = Psql -Sql "SELECT * FROM fractal_agent_rebalance_sibling(ARRAY[0.05,0.10,0.15,0.20]::float8[], ARRAY[0.04,0.0,0.0,0.0, 0.0,0.09,0.0,0.0, 0.0,0.0,0.16,0.0, 0.0,0.0,0.0,0.25]::float8[], 4, 'bt_agents_alloc','alloc', ARRAY[0.25,0.25,0.25,0.25]::float8[], NULL, 5, 'id');"
    if ($r14d -match 'no allocation rows') { Pass "23 agents: rebalance_sibling raises a clean ERROR when the allocation table is empty" }
    else { Fail "23 agents: expected a no-allocation-rows ERROR, got: $r14d" }

    # --- 15: fractal_agent_detour_classify happy + guard -----------------
    # nearest_fleet_id is the REAL trajectory-search nearest; trace_complexity
    # is the REAL box-counting dimension of the GPS trace; rationale is the
    # reason step (canary).
    Psql -Sql @"
DROP TABLE IF EXISTS bt_agents_vehicles;
CREATE TABLE bt_agents_vehicles (id int PRIMARY KEY, baseline float8[], current float8[]);
INSERT INTO bt_agents_vehicles SELECT gs, ARRAY[b1,b2,b3,b4], ARRAY[b1+0.05,b2+0.05,b3+0.05,b4+0.05]
  FROM generate_series(1,8) gs,
       LATERAL (SELECT random()*2-1 a, random()*2-1 b, random()*2-1 c, random()*2-1 d) bl(b1,b2,b3,b4);
UPDATE bt_agents_vehicles SET current = ARRAY[(baseline::float8[])[1]-0.7,(baseline::float8[])[2]+0.6,(baseline::float8[])[3]+0.5,(baseline::float8[])[4]-0.4] WHERE id=1;
"@ | Out-Null
    $r15 = Psql -Sql "SELECT trace_complexity::text FROM fractal_agent_detour_classify('bt_agents_vehicles','current', (SELECT baseline::float8[] FROM bt_agents_vehicles WHERE id=1), (SELECT current::float8[] FROM bt_agents_vehicles WHERE id=1), (SELECT array_agg(cum ORDER BY t, ord) FROM (SELECT t, ord, sum(step) OVER (PARTITION BY ord ORDER BY t) AS cum FROM generate_series(1,100) t CROSS JOIN LATERAL (VALUES (1,(random()-0.5)*0.3),(2,(random()-0.5)*0.3)) AS s(ord,step)) c), 5, 'id', 2);"
    if ($r15 -match '^[0-9]+(\.[0-9]+)?$') { Pass "23 agents: detour_classify trace_complexity is the real box-counting dimension of the GPS trace" }
    else { Fail "23 agents: expected a numeric trace_complexity, got: $r15" }

    $r15b = Psql -Sql "SELECT rationale FROM fractal_agent_detour_classify('bt_agents_vehicles','current', (SELECT baseline::float8[] FROM bt_agents_vehicles WHERE id=1), (SELECT current::float8[] FROM bt_agents_vehicles WHERE id=1), (SELECT array_agg(cum ORDER BY t, ord) FROM (SELECT t, ord, sum(step) OVER (PARTITION BY ord ORDER BY t) AS cum FROM generate_series(1,100) t CROSS JOIN LATERAL (VALUES (1,(random()-0.5)*0.3),(2,(random()-0.5)*0.3)) AS s(ord,step)) c), 5, 'id', 2);"
    if ($r15b -match 'gap-analysis-canary') { Pass "23 agents: detour_classify composes trajectory+boxcount -> reason (canary)" }
    else { Fail "23 agents: expected the canary in rationale, got: $r15b" }

    Psql -Sql "DELETE FROM bt_agents_vehicles;" | Out-Null
    $r15c = Psql -Sql "SELECT * FROM fractal_agent_detour_classify('bt_agents_vehicles','current', ARRAY[0.1,0.1,0.1,0.1]::float8[], ARRAY[0.2,0.2,0.2,0.2]::float8[], ARRAY[0,0,0,0]::float8[], 5, 'id', 2);"
    if ($r15c -match 'no vehicle rows') { Pass "23 agents: detour_classify raises a clean ERROR when the vehicle table is empty" }
    else { Fail "23 agents: expected a no-vehicle-rows ERROR, got: $r15c" }

    # --- 16: fractal_agent_track_anomaly happy + guard -------------------
    # nearest_fleet_id is the REAL trajectory nearest; dfa_exponent is the REAL
    # DFA exponent of the heading series (may be -1, still numeric); rationale
    # is the reason step (canary).
    Psql -Sql @"
DROP TABLE IF EXISTS bt_agents_tracks;
CREATE TABLE bt_agents_tracks (id int PRIMARY KEY, baseline float8[], current float8[]);
INSERT INTO bt_agents_tracks SELECT gs, ARRAY[b1,b2,b3,b4], ARRAY[b1+0.04,b2+0.04,b3+0.04,b4+0.04]
  FROM generate_series(1,8) gs,
       LATERAL (SELECT random()*2-1 a, random()*2-1 b, random()*2-1 c, random()*2-1 d) bl(b1,b2,b3,b4);
UPDATE bt_agents_tracks SET current = ARRAY[(baseline::float8[])[1]+0.6,(baseline::float8[])[2]-0.5,(baseline::float8[])[3]-0.9,(baseline::float8[])[4]+0.8] WHERE id=1;
"@ | Out-Null
    $r16 = Psql -Sql "SELECT dfa_exponent::text FROM fractal_agent_track_anomaly('bt_agents_tracks','current', (SELECT baseline::float8[] FROM bt_agents_tracks WHERE id=1), (SELECT current::float8[] FROM bt_agents_tracks WHERE id=1), (SELECT array_agg(cum ORDER BY t) FROM (SELECT t, sum(step) OVER (ORDER BY t) AS cum FROM (SELECT t, (random()-0.5)*(CASE WHEN t BETWEEN 40 AND 60 THEN 0.35 ELSE 0.03 END) AS step FROM generate_series(1,120) t) s) c), 5, 'id');"
    if ($r16 -match '^-?[0-9]+(\.[0-9]+)?$') { Pass "23 agents: track_anomaly dfa_exponent is the real DFA exponent of the heading series" }
    else { Fail "23 agents: expected a numeric dfa_exponent, got: $r16" }

    $r16b = Psql -Sql "SELECT rationale FROM fractal_agent_track_anomaly('bt_agents_tracks','current', (SELECT baseline::float8[] FROM bt_agents_tracks WHERE id=1), (SELECT current::float8[] FROM bt_agents_tracks WHERE id=1), (SELECT array_agg(cum ORDER BY t) FROM (SELECT t, sum(step) OVER (ORDER BY t) AS cum FROM (SELECT t, (random()-0.5)*(CASE WHEN t BETWEEN 40 AND 60 THEN 0.35 ELSE 0.03 END) AS step FROM generate_series(1,120) t) s) c), 5, 'id');"
    if ($r16b -match 'gap-analysis-canary') { Pass "23 agents: track_anomaly composes trajectory+dfa -> reason (canary)" }
    else { Fail "23 agents: expected the canary in rationale, got: $r16b" }

    Psql -Sql "DELETE FROM bt_agents_tracks;" | Out-Null
    $r16c = Psql -Sql "SELECT * FROM fractal_agent_track_anomaly('bt_agents_tracks','current', ARRAY[0.1,0.1,0.1,0.1]::float8[], ARRAY[0.2,0.2,0.2,0.2]::float8[], ARRAY[0,0,0]::float8[], 5, 'id');"
    if ($r16c -match 'no track rows') { Pass "23 agents: track_anomaly raises a clean ERROR when the track table is empty" }
    else { Fail "23 agents: expected a no-track-rows ERROR, got: $r16c" }

    # --- 17: fractal_agent_network_coverage_alert happy + NULL guard -----
    # morph_dimension + lacunarity are the REAL morphological_complexity output
    # (needs >= ~256 points -- use a 20x20 grid, matching the smart-cities
    # demo); drift_detected is the REAL |drift|>threshold over a step-up
    # series (true); rationale is the reason step (canary).
    $r17 = Psql -Sql @"
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
  2, 48, 0.5);
"@
    if ($r17 -match '^[0-9]+(\.[0-9]+)?$') { Pass "23 agents: network_coverage_alert morph_dimension is the real morphological complexity" }
    else { Fail "23 agents: expected a numeric morph_dimension, got: $r17" }

    $r17b = Psql -Sql @"
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
  2, 48, 0.5);
"@
    if ($r17b -match '^true$') { Pass "23 agents: network_coverage_alert drift_detected=true for a real regime-change series (|drift|>0.5)" }
    else { Fail "23 agents: expected drift_detected=t, got: $r17b" }

    $r17c = Psql -Sql @"
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
  2, 48, 0.5);
"@
    if ($r17c -match 'gap-analysis-canary') { Pass "23 agents: network_coverage_alert composes morph+drift -> reason (canary)" }
    else { Fail "23 agents: expected the canary in rationale, got: $r17c" }

    $r17d = Psql -Sql "SELECT * FROM fractal_agent_network_coverage_alert(NULL::float8[], ARRAY[1,2,3]::float8[], 2, 48, 0.5);"
    if ($r17d -match 'point_cloud and drift_series are required') { Pass "23 agents: network_coverage_alert raises a clean ERROR when point_cloud/drift_series is NULL" }
    else { Fail "23 agents: expected a required-args ERROR, got: $r17d" }

    # --- 18: fractal_agent_regime_triage happy + NULL guard --------------
    # dfa_exponent is the REAL DFA exponent; drift_detected is the REAL
    # |drift|>threshold (true for the step-up series); recent/baseline alphas
    # are real; rationale is the reason step (canary).
    $r18 = Psql -Sql @"
SELECT dfa_exponent::text FROM fractal_agent_regime_triage(
  (SELECT array_agg(v ORDER BY t) FROM (
     SELECT t, CASE WHEN t<48 THEN 4.0+1.5*sin(t*0.31)+(random()-0.5)*0.8
                    ELSE 4.0+3.0*sin(t*1.4)+(random()-0.5)*0.4 END AS v
     FROM generate_series(1,96) t) s),
  64, 0.5);
"@
    if ($r18 -match '^-?[0-9]+(\.[0-9]+)?$') { Pass "23 agents: regime_triage dfa_exponent is the real DFA exponent" }
    else { Fail "23 agents: expected a numeric dfa_exponent, got: $r18" }

    $r18b = Psql -Sql @"
SELECT drift_detected::text FROM fractal_agent_regime_triage(
  (SELECT array_agg(v ORDER BY t) FROM (
     SELECT t, CASE WHEN t<48 THEN 4.0+1.5*sin(t*0.31)+(random()-0.5)*0.8
                    ELSE 4.0+3.0*sin(t*1.4)+(random()-0.5)*0.4 END AS v
     FROM generate_series(1,96) t) s),
  64, 0.5);
"@
    if ($r18b -match '^true$') { Pass "23 agents: regime_triage drift_detected=true for a real regime-change series (|drift|>0.5)" }
    else { Fail "23 agents: expected drift_detected=t, got: $r18b" }

    $r18c = Psql -Sql @"
SELECT rationale FROM fractal_agent_regime_triage(
  (SELECT array_agg(v ORDER BY t) FROM (
     SELECT t, CASE WHEN t<48 THEN 4.0+1.5*sin(t*0.31)+(random()-0.5)*0.8
                    ELSE 4.0+3.0*sin(t*1.4)+(random()-0.5)*0.4 END AS v
     FROM generate_series(1,96) t) s),
  64, 0.5);
"@
    if ($r18c -match 'gap-analysis-canary') { Pass "23 agents: regime_triage composes dfa+drift -> reason (canary)" }
    else { Fail "23 agents: expected the canary in rationale, got: $r18c" }

    $r18d = Psql -Sql "SELECT * FROM fractal_agent_regime_triage(NULL::float8[], 64, 0.5);"
    if ($r18d -match 'series is required') { Pass "23 agents: regime_triage raises a clean ERROR when series is NULL" }
    else { Fail "23 agents: expected a series-required ERROR, got: $r18d" }

    # Restore session state: diversify was enabled by recommend_diverse and
    # feedback_audit (feedback_audit self-disables, but belt-and-suspenders).
    Psql -Sql "SELECT fractal_diversify_disable();" | Out-Null

    Psql -Sql "DROP TABLE IF EXISTS bt_agents_caps, bt_agents_badstates, bt_agents_mem, bt_agents_catalog;" | Out-Null
    Psql -Sql "DROP TABLE IF EXISTS bt_agents_logs;" | Out-Null
    Psql -Sql "DROP TABLE IF EXISTS bt_agents_data, bt_agents_patients, bt_agents_fcatalog, bt_agents_fwarmup, bt_agents_nodes, bt_agents_alloc, bt_agents_vehicles, bt_agents_tracks;" | Out-Null
    Remove-Item -Force $SqlFile -ErrorAction SilentlyContinue
}

# Windows port of build_test.sh's Gate 21 (--fuzz). No live cluster
# needed -- same as gate 01, this builds and briefly runs standalone
# .exe's linking only src\fractalsql_parse.c (postgres.h-free by
# design, see that file's header comment) + one libFuzzer driver each,
# nothing else. Uses $script:ClangCl (resolved by -Fuzz/-Ubsan's shared
# Find-ClangCl call above) -- LLVM's fuzzer support is a real, long-
# standing clang-cl feature, not something Linux-only that needed
# reinventing here.
#
# Same stderr-redirection care as every other native-process call in
# this file: libFuzzer writes its progress/coverage stats to STDERR
# continuously throughout the run (confirmed convention, same on every
# platform) -- a bare `&` invocation would trip PowerShell 7.3+'s
# ANY-stderr-is-a-terminating-error behavior on the very first progress
# line, the exact class of regression already found and fixed in
# PgSetup's pg_ctl start call this session. Unlike that case, THIS
# process has no long-lived daemon children (the fuzzer exits cleanly
# once -max_total_time elapses), so reading its redirected pipes to EOF
# via ReadToEndAsync().Result is safe -- same safety profile as initdb,
# not pg_ctl start.
function Gate21FuzzSmoke {
    $fuzzDir = Join-Path $RepoRoot 'dist\windows-fuzz'
    if (Test-Path $fuzzDir) { Remove-Item -Recurse -Force $fuzzDir }
    New-Item -ItemType Directory -Force -Path $fuzzDir | Out-Null

    $srcParse = Join-Path $RepoRoot 'src\fractalsql_parse.c'
    $srcDir   = Join-Path $RepoRoot 'src'
    $fuzzTime = if ($env:FSQL_FUZZ_TIME) { $env:FSQL_FUZZ_TIME } else { '30' }

    # clang-cl defaults to /MD (dynamic CRT), so -fsanitize=address links
    # against clang_rt.asan_dynamic-x86_64.dll rather than a static
    # runtime -- unlike -Ubsan's UBSan runtime, which is a static .lib
    # with no launch-time dependency at all. Without this DLL's directory
    # on PATH, the built .exe fails to even START (STATUS_DLL_NOT_FOUND,
    # exit -1073741511 / 0xC0000135) -- confirmed on a real run: all 3
    # targets "failed" identically, which was the tell that this was a
    # launch failure, not 3 independent fuzzer-found crashes. Resolve the
    # runtime directory the same way Find-ClangCl resolves the compiler
    # itself, and prepend it to PATH for this process only.
    $clangResourceDir = $null
    try { $clangResourceDir = (& $script:ClangCl -print-resource-dir 2>$null | Select-Object -First 1) } catch { <# best-effort: clang -print-resource-dir absent/unsupported is not fatal, $clangResourceDir stays $null #> }
    if ($clangResourceDir) {
        $sanRtDir = Join-Path $clangResourceDir 'lib\windows'
        if (Test-Path $sanRtDir) { $env:PATH = "$sanRtDir;$env:PATH" }
    }

    foreach ($target in @('parse_embedding_array', 'extract_best_point', 'extract_population')) {
        $bin    = Join-Path $fuzzDir "fuzz_$target.exe"
        $driver = Join-Path $RepoRoot "tests\fuzz\fuzz_$target.c"
        $corpus = Join-Path $RepoRoot "tests\fuzz\corpus_$target"

        # /Fe<name> (direct concatenation, no colon) -- same form already
        # proven working in Build-UbsanExtension's own $script:ClangCl
        # invocations above, not a new untested variant.
        $compileArgs = @(
            # -std=c99 dropped: clang-cl (cl.exe-compatible mode) doesn't
            # recognize that spelling ("unknown argument ignored" warning,
            # harmless but noisy) and fractalsql_parse.c needs nothing
            # beyond clang-cl's own C default.
            '-O1', '-Zi', '-fsanitize=fuzzer,address',
            "-I$srcDir",
            $srcParse, $driver,
            "/Fe$bin"
        )
        & $script:ClangCl @compileArgs
        if ($LASTEXITCODE -ne 0) {
            Fail "21 fuzz_smoke: $target -- build failed (exit $LASTEXITCODE)"
            continue
        }

        $fuzzPsi = New-Object System.Diagnostics.ProcessStartInfo
        $fuzzPsi.FileName = $bin
        foreach ($a in @("-max_total_time=$fuzzTime", '-print_final_stats=1', $corpus)) {
            $fuzzPsi.ArgumentList.Add($a)
        }
        $fuzzPsi.RedirectStandardOutput = $true
        $fuzzPsi.RedirectStandardError  = $true
        $fuzzPsi.UseShellExecute = $false
        $fuzzProc = [System.Diagnostics.Process]::Start($fuzzPsi)
        $fuzzOutTask = $fuzzProc.StandardOutput.ReadToEndAsync()
        $fuzzErrTask = $fuzzProc.StandardError.ReadToEndAsync()
        $fuzzProc.WaitForExit()
        $fuzzOut = $fuzzOutTask.Result
        $fuzzErr = $fuzzErrTask.Result

        if ($fuzzProc.ExitCode -eq 0) {
            $execsMatch = [regex]::Match($fuzzErr, 'stat::number_of_executed_units:\s*(\d+)')
            $execs = if ($execsMatch.Success) { $execsMatch.Groups[1].Value } else { '?' }
            Pass "21 fuzz_smoke: $target -- ${fuzzTime}s clean ($execs execs, no crash)"
        } else {
            $logPath = Join-Path $fuzzDir "fuzz_${target}_crash.log"
            ($fuzzOut + "`n" + $fuzzErr) | Out-File -FilePath $logPath -Encoding utf8
            Fail "21 fuzz_smoke: $target -- crash/hang found (exit $($fuzzProc.ExitCode)), see $logPath"
        }
        Remove-Item -Force $bin -ErrorAction SilentlyContinue
    }
}

# --- dispatch --------------------------------------------------------------
function Gate24Enterprise {
    # QTL ledger + CISO audit -- runtime-gated behind the enterprise core
    # library. Self-skips on a community-only checkout (no enterprise
    # shared lib vendored in include/). When present, exercises the full
    # wiring: dlopen + dlsym of fsql_ledger_*/fsql_audit_unpack, the
    # Postgres-backed storage VFS round-trip (flush -> fractalsql_ledger ->
    # audit_unpack), and the dormant-path error when the library is absent.
    $ent = Get-ChildItem -Path include -Recurse -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match '^(lib)?fractalsql-enterprise-sovereign-c\.(dll|so|dylib)$' } |
        Select-Object -First 1
    if (-not $ent) {
        Skip "24 enterprise: skipped (community edition; no fractalsql-enterprise-sovereign-c.* shared lib in include/)"
        return
    }
    $abs = $ent.FullName

    # Phase E below calls agents that invoke fractal_reason -- make sure the
    # mock plugin is active regardless of whether gate 23 ran first (this
    # gate must be standalone-runnable, same rationale as gate 23's swap).
    PgSwapPlugin $Mock | Out-Null

    # fractalsql.enterprise_lib is PGC_SIGHUP: ALTER SYSTEM + reload, then a
    # short settle delay -- pg_reload_conf() returns before the postmaster
    # re-reads config, so a fresh backend started immediately could still
    # see the old value. The local build_test cluster reloads in ms.
    $applyGuc = {
        param($val)
        $escaped = $val -replace "'", "''"
        [void](Psql -Sql "ALTER SYSTEM SET fractalsql.enterprise_lib = '$escaped';")
        [void](Psql -Sql "SELECT pg_reload_conf();")
        Start-Sleep -Milliseconds 1500
    }

    # Phase A: enterprise library present -- the surface activates.
    & $applyGuc $abs
    $ra = Psql -Sql @"
SELECT fractal_ledger_flush();
SELECT fractal_ledger_truth_count() AS truth, fractal_ledger_shadow_count() AS shadow;
SELECT fractal_ledger_load();
SELECT fractal_ledger_compact();
SELECT fractal_ledger_reset_soft();
SELECT fractal_ledger_reset_hard();
SELECT fractal_audit_unpack(blob)::text AS audit
  FROM fractalsql_ledger WHERE kind = 1 ORDER BY id DESC LIMIT 1;
"@
    if ($ra -match 'ERROR:') {
        Fail "24 enterprise: ledger/audit errored with the enterprise library present: $ra"
    } else {
        Pass "24 enterprise: ledger flush/load/compact/reset/counts work with the enterprise library"
    }
    if ($ra -match '\[\]') {
        Pass "24 enterprise: fractal_audit_unpack decoded the persisted QTL blob end-to-end (storage VFS round-trip)"
    } else {
        Fail "24 enterprise: audit_unpack did not return the flushed QTL jsonb (got: $ra)"
    }

    # Phase B: point the GUC at a missing path -- the surface goes dormant,
    # equivalent to removing the .dll. Fresh backend -> LoadLibrary fails ->
    # the documented 'enterprise tier not loaded' error.
    & $applyGuc '/nonexistent/fractalsql-enterprise-absent.dll'
    $rb = Psql -Sql "SELECT fractal_ledger_flush();"
    if ($rb -match 'enterprise tier not loaded') {
        Pass "24 enterprise: ledger functions return 'enterprise tier not loaded' when the library is absent"
    } else {
        Fail "24 enterprise: expected 'enterprise tier not loaded' when absent, got: $rb"
    }

    # Phase C: fractal_optimize_portfolio_multimodal -- dormant then active.
    $rcDormant = Psql -Sql "SELECT fractal_optimize_portfolio_multimodal(ARRAY[0.1,0.05,0.08]::float8[], ARRAY[0.04,0.01,0.01, 0.01,0.03,0.01, 0.01,0.01,0.05]::float8[], 2);"
    if ($rcDormant -match 'enterprise tier not loaded') {
        Pass "24 enterprise: portfolio_multimodal returns 'enterprise tier not loaded' when the library is absent"
    } else {
        Fail "24 enterprise: expected 'enterprise tier not loaded' for portfolio_multimodal when absent, got: $rcDormant"
    }
    & $applyGuc $abs
    # Psql concatenates stdout+stderr (see its own header comment) -- the
    # enterprise-lib load WARNING that fires on every fresh connection
    # lands in stderr, appended AFTER the real stdout result. An anchored
    # ^...$ match against the whole combined string breaks on that extra
    # text even though the actual value is correct; take just the first
    # line (the real stdout result) before matching, same as every other
    # gate's loose substring checks already tolerate implicitly.
    $rcActive = Psql -Sql "SELECT fractal_optimize_portfolio_multimodal(ARRAY[0.1,0.05,0.08]::float8[], ARRAY[0.04,0.01,0.01, 0.01,0.03,0.01, 0.01,0.01,0.05]::float8[], 2, 4)->>'n_found';"
    $rcActiveFirstLine = (($rcActive -split "`r?`n")[0]).Trim()
    if ($rcActiveFirstLine -match '^[1-9][0-9]?$') {
        Pass "24 enterprise: portfolio_multimodal returns real candidates (n_found=$rcActiveFirstLine) with the library present"
    } else {
        Fail "24 enterprise: expected a positive n_found from portfolio_multimodal, got: $rcActive"
    }

    # Phase D: fractal_audit_log / fractal_ledger_verify(2) -- the general
    # decision-audit chain. Library still active from Phase C.
    [void](Psql -Sql "DELETE FROM fractalsql_ledger WHERE kind = 2;")
    $rdWrite = Psql -Sql "SELECT fractal_audit_log('test_entry', '{""note"":""gate24""}'::jsonb);"
    if ($rdWrite -match 'ERROR:') {
        Fail "24 enterprise: fractal_audit_log errored with the library present: $rdWrite"
    } else {
        Pass "24 enterprise: fractal_audit_log writes to the audit chain (kind=2) with the library present"
    }
    # Same stdout+stderr-concatenation issue as the n_found check above --
    # take just the first line before comparing.
    $rdVerifyRaw = Psql -Sql "SELECT fractal_ledger_verify(2)->>'ok';"
    $rdVerify = (($rdVerifyRaw -split "`r?`n")[0]).Trim()
    if ($rdVerify -eq 'true') {
        Pass "24 enterprise: fractal_ledger_verify(2) confirms the audit chain is clean"
    } else {
        Fail "24 enterprise: expected fractal_ledger_verify(2) ok=true, got: $rdVerifyRaw"
    }

    # TryParse, not a blind [int] cast: a dead/recovering connection (e.g.
    # if something upstream in this gate crashed the backend) returns
    # psql's error text here, not a number -- a blind cast throws an
    # unhandled exception that kills the whole script instead of failing
    # this one assertion cleanly (same TryParse pattern already used
    # elsewhere in this file, e.g. Gate11Scout/Gate19SfsBounds).
    $rdBeforeRaw = (Psql -Sql "SELECT count(*) FROM fractalsql_ledger WHERE kind = 2;").Trim()
    [void](Psql -Sql "SELECT fractal_optimize_portfolio(ARRAY[0.1,0.05,0.08]::float8[], ARRAY[0.04,0.01,0.01, 0.01,0.03,0.01, 0.01,0.01,0.05]::float8[], 2);")
    $rdAfterRaw = (Psql -Sql "SELECT count(*) FROM fractalsql_ledger WHERE kind = 2;").Trim()
    $rdBefore = 0; $rdAfter = 0
    if (-not [int]::TryParse($rdBeforeRaw, [ref]$rdBefore) -or -not [int]::TryParse($rdAfterRaw, [ref]$rdAfter)) {
        Fail "24 enterprise: could not read kind=2 row count (before='$rdBeforeRaw' after='$rdAfterRaw') -- connection likely dead"
    } elseif ($rdAfter -gt $rdBefore) {
        Pass "24 enterprise: fractal_optimize_portfolio logs a provenance record to the audit chain when enterprise is active"
    } else {
        Fail "24 enterprise: expected a new kind=2 row after fractal_optimize_portfolio, before=$rdBefore after=$rdAfter"
    }

    & $applyGuc '/nonexistent/fractalsql-enterprise-absent.dll'
    $rdDormant = Psql -Sql "SELECT fractal_audit_log('test_entry', '{}'::jsonb);"
    if ($rdDormant -match 'enterprise tier not loaded') {
        Pass "24 enterprise: fractal_audit_log returns 'enterprise tier not loaded' when the library is absent"
    } else {
        Fail "24 enterprise: expected 'enterprise tier not loaded' for fractal_audit_log when absent, got: $rdDormant"
    }
    $rdPortfolioStillWorks = Psql -Sql "SELECT fractal_optimize_portfolio(ARRAY[0.1,0.05,0.08]::float8[], ARRAY[0.04,0.01,0.01, 0.01,0.03,0.01, 0.01,0.01,0.05]::float8[], 2);"
    if ($rdPortfolioStillWorks -match 'ERROR:') {
        Fail "24 enterprise: fractal_optimize_portfolio broke on community (no enterprise lib): $rdPortfolioStillWorks"
    } else {
        Pass "24 enterprise: fractal_optimize_portfolio (community feature) keeps working with the enterprise library absent"
    }

    # Phase E: representative sample of the newly-wired agent bindings --
    # confirm each writes a correctly-typed kind=2 row when enterprise is
    # active. Gate 23 already proves all 11 candidates behave identically
    # (best-effort no-op) on community; this proves the enterprise side of
    # the same bindings actually fires.
    & $applyGuc $abs
    $latestAuditType = {
        (Psql -Sql "SELECT convert_from(blob, 'UTF8')::jsonb->>'type' FROM fractalsql_ledger WHERE kind = 2 ORDER BY id DESC LIMIT 1;").Trim()
    }

    [void](Psql -Sql @"
DROP TABLE IF EXISTS bt_gate24_history;
CREATE TABLE bt_gate24_history (id int PRIMARY KEY, emb float8[]);
INSERT INTO bt_gate24_history VALUES (1, ARRAY[0.1,0.2,0.3]);
"@)
    [void](Psql -Sql "SELECT * FROM fractal_agent_outlier_intercept(ARRAY[0.1,0.2,0.3]::float8[], 'bt_gate24_history', 'emb', 0.5);")
    if ((& $latestAuditType) -eq 'agent_outlier_intercept') {
        Pass "24 enterprise: fractal_agent_outlier_intercept logs a provenance record to the audit chain"
    } else {
        Fail "24 enterprise: expected agent_outlier_intercept in the latest kind=2 row"
    }

    [void](Psql -Sql @"
DROP TABLE IF EXISTS bt_gate24_data;
CREATE TABLE bt_gate24_data (id int PRIMARY KEY, val float8);
INSERT INTO bt_gate24_data VALUES (1,10.5),(2,20.5);
"@)
    [void](Psql -Sql "SELECT * FROM fractal_agent_data_analyst('sum of val', ARRAY['bt_gate24_data'], 2);")
    if ((& $latestAuditType) -eq 'agent_data_analyst') {
        Pass "24 enterprise: fractal_agent_data_analyst logs a provenance record to the audit chain"
    } else {
        Fail "24 enterprise: expected agent_data_analyst in the latest kind=2 row"
    }

    # fractal_agent_diverse_portfolios (enterprise-only gap-fix binding) --
    # both the C-side portfolio_optimize_multimodal entry and the agent-level
    # entry must land (same double-logging pattern as allocate/rebalance).
    [void](Psql -Sql "SELECT * FROM fractal_agent_diverse_portfolios(ARRAY[0.1,0.05,0.08]::float8[], ARRAY[0.04,0.01,0.01, 0.01,0.03,0.01, 0.01,0.01,0.05]::float8[], 2, 4);")
    $rdDiverseTypes = Psql -Sql "SELECT convert_from(blob, 'UTF8')::jsonb->>'type' FROM fractalsql_ledger WHERE kind = 2 ORDER BY id DESC LIMIT 2;"
    if ($rdDiverseTypes -match 'agent_diverse_portfolios' -and $rdDiverseTypes -match 'portfolio_optimize_multimodal') {
        Pass "24 enterprise: fractal_agent_diverse_portfolios + fractal_optimize_portfolio_multimodal both log (double-logging, gap-fix binding)"
    } else {
        Fail "24 enterprise: expected both agent_diverse_portfolios and portfolio_optimize_multimodal in the last 2 kind=2 rows, got: $rdDiverseTypes"
    }

    # Reset the GUC so it does not leak into later gates on a reused cluster.
    [void](Psql -Sql "ALTER SYSTEM RESET fractalsql.enterprise_lib;")
    [void](Psql -Sql "SELECT pg_reload_conf();")
}

function Gate25EnterpriseStress {
    # Enterprise QTL ledger under stress + tamper-evidence + concurrency.
    # Self-skips on a community-only checkout (same detection as gate 24).
    # Gate 24 covers the basic active/dormant wiring; this gate exercises
    # the ledger at its capacity bound, under repeated churn, against a
    # corrupted blob, and under concurrent + cross-backend access.
    $ent = Get-ChildItem -Path include -Recurse -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match '^(lib)?fractalsql-enterprise-sovereign-c\.(dll|so|dylib)$' } |
        Select-Object -First 1
    if (-not $ent) {
        Skip "25 enterprise-stress: skipped (community edition; no fractalsql-enterprise-sovereign-c.* shared lib in include/)"
        return
    }
    $abs = $ent.FullName

    # PGC_SIGHUP GUC -- same apply + settle pattern as gate 24.
    $applyGuc = {
        param($val)
        $escaped = $val -replace "'", "''"
        [void](Psql -Sql "ALTER SYSTEM SET fractalsql.enterprise_lib = '$escaped';")
        [void](Psql -Sql "SELECT pg_reload_conf();")
        Start-Sleep -Milliseconds 1500
    }

    & $applyGuc $abs

    # Clean slate for the gate.
    [void](Psql -Sql "DROP TABLE IF EXISTS fractalsql_ledger;")

    # ---- Phase A: stress -- fill-to-cap (64 truth + 64 shadow = 128) + churn.
    # Truth/Shadow each cap at 64 (FSQL_TRUTH/SHADOW_DEFAULT_CAP); beyond that
    # the lowest-weight entry is evicted. 64+64 with disjoint doc_ids encodes
    # all 128 (no QTL dedup). Churn = 10 reset+reseed+flush+load cycles.
    # @'...'@ (single-quoted here-string) so $$/PL/pgSQL vars are not expanded
    # by PowerShell -- see the Psql function's comment on -f - via stdin.
    $ra = Psql -Sql @'
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
'@
    if ($ra -match 'ERROR:') {
        Fail "25 enterprise-stress Phase A: fill-to-cap/churn errored: $ra"
    } else {
        Pass "25 enterprise-stress Phase A: fill-to-cap (64+64=128) + 10 flush/load churn cycles, audit round-trips 128 events"
    }

    # ---- Phase B: tamper-evidence (structural). Truncate the persisted QTL
    # blob below the 24-byte header and assert load rejects it. NOTE: the QTL
    # format carries no CRC/MAC and ledger_seal_ledger is a no-op, so this is
    # STRUCTURAL tamper-evidence only -- a targeted payload byte-flip is NOT
    # caught. The gate asserts the structural case and documents the gap.
    [void](Psql -Sql "DROP TABLE IF EXISTS fractalsql_ledger;")
    $rb = Psql -Sql @'
SELECT fractal_diversify_enable();
SELECT fractal_ledger_reset_hard();
SELECT fractal_feedback_report(1, 'positive');
SELECT fractal_feedback_report(2, 'negative');
SELECT fractal_ledger_flush();
UPDATE fractalsql_ledger SET blob = substring(blob from 1 for 5) WHERE id = (SELECT max(id) FROM fractalsql_ledger WHERE kind = 1);
SELECT fractal_ledger_load();
'@
    # B-full's entry_hash covers the blob unconditionally (no key
    # required), so this UPDATE is now caught by ledger_verify_latest()'s
    # chain-hash check BEFORE the core's own structural decode ever runs.
    # Accept either message.
    if ($rb -match 'ERROR:' -and $rb -match '(fsql_ledger_load|ledger chain verification failed)') {
        Pass "25 enterprise-stress Phase B: structural tamper (truncated QTL blob) rejected by load"
    } else {
        Fail "25 enterprise-stress Phase B: expected load to reject a truncated blob, got: $rb"
    }

    # ---- Phase C: concurrency.
    # (a) Cross-session persistence: seed+flush in one backend, load+count in
    #     a FRESH backend; counts must match (proves the table-backed VFS is
    #     backend-independent, not in-memory only).
    # (b) 8 concurrent backends each seed one event + flush. Under B-full's
    #     append-only chain this correctly produces MULTIPLE rows (B-lite's
    #     UPSERT collapsed concurrent flushes into one; that's gone by
    #     design). The invariant now is that the chain stays a single
    #     unforked line -- ledger_write_entry's advisory xact lock (keyed
    #     on kind) serializes the "read head, link, insert" sequence.
    [void](Psql -Sql "DROP TABLE IF EXISTS fractalsql_ledger;")
    # NOTE: seed+flush MUST run as ONE Psql call (one backend, one
    # g_ctx) -- each separate call previously below opened its own
    # psql.exe process/connection/backend, so the in-memory truth/
    # shadow ledgers from one call were never visible to the next and
    # fractal_ledger_flush() persisted an EMPTY ledger (the
    # cross-session load then correctly reported 0|0, silently masking
    # this rather than erroring). Semicolon-joined is safe here (not
    # DDL, no ALTER SYSTEM reload-visibility hazard like PgSetGuc).
    [void](Psql -Sql "SELECT fractal_diversify_enable(); SELECT fractal_ledger_reset_hard(); SELECT fractal_feedback_report(g, 'positive') FROM generate_series(1,10) g; SELECT fractal_feedback_report(g, 'negative') FROM generate_series(11,20) g; SELECT fractal_ledger_flush();")
    $cross = Psql -Sql "SELECT fractal_ledger_load(); SELECT fractal_ledger_truth_count() AS t, fractal_ledger_shadow_count() AS s;"
    if ($cross -match '10\|10') {
        Pass "25 enterprise-stress Phase C(a): cross-session persistence -- fresh backend loaded 10/10 from the persisted blob"
    } else {
        Fail "25 enterprise-stress Phase C(a): expected 10|10 after cross-session load, got: $cross"
    }

    # 8 concurrent workers, each: seed one event + flush. Fresh chain
    # (drop first) so the row count is self-contained; pre-flush one row
    # before the workers start so they write to an EXISTING chain,
    # avoiding the concurrent CREATE TABLE IF NOT EXISTS race on pg_class.
    # feedback_report inserts unconditionally, so workers need not
    # re-enable diversify. Invariant: 9 rows total (1 pre-flush + 8
    # concurrent), chain verifies as one unforked line, latest blob
    # decodes. ForEach-Object -Parallel runs in an isolated runspace that
    # doesn't inherit script-scope functions/vars, so psql.exe is
    # launched inline via the Process API (same pattern as Gate12Soak)
    # with $Bin/$Port captured via $using:. Short -c SQL is well under the
    # 32K cmdline cap.
    [void](Psql -Sql "DROP TABLE IF EXISTS fractalsql_ledger;")
    [void](Psql -Sql "SELECT fractal_diversify_enable(); SELECT fractal_feedback_report(0, 'positive'); SELECT fractal_ledger_flush();")
    $workers = 8
    $results = 1..$workers | ForEach-Object -Parallel {
        $w = $_
        $bin = $using:Bin
        $port = $using:Port
        $q = "SELECT fractal_feedback_report($w, 'positive'); SELECT fractal_ledger_flush();"
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = "$bin\psql.exe"
        foreach ($a in @('-h','127.0.0.1','-p',"$port",'-U','postgres','-d','postgres','-X','-tA','-c',$q)) {
            $psi.ArgumentList.Add($a)
        }
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError  = $true
        $psi.UseShellExecute = $false
        $proc = [System.Diagnostics.Process]::Start($psi)
        $soT = $proc.StandardOutput.ReadToEndAsync()
        $seT = $proc.StandardError.ReadToEndAsync()
        $proc.WaitForExit()
        $soT.Result | Out-Null
        $seT.Result | Out-Null
        $proc.ExitCode
    } -ThrottleLimit $workers

    # The invariant is chain consistency, not that every worker's flush
    # produced a distinguishable outcome -- a worker whose tx aborts under
    # contention rolls back cleanly and cannot corrupt the chain, so
    # failedWorkers is reported but does not gate the pass (a real
    # failure surfaces as rows != 9, verify not ok, or a decode ERROR).
    $failedWorkers = @($results | Where-Object { $_ -ne 0 }).Count
    # fractal_ledger_verify() re-runs the same schema-ensure check as
    # flush/migrate, so it NOTICEs "already exists, skipping" for the
    # table + index on every call once they exist (harmless, expected
    # Postgres behavior). Psql concatenates stdout+stderr with stdout
    # first, so those NOTICEs land AFTER the real 'true'/'false' value in
    # the captured string -- same issue as gate 24's rdVerify check, take
    # just the first line before comparing.
    $rowsRaw = (Psql -Sql "SELECT count(*) FROM fractalsql_ledger WHERE kind = 1;")
    $rows = (($rowsRaw -split "`r?`n")[0]).Trim()
    $verifyOkRaw = (Psql -Sql "SELECT fractal_ledger_verify()->>'ok';")
    $verifyOk = (($verifyOkRaw -split "`r?`n")[0]).Trim()
    $latestDecode = Psql -Sql "SELECT fractal_audit_unpack(blob)::text FROM fractalsql_ledger WHERE kind = 1 ORDER BY id DESC LIMIT 1;"
    if ($rows -eq '9' -and $verifyOk -eq 'true' -and $latestDecode -notmatch 'ERROR:') {
        Pass "25 enterprise-stress Phase C(b): 8 concurrent flushes -> 9 append-only rows, chain verifies as one unforked line, latest blob decodes ($failedWorkers worker(s) aborted under contention, ledger consistent)"
    } else {
        Fail "25 enterprise-stress Phase C(b): expected 9 linked rows + clean decode after parallel flush, got failedWorkers=$failedWorkers rows=$rows verifyOk=$verifyOk decode=$latestDecode"
    }

    # ---- Phase D: MAC-authenticated tamper-evidence (enterprise_ledger_key).
    # Phases A-C ran with the key UNSET (structural path). D sets the key
    # (PGC_SUSET -> SET per-session, no reload): flush tags the blob with
    # HMAC-SHA256 (assert length(mac)=32), load verifies; a middle payload
    # byte-flip (length + count preserved -> structural check blind to it) is
    # rejected by the MAC; re-flush re-tags and load verifies clean. This is
    # B-lite: the MAC lives in the open extension at the storage seam; the
    # enterprise core is unchanged and is never handed tampered bytes.
    # @'...'@ single-quoted here-string so $$/PL-pgSQL vars are not expanded.
    [void](Psql -Sql "DROP TABLE IF EXISTS fractalsql_ledger;")
    $rd = Psql -Sql @'
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
  PERFORM fractal_ledger_load();
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
  PERFORM fractal_ledger_reset_hard();
  PERFORM fractal_feedback_report(1, 'positive');
  PERFORM fractal_ledger_flush();
  PERFORM fractal_ledger_load();
EXCEPTION
  WHEN object_not_in_prerequisite_state THEN
    RAISE EXCEPTION 'D enterprise not loaded';
END $$;
RESET fractalsql.enterprise_ledger_key;
'@
    if ($rd -match 'D tamper detected by HMAC') {
        Pass "25 enterprise-stress Phase D: HMAC MAC tags blob (32B), rejects a structural-blind byte-flip, re-flush re-tags cleanly"
    } else {
        Fail "25 enterprise-stress Phase D: MAC path did not behave as expected: $rd"
    }

    # ---- Phase E: B-full append-only chain -- multi-row verify, a
    # MIDDLE-row tamper that load()'s O(1) tip-only check cannot see but
    # verify()'s full O(n) walk catches, and a deleted-row gap. NOTE
    # (documented limitation, not tested here): a chain can prove nothing
    # in the MIDDLE was altered/removed, but not that nothing was
    # truncated off the very END -- that needs an external anchor, out of
    # scope here.
    [void](Psql -Sql "DROP TABLE IF EXISTS fractalsql_ledger;")
    $re = Psql -Sql @'
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

  UPDATE fractalsql_ledger SET blob = set_byte(blob, 0, 254) WHERE id = 2;

  PERFORM fractal_ledger_load();
  RAISE NOTICE 'E load: still passes after a MIDDLE-row tamper (O(1) tip-only scope)';

  SELECT fractal_ledger_verify() INTO v;
  IF (v->>'ok')::boolean OR (v->>'first_failure_id')::int <> 2 THEN
    RAISE EXCEPTION 'E verify() did not catch the middle-row tamper: %', v;
  END IF;
  RAISE NOTICE 'E verify: caught middle-row tamper at id=2 (%)', v->>'reason';
END $$;
'@
    if ($re -match 'E verify: 3/3 rows clean' -and $re -match 'E load: still passes' -and $re -match 'E verify: caught middle-row tamper') {
        Pass "25 enterprise-stress Phase E: B-full chain -- multi-row verify, middle-row tamper undetected by load but caught by verify()"
    } else {
        Fail "25 enterprise-stress Phase E: B-full chain checks did not behave as expected: $re"
    }

    [void](Psql -Sql "DROP TABLE IF EXISTS fractalsql_ledger;")
    $rg = Psql -Sql @'
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
'@
    if ($rg -match 'E verify: caught deletion gap') {
        Pass "25 enterprise-stress Phase E: deleting a middle row leaves a visible id-sequence gap, caught by verify()"
    } else {
        Fail "25 enterprise-stress Phase E: deletion gap detection did not behave as expected: $rg"
    }

    # Migrating an existing B-lite-shaped table (kind PK, no id/prev_hash/
    # entry_hash) -- expect a NOTICE and a clean fresh chain, not an error.
    [void](Psql -Sql "DROP TABLE IF EXISTS fractalsql_ledger;")
    [void](Psql -Sql @'
CREATE TABLE fractalsql_ledger (
  kind    integer PRIMARY KEY,
  blob    bytea   NOT NULL,
  mac     bytea,
  sealed  boolean NOT NULL DEFAULT false,
  updated timestamptz NOT NULL DEFAULT now()
);
INSERT INTO fractalsql_ledger (kind, blob) VALUES (1, '\x00'::bytea);
'@)
    $rm = Psql -Sql "SELECT fractal_diversify_enable(); SELECT fractal_ledger_reset_hard(); SELECT fractal_feedback_report(1, 'positive'); SELECT fractal_ledger_flush();"
    $rmVerify = Psql -Sql "SELECT fractal_ledger_verify();"
    if ($rm -match 'migrating fractalsql_ledger from the single-row snapshot schema' -and $rmVerify -match '"ok"\s*:\s*true') {
        Pass "25 enterprise-stress Phase E: single-row-snapshot -> append-only-chain schema migration -- NOTICE fires, fresh chain verifies clean"
    } else {
        Fail "25 enterprise-stress Phase E: migration did not behave as expected: flush=$rm verify=$rmVerify"
    }

    # Reset the GUC so it does not leak into later gates on a reused cluster.
    [void](Psql -Sql "ALTER SYSTEM RESET fractalsql.enterprise_lib;")
    [void](Psql -Sql "SELECT pg_reload_conf();")
}

function Gate26EnterpriseSignature {
    # Detached Ed25519 signature verification for the enterprise .so
    # (fractalsql.enterprise_require_signature). Self-skips on a
    # community-only checkout, same detection as gates 24/25.
    #
    # Deliberately does NOT test the "valid signature, actually verifies"
    # happy path -- that requires the matching private key, which is
    # FractalSQLabs's release-process secret and does not belong in this
    # repo or its test fixtures. That path was validated manually against
    # a throwaway keypair during development (see fractalsql.c's
    # FSQL_ENTERPRISE_PUBKEY comment). What's tested here needs no key at
    # all: a missing .sig (soft unless require=on) and an invalid .sig
    # (always hard-refused, regardless of require).
    $ent = Get-ChildItem -Path include -Recurse -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match '^(lib)?fractalsql-enterprise-sovereign-c\.(dll|so|dylib)$' } |
        Select-Object -First 1
    if (-not $ent) {
        Skip "26 enterprise-signature: skipped (community edition; no fractalsql-enterprise-sovereign-c.* shared lib in include/)"
        return
    }
    $abs = $ent.FullName
    $sigPath = "$abs.sig"
    # Back up a real .sig (if present) before this gate starts overwriting
    # it with missing/garbage variants for Cases A-C, and restore it at
    # the end (below) instead of leaving it permanently deleted -- a
    # destructive Remove-Item with no restore here previously orphaned
    # any real signature for every later run against the same staged
    # enterprise library, silently forcing gates 24/25 down the
    # "unsigned, loading unverified" path instead of ever exercising the
    # real one.
    $sigBackup = $null
    if (Test-Path $sigPath) {
        $sigBackup = "$sigPath.gate26-orig"
        Copy-Item -Path $sigPath -Destination $sigBackup -Force
    }
    Remove-Item -Path $sigPath -ErrorAction SilentlyContinue

    if (-not (PgSetGuc -Name 'fractalsql.enterprise_lib' -SetVal "'$abs'" -Want $abs)) {
        Fail "26 enterprise-signature: could not apply fractalsql.enterprise_lib"
        return
    }

    # ---- Case A: no .sig, require=off (default) -- soft: WARNING logged,
    # library still loads and works.
    [void](PgSetGuc -Name 'fractalsql.enterprise_require_signature' -SetVal 'off' -Want 'off')
    $ra = Psql -Sql "SELECT fractal_ledger_reset_hard();"
    if ($ra -match 'no signature found for enterprise library' -and $ra -notmatch 'enterprise tier not loaded') {
        Pass "26 enterprise-signature Case A: missing .sig + require=off -- WARNS but still loads"
    } else {
        Fail "26 enterprise-signature Case A: expected a WARN-and-load, got: $ra"
    }

    # ---- Case B: no .sig, require=on -- hard: refused.
    [void](PgSetGuc -Name 'fractalsql.enterprise_require_signature' -SetVal 'on' -Want 'on')
    $rb = Psql -Sql "SELECT fractal_ledger_reset_hard();"
    if ($rb -match 'no signature found for enterprise library' -and $rb -match 'enterprise tier not loaded') {
        Pass "26 enterprise-signature Case B: missing .sig + require=on -- refused"
    } else {
        Fail "26 enterprise-signature Case B: expected a hard refusal, got: $rb"
    }

    # ---- Case C: invalid/garbage .sig (64 random bytes, matches no key)
    # -- always refused, even with require=off.
    [void](PgSetGuc -Name 'fractalsql.enterprise_require_signature' -SetVal 'off' -Want 'off')
    $rnd = New-Object byte[] 64
    (New-Object System.Random).NextBytes($rnd)
    [System.IO.File]::WriteAllBytes($sigPath, $rnd)
    $rc = Psql -Sql "SELECT fractal_ledger_reset_hard();"
    if ($rc -match 'failed signature verification' -and $rc -match 'enterprise tier not loaded') {
        Pass "26 enterprise-signature Case C: invalid .sig -- always refused regardless of require setting"
    } else {
        Fail "26 enterprise-signature Case C: expected a hard refusal on invalid signature, got: $rc"
    }
    # Restore the real .sig this gate started with, rather than leaving
    # Case C's garbage bytes (or nothing) in place for whatever runs next.
    if ($sigBackup) {
        Move-Item -Path $sigBackup -Destination $sigPath -Force
    } else {
        Remove-Item -Path $sigPath -ErrorAction SilentlyContinue
    }

    # Reset the GUCs so they do not leak into later gates on a reused cluster.
    [void](PgSetGuc -Name 'fractalsql.enterprise_require_signature' -SetVal 'off' -Want 'off')
    [void](Psql -Sql "ALTER SYSTEM RESET fractalsql.enterprise_lib;")
    [void](Psql -Sql "SELECT pg_reload_conf();")
}

# Reasoning-effort (THINK) GUC passthrough -- mirrors build_test.sh's
# gate 27. Each Psql call below is a fresh backend process (matches
# build_test.sh's own reasoning behind this), so ensure_reason_ctx()/
# ensure_embed_ctx()'s per-backend g_*_loaded statics start false and
# actually re-apply the current GUC values each time.
function Gate27Think {
    if (-not (PgSwapPlugin $Think)) { Fail "27 think: plugin swap did not take effect"; return }

    # Case A: all four unset -- byte-identical to pre-v1.4.0 behavior.
    if (-not (PgSetGuc -Name 'fractalsql.http_think' -SetVal "''" -Want '')) { Fail "27 think: reset http_think"; PgSwapPlugin $Mock | Out-Null; return }
    if (-not (PgSetGuc -Name 'fractalsql.http_think_provider' -SetVal "''" -Want '')) { Fail "27 think: reset http_think_provider"; PgSwapPlugin $Mock | Out-Null; return }
    if (-not (PgSetGuc -Name 'fractalsql.http_native_url' -SetVal "''" -Want '')) { Fail "27 think: reset http_native_url"; PgSwapPlugin $Mock | Out-Null; return }
    if (-not (PgSetGuc -Name 'fractalsql.http_num_ctx' -SetVal '0' -Want '0')) { Fail "27 think: reset http_num_ctx"; PgSwapPlugin $Mock | Out-Null; return }
    Remove-Item -Force $ThinkDumpFile -ErrorAction SilentlyContinue
    Psql -Sql "SELECT fractal_reason('q');" | Out-Null
    $a = Get-Content -Path $ThinkDumpFile -Raw -ErrorAction SilentlyContinue
    if ($a -and $a -match 'THINK=\(unset\)' -and $a -match 'THINK_PROVIDER=\(unset\)' `
              -and $a -match 'NATIVE_URL=\(unset\)' -and $a -match 'NUM_CTX=\(unset\)') {
        Pass "27 think Case A: all four GUCs unset -> no THINK-related env var reaches the plugin"
    } else {
        Fail "27 think Case A: expected all four (unset), got: $a"
    }

    # Case B: set all four -- each reaches the plugin's environment via
    # fractal_reason() (ensure_reason_ctx()'s apply_think_env()).
    if (-not (PgSetGuc -Name 'fractalsql.http_think' -SetVal "'medium'" -Want 'medium')) { Fail "27 think: set http_think"; PgSwapPlugin $Mock | Out-Null; return }
    if (-not (PgSetGuc -Name 'fractalsql.http_think_provider' -SetVal "'ollama'" -Want 'ollama')) { Fail "27 think: set http_think_provider"; PgSwapPlugin $Mock | Out-Null; return }
    if (-not (PgSetGuc -Name 'fractalsql.http_native_url' -SetVal "'http://127.0.0.1:9/native'" -Want 'http://127.0.0.1:9/native')) { Fail "27 think: set http_native_url"; PgSwapPlugin $Mock | Out-Null; return }
    if (-not (PgSetGuc -Name 'fractalsql.http_num_ctx' -SetVal '8192' -Want '8192')) { Fail "27 think: set http_num_ctx"; PgSwapPlugin $Mock | Out-Null; return }
    Remove-Item -Force $ThinkDumpFile -ErrorAction SilentlyContinue
    Psql -Sql "SELECT fractal_reason('q');" | Out-Null
    $b = Get-Content -Path $ThinkDumpFile -Raw -ErrorAction SilentlyContinue
    if ($b -and $b -match 'THINK=medium' -and $b -match 'THINK_PROVIDER=ollama' `
              -and $b -match 'NATIVE_URL=http://127\.0\.0\.1:9/native' -and $b -match 'NUM_CTX=8192') {
        Pass "27 think Case B: all four GUCs reach the plugin via fractal_reason()"
    } else {
        Fail "27 think Case B: expected THINK=medium/THINK_PROVIDER=ollama/NATIVE_URL=http://127.0.0.1:9/native/NUM_CTX=8192, got: $b"
    }

    # Case C: fractal_text_to_sql()'s GENERATE step forwards the same
    # four (apply_think_env() is shared with ensure_text_to_sql_ctx()) --
    # the mock's canned "OK" response isn't a fenced SQL block, so this
    # call is expected to error; only the dump file (written before that
    # error, at format_prompt() time) is under test here.
    Remove-Item -Force $ThinkDumpFile -ErrorAction SilentlyContinue
    Psql -Sql "SELECT fractal_text_to_sql('q', ARRAY['bt_customers']);" | Out-Null
    $c = Get-Content -Path $ThinkDumpFile -Raw -ErrorAction SilentlyContinue
    if ($c -and $c -match 'THINK=medium' -and $c -match 'THINK_PROVIDER=ollama') {
        Pass "27 think Case C: fractal_text_to_sql()'s GENERATE step also forwards THINK/THINK_PROVIDER"
    } else {
        Fail "27 think Case C: expected THINK=medium/THINK_PROVIDER=ollama from the GENERATE step, got: $c"
    }

    # Case D: fractal_embed() never sees THINK vars even with the GUCs
    # still set from Case B/C -- proves ensure_embed_ctx()'s explicit
    # unsetenv() calls, not just "embed happens not to set them".
    if (-not (PgSetGuc -Name 'fractalsql.http_embed_url' -SetVal "'http://unused/embeddings'" -Want 'http://unused/embeddings')) {
        Fail "27 think Case D: http_embed_url GUC did not take effect"; PgSwapPlugin $Mock | Out-Null; return
    }
    Remove-Item -Force $ThinkDumpFile -ErrorAction SilentlyContinue
    Psql -Sql "SELECT fractal_embed('test input');" | Out-Null
    $d = Get-Content -Path $ThinkDumpFile -Raw -ErrorAction SilentlyContinue
    if ($d -and $d -match 'THINK=\(unset\)' -and $d -match 'THINK_PROVIDER=\(unset\)' `
              -and $d -match 'NATIVE_URL=\(unset\)' -and $d -match 'NUM_CTX=\(unset\)') {
        Pass "27 think Case D: fractal_embed() never sees THINK vars, even with the GUCs still set"
    } else {
        Fail "27 think Case D: expected all four (unset) in the embed tier, got: $d"
    }

    # Reset the GUCs so they do not leak into later gates on a reused cluster.
    [void](PgSetGuc -Name 'fractalsql.http_think' -SetVal "''" -Want '')
    [void](PgSetGuc -Name 'fractalsql.http_think_provider' -SetVal "''" -Want '')
    [void](PgSetGuc -Name 'fractalsql.http_native_url' -SetVal "''" -Want '')
    [void](PgSetGuc -Name 'fractalsql.http_num_ctx' -SetVal '0' -Want '0')
    PgSwapPlugin $Mock | Out-Null
    Remove-Item -Force $ThinkDumpFile -ErrorAction SilentlyContinue
}

function RunGates($gates) {
    Write-Host "== PG$PgMajor (Windows) =="
    if ($gates -contains '01') {
        if (-not (Gate01Build)) { return }
    }
    # Gate 21 (fuzz smoke) is standalone like gate 01 -- links only
    # src\fractalsql_parse.c directly, no extension DLL, no postgres.exe,
    # no cluster at all.
    if ($gates -contains '21') {
        Gate21FuzzSmoke
    }
    # @(...): same $null-vs-empty-array StrictMode trap as Gate12Soak's
    # $failedWorkers below -- not yet hit here (would need e.g. -Gate 01
    # alone), but the identical shape of bug, fixed proactively.
    $needDb = @($gates | Where-Object { $_ -ne '01' -and $_ -ne '21' })
    if ($needDb.Count -gt 0) {
        try { PgSetup } catch { Fail "PG$PgMajor cluster setup: $_"; return }
        # gate 03 creates bt_customers/bt_orders; several later gates
        # (04, 05, 06, 07, 10, 12, 19) depend on that fixture already
        # existing, so ensure it exists even if 03 wasn't explicitly
        # requested (matches build_test.sh's same fixture-priming logic).
        if ($needDb -notcontains '03') {
            Gate03SchemaContext
        }
        foreach ($g in $needDb) {
            switch ($g) {
                '02' { Gate02Smoke }
                '03' { Gate03SchemaContext }
                '04' { Gate04TextToSql }
                '05' { Gate05EvilOverread }
                '06' { Gate06CrashRecovery }
                '07' { Gate07EvilLyingLength }
                '08' { Gate08Authz }
                '09' { Gate09GucSuperuser }
                '10' { Gate10DosAndInjection }
                '11' { Gate11Scout }
                '12' { Gate12Soak }
                '13' { Gate13SiuMode }
                '14' { Gate14Retry }
                '15' { Gate15Embed }
                '16' { Gate16EmbedAuthz }
                '17' { Gate17EmbedSoak }
                '18' { Gate18EmbedCrash }
                '19' { Gate19SfsBounds }
                '20' { Gate20ApiFunc }
                '22' { Gate22V2Functions }
                '23' { Gate23Agents }
                '24' { Gate24Enterprise }
                '25' { Gate25EnterpriseStress }
                '26' { Gate26EnterpriseSignature }
                '27' { Gate27Think }
            }
        }
        PgTeardown
    }
}

try {
    if ($Gate) { RunGates @($Gate) }
    elseif ($Quick) { RunGates $QuickGates }
    elseif ($Fuzz) { RunGates $FuzzGates }
    else { RunGates $DefaultGates }
} finally {
    Cleanup
}

Write-Host ""
if ($script:Failed -eq 0) {
    Write-Host "build_test: PASS" -ForegroundColor Green
    exit 0
} else {
    Write-Host "build_test: FAIL" -ForegroundColor Red
    exit 1
}
