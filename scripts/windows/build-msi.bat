@echo off
REM scripts/windows/build-msi.bat
REM
REM Packages fractalsql.dll (pre-built by build.bat) plus
REM fractalsql.control / fractalsql--1.0.sql / LICENSE /
REM LICENSE-THIRD-PARTY into a Windows MSI using the WiX Toolset.
REM
REM One MSI per (PG major, arch) pair. The resulting MSI installs into
REM the target PG server's own on-disk layout:
REM
REM     C:\Program Files\PostgreSQL\<PG_MAJOR>\lib\fractalsql.dll
REM     C:\Program Files\PostgreSQL\<PG_MAJOR>\share\extension\fractalsql.control
REM     C:\Program Files\PostgreSQL\<PG_MAJOR>\share\extension\fractalsql--1.0.sql
REM     C:\Program Files\PostgreSQL\<PG_MAJOR>\share\doc\fractalsql\LICENSE
REM     C:\Program Files\PostgreSQL\<PG_MAJOR>\share\doc\fractalsql\LICENSE-THIRD-PARTY
REM
REM That matches EDB's default PG install root, so end-users who took
REM the EDB one-click installer can immediately run
REM     psql -c "CREATE EXTENSION fractalsql;"
REM with no further path munging.
REM
REM Prerequisites
REM   * WiX Toolset v3.x installed (candle.exe / light.exe on PATH).
REM   * dist\windows\pg<PG_MAJOR>\fractalsql.dll already produced by
REM     scripts\windows\build.bat.
REM
REM Environment
REM   PG_MAJOR   14..18 — selects UpgradeCode and install-folder name
REM   MSI_ARCH   x64 | arm64 — passed to candle -arch
REM   MSI_VERSION overrides the Product Version (default 1.0.0)

setlocal ENABLEEXTENSIONS ENABLEDELAYEDEXPANSION

set REPO_ROOT=%~dp0..\..
pushd %REPO_ROOT%

if "%PG_MAJOR%"==""    (
    echo ==^> ERROR: PG_MAJOR must be set ^(14^|15^|16^|17^|18^)
    popd & exit /b 1
)
if "%MSI_ARCH%"=="" set MSI_ARCH=x64
if "%MSI_VERSION%"=="" set MSI_VERSION=1.0.0

set DLL=dist\windows\pg%PG_MAJOR%\fractalsql.dll
if not exist "%DLL%" (
    echo ==^> ERROR: %DLL% missing — run build.bat with PG_MAJOR=%PG_MAJOR% first
    popd & exit /b 1
)

REM Per-PG-major staging dir so candle can reference a stable
REM "dist\windows\staging\fractalsql.dll" path from the wxs. This
REM avoids threading PG_MAJOR through every File/@Source attribute.
set STAGE=dist\windows\staging-pg%PG_MAJOR%-%MSI_ARCH%
if exist "%STAGE%" rmdir /s /q "%STAGE%"
mkdir "%STAGE%"

copy /Y "%DLL%"                      "%STAGE%\fractalsql.dll"            > nul
copy /Y fractalsql.control           "%STAGE%\fractalsql.control"        > nul
copy /Y sql\fractalsql--1.0.sql      "%STAGE%\fractalsql--1.0.sql"       > nul
copy /Y LICENSE                      "%STAGE%\LICENSE"                   > nul
copy /Y LICENSE-THIRD-PARTY          "%STAGE%\LICENSE-THIRD-PARTY"       > nul

REM Per-cell README ships in the MSI so users who only grab the .msi
REM still see the "which PG, which arch" pairing without hopping to
REM GitHub.
(
  echo FractalSQL for PostgreSQL %PG_MAJOR%, Community Edition %MSI_VERSION%
  echo Architecture: %MSI_ARCH%
  echo.
  echo This MSI installs the fractalsql extension files into the
  echo canonical EDB PostgreSQL install root:
  echo     C:\Program Files\PostgreSQL\%PG_MAJOR%\lib\fractalsql.dll
  echo     C:\Program Files\PostgreSQL\%PG_MAJOR%\share\extension\fractalsql.control
  echo     C:\Program Files\PostgreSQL\%PG_MAJOR%\share\extension\fractalsql--1.0.sql
  echo.
  echo After install, activate the extension once per database:
  echo     psql -U postgres -c "CREATE EXTENSION fractalsql;"
  echo     psql -U postgres -c "SELECT fractalsql_edition^(^), fractalsql_version^(^);"
  echo.
  echo PG_MODULE_MAGIC is stamped at build time — do not install a
  echo pg16 MSI against a PostgreSQL 17 server. Pick the MSI whose
  echo filename matches your server's major version.
) > "%STAGE%\README.txt"

if not exist obj mkdir obj
set OBJ=obj\fractalsql-pg%PG_MAJOR%-%MSI_ARCH%.wixobj

set MSI=dist\windows\FractalSQL-PostgreSQL-%PG_MAJOR%-%MSI_VERSION%-%MSI_ARCH%.msi
if not exist "dist\windows" mkdir "dist\windows"

set WXS=scripts\windows\fractalsql.wxs

echo ==^> PG_MAJOR   = %PG_MAJOR%
echo ==^> MSI_ARCH   = %MSI_ARCH%
echo ==^> MSI_VERSION= %MSI_VERSION%
echo ==^> STAGE      = %STAGE%
echo ==^> MSI        = %MSI%

REM -arch propagates into $(sys.BUILDARCH) inside the WXS, which sets
REM <Package Platform="…"/> and keeps ICE80 happy about the
REM component/directory bitness pairing.
REM -dPG_MAJOR / -dSTAGE_DIR / -dMSI_VERSION are consumed by the
REM preprocessor inside fractalsql.wxs (see <?define?> section).
candle -nologo -arch %MSI_ARCH% ^
    -dPG_MAJOR=%PG_MAJOR% ^
    -dSTAGE_DIR=%STAGE% ^
    -dMSI_VERSION=%MSI_VERSION% ^
    -out %OBJ% %WXS%
if errorlevel 1 (
    echo ==^> candle failed
    popd & exit /b 1
)

light -nologo ^
      -ext WixUIExtension ^
      -ext WixUtilExtension ^
      -out "%MSI%" ^
      %OBJ%
if errorlevel 1 (
    echo ==^> light failed
    popd & exit /b 1
)

echo ==^> Built %MSI%
dir "%MSI%"

popd
endlocal
