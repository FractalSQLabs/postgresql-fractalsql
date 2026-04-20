@echo off
REM scripts/windows/build.bat
REM
REM Builds fractalsql.dll against a single target PostgreSQL major on
REM Windows using the MSVC toolchain. Mirrors the Linux static posture:
REM static CRT (/MT), whole-program optimization (/GL), static LuaJIT
REM archive — zero runtime dependency on the Visual C++ Redistributable
REM and zero dependency on libluajit at load time.
REM
REM Prerequisites
REM   * Visual Studio Build Tools (cl.exe on PATH — invoke from a
REM     Developer Command Prompt, or `call vcvarsall.bat <arch>` first).
REM   * A static LuaJIT archive (lua51.lib) built with msvcbuild.bat
REM     static against the same host arch as cl.exe.
REM   * An EDB PostgreSQL binaries tree (the .zip published at
REM     get.enterprisedb.com), unpacked so that the following exist:
REM         %PG_DIR%\include\server\postgres.h
REM         %PG_DIR%\include\server\port\win32\*
REM         %PG_DIR%\include\server\port\win32_msvc\*
REM         %PG_DIR%\lib\postgres.lib
REM
REM Environment overrides
REM   LUAJIT_DIR   directory with lua.h / lualib.h / lauxlib.h + lua51.lib
REM   PG_DIR       directory with PostgreSQL binaries tree
REM                (the "pgsql" root from the EDB binaries.zip)
REM   PG_MAJOR     PostgreSQL major version being targeted (14..18)
REM   OUT_DIR      output directory for fractalsql.dll
REM
REM The emitted DLL's PG_MODULE_MAGIC is stamped for %PG_MAJOR%, so one
REM call to this script produces one DLL bound to one server ABI.

setlocal ENABLEEXTENSIONS ENABLEDELAYEDEXPANSION

if "%LUAJIT_DIR%"=="" set LUAJIT_DIR=%CD%\deps\LuaJIT\src
if "%PG_DIR%"==""     (
    echo ==^> ERROR: PG_DIR must point at an unpacked PostgreSQL binaries tree
    exit /b 1
)
if "%PG_MAJOR%"==""   (
    echo ==^> ERROR: PG_MAJOR must be set ^(14^|15^|16^|17^|18^)
    exit /b 1
)
if "%OUT_DIR%"==""    set OUT_DIR=dist\windows\pg%PG_MAJOR%

if not exist "%OUT_DIR%" mkdir "%OUT_DIR%"

echo ==^> LUAJIT_DIR = %LUAJIT_DIR%
echo ==^> PG_DIR     = %PG_DIR%
echo ==^> PG_MAJOR   = %PG_MAJOR%
echo ==^> OUT_DIR    = %OUT_DIR%

REM LuaJIT's msvcbuild.bat static emits lua51.lib; accept the
REM Makefile-style libluajit-5.1.lib name too if present.
set LUAJIT_LIB=%LUAJIT_DIR%\libluajit-5.1.lib
if not exist "%LUAJIT_LIB%" (
    if exist "%LUAJIT_DIR%\lua51.lib" set LUAJIT_LIB=%LUAJIT_DIR%\lua51.lib
)
if not exist "%LUAJIT_LIB%" (
    echo ==^> ERROR: no LuaJIT static library in %LUAJIT_DIR%
    echo         ^(expected libluajit-5.1.lib or lua51.lib^)
    exit /b 1
)
echo ==^> LUAJIT_LIB = %LUAJIT_LIB%

REM PostgreSQL server stub import library. Linking against postgres.lib
REM lets the extension resolve server-exported symbols (palloc, ereport,
REM SPI_*, etc.) — the Windows analogue of Linux's unresolved-at-build,
REM resolved-at-dlopen behaviour. Every backend PID on Windows loads
REM the DLL via LoadLibrary and the linker needs the stub to know which
REM symbols come from the host process.
set PG_LIB=%PG_DIR%\lib\postgres.lib
if not exist "%PG_LIB%" (
    echo ==^> ERROR: %PG_LIB% not found — check PG_DIR layout
    exit /b 1
)
echo ==^> PG_LIB     = %PG_LIB%

REM cl.exe flags:
REM   /MT     static CRT (no MSVC runtime DLL dependency)
REM   /GL     whole-program optimization (paired with /LTCG at link)
REM   /O2     optimize for speed
REM   /LD     build a DLL
REM   /DWIN32 /D_WINDOWS /D_CRT_SECURE_NO_WARNINGS — PG's own headers
REM       reference strdup/strncpy/etc. without the _s variants.
REM
REM PostgreSQL's Windows server headers expect this include order:
REM     include/server/port/win32_msvc     compiler-specific shims
REM     include/server/port/win32          platform shims
REM     include/server                     core server headers
REM     include                             client-side headers (libpq etc.)
REM Getting the order wrong produces "redefinition of struct timezone"
REM and similar diagnostics.
cl.exe /nologo /MT /GL /O2 ^
    /DWIN32 /D_WINDOWS /D_CRT_SECURE_NO_WARNINGS ^
    /I"%LUAJIT_DIR%" ^
    /I"%PG_DIR%\include\server\port\win32_msvc" ^
    /I"%PG_DIR%\include\server\port\win32" ^
    /I"%PG_DIR%\include\server" ^
    /I"%PG_DIR%\include" ^
    /Iinclude ^
    /LD src\fractalsql.c ^
    /Fo"%OUT_DIR%\\" ^
    /Fe"%OUT_DIR%\fractalsql.dll" ^
    /link /LTCG ^
        "%LUAJIT_LIB%" ^
        "%PG_LIB%" ^
        ws2_32.lib advapi32.lib secur32.lib

if errorlevel 1 (
    echo.
    echo ==^> BUILD FAILED for PG %PG_MAJOR%
    exit /b 1
)

echo.
echo ==^> Built %OUT_DIR%\fractalsql.dll ^(PG %PG_MAJOR%^)
dir "%OUT_DIR%\fractalsql.dll"

endlocal
