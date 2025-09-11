@echo off
setlocal ENABLEEXTENSIONS ENABLEDELAYEDEXPANSION
REM Determine repo root (parent of this script directory)
set SCRIPT_DIR=%~dp0
set ROOT=%SCRIPT_DIR%..
REM Prefer GNU (works with cgo), fall back to MSVC only if a MinGW import lib is found
set LIBDIR_GNU=%ROOT%\target\x86_64-pc-windows-gnu\release
set LIBDIR_MSVC=%ROOT%\target\x86_64-pc-windows-msvc\release
set LIBDIR=
if exist "%LIBDIR_GNU%\simple_add_ffi.dll" (
  set LIBDIR=%LIBDIR_GNU%
) else if exist "%LIBDIR_MSVC%\simple_add_ffi.dll" (
  set LIBDIR=%LIBDIR_MSVC%
)
if "%LIBDIR%"=="" (
  echo Could not find simple_add_ffi.dll in MSVC or GNU target release directories.
  echo Build it first, e.g.:
  echo   cargo build -p simple_add_ffi --release --target x86_64-pc-windows-msvc
  echo or:
  echo   cargo build -p simple_add_ffi --release --target x86_64-pc-windows-gnu
  exit /b 1
)

REM If using GNU toolchain, ensure import library exists for cgo linking
if "%LIBDIR%"=="%LIBDIR_GNU%" (
  if exist "%LIBDIR%\libsimple_add_ffi.dll.a" (
    REM ok
  ) else if exist "%LIBDIR%\libsimple_add_ffi.a" (
    REM ok
  ) else (
    echo GNU import library not found in %LIBDIR%.
    echo Expected one of: libsimple_add_ffi.dll.a or libsimple_add_ffi.a
    echo Rebuild with: cargo build -p simple_add_ffi --release --target x86_64-pc-windows-gnu
    exit /b 1
  )
)
REM Ensure proof exists
if not exist "%ROOT%\proof.bin" (
  pushd "%ROOT%"
  cargo run -p halo2_proofs --example simple-add || (
    echo Failed to generate proof.bin
    popd
    exit /b 1
  )
  popd
)
REM Set up environment for cgo linking and runtime loading (no quotes to avoid cgo parsing issues)
set CGO_LDFLAGS=-L%LIBDIR% -lsimple_add_ffi
set PATH=%LIBDIR%;%PATH%
REM Run Go verifier
pushd "%SCRIPT_DIR%"
 go build -o simple_add_go.exe .
set ERR=%ERRORLEVEL%
popd
exit /b %ERR%
