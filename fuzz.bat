@echo off
setlocal EnableExtensions EnableDelayedExpansion

rem Windows port of fuzz.sh (stress profiles + display modes).
rem
rem   fuzz.bat [firefox-binary] [runtime-seconds] [flags...]
rem
rem Built-in flags:
rem   headless / --headless   Grizzly --display headless
rem   headful  / --headful    Grizzly --display default
rem   xvfb     / --xvfb       Grizzly --display xvfb (no-op on native Windows)
rem   --chaos[=HEX]           MOZ_CHAOSMODE (default 0xfb)
rem   --zeal[=MODE]           JS_GC_ZEAL (default 2,100)
rem   --stress                chaos + zeal
rem   --asan                  hardened ASAN_OPTIONS
rem
rem Other args are forwarded to Grizzly.

set "ROOT=%~dp0"
if exist "%ROOT%.env" (
  for /f "usebackq eol=# tokens=1,* delims==" %%A in ("%ROOT%.env") do (
    if not "%%A"=="" if not defined %%A set "%%A=%%B"
  )
)

set "RUNTIME_DEFAULT=360000"
set "BROWSER="
set "RUNTIME="
set "DISPLAY_MODE="
set "EXTRA="
set "SEEN_FLAG=0"
set "POS_COUNT=0"

:parse
if "%~1"=="" goto after_parse
set "ARG=%~1"
if /I "%ARG%"=="headless" set "DISPLAY_MODE=headless" & shift & goto parse
if /I "%ARG%"=="--headless" set "DISPLAY_MODE=headless" & shift & goto parse
if /I "%ARG%"=="headful" set "DISPLAY_MODE=default" & shift & goto parse
if /I "%ARG%"=="--headful" set "DISPLAY_MODE=default" & shift & goto parse
if /I "%ARG%"=="xvfb" set "DISPLAY_MODE=xvfb" & shift & goto parse
if /I "%ARG%"=="--xvfb" set "DISPLAY_MODE=xvfb" & shift & goto parse
if /I "%ARG%"=="--chaos" (
  if not defined MOZ_CHAOSMODE set "MOZ_CHAOSMODE=0xfb"
  shift & goto parse
)
if /I "%ARG:~0,8%"=="--chaos=" (
  set "MOZ_CHAOSMODE=%ARG:~8%"
  shift & goto parse
)
if /I "%ARG%"=="--zeal" (
  if not defined JS_GC_ZEAL set "JS_GC_ZEAL=2,100"
  shift & goto parse
)
if /I "%ARG:~0,7%"=="--zeal=" (
  set "JS_GC_ZEAL=%ARG:~7%"
  shift & goto parse
)
if /I "%ARG%"=="--stress" (
  if not defined MOZ_CHAOSMODE set "MOZ_CHAOSMODE=0xfb"
  if not defined JS_GC_ZEAL set "JS_GC_ZEAL=2,100"
  shift & goto parse
)
if /I "%ARG%"=="--asan" (
  if not defined ASAN_OPTIONS set "ASAN_OPTIONS=detect_leaks=0:abort_on_error=1:symbolize=1:handle_segv=1"
  shift & goto parse
)
echo %ARG%| findstr /B /C:"-" >nul
if not errorlevel 1 (
  set "SEEN_FLAG=1"
  set "EXTRA=!EXTRA! %ARG%"
  shift & goto parse
)
if "!SEEN_FLAG!"=="1" (
  set "EXTRA=!EXTRA! %ARG%"
) else (
  set /a POS_COUNT+=1
  if !POS_COUNT! EQU 1 set "BROWSER=%ARG%"
  if !POS_COUNT! EQU 2 set "RUNTIME=%ARG%"
)
shift & goto parse

:after_parse
if not defined BROWSER if defined FIREFOX_BIN set "BROWSER=%FIREFOX_BIN%"
if not defined BROWSER (
  echo Firefox binary not set. Pass it as the first argument, set FIREFOX_BIN, or copy .env.example -^> .env
  exit /b 1
)
if not defined RUNTIME set "RUNTIME=%RUNTIME_DEFAULT%"
if defined DISPLAY_MODE set "EXTRA=!EXTRA! --display %DISPLAY_MODE%"

set "OUT=%ROOT%results"
if not exist "%OUT%" mkdir "%OUT%"

if defined PYTHON_BIN (
  set "PYTHON=%PYTHON_BIN%"
) else (
  set "PYTHON=py -3.14"
)

echo ==================================================
echo Grizzly + Domato DOM/WebIDL Fuzzing
echo ==================================================
echo Python:     %PYTHON%
echo Browser:    %BROWSER%
echo Runtime:    %RUNTIME%s (stop via Ctrl+C)
if defined DISPLAY_MODE (echo Display:    %DISPLAY_MODE%) else (echo Display:    default)
echo Output:     %OUT%
if defined MOZ_CHAOSMODE (echo Chaos Mode: %MOZ_CHAOSMODE%) else (echo Chaos Mode: disabled)
if defined JS_GC_ZEAL (echo GC Zeal:    %JS_GC_ZEAL%) else (echo GC Zeal:    disabled)
if defined ASAN_OPTIONS echo ASan Opts:  %ASAN_OPTIONS%
echo Grizzly:    %EXTRA%
echo ==================================================
echo.

%PYTHON% -m grizzly --runtime %RUNTIME% -o "%OUT%" %EXTRA% "%BROWSER%" domato
set "EC=%ERRORLEVEL%"
echo.
echo Done.
exit /b %EC%
