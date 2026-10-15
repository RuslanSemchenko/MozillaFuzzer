@echo off
setlocal

set "DEFAULT_BROWSER=C:\mozilla-source\firefox\obj-x86_64-pc-windows-msvc\dist\bin\firefox.exe"
if "%~1" neq "" (
    set "BROWSER=%~1"
) else if defined FIREFOX_BIN (
    set "BROWSER=%FIREFOX_BIN%"
) else (
    set "BROWSER=%DEFAULT_BROWSER%"
)

set "OUT=%~dp0results"
if "%~2" neq "" (
    set "RUNTIME=%~2"
) else (
    set "RUNTIME=360000"
)

if not exist "%OUT%" mkdir "%OUT%"

if defined PYTHON_BIN (
    set "PYTHON=%PYTHON_BIN%"
) else (
    set "PYTHON=py -3.14"
)

echo Grizzly + Domato fuzzing
echo Python:  %PYTHON%
echo Browser: %BROWSER%
echo Runtime: %RUNTIME%s (stop via Ctrl+C)
echo Output:  %OUT%
echo.

%PYTHON% -m grizzly --runtime %RUNTIME% -o "%OUT%" "%BROWSER%" domato

echo.
echo Done.
endlocal