@echo off
setlocal

set "SCRIPT_DIR=%~dp0"
set "PYTHON=%~dp0..\..\.venv\Scripts\python.exe"
if not exist "%PYTHON%" set "PYTHON=%~dp0..\.venv\Scripts\python.exe"
if not exist "%PYTHON%" set "PYTHON=%~dp0.venv\Scripts\python.exe"
set "COLLECTOR=%SCRIPT_DIR%collector.py"

powershell.exe -NoProfile -Command "$identity = [Security.Principal.WindowsIdentity]::GetCurrent(); $principal = New-Object Security.Principal.WindowsPrincipal($identity); if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { exit 0 }; exit 1" >nul 2>&1
if not errorlevel 1 goto administrator

echo Administrator permission is required. Approve the Windows UAC prompt to continue.
set "CUSTOS_LAUNCHER=%~f0"
set "CUSTOS_ARGUMENTS=%*"
powershell.exe -NoProfile -Command "try { $launcher = $env:CUSTOS_LAUNCHER; $arguments = $env:CUSTOS_ARGUMENTS; if ([string]::IsNullOrWhiteSpace($arguments)) { $process = Start-Process -FilePath $launcher -Verb RunAs -Wait -PassThru } else { $process = Start-Process -FilePath $launcher -ArgumentList $arguments -Verb RunAs -Wait -PassThru }; exit $process.ExitCode } catch { Write-Error ('Elevation was cancelled or failed: ' + $_.Exception.Message); exit 1223 }"
set "COLLECTOR_EXIT=%ERRORLEVEL%"
if not "%COLLECTOR_EXIT%"=="0" if not "%COLLECTOR_EXIT%"=="1" (
    echo A05 did not complete successfully. See the error above.
)
echo.
echo A05 ARP cache collector exit code: %COLLECTOR_EXIT%
pause
exit /b %COLLECTOR_EXIT%

:administrator
if not exist "%PYTHON%" (
    echo Project Windows Python was not found: "%PYTHON%"
    goto failed
)

if not exist "%COLLECTOR%" (
    echo A05 collector was not found: "%COLLECTOR%"
    goto failed
)

if "%~1"=="" goto prompt_output
"%PYTHON%" "%COLLECTOR%" %*
set "COLLECTOR_EXIT=%ERRORLEVEL%"
goto finish

:prompt_output
for /f %%I in ('powershell.exe -NoProfile -Command "Get-Date -Format yyyyMMdd_HHmmss"') do set "OUTPUT_STAMP=%%I"
if not defined OUTPUT_STAMP (
    echo Could not create a timestamp for the default output filename.
    goto failed
)
set "DEFAULT_OUTPUT=%SCRIPT_DIR%A05_arp_cache_%OUTPUT_STAMP%.json"
set "OUTPUT_PATH="
set /p "OUTPUT_PATH=Enter a JSON file path or an existing folder, or press Enter to save here [%DEFAULT_OUTPUT%]: "
if not defined OUTPUT_PATH set "OUTPUT_PATH=%DEFAULT_OUTPUT%"
"%PYTHON%" "%COLLECTOR%" --output "%OUTPUT_PATH%"
set "COLLECTOR_EXIT=%ERRORLEVEL%"
goto finish

:failed
set "COLLECTOR_EXIT=2"

:finish
if not "%COLLECTOR_EXIT%"=="0" if not "%COLLECTOR_EXIT%"=="1" (
    echo A05 did not complete successfully. See the error above.
)
echo.
echo A05 ARP cache collector exit code: %COLLECTOR_EXIT%
pause
exit /b %COLLECTOR_EXIT%
