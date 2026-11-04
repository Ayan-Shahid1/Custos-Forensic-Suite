@echo off
setlocal

powershell.exe -NoProfile -Command "$identity = [Security.Principal.WindowsIdentity]::GetCurrent(); $principal = New-Object Security.Principal.WindowsPrincipal($identity); if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { exit 0 }; exit 1" >nul 2>&1
if not errorlevel 1 goto administrator

echo Administrator permission is required. Approve the Windows UAC prompt to continue.
set "CUSTOS_LAUNCHER=%~f0"
set "CUSTOS_ARGUMENTS=%*"
powershell.exe -NoProfile -Command "try { $launcher = $env:CUSTOS_LAUNCHER; $arguments = $env:CUSTOS_ARGUMENTS; if ([string]::IsNullOrWhiteSpace($arguments)) { $process = Start-Process -FilePath $launcher -Verb RunAs -Wait -PassThru } else { $process = Start-Process -FilePath $launcher -ArgumentList $arguments -Verb RunAs -Wait -PassThru }; exit $process.ExitCode } catch { Write-Error ('Elevation was cancelled or failed: ' + $_.Exception.Message); exit 1223 }"
set "ELEVATION_EXIT=%ERRORLEVEL%"
if not "%ELEVATION_EXIT%"=="0" echo Collector did not run because administrator elevation was cancelled or failed.
if not "%ELEVATION_EXIT%"=="0" pause
exit /b %ELEVATION_EXIT%

:administrator
set "PYTHON=%~dp0..\..\.venv\Scripts\python.exe"
if not exist "%PYTHON%" set "PYTHON=%~dp0..\.venv\Scripts\python.exe"
if not exist "%PYTHON%" set "PYTHON=%~dp0.venv\Scripts\python.exe"
set "COLLECTOR=%~dp0collector.py"

if not exist "%PYTHON%" (
    echo Required project Python was not found:
    echo "%PYTHON%"
    echo Restore that interpreter or update this launcher to the approved Python path.
    goto failed
)

if not exist "%COLLECTOR%" (
    echo A06 collector is missing: "%COLLECTOR%"
    goto failed
)

"%PYTHON%" -c "import win32service, win32security" >nul 2>nul
if errorlevel 1 (
    echo Required pywin32 modules are unavailable in the existing project environment.
    echo Install manually with:
    echo "%PYTHON%" -m pip install "pywin32==312"
    goto failed
)

if "%~1"=="" goto prompt_output
"%PYTHON%" "%COLLECTOR%" %*
set "COLLECTOR_EXIT=%ERRORLEVEL%"
goto finish

:prompt_output
set "OUTPUT_PATH="
set /p "OUTPUT_PATH=Enter an output folder or JSON file path (leave blank to save in the A06 folder): "
if not defined OUTPUT_PATH (
    "%PYTHON%" "%COLLECTOR%"
) else (
    "%PYTHON%" "%COLLECTOR%" --output "%OUTPUT_PATH%"
)
set "COLLECTOR_EXIT=%ERRORLEVEL%"

:finish
if "%COLLECTOR_EXIT%"=="1" echo Collection completed with partial results; check the JSON errors and limitations.
if "%COLLECTOR_EXIT%"=="2" echo Collection failed.
echo A06 launcher exit code: %COLLECTOR_EXIT%
pause
exit /b %COLLECTOR_EXIT%

:failed
echo A06 launcher exit code: 2
pause
exit /b 2
