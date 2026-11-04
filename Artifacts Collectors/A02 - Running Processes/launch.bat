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
set "ELEVATION_EXIT=%ERRORLEVEL%"
if not "%ELEVATION_EXIT%"=="0" echo Collector did not run because administrator elevation was cancelled or failed.
if not "%ELEVATION_EXIT%"=="0" pause
exit /b %ELEVATION_EXIT%

:administrator
if not exist "%PYTHON%" goto python_missing

"%PYTHON%" -c "import psutil" >nul 2>&1
if errorlevel 1 goto psutil_missing

if "%~1"=="" goto prompt_output

"%PYTHON%" "%COLLECTOR%" %*
set "COLLECTOR_EXIT=%ERRORLEVEL%"
goto finish

:prompt_output
for /f %%I in ('powershell.exe -NoProfile -Command "Get-Date -Format yyyyMMdd_HHmmss"') do set "OUTPUT_STAMP=%%I"
if not defined OUTPUT_STAMP goto timestamp_failed
set "DEFAULT_OUTPUT=%SCRIPT_DIR%processes_%OUTPUT_STAMP%.json"
set "OUTPUT_PATH="
set /p "OUTPUT_PATH=Enter an output folder or JSON filename; press Enter for this A02 folder [%DEFAULT_OUTPUT%]: "
if not defined OUTPUT_PATH set "OUTPUT_PATH=%DEFAULT_OUTPUT%"
if not defined OUTPUT_PATH goto output_missing

echo The collector will write separate process and system-wide thread JSON files.
echo The thread file does not classify threads as user-mode or kernel-mode.
"%PYTHON%" "%COLLECTOR%" --output "%OUTPUT_PATH%"
set "COLLECTOR_EXIT=%ERRORLEVEL%"
goto finish

:python_missing
echo Project Windows Python was not found:
echo "%PYTHON%"
echo Configure the project .venv before running this collector.
set "COLLECTOR_EXIT=2"
goto finish

:psutil_missing
echo The A02 collector requires psutil, which is not available in the project Python environment.
echo Install it manually with:
echo "%PYTHON%" -m pip install psutil
set "COLLECTOR_EXIT=2"
goto finish

:output_missing
echo No output path was entered.
set "COLLECTOR_EXIT=2"
goto finish

:timestamp_failed
echo Could not create a timestamp for the default output filename.
echo Enter an existing output folder or an explicit JSON filename.
set "OUTPUT_PATH="
set /p "OUTPUT_PATH=Enter output folder or JSON filename: "
if not defined OUTPUT_PATH goto output_missing
echo The collector will write separate process and system-wide thread JSON files.
echo The thread file does not classify threads as user-mode or kernel-mode.
"%PYTHON%" "%COLLECTOR%" --output "%OUTPUT_PATH%"
set "COLLECTOR_EXIT=%ERRORLEVEL%"
goto finish

:finish
echo.
echo A02 collector exit code: %COLLECTOR_EXIT%
pause
exit /b %COLLECTOR_EXIT%
