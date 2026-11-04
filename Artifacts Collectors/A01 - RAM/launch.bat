@echo off
setlocal DisableDelayedExpansion
set "A01_DIRECTORY=%~dp0."
for %%I in ("%~dp0..\..") do set "A01_PROJECT_ROOT=%%~fI"
set "A01_PYTHON=%A01_PROJECT_ROOT%\.venv\Scripts\python.exe"
if not exist "%A01_PYTHON%" set "A01_PYTHON=%~dp0..\.venv\Scripts\python.exe"
if not exist "%A01_PYTHON%" set "A01_PYTHON=%~dp0.venv\Scripts\python.exe"
set "A01_COLLECTOR=%~dp0collector.py"
set "A01_TOOL=%~dp0go-winpmem_amd64_1.0-rc2_signed.exe"
set "A01_WORKING_DIRECTORY=%CD%"
set "A01_INTERACTIVE=0"
if "%~1"=="" set "A01_INTERACTIVE=1"

if not exist "%A01_PYTHON%" (
    echo A01 project Python was not found:
    echo "%A01_PYTHON%"
    goto :failed
)
if not exist "%A01_COLLECTOR%" (
    echo A01 collector was not found:
    echo "%A01_COLLECTOR%"
    goto :failed
)
if not exist "%A01_TOOL%" (
    echo A01 WinPmem executable was not found:
    echo "%A01_TOOL%"
    goto :failed
)

"%A01_PYTHON%" -c "import sys; print('A01 collector Python: ' + str(sys.version_info.major) + '.' + str(sys.version_info.minor) + '.')"
if errorlevel 1 (
    echo A01 could not verify the project Python interpreter.
    goto :failed
)

set "A01_ARGUMENTS_FILE=%TEMP%\A01-arguments-%RANDOM%-%RANDOM%.txt"
set "A01_LOG_FILE=%TEMP%\A01-output-%RANDOM%-%RANDOM%.txt"
"%A01_PYTHON%" -c "import base64,json,sys; print(base64.b64encode(json.dumps(sys.argv[1:],ensure_ascii=True).encode('utf-8')).decode('ascii'))" %* > "%A01_ARGUMENTS_FILE%"
if errorlevel 1 goto :argument_encoding_failed

powershell.exe -NoProfile -Command "$ErrorActionPreference = 'Stop'; try { $encoded = [IO.File]::ReadAllText($env:A01_ARGUMENTS_FILE).Trim(); $arguments = ConvertFrom-Json -InputObject ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($encoded))); if ($null -eq $arguments) { $arguments = @() } elseif ($arguments -isnot [array]) { $arguments = @($arguments) }; $arguments = [string[]]$arguments; Remove-Item -LiteralPath $env:A01_ARGUMENTS_FILE -Force; $hasOutput = @($arguments | Where-Object { $_ -eq '--output-dir' -or $_.StartsWith('--output-dir=') }).Count -gt 0; if (-not $hasOutput) { $folder = Read-Host 'Enter a custom save folder, or press Enter to save in this artifact folder'; if ([string]::IsNullOrWhiteSpace($folder)) { $folder = $env:A01_DIRECTORY }; $arguments += @('--output-dir', $folder) }; $arguments = [string[]]$arguments; $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent()); $isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator); if ($isAdmin) { Set-Location -LiteralPath $env:A01_WORKING_DIRECTORY; & $env:A01_PYTHON $env:A01_COLLECTOR @arguments; exit $LASTEXITCODE }; $payloadData = @{ arguments = $arguments; python = $env:A01_PYTHON; collector = $env:A01_COLLECTOR; workingDirectory = $env:A01_WORKING_DIRECTORY; log = $env:A01_LOG_FILE }; $payload = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes((ConvertTo-Json -InputObject $payloadData -Compress))); $elevatedScript = '$ErrorActionPreference = ''Stop''; try { $data = ConvertFrom-Json -InputObject ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String(''' + $payload + '''))); $arguments = @($data.arguments); Set-Location -LiteralPath $data.workingDirectory; & $data.python $data.collector @arguments *> $data.log; exit $LASTEXITCODE } catch { $message = $_ | Out-String; [Console]::Error.WriteLine($message); exit 2 }'; $encodedCommand = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($elevatedScript)); Write-Host 'Requesting administrator approval through Windows UAC...'; $process = Start-Process -FilePath 'powershell.exe' -ArgumentList @('-NoProfile', '-EncodedCommand', $encodedCommand) -WorkingDirectory $env:A01_WORKING_DIRECTORY -Verb RunAs -PassThru -Wait; if (Test-Path -LiteralPath $env:A01_LOG_FILE -PathType Leaf) { [Console]::Write([IO.File]::ReadAllText($env:A01_LOG_FILE)) }; exit $process.ExitCode } catch { $nativeCode = $_.Exception.NativeErrorCode; if ($_.Exception.HResult -eq -2147023673 -or $nativeCode -eq 1223) { Write-Host 'UAC approval was cancelled. No acquisition was started.' } else { Write-Host ('A01 could not start acquisition: ' + $_.Exception.Message + '. No acquisition was started.') }; exit 2 } finally { if (Test-Path -LiteralPath $env:A01_ARGUMENTS_FILE) { Remove-Item -LiteralPath $env:A01_ARGUMENTS_FILE -Force }; if (Test-Path -LiteralPath $env:A01_LOG_FILE) { Remove-Item -LiteralPath $env:A01_LOG_FILE -Force } }"
set "A01_EXIT=%ERRORLEVEL%"
if exist "%A01_ARGUMENTS_FILE%" del /q "%A01_ARGUMENTS_FILE%" >nul 2>&1
if exist "%A01_LOG_FILE%" del /q "%A01_LOG_FILE%" >nul 2>&1
if "%A01_EXIT%"=="0" echo A01 RAM acquisition completed. Review the image and collection-result JSON paths above.
if "%A01_EXIT%"=="1" echo A01 acquisition was partial or cancelled. Keep the output only as an incomplete capture.
if "%A01_EXIT%"=="2" echo A01 acquisition failed. Review the reported diagnostics.
if not "%A01_EXIT%"=="0" if not "%A01_EXIT%"=="1" if not "%A01_EXIT%"=="2" echo A01 collector exited with code %A01_EXIT%.
if "%A01_INTERACTIVE%"=="1" pause
exit /b %A01_EXIT%

:argument_encoding_failed
if exist "%A01_ARGUMENTS_FILE%" del /q "%A01_ARGUMENTS_FILE%" >nul 2>&1
echo A01 could not safely prepare arguments for elevation.

:failed
set "A01_EXIT=2"
if "%A01_INTERACTIVE%"=="1" pause
exit /b %A01_EXIT%
