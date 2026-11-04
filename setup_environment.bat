@echo off
setlocal EnableExtensions DisableDelayedExpansion
title Custos Python Environment Setup

set "PROJECT_ROOT=%~dp0"
set "VENV_DIR=%PROJECT_ROOT%.venv"
set "VENV_PYTHON=%VENV_DIR%\Scripts\python.exe"
set "REQUIREMENTS_FILE=%PROJECT_ROOT%requirements-dev-lock.txt"

echo Custos Forensic Suite - Python environment setup
echo Setup script revision: 2026-11-02.2
echo Project folder: "%PROJECT_ROOT%"
echo.

if not exist "%REQUIREMENTS_FILE%" (
    echo ERROR: Dependency lock file was not found:
    echo "%REQUIREMENTS_FILE%"
    echo Copy requirements-dev-lock.txt beside this batch file and try again.
    goto failed
)

if exist "%VENV_DIR%\" goto existing_venv
goto find_python

:existing_venv
if not exist "%VENV_PYTHON%" (
    echo ERROR: "%VENV_DIR%" exists but does not contain Scripts\python.exe.
    echo Rename this incomplete .venv folder, then run setup again.
    goto failed
)
echo Reusing the existing .venv environment.
goto validate_python

:find_python
where py >nul 2>nul
if errorlevel 1 goto try_python_command
py -3.12-64 --version >nul 2>nul
if errorlevel 1 goto try_python_command
echo Creating the project .venv environment with Python Launcher py -3.12-64...
py -3.12-64 -m venv "%VENV_DIR%"
if errorlevel 1 goto venv_creation_failed
goto validate_python

:try_python_command
where python >nul 2>nul
if errorlevel 1 goto python_missing
python -c "import struct,sys; raise SystemExit(0 if sys.version_info[:2] == (3, 12) and struct.calcsize('P') * 8 == 64 else 1)" >nul 2>nul
if errorlevel 1 goto python_missing
echo Creating the project .venv environment with 64-bit Python 3.12...
python -m venv "%VENV_DIR%"
if errorlevel 1 goto venv_creation_failed
goto validate_python

:validate_python
if not exist "%VENV_PYTHON%" (
    echo ERROR: The project virtual environment does not contain Scripts\python.exe.
    goto failed
)

"%VENV_PYTHON%" -c "import struct,sys; print('Selected Python: ' + sys.version.split()[0] + ' (' + str(struct.calcsize('P') * 8) + '-bit)'); raise SystemExit(0 if sys.version_info[:2] == (3, 12) and struct.calcsize('P') * 8 == 64 else 1)"
if errorlevel 1 (
    echo ERROR: Custos requires 64-bit Python 3.12 for the validated Windows dependencies.
    echo Install 64-bit Python 3.12, rename the existing .venv folder, and run setup again.
    goto failed
)

"%VENV_PYTHON%" -m pip --version >nul 2>nul
if errorlevel 1 (
    echo Bootstrapping pip in the project environment...
    "%VENV_PYTHON%" -m ensurepip --upgrade
    if errorlevel 1 (
        echo ERROR: pip could not be bootstrapped in the project environment.
        goto failed
    )
)

echo.
echo Installing packages listed in requirements-dev-lock.txt...
"%VENV_PYTHON%" -m pip install --disable-pip-version-check -r "%REQUIREMENTS_FILE%"
if errorlevel 1 (
    echo ERROR: Dependency installation failed.
    echo Check the network connection and the pip error shown above, then retry.
    goto failed
)

echo.
echo Checking installed dependencies...
"%VENV_PYTHON%" -m pip check
if errorlevel 1 (
    echo ERROR: Installed packages have missing or incompatible dependencies.
    goto failed
)

"%VENV_PYTHON%" -c "import pefile, psutil, win32api, win32net, win32security, win32service, win32ts, win32wnet; print('Required Custos package imports succeeded.')"
if errorlevel 1 (
    echo ERROR: One or more required Custos packages could not be imported.
    echo Review the Python error above and rerun setup after resolving it.
    goto failed
)

echo.
echo Environment setup completed successfully.
echo Environment: "%VENV_DIR%"
echo Python: "%VENV_PYTHON%"
echo Dependencies: "%REQUIREMENTS_FILE%"
echo.
echo Some artifacts also require Windows features, administrator approval,
echo a supported Windows version, or separately supplied tools. This setup
echo cannot guarantee collection on unsupported or unprepared computers.
if /I "%SESSIONNAME%"=="Console" pause
exit /b 0

:python_missing
echo ERROR: 64-bit Python 3.12 was not found.
echo Install Python 3.12 for Windows, then run this file again.
echo The Python Launcher command py -3.12-64 or the python command must be available.
goto failed

:venv_creation_failed
echo ERROR: Python could not create the .venv environment.
echo Confirm that 64-bit Python 3.12 is installed and includes the venv and pip modules.
goto failed

:failed
echo.
echo Environment setup did not complete.
if /I "%SESSIONNAME%"=="Console" pause
exit /b 1
