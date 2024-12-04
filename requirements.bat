@echo off
color 0A
title [==== R0BL0X PR0XY C0MMANDER - SETUP ====]
echo.
echo [===============================================]
echo [        TheZ's Cookie Bypasser SETUP           ]
echo [===============================================]
echo.

Echo Checking if python installed
:: Check if Python is installed
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [*] Python not detected. Installing Python 3.12...
    
    :: Define the URL for Python 3.12 installer
    set PYTHON_URL=https://www.python.org/ftp/python/3.12.0/python-3.12.0-amd64.exe

    :: Download Python installer using PowerShell
    powershell -Command "Invoke-WebRequest -Uri %PYTHON_URL% -OutFile python-installer.exe"

    :: Install Python silently
    start /wait python-installer.exe /quiet InstallAllUsers=1 PrependPath=1

    :: Cleanup installer
    del python-installer.exe

    :: Verify Python installation
    python --version >nul 2>&1
    if %errorlevel% neq 0 (
        echo [!] Python installation failed. Exiting...
        pause
        exit /b
    )
)

:: Update pip
echo [*] Updating pip...
python -m pip install --upgrade pip

:: Install required packages
echo [*] Installing dependencies...
python -m pip install customtkinter matplotlib requests pygame fake-useragent urllib3 websockets cryptography pillow colorama tqdm

cls
color 0A
echo [===============================================]
echo [  Requirements Installed Starting the Launcher ]
echo [===============================================]
echo.
start _No_Selenium-Launcher.py
echo Press any key to jack out...
pause >nul
