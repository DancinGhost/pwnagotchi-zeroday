@echo off
rem Simple Windows Flasher Launcher for pwnagotchi-zeroday
cd /d "%~dp0"

where python >nul 2>nul
if %errorlevel% equ 0 (
    python flash.py
    goto :done
)

where py >nul 2>nul
if %errorlevel% equ 0 (
    py flash.py
    goto :done
)

echo Python 3 is required for the automated flasher.
echo Please install Python from python.org or flash using Chrome/Edge at:
echo   https://espressif.github.io/esptool-js/
echo   https://adafruit.github.io/Adafruit_WebSerial_ESPTool/
echo   https://esptool.spacehuhn.com/
pause

:done
pause
