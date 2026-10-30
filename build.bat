@echo off
rem ------------------------------------------------------------------
rem  Builds d3d11.dll (32-bit) for GRANDIA HD Remaster.
rem  Run this script from the "x86 Native Tools Command Prompt for VS"
rem  (in the Start menu under Visual Studio).
rem ------------------------------------------------------------------
 
if /I not "%VSCMD_ARG_TGT_ARCH%"=="x86" (
    echo.
    echo  This script must run in the "x86 Native Tools Command Prompt for VS".
    echo  ^(Detected target platform: "%VSCMD_ARG_TGT_ARCH%"^)
    echo.
    exit /b 1
)
 
cd /d "%~dp0"
 
rc /nologo /fo grandia_aspect.res grandia_aspect.rc
if errorlevel 1 (
    echo.
    echo  Building the version information failed - see the messages above.
    exit /b 1
)
 
cl /nologo /utf-8 /LD /O2 /MT /W4 /EHsc /DUNICODE /D_UNICODE grandia_proxy.cpp grandia_aspect.res /Fe:d3d11.dll
if errorlevel 1 (
    echo.
    echo  Build failed - see the messages above.
    exit /b 1
)
 
echo.
echo  Done: d3d11.dll is in %~dp0
echo  Copy d3d11.dll and grandia_mod.ini to the folder that contains grandia.exe.