@echo off

NET SESSION >nul 2>&1
IF %ERRORLEVEL% EQU 0 (
    ECHO Administrator PRIVILEGES Detected! 
) ELSE (
   echo ######## ########  ########   #######  ########  
   echo ##       ##     ## ##     ## ##     ## ##     ## 
   echo ##       ##     ## ##     ## ##     ## ##     ## 
   echo ######   ########  ########  ##     ## ########  
   echo ##       ##   ##   ##   ##   ##     ## ##   ##   
   echo ##       ##    ##  ##    ##  ##     ## ##    ##  
   echo ######## ##     ## ##     ##  #######  ##     ## 
   echo.
   echo.
   echo ####### ERROR: ADMINISTRATOR PRIVILEGES REQUIRED #########
   echo This script must be run as administrator to work properly!  
   echo ##########################################################
   echo.
   PAUSE
   EXIT /B 1
)

echo "Terminating the extension process, if present"
taskkill /F /IM plgx_win_extension.ext.exe

timeout /t 5 /nobreak

echo "Cleaning the db files.."
REM Clean up the extension db
rmdir /S /Q c:\ProgramData\plgx_win_extension >nul 2>&1

REM Clean up the drivers
sc stop vast >nul 2>&1
sc delete vast >nul 2>&1
del /F /Q /S %systemroot%\System32\drivers\vast.sys >nul 2>&1
sc stop vastnw >nul 2>&1
sc delete vastnw >nul 2>&1
del /F /Q /S %systemroot%\System32\drivers\vastnw.sys >nul 2>&1

REM clean up the extension binary

IF EXIST "%ProgramFiles%\osquery\plgx_win_extension.ext.exe" (
del /F /Q /S "%ProgramFiles%\osquery\plgx_win_extension.ext.exe" >nul 2>&1
)

IF EXIST "%ProgramData%\osquery\plgx_win_extension.ext.exe" (
del /F /Q /S "%ProgramData%\osquery\plgx_win_extension.ext.exe" >nul 2>&1
)

echo "Clean up done."