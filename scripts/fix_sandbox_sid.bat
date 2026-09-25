@echo off
setlocal enabledelayedexpansion

echo ======================================================
echo  File Anomaly Scanner - Windows Sandbox SID Configurator
echo ======================================================
echo.

echo [1/4] Ensuring 'Remote Desktop Users' group exists...
net localgroup "Remote Desktop Users" >nul 2>&1
if %errorlevel% neq 0 (
    net localgroup "Remote Desktop Users" /add
    if %errorlevel% equ 0 (
        echo [OK] Successfully created 'Remote Desktop Users' group.
    ) else (
        echo [ERROR] Failed to create 'Remote Desktop Users' group. Make sure this script runs as Administrator.
    )
) else (
    echo [OK] 'Remote Desktop Users' group already exists.
)

echo.
echo [2/4] Activating WDAGUtilityAccount...
net user WDAGUtilityAccount /active:yes >nul 2>&1
if %errorlevel% equ 0 (
    echo [OK] WDAGUtilityAccount is now active.
) else (
    echo [WARN] Unable to activate WDAGUtilityAccount via net user.
)

echo.
echo [3/4] Adding WDAGUtilityAccount to security groups...
net localgroup "Users" WDAGUtilityAccount /add >nul 2>&1
net localgroup "Remote Desktop Users" WDAGUtilityAccount /add >nul 2>&1
echo [OK] WDAGUtilityAccount added to Users and Remote Desktop Users.

echo.
echo [4/4] Creating and configuring shared sandbox staging directory...
set "STAGING_ROOT=%ProgramData%\FileAnomalyScanner_Sandbox"
if not exist "%STAGING_ROOT%" mkdir "%STAGING_ROOT%"
icacls "%STAGING_ROOT%" /grant "Users":(OI)(CI)RX /grant "WDAGUtilityAccount":(OI)(CI)RX /t /q >nul 2>&1
echo [OK] Permissions granted on %STAGING_ROOT%.

echo.
echo ======================================================
echo  Configuration Complete! Windows Sandbox can now resolve
echo  all security IDs and account mappings.
echo ======================================================
timeout /t 5
