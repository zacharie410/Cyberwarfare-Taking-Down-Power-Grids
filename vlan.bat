@echo off

:main
cls
echo 1. Create VLAN
echo 2. Delete VLAN
echo 3. Exit

netsh bridge show adapter
set /p option=Enter option:

if "%option%"=="1" goto create_vlan
if "%option%"=="2" goto delete_vlan
if "%option%"=="3" exit

:create_vlan
set /p vlan_id=Enter VLAN ID:
netsh bridge install vlan name=VLAN%vlan_id% vid=%vlan_id%
pause
goto main

:delete_vlan
set /p vlan_id=Enter VLAN ID:
netsh bridge uninstall vlan name=VLAN%vlan_id%
pause
goto main
