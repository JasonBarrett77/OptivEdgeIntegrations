@echo off
REM Launches the collection script.
REM
REM This .cmd exists because a downloaded .ps1 will not run on a default Windows install:
REM the execution policy is Restricted and the file carries a mark-of-the-web. A .cmd is not
REM subject to the execution policy, and -ExecutionPolicy Bypass applies to this process
REM only - nothing about the machine is changed, and no setting is left behind.
REM
REM If your organisation sets the PowerShell execution policy by Group Policy, this cannot
REM override it and the script will not start. Tell your Optiv contact if that happens.

setlocal
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Collect-OptivEdgeConfiguration.ps1" %*
echo.
pause
