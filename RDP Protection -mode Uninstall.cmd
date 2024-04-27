@echo off
set psfolder=%~n0
set ps1file=%~dp0RDP Protection.ps1
::               RDP Protection -settingname block_afterntries -settingvalue 5
::               12345678901234567890
::For Params, use name of this .cmd file, but skip x characters and then extract everything else
set ps1file_double=%ps1file:'=''%
SET params=%~n0
SET params=%params:~15%
echo -------------------------------------------------
echo - %~nx0            Computer:%computername% User:%username%%
echo - 
echo - Runs a powershell script as admin and with params.
echo - 
echo - Same as dbl-clicking a .ps1, except with .cmd files you can also
echo - right click and 'run as admin'
echo - 
echo - ps1file: [%ps1file%]
echo -  params: [%params%]
echo -------------------------------------------------
if not exist "%ps1file%"  echo ERR: Couldn't find '%ps1file%' & pause & goto :eof
:: check admin
net session >nul 2>&1
if %errorLevel% == 0 (echo [Admin confirmed]) else (echo ERR: Admin denied. Right-click and run as administrator. & pause & goto :EOF)
:: check admin
if /I "%quiet%" EQU "false" (pause) else (echo [-quiet: 2 seconds...] & ping -n 3 127.0.0.1>nul)

@echo on
cls
PowerShell.exe -NoProfile -ExecutionPolicy Bypass -Command "write-host [Starting PS1 called from CMD]; Set-Variable -Name PSCommandPath -value '%ps1file_double%';& '%ps1file_double%' %params%"
@echo off

echo ----- Done.
if /I "%quiet%" EQU "false" (pause) else (echo [-quiet: 2 seconds...] & ping -n 3 127.0.0.1>nul)