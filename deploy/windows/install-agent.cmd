@echo off
setlocal EnableExtensions
echo.
echo Tunnel Control Agent setup
echo.
set /p SERVER_URL=Server WebSocket URL (example: ws://203.0.113.10:8080/control): 
if "%SERVER_URL%"=="" exit /b 1
set /p DEVICE_TOKEN=Device token: 
if "%DEVICE_TOKEN%"=="" exit /b 1

set "INSTALL_ROOT=%ProgramFiles%\TunnelControl"
if not exist "%INSTALL_ROOT%" mkdir "%INSTALL_ROOT%"
copy /Y "tunnel-agent.exe" "%INSTALL_ROOT%\tunnel-agent.exe" >nul
setx TUNNEL_SERVER_URL "%SERVER_URL%" /M >nul
setx TUNNEL_TOKEN "%DEVICE_TOKEN%" /M >nul
sc query TunnelAgent >nul 2>&1
if not errorlevel 1 sc stop TunnelAgent >nul 2>&1
if not errorlevel 1 sc delete TunnelAgent >nul 2>&1
sc create TunnelAgent binPath= "\"%INSTALL_ROOT%\tunnel-agent.exe\"" start= auto DisplayName= "Tunnel Control Agent" >nul
sc description TunnelAgent "Maintains Tunnel Control connections for this Windows computer." >nul
sc failure TunnelAgent reset= 86400 actions= restart/5000/restart/10000/restart/30000 >nul
sc start TunnelAgent >nul
echo.
echo TunnelAgent service is installed and running.
echo.
pause
