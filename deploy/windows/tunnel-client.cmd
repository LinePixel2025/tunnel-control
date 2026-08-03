@echo off
rem One-click entry point for the Tunnel Control agent. Runs the interactive
rem PowerShell controller, which auto-starts the agent and accepts commands
rem such as stop / restart / status / logs.
setlocal
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0tunnel-client.ps1" %*
exit /b %errorlevel%
