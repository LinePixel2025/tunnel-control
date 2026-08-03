<#
.SYNOPSIS
    One-click controller for the Tunnel Control agent.

.DESCRIPTION
    Starts tunnel-agent.exe as a hidden background process and, in interactive
    mode, keeps a command prompt that can terminate or restart the agent:

      start     start the agent if it is not running
      stop      terminate the agent
      restart   terminate and start again
      reset     stop the agent and delete ALL local data (token, enrollment
                code, logs, bootstrap config); the next start re-enrolls
      status    show process/service/credential state
      logs      print the latest agent log lines
      exit      leave the prompt (the agent keeps running)

    Script mode uses per-user state under %LOCALAPPDATA%\TunnelControl, so it
    does not touch the Windows service credentials in %PROGRAMDATA% and can be
    run without elevation.

.PARAMETER AgentPath
    Path to tunnel-agent.exe. Defaults to the script's own directory.

.PARAMETER Command
    One-shot command (start|stop|restart|status|logs|help). Omit to enter the
    interactive prompt, which also auto-starts the agent.
#>
param(
    [string]$AgentPath = (Join-Path $PSScriptRoot "tunnel-agent.exe"),
    [string]$Command = ""
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $AgentPath)) {
    throw "tunnel-agent.exe not found at: $AgentPath"
}
$Agent = (Resolve-Path $AgentPath).Path

$StateDir = Join-Path $env:LOCALAPPDATA "TunnelControl"
$LogDir = Join-Path $StateDir "logs"
$PidFile = Join-Path $StateDir "agent.pid"
$CredentialFile = Join-Path $StateDir "credentials"
$ConsoleLog = Join-Path $StateDir "console.log"
$ConsoleErr = Join-Path $StateDir "console.err.log"
New-Item -ItemType Directory -Force -Path $StateDir, $LogDir | Out-Null

# Script mode has its own credentials/logs so a non-elevated user can run it
# without touching the Windows service files under %PROGRAMDATA%.
$env:TUNNEL_CREDENTIALS_FILE = $CredentialFile
$env:TUNNEL_LOG_DIR = $LogDir

function Get-RunningAgent {
    if (Test-Path $PidFile) {
        $pidValue = (Get-Content -LiteralPath $PidFile -Raw -ErrorAction SilentlyContinue).Trim()
        if ($pidValue -match '^\d+$') {
            $proc = Get-Process -Id ([int]$pidValue) -ErrorAction SilentlyContinue
            if ($proc -and $proc.ProcessName -like "tunnel-agent*") {
                return $proc
            }
        }
    }
    # Fallback for a stale pid file: locate the process by name.
    Get-Process -Name "tunnel-agent" -ErrorAction SilentlyContinue | Select-Object -First 1
}

function Get-TunnelService {
    Get-Service -Name TunnelAgent -ErrorAction SilentlyContinue
}

function Start-AgentProcess {
    $running = Get-RunningAgent
    if ($running) {
        Write-Host "Agent is already running (PID $($running.Id))."
        return
    }
    $service = Get-TunnelService
    if ($service -and $service.Status -eq "Running") {
        Write-Host "WARNING: the TunnelAgent Windows service is running." -ForegroundColor Yellow
        Write-Host "Script mode and service mode would fight over the same device session." -ForegroundColor Yellow
        Write-Host "Stop it first with:  sc.exe stop TunnelAgent   (or: tunnel-agent.exe --uninstall)" -ForegroundColor Yellow
        return
    }
    $process = Start-Process -FilePath $Agent `
        -ArgumentList "--agent" `
        -WindowStyle Hidden `
        -RedirectStandardOutput $ConsoleLog `
        -RedirectStandardError $ConsoleErr `
        -PassThru
    Set-Content -LiteralPath $PidFile -Value $process.Id
    Write-Host "Agent started (PID $($process.Id))."
    Write-Host "First run shows an enrollment code; type 'logs' to view it, then approve it in the admin console."
}

function Stop-AgentProcess {
    $running = Get-RunningAgent
    if (-not $running) {
        Write-Host "Agent is not running."
        return
    }
    Stop-Process -Id $running.Id -Force -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 300
    if (Test-Path $PidFile) {
        Remove-Item -LiteralPath $PidFile -Force
    }
    Write-Host "Agent stopped."
}

function Restart-AgentProcess {
    Stop-AgentProcess
    Start-Sleep -Milliseconds 300
    Start-AgentProcess
}

function Reset-AgentProcess {
    Stop-AgentProcess
    # The agent's own reset stops the Windows service, removes the issued
    # token, enrollment code, bootstrap config, and every log file.
    & $Agent reset
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Reset failed. Run 'tunnel-client.ps1 reset' as Administrator if the agent is installed under Program Files." -ForegroundColor Yellow
        return
    }
    Write-Host "Local agent data has been reset. Type 'start' to re-enroll."
}

function Show-Status {
    $running = Get-RunningAgent
    $service = Get-TunnelService
    Write-Host "Agent binary : $Agent"
    if ($running) {
        Write-Host "Agent process: RUNNING (PID $($running.Id))"
    } else {
        Write-Host "Agent process: stopped"
    }
    if ($service) {
        Write-Host "Windows service: $($service.Status) (TunnelAgent)"
    } else {
        Write-Host "Windows service: not installed"
    }
    if (Test-Path $CredentialFile) {
        $issued = Select-String -LiteralPath $CredentialFile -Pattern '^TOKEN=' -Quiet
        if ($issued) {
            Write-Host "Credentials   : token issued (enrolled)"
        } else {
            Write-Host "Credentials   : pending enrollment"
        }
    } else {
        Write-Host "Credentials   : none (device-code enrollment required)"
    }
}

function Show-Logs {
    & $Agent logs -n 60
}

function Show-Help {
    Write-Host "Commands:"
    Write-Host "  start     start the agent if it is not running"
    Write-Host "  stop      terminate the agent"
    Write-Host "  restart   terminate and start again"
    Write-Host "  reset     stop the agent and delete ALL local data (re-enroll on next start)"
    Write-Host "  status    show process/service/credential state"
    Write-Host "  logs      print the latest agent log lines"
    Write-Host "  exit      leave the prompt (the agent keeps running)"
}

function Enter-Interactive {
    Write-Host "==============================================" -ForegroundColor Cyan
    Write-Host "  Tunnel Control Client" -ForegroundColor Cyan
    Write-Host "==============================================" -ForegroundColor Cyan
    Start-AgentProcess
    while ($true) {
        $input = Read-Host "tunnel-client"
        switch ($input.Trim().ToLower()) {
            "start"   { Start-AgentProcess }
            "stop"    { Stop-AgentProcess }
            "restart" { Restart-AgentProcess }
            "reset"   { Reset-AgentProcess }
            "status"  { Show-Status }
            "logs"    { Show-Logs }
            "help"    { Show-Help }
            "exit"    { Write-Host "Exiting. The agent keeps running in the background; type 'stop' to terminate it next time."; return }
            default   { Write-Host "Unknown command '$input'. Type 'help'." }
        }
    }
}

if ($Command) {
    switch ($Command.ToLower()) {
        "start"   { Start-AgentProcess }
        "stop"    { Stop-AgentProcess }
        "restart" { Restart-AgentProcess }
        "reset"   { Reset-AgentProcess }
        "status"  { Show-Status }
        "logs"    { Show-Logs }
        "help"    { Show-Help }
        default   { throw "Unknown command '$Command'. Use start|stop|restart|reset|status|logs|help" }
    }
} else {
    Enter-Interactive
}
