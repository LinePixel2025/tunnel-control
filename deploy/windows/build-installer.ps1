param(
    [string]$OutputPath = "release\tunnel-agent.exe",
    [string]$Version = ""
)

$ErrorActionPreference = "Stop"
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$agentPath = Join-Path $projectRoot "target\release\tunnel-agent.exe"

if (!(Test-Path $agentPath)) {
    & cargo build --release -p tunnel-agent
    if ($LASTEXITCODE -ne 0) { throw "Failed to build tunnel-agent." }
}

if ($Version) {
    # Each release lives in its own folder so the release directory stays
    # organized across versions.
    $versionDir = Join-Path $projectRoot "release\V$Version"
    New-Item -ItemType Directory -Force -Path $versionDir | Out-Null
    $versionedCli = Join-Path $versionDir "tunnel-agent.exe"
    Copy-Item -LiteralPath $agentPath -Destination $versionedCli -Force
    $versionedSize = (Get-Item -LiteralPath $versionedCli).Length
    Write-Host "Created versioned CLI installer: $versionedCli ($versionedSize bytes)"
    $setupFile = Join-Path $versionDir "Tunnel-Agent-Setup-V$Version.exe"
    Copy-Item -LiteralPath $agentPath -Destination $setupFile -Force
    $setupSize = (Get-Item -LiteralPath $setupFile).Length
    Write-Host "Created setup package: $setupFile ($setupSize bytes)"
    Write-Host "Install with: tunnel-agent.exe --install --server ws://SERVER_IP:18080/control"
    return
}

$outputFile = Join-Path $projectRoot $OutputPath
New-Item -ItemType Directory -Force -Path (Split-Path $outputFile) | Out-Null
Copy-Item -LiteralPath $agentPath -Destination $outputFile -Force
$size = (Get-Item -LiteralPath $outputFile).Length
if ($size -lt 1MB) { throw "Installer validation failed: output is unexpectedly small." }
Write-Host "Created CLI installer: $outputFile ($size bytes)"
Write-Host "Install with: tunnel-agent.exe --install --server ws://SERVER_IP:18080/control"
