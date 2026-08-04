param(
    [string]$OutputPath = "release\tunnel-agent.exe",
    [string]$Version = ""
)

$ErrorActionPreference = "Stop"
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$agentPath = Join-Path $projectRoot "target\release\tunnel-agent.exe"
$outputFile = Join-Path $projectRoot $OutputPath

if (!(Test-Path $agentPath)) {
    & cargo build --release -p tunnel-agent
    if ($LASTEXITCODE -ne 0) { throw "Failed to build tunnel-agent." }
}

New-Item -ItemType Directory -Force -Path (Split-Path $outputFile) | Out-Null
Copy-Item -LiteralPath $agentPath -Destination $outputFile -Force
$size = (Get-Item -LiteralPath $outputFile).Length
if ($size -lt 1MB) { throw "Installer validation failed: output is unexpectedly small." }
Write-Host "Created CLI installer: $outputFile ($size bytes)"
if ($Version) {
    $versionedFile = Join-Path $projectRoot "release\tunnel-agent-V$Version.exe"
    New-Item -ItemType Directory -Force -Path (Split-Path $versionedFile) | Out-Null
    Copy-Item -LiteralPath $agentPath -Destination $versionedFile -Force
    $versionedSize = (Get-Item -LiteralPath $versionedFile).Length
    Write-Host "Created versioned CLI installer: $versionedFile ($versionedSize bytes)"
}
Write-Host "Install with: tunnel-agent.exe --install --server ws://SERVER_IP:18080/control"
