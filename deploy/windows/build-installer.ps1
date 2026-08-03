param([string]$OutputPath = "release\tunnel-agent.exe")

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
Write-Host "Install with: tunnel-agent.exe --install --server ws://SERVER_IP:18080/control"
