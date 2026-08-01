param([Parameter(Mandatory=$true)][string]$ServerUrl,[Parameter(Mandatory=$true)][string]$Token,[string]$InstallRoot="$env:ProgramFiles\TunnelControl")
$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Force -Path $InstallRoot | Out-Null
$agent = Join-Path $InstallRoot 'tunnel-agent.exe'
if (!(Test-Path $agent)) { throw "Copy tunnel-agent.exe to $agent before installing." }
[Environment]::SetEnvironmentVariable('TUNNEL_SERVER_URL',$ServerUrl,'Machine')
[Environment]::SetEnvironmentVariable('TUNNEL_TOKEN',$Token,'Machine')
sc.exe create TunnelAgent binPath= "\"$agent\"" start= auto DisplayName= "Tunnel Control Agent" | Out-Null
sc.exe description TunnelAgent "Maintains encrypted Tunnel Control connections for this Windows computer." | Out-Null
sc.exe failure TunnelAgent reset= 86400 actions= restart/5000/restart/10000/restart/30000 | Out-Null
Start-Service TunnelAgent
Write-Host 'TunnelAgent service installed and started.'
