param([Parameter(Mandatory=$true)][string]$ServerUrl,[string]$InstallRoot="$env:ProgramFiles\TunnelControl")
$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Force -Path $InstallRoot | Out-Null
$agent = Join-Path $InstallRoot 'tunnel-agent.exe'
if (!(Test-Path $agent)) { throw "Copy tunnel-agent.exe to $agent before installing." }
# Bootstrap only the server URL; the access token is issued by the server after
# the admin approves the device-code enrollment in the management console.
Set-Content -LiteralPath (Join-Path $InstallRoot 'agent.env') -Value "TUNNEL_SERVER_URL=$ServerUrl" -Encoding ASCII
sc.exe create TunnelAgent binPath= "\"$agent\"" start= auto DisplayName= "Tunnel Control Agent" | Out-Null
sc.exe description TunnelAgent "Maintains encrypted Tunnel Control connections for this Windows computer." | Out-Null
sc.exe failure TunnelAgent reset= 86400 actions= restart/5000/restart/10000/restart/30000 | Out-Null
Start-Service TunnelAgent
Write-Host 'TunnelAgent service installed and started.'
Write-Host 'Run "tunnel-agent.exe logs" to see the enrollment code, then approve the device in the admin console.'
