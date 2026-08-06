param([Parameter(Mandatory=$true)][string]$ServerUrl,[string]$InstallRoot="$env:ProgramFiles\TunnelControl")
$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Force -Path $InstallRoot | Out-Null
$agent = Join-Path $InstallRoot 'tunnel-agent.exe'
if (!(Test-Path $agent)) { throw "Copy tunnel-agent.exe to $agent before installing." }
# Upgrade path: if the service already exists, stop it and wait for the stop
# to fully complete before deleting, otherwise sc.exe create fails with
# "service already exists" and the still-running service blocks the caller
# from overwriting tunnel-agent.exe. A missing service is skipped.
$existing = Get-Service TunnelAgent -ErrorAction SilentlyContinue
if ($existing) {
    Stop-Service TunnelAgent -Force -ErrorAction SilentlyContinue
    $deadline = (Get-Date).AddSeconds(30)
    while ((Get-Service TunnelAgent -ErrorAction SilentlyContinue).Status -ne 'Stopped') {
        if ((Get-Date) -ge $deadline) { throw 'TunnelAgent did not stop within 30 seconds.' }
        Start-Sleep -Milliseconds 200
    }
    sc.exe delete TunnelAgent | Out-Null
}
# Bootstrap only the server URL; the access token is issued by the server after
# the admin approves the device-code enrollment in the management console.
Set-Content -LiteralPath (Join-Path $InstallRoot 'agent.env') -Value "TUNNEL_SERVER_URL=$ServerUrl" -Encoding ASCII
sc.exe create TunnelAgent binPath= "\"$agent\"" start= auto DisplayName= "Tunnel Control Agent" | Out-Null
sc.exe description TunnelAgent "Maintains encrypted Tunnel Control connections for this Windows computer." | Out-Null
sc.exe failure TunnelAgent reset= 86400 actions= restart/5000/restart/10000/restart/30000 | Out-Null
Start-Service TunnelAgent
Write-Host 'TunnelAgent service installed and started.'
Write-Host 'Run "tunnel-agent.exe logs" to see the enrollment code, then approve the device in the admin console.'
