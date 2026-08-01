$ErrorActionPreference = 'Stop'
if (Get-Service TunnelAgent -ErrorAction SilentlyContinue) { Stop-Service TunnelAgent -Force; sc.exe delete TunnelAgent | Out-Null }
[Environment]::SetEnvironmentVariable('TUNNEL_SERVER_URL',$null,'Machine')
[Environment]::SetEnvironmentVariable('TUNNEL_TOKEN',$null,'Machine')
Write-Host 'TunnelAgent service removed.'
