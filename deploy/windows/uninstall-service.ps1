$ErrorActionPreference = 'Stop'
if (Get-Service TunnelAgent -ErrorAction SilentlyContinue) { Stop-Service TunnelAgent -Force; sc.exe delete TunnelAgent | Out-Null }
[Environment]::SetEnvironmentVariable('TUNNEL_SERVER_URL',$null,'Machine')
[Environment]::SetEnvironmentVariable('TUNNEL_TOKEN',$null,'Machine')
# %PROGRAMDATA%\TunnelControl\credentials is kept so a reinstall reuses the
# issued token; delete it manually to force re-enrollment.
Write-Host 'TunnelAgent service removed.'
