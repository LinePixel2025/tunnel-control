#define MyAppName "Tunnel Agent"
#define MyAppVersion "0.1.0"
#define MyAppPublisher "Tunnel Control"
#define MyAppExeName "Tunnel Agent.exe"

[Setup]
AppId={{D4A765B0-66B8-4C63-B708-483430B5A790}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\TunnelControl
DefaultGroupName=Tunnel Control
OutputDir=..\..\..\release
OutputBaseFilename=Tunnel-Agent-Setup
Compression=lzma
SolidCompression=yes
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64

[Files]
Source: "..\dist\*"; DestDir: "{app}\ui"; Flags: recursesubdirs ignoreversion
Source: "..\..\..\target\release\tunnel-agent.exe"; DestDir: "{app}"; Flags: ignoreversion

[Run]
Filename: "{sys}\sc.exe"; Parameters: "create TunnelAgent binPath= """"{app}\tunnel-agent.exe"""" start= auto DisplayName= ""Tunnel Control Agent"""; Flags: runhidden
Filename: "{sys}\sc.exe"; Parameters: "failure TunnelAgent reset= 86400 actions= restart/5000/restart/10000/restart/30000"; Flags: runhidden
Filename: "{sys}\sc.exe"; Parameters: "start TunnelAgent"; Flags: runhidden

[UninstallRun]
Filename: "{sys}\sc.exe"; Parameters: "stop TunnelAgent"; Flags: runhidden
Filename: "{sys}\sc.exe"; Parameters: "delete TunnelAgent"; Flags: runhidden
