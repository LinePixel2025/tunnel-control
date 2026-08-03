[Version]
Class=IEXPRESS
SEDVersion=3
[Options]
PackagePurpose=InstallApp
ShowInstallProgramWindow=0
HideExtractAnimation=1
UseLongFileName=1
InsideCompressed=1
CAB_FixedSize=0
CAB_ResvCodeSigning=0
RebootMode=N
InstallPrompt=
DisplayLicense=
FinishMessage=Tunnel Agent extracted. Run "tunnel-agent.exe --install --server ws://SERVER_IP:18080/control" as Administrator.
TargetName=release\Tunnel-Agent-Setup.exe
FriendlyName=Tunnel Agent CLI
AppLaunched=<None>
PostInstallCmd=<None>
AdminQuietInstCmd=
UserQuietInstCmd=
SourceFiles=0
[Strings]
FILE0="target\release\tunnel-agent.exe"
[SourceFiles]
SourceFiles0=.
[SourceFiles0]
%FILE0%=
