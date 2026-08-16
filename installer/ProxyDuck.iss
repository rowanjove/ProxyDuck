#ifndef AppVersion
  #define AppVersion "1.0.0"
#endif
#define WinpkFilterMsi "Windows.Packet.Filter.3.6.2.1.x64.msi"

[Setup]
AppId={{8BC12519-3477-48EE-A7E7-64DAA14A8974}
AppName=ProxyDuck
AppVersion={#AppVersion}
AppPublisher=ProxyDuck contributors
DefaultDirName={autopf}\ProxyDuck
DefaultGroupName=ProxyDuck
OutputDir=..\release\installer
OutputBaseFilename=ProxyDuck-{#AppVersion}-setup
Compression=lzma2
SolidCompression=yes
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=admin
WizardStyle=modern
UninstallDisplayIcon={app}\ProxyDuck.exe
SetupIconFile=..\smartflow-ui\src-tauri\icons\icon.ico
LicenseFile=..\LICENSE
InfoBeforeFile=..\THIRD_PARTY_NOTICES.md

[Files]
Source: "..\release\ProxyDuck\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\ProxyDuck"; Filename: "{app}\ProxyDuck.exe"
Name: "{autodesktop}\ProxyDuck"; Filename: "{app}\ProxyDuck.exe"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Additional shortcuts:"

[Run]
Filename: "{app}\ProxyDuck.exe"; Description: "Launch ProxyDuck"; Flags: nowait postinstall skipifsilent

[Code]
var
  WinpkFilterNeedsRestart: Boolean;

procedure CurStepChanged(CurStep: TSetupStep);
var
  ResultCode: Integer;
  MsiPath: String;
begin
  if CurStep <> ssPostInstall then
    Exit;

  MsiPath := ExpandConstant('{app}\drivers\{#WinpkFilterMsi}');
  WizardForm.StatusLabel.Caption := 'Installing the bundled WinpkFilter driver...';
  if not Exec(
    ExpandConstant('{sys}\msiexec.exe'),
    '/i "' + MsiPath + '" /qn /norestart',
    ExpandConstant('{app}\drivers'),
    SW_HIDE,
    ewWaitUntilTerminated,
    ResultCode
  ) then
    RaiseException('Unable to start the WinpkFilter driver installer.');

  if (ResultCode = 1641) or (ResultCode = 3010) then
    WinpkFilterNeedsRestart := True
  else if ResultCode <> 0 then
    RaiseException(Format('WinpkFilter installation failed with Windows Installer exit code %d.', [ResultCode]));
end;

function NeedRestart(): Boolean;
begin
  Result := WinpkFilterNeedsRestart;
end;
