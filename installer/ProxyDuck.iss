#ifndef AppVersion
  #define AppVersion "1.1.0"
#endif
#define WinpkFilterMsi "Windows.Packet.Filter.3.6.2.1.x64.msi"
#define WinpkFilterVersion "3.6.2.1"
#define WinpkFilterProductCode "{4EC4289E-7F4B-424C-8EA9-B7AC9850FFBE}"

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

[UninstallRun]
Filename: "{app}\proxyduck-service.exe"; Parameters: "--uninstall"; Flags: runhidden waituntilterminated; RunOnceId: "ProxyDuckCoreUninstall"

[Code]
var
  WinpkFilterNeedsRestart: Boolean;
  InstallSucceeded: Boolean;

function RunPowerShell(const Script: String; var ResultCode: Integer): Boolean;
begin
  Result := Exec(
    ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe'),
    '-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "' + Script + '"',
    ExpandConstant('{app}'),
    SW_HIDE,
    ewWaitUntilTerminated,
    ResultCode
  );
end;

procedure ClearServiceMarker;
var
  ResultCode: Integer;
begin
  RunPowerShell(
    '$root=Join-Path $env:ProgramData ''ProxyDuck''; @(''.service-was-running'',''.service-was-present'',''.service-install-attempted'',''.proxyduck-service.exe.backup'',''.winpkfilter-was-present'',''.winpkfilter-install-attempted'',''.winpkfilter-rollback-failed'',''.service-restore-failed'') | ForEach-Object { Remove-Item -LiteralPath (Join-Path $root $_) -Force -ErrorAction SilentlyContinue }',
    ResultCode);
end;

procedure RollbackFreshDriver;
var
  ResultCode: Integer;
begin
  if (not RunPowerShell(
    '$ErrorActionPreference=''Stop''; $root=Join-Path $env:ProgramData ''ProxyDuck''; $marker=Join-Path $root ''.winpkfilter-was-present''; $attempt=Join-Path $root ''.winpkfilter-install-attempted''; $failed=Join-Path $root ''.winpkfilter-rollback-failed''; if ((Test-Path -LiteralPath $attempt) -and (-not (Test-Path -LiteralPath $marker))) { $p=Start-Process -FilePath (Join-Path $env:SystemRoot ''System32\msiexec.exe'') -ArgumentList @(''/x'', ''{#WinpkFilterProductCode}'', ''/qn'', ''/norestart'') -Wait -PassThru; if ($p.ExitCode -notin @(0,1605,1641,3010)) { Set-Content -LiteralPath $failed -Value (''msiexec exit '' + $p.ExitCode) -Encoding ascii; throw "fresh WinpkFilter rollback failed with exit code $($p.ExitCode)" } }; Remove-Item -LiteralPath $marker -Force -ErrorAction SilentlyContinue; Remove-Item -LiteralPath $attempt -Force -ErrorAction SilentlyContinue',
    ResultCode)) or (ResultCode <> 0) then
    Log(Format('Fresh WinpkFilter rollback did not complete; transaction markers were retained (exit code %d).', [ResultCode]));
end;

procedure RestoreServiceIfNeeded;
var
  ResultCode: Integer;
begin
  if (not RunPowerShell(
    '$ErrorActionPreference=''Stop''; $root=Join-Path $env:ProgramData ''ProxyDuck''; $running=Join-Path $root ''.service-was-running''; $present=Join-Path $root ''.service-was-present''; $attempt=Join-Path $root ''.service-install-attempted''; $backup=Join-Path $root ''.proxyduck-service.exe.backup''; $failed=Join-Path $root ''.service-restore-failed''; $target=Join-Path (Get-Location) ''proxyduck-service.exe''; try { if ((-not (Test-Path -LiteralPath $present)) -and (Test-Path -LiteralPath $attempt)) { $svc=Get-Service -Name ''ProxyDuckCore'' -ErrorAction SilentlyContinue; if ($null -ne $svc) { if ($svc.Status -ne ''Stopped'') { Stop-Service -Name ''ProxyDuckCore'' -Force; $svc.WaitForStatus(''Stopped'', [TimeSpan]::FromSeconds(30)) }; $p=Start-Process -FilePath (Join-Path $env:SystemRoot ''System32\sc.exe'') -ArgumentList @(''delete'',''ProxyDuckCore'') -Wait -PassThru; if ($p.ExitCode -ne 0) { throw (''sc delete exit '' + $p.ExitCode) } } } elseif (Test-Path -LiteralPath $backup) { Copy-Item -LiteralPath $backup -Destination $target -Force; if (Test-Path -LiteralPath $running) { $svc=Get-Service -Name ''ProxyDuckCore'' -ErrorAction SilentlyContinue; if ($null -eq $svc) { throw ''ProxyDuckCore service was expected during restore but was not found'' }; Start-Service -Name ''ProxyDuckCore''; $svc.WaitForStatus(''Running'', [TimeSpan]::FromSeconds(30)) } }; Remove-Item -LiteralPath $running -Force -ErrorAction SilentlyContinue; Remove-Item -LiteralPath $present -Force -ErrorAction SilentlyContinue; Remove-Item -LiteralPath $attempt -Force -ErrorAction SilentlyContinue; Remove-Item -LiteralPath $backup -Force -ErrorAction SilentlyContinue } catch { Set-Content -LiteralPath $failed -Value $_.Exception.Message -Encoding ascii; exit 1 }',
    ResultCode)) or (ResultCode <> 0) then
    Log(Format('ProxyDuck Core service rollback did not complete; transaction markers were retained (exit code %d).', [ResultCode]));
end;

procedure FailInstall(const Message: String);
begin
  RaiseException(Message);
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  ResultCode: Integer;
  MsiPath: String;
  StopScript: String;
begin
  if CurStep = ssDone then begin
    InstallSucceeded := True;
    Exit;
  end;

  if CurStep = ssInstall then begin
    { Stop before [Files] copies over a running service binary during an
      upgrade.  The command is idempotent for a first install. }
    WizardForm.StatusLabel.Caption := 'Stopping the existing ProxyDuck Core service...';
    StopScript := '$ErrorActionPreference=''Stop''; $root=Join-Path $env:ProgramData ''ProxyDuck''; $marker=Join-Path $root ''.service-was-running''; $present=Join-Path $root ''.service-was-present''; $backup=Join-Path $root ''.proxyduck-service.exe.backup''; $driverMarker=Join-Path $root ''.winpkfilter-was-present''; New-Item -ItemType Directory -Path $root -Force | Out-Null; Remove-Item -LiteralPath $marker -Force -ErrorAction SilentlyContinue; Remove-Item -LiteralPath $present -Force -ErrorAction SilentlyContinue; Remove-Item -LiteralPath $backup -Force -ErrorAction SilentlyContinue; Remove-Item -LiteralPath $driverMarker -Force -ErrorAction SilentlyContinue; $roots=@(''HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'',''HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*''); $driver=Get-ItemProperty $roots -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -eq ''Windows Packet Filter x64'' -or $_.PSChildName -eq ''{#WinpkFilterProductCode}'' } | Select-Object -First 1; if ($null -ne $driver -and [string]$driver.DisplayVersion -ne ''{#WinpkFilterVersion}'') { throw "an unsupported Windows Packet Filter version is already installed ($($driver.DisplayVersion)); refusing an unrollbackable driver upgrade" }; if ($null -ne $driver) { New-Item -ItemType File -Path $driverMarker -Force | Out-Null }; $target=Join-Path (Get-Location) ''proxyduck-service.exe''; $svc=Get-Service -Name ''ProxyDuckCore'' -ErrorAction SilentlyContinue; if ($null -ne $svc -and -not (Test-Path -LiteralPath $target -PathType Leaf)) { throw ''ProxyDuckCore service exists but the current service host is missing; refusing an unrollbackable upgrade'' }; if (Test-Path -LiteralPath $target -PathType Leaf) { Copy-Item -LiteralPath $target -Destination $backup -Force }; if ($null -ne $svc) { New-Item -ItemType File -Path $present -Force | Out-Null }; if ($null -ne $svc -and $svc.Status -ne ''Stopped'') { New-Item -ItemType File -Path $marker -Force | Out-Null; Stop-Service -Name ''ProxyDuckCore'' -Force; $svc.WaitForStatus(''Stopped'', [TimeSpan]::FromSeconds(30)) }';
    if (not Exec(
      ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe'),
      '-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "' + StopScript + '"',
      ExpandConstant('{app}'),
      SW_HIDE,
      ewWaitUntilTerminated,
      ResultCode
    )) or (ResultCode <> 0) then
      RaiseException(Format('Unable to stop the existing ProxyDuck Core service (exit code %d).', [ResultCode]));
    Exit;
  end;

  if CurStep <> ssPostInstall then
    Exit;

  MsiPath := ExpandConstant('{app}\drivers\{#WinpkFilterMsi}');
  if (not RunPowerShell(
    '$ErrorActionPreference=''Stop''; $root=Join-Path $env:ProgramData ''ProxyDuck''; New-Item -ItemType File -Path (Join-Path $root ''.winpkfilter-install-attempted'') -Force | Out-Null',
    ResultCode)) or (ResultCode <> 0) then
    FailInstall(Format('Unable to record the WinpkFilter transaction marker (exit code %d).', [ResultCode]));
  WizardForm.StatusLabel.Caption := 'Installing the bundled WinpkFilter driver...';
  if not Exec(
    ExpandConstant('{sys}\msiexec.exe'),
    '/i "' + MsiPath + '" /qn /norestart',
    ExpandConstant('{app}\drivers'),
    SW_HIDE,
    ewWaitUntilTerminated,
    ResultCode
  ) then
    FailInstall('Unable to start the WinpkFilter driver installer.');

  if (ResultCode = 1641) or (ResultCode = 3010) then
    WinpkFilterNeedsRestart := True
  else if ResultCode <> 0 then
    FailInstall(Format('WinpkFilter installation failed with Windows Installer exit code %d.', [ResultCode]));

  WizardForm.StatusLabel.Caption := 'Installing the ProxyDuck Core service...';
  if (not RunPowerShell(
    '$ErrorActionPreference=''Stop''; $root=Join-Path $env:ProgramData ''ProxyDuck''; New-Item -ItemType File -Path (Join-Path $root ''.service-install-attempted'') -Force | Out-Null',
    ResultCode)) or (ResultCode <> 0) then
    FailInstall(Format('Unable to record the ProxyDuck Core service transaction marker (exit code %d).', [ResultCode]));
  if (not Exec(
    ExpandConstant('{app}\proxyduck-service.exe'),
    '--install',
    ExpandConstant('{app}'),
    SW_HIDE,
    ewWaitUntilTerminated,
    ResultCode
  )) or (ResultCode <> 0) then
    FailInstall(Format('ProxyDuck Core service installation failed with exit code %d.', [ResultCode]));

  if not WinpkFilterNeedsRestart then begin
    WizardForm.StatusLabel.Caption := 'Starting the ProxyDuck Core service...';
    if (not Exec(
      ExpandConstant('{app}\proxyduck-service.exe'),
      '--start',
      ExpandConstant('{app}'),
      SW_HIDE,
      ewWaitUntilTerminated,
      ResultCode
    )) or (ResultCode <> 0) then
      FailInstall(Format('ProxyDuck Core service start failed with exit code %d.', [ResultCode]));
  end else
    WizardForm.StatusLabel.Caption := 'WinpkFilter requires a restart; the service will start after reboot.';
  ClearServiceMarker;
end;

procedure DeinitializeSetup;
begin
  { Runs for cancel/error paths as well as normal completion.  Inno has
    already performed its file rollback by the time this hook runs, so the
    backed-up service host is restored only after the new files are gone. }
  if not InstallSucceeded then begin
    { Inno may remove the application directory before this hook on a
      failed fresh install.  Keep a valid working directory for the
      rollback PowerShell calls; RestoreServiceIfNeeded removes any
      transaction artifacts after a successful restore. }
    if not DirExists(ExpandConstant('{app}')) then
      ForceDirectories(ExpandConstant('{app}'));
    RollbackFreshDriver;
    RestoreServiceIfNeeded;
  end;
end;

function NeedRestart(): Boolean;
begin
  Result := WinpkFilterNeedsRestart;
end;
