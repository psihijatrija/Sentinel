[Setup]
AppName=Sentinel
AppVersion=3.4.0
AppPublisher=Gorstak
AppPublisherURL=https://gorstak.eu
AppCopyright=Copyright (C) 2026 Gorstak
VersionInfoVersion=3.4.0.0
VersionInfoCompany=Gorstak
VersionInfoDescription=Sentinel Endpoint Detection and Response Setup
VersionInfoCopyright=Copyright (C) 2026 Gorstak
VersionInfoProductName=Sentinel EDR
VersionInfoProductVersion=3.4.0.0
VersionInfoOriginalFileName=SentinelSetup-3.4.0.exe
SourceDir=.
DefaultDirName={autopf}\Sentinel
DefaultGroupName=Sentinel
SetupIconFile=assets\Sentinel.ico
LicenseFile=assets\disclaimer.txt
UninstallDisplayIcon={app}\Sentinel.ico
Compression=lzma/max
SolidCompression=no
OutputDir=.
OutputBaseFilename=SentinelSetup-3.4.0
PrivilegesRequired=admin
SetupMutex=Global\SentinelSetupMutex
UsePreviousAppDir=yes
CloseApplications=no
RestartApplications=no

[Files]
Source: "assets\Sentinel.ico"; DestDir: "{app}"; Flags: ignoreversion
Source: "assets\disclaimer.txt"; DestDir: "{app}"; DestName: "DISCLAIMER.txt"; Flags: ignoreversion
Source: "..\publish\service\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\publish\agent\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\publish\autorotate\SentinelAutoRotate.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\publish\exploitshield\*"; DestDir: "{app}\ExploitShield"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\publish\nanoav\NanoAV.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\publish\nanoav\NanoAV.dll"; DestDir: "{app}"; Flags: ignoreversion

[InstallDelete]
; Force the unchanged NanoAV bootstrap to refresh its copied DLL and Run entry.
; Keep its configuration, database, logs, backups and quarantine intact.
Type: files; Name: "{commonappdata}\NanoAV\.installed"

[Tasks]
Name: "autorotate"; Description: "Enable SentinelAutoRotate (rotates this PC local account password to a random value every 10 minutes and turns on Windows autologon). The password becomes unknown to everyone and a machine-recoverable logon credential is stored, lowering at-rest security. Leave unchecked unless you specifically want this."; Flags: unchecked

[Icons]
Name: "{group}\Sentinel Agent"; Filename: "{app}\Sentinel.Agent.exe"; IconFilename: "{app}\Sentinel.ico"

[Run]
Filename: "{app}\Sentinel.Service.exe"; Parameters: "--install"; Flags: runhidden waituntilterminated; StatusMsg: "Starting Sentinel..."
Filename: "{app}\NanoAV.exe"; Flags: nowait; StatusMsg: "Starting independent NanoAV..."
Filename: "{app}\SentinelAutoRotate.exe"; Parameters: "--install"; Tasks: autorotate; Flags: runhidden waituntilterminated; StatusMsg: "Configuring SentinelAutoRotate..."
Filename: "{sys}\cmd.exe"; Parameters: "/c del /f /q ""{app}\*.old"" 2>nul & exit /b 0"; Flags: runhidden waituntilterminated

[UninstallDelete]
Type: filesandordirs; Name: "{app}"
Type: filesandordirs; Name: "{commonpf32}\Sentinel"

[Code]
procedure CurStepChanged(CurStep: TSetupStep);
var
  ResultCode: Integer;
begin
  if CurStep = ssPostInstall then
  begin
    ResultCode := -1;
    if not Exec(ExpandConstant('{app}\ExploitShield\Sentinel.ExploitShield.exe'), '--install', '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
      RaiseException('Could not start automatic exploit protection configuration.');
    if ResultCode <> 0 then
      RaiseException('Automatic exploit protection could not be scheduled. Check the ExploitShield audit log.');
  end;
end;

function IsDotNet48OrHigher(): Boolean;
var
  Release: Cardinal;
begin
  Result := False;
  if IsWin64 then
  begin
    if RegQueryDWordValue(HKLM64, 'SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full', 'Release', Release) then
    begin
      Result := Release >= 528040;
      Exit;
    end;
  end;
  if RegQueryDWordValue(HKLM, 'SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full', 'Release', Release) then
    Result := Release >= 528040;
end;

function OfferDotNet48Download(): Boolean;
var
  ErrCode: Integer;
begin
  Result := False;
  if MsgBox(
    'Sentinel requires .NET Framework 4.8.' + #13#10#13#10 +
    'Yes = open the Microsoft download page' + #13#10 +
    'No  = cancel Setup',
    mbConfirmation, MB_YESNO) = IDYES then
  begin
    ShellExec('open',
      'https://dotnet.microsoft.com/download/dotnet-framework/net48',
      '', '', SW_SHOWNORMAL, ewNoWait, ErrCode);
    MsgBox('After installing .NET Framework 4.8, run SentinelSetup again.', mbInformation, MB_OK);
  end;
end;

function InitializeSetup(): Boolean;
begin
  Result := True;
  if not IsDotNet48OrHigher() then
    Result := OfferDotNet48Download();
end;

function SysNative(const FileName: String): String;
begin
  Result := ExpandConstant('{sysnative}\') + FileName;
  if not FileExists(Result) then
    Result := ExpandConstant('{sys}\') + FileName;
end;

// Restore v2.3.7 upgrade unlock. Hardened installs add a Users Deny-Write on
// {app}; admin accounts are in Users, so Inno cannot overwrite unins000.exe
// (Access is denied). Window is admin Setup only; the service re-locks on start.
procedure ResetInstallDirAcls(const DirPath: String);
var
  ResultCode: Integer;
  Icacls, Takeown: String;
begin
  if not DirExists(DirPath) then
    Exit;

  Icacls := SysNative('icacls.exe');
  Takeown := SysNative('takeown.exe');

  if FileExists(DirPath + '\unins000.exe') then
  begin
    Exec(Takeown, '/A /F "' + DirPath + '\unins000.exe"', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Exec(Icacls, '"' + DirPath + '\unins000.exe" /remove:d *S-1-5-32-545 /C /Q', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Exec(Icacls, '"' + DirPath + '\unins000.exe" /grant Administrators:F /C /Q', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  end;
  if FileExists(DirPath + '\unins000.dat') then
  begin
    Exec(Takeown, '/A /F "' + DirPath + '\unins000.dat"', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Exec(Icacls, '"' + DirPath + '\unins000.dat" /remove:d *S-1-5-32-545 /C /Q', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Exec(Icacls, '"' + DirPath + '\unins000.dat" /grant Administrators:F /C /Q', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  end;

  Exec(Icacls, '"' + DirPath + '" /grant Administrators:(OI)(CI)F /T /C /Q', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec(Icacls, '"' + DirPath + '" /remove:d *S-1-5-32-545 /T /C /Q', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
end;

// Rename every loaded PE (EXE + DLL) in the install dir to *.old before the copy.
// A DLL mapped by the running Service/Agent cannot be overwritten or deleted
// (DeleteFile fails with "code 5, Access is denied"), but it CAN be renamed -
// Windows lets you rename a mapped image, and Inno then writes the new file in
// its place. The [Run] "del *.old" step cleans the renamed originals afterward.
procedure RenameLockedBinariesAside(const DirPath: String);
var
  FindRec: TFindRec;
  Name, Lower, Full: String;
begin
  if not DirExists(DirPath) then
    Exit;
  if FindFirst(DirPath + '\*', FindRec) then
  begin
    try
      repeat
        if (FindRec.Attributes and FILE_ATTRIBUTE_DIRECTORY) = 0 then
        begin
          Name := FindRec.Name;
          Lower := Lowercase(Name);
          // Only relocate PE images we ship and overwrite; leave *.old alone.
          if ((Copy(Lower, Length(Lower) - 3, 4) = '.dll') or
              (Copy(Lower, Length(Lower) - 3, 4) = '.exe')) then
          begin
            Full := DirPath + '\' + Name;
            RenameFile(Full, Full + '.old');
          end;
        end;
      until not FindNext(FindRec);
    finally
      FindClose(FindRec);
    end;
  end;
end;

procedure StopExistingService();
var
  ResultCode: Integer;
  Svc, Taskkill, Sc: String;
begin
  if FileExists(ExpandConstant('{app}\ExploitShield\Sentinel.ExploitShield.exe')) then
  begin
    ResultCode := -1;
    if not Exec(ExpandConstant('{app}\ExploitShield\Sentinel.ExploitShield.exe'), '--uninstall', '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
      RaiseException('Could not stop automatic exploit protection before upgrade.');
    if ResultCode <> 0 then
      RaiseException('Could not remove the old exploit protection schedule before upgrade.');
  end;
  Svc := ExpandConstant('{app}\Sentinel.Service.exe');
  if FileExists(Svc) then
  begin
    Exec(Svc, '--prepare-upgrade', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Sleep(800);
  end;

  // Stop the watchdog FIRST via the SCM, otherwise SentinelGuard restarts
  // Sentinel.Service mid-upgrade and re-locks the DLLs (the regression that
  // brought back "DeleteFile code 5"). Then stop the main service. Give the
  // SCM time to actually transition to STOPPED before we taskkill/rename.
  Sc := SysNative('sc.exe');
  Exec(Sc, 'stop SentinelGuard', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec(Sc, 'stop Sentinel', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Sleep(2000);

  Taskkill := SysNative('taskkill.exe');
  Exec(Taskkill, '/F /IM "Sentinel.Service.exe"', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec(Taskkill, '/F /IM "Sentinel.Agent.exe"', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec(Taskkill, '/F /IM "NanoAV.exe"', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Sleep(1500);

  ResetInstallDirAcls(ExpandConstant('{app}'));
  ResetInstallDirAcls(ExpandConstant('{commonpf}\Sentinel'));
  ResetInstallDirAcls(ExpandConstant('{commonpf32}\Sentinel'));
  ResetInstallDirAcls(ExpandConstant('{autopf}\Sentinel'));

  // Rename every loaded EXE/DLL aside so Inno can write the new payload even if
  // a handle is still mapped. Covers Sentinel.Core.dll and the
  // Microsoft.Extensions.*.dll set that tripped the failed upgrade.
  RenameLockedBinariesAside(ExpandConstant('{app}'));
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  Result := '';
  NeedsRestart := False;

  if RegValueExists(HKLM, 'SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'SentinelAgent') or
     RegKeyExists(HKLM, 'SYSTEM\CurrentControlSet\Services\Sentinel') or
     DirExists(ExpandConstant('{app}')) or
     DirExists(ExpandConstant('{commonpf32}\Sentinel')) then
  begin
    StopExistingService();
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  ResultCode: Integer;
  Taskkill, Svc: String;
begin
  if CurUninstallStep = usUninstall then
  begin
    if FileExists(ExpandConstant('{app}\ExploitShield\Sentinel.ExploitShield.exe')) then
    begin
      ResultCode := -1;
      if not Exec(ExpandConstant('{app}\ExploitShield\Sentinel.ExploitShield.exe'), '--uninstall', '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
        RaiseException('Could not stop Sentinel ExploitShield; uninstall cancelled.');
      if ResultCode <> 0 then
        RaiseException('Could not remove Sentinel ExploitShield schedule; uninstall cancelled.');
    end;
    // Tear down SentinelAutoRotate (scheduled tasks + autologon) before files
    // are removed, so the exe is still present to run its --uninstall cleanup.
    if FileExists(ExpandConstant('{app}\SentinelAutoRotate.exe')) then
      Exec(ExpandConstant('{app}\SentinelAutoRotate.exe'), '--uninstall', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);

    // Stop and kill service + agent before files are removed.
    // Without this the processes stay running and file deletion fails silently,
    // leaving both binaries on disk and the service registered.
    Svc := ExpandConstant('{app}\Sentinel.Service.exe');
    if FileExists(Svc) then
    begin
      ResultCode := -1;
      if not Exec(Svc, '--uninstall-cleanup', '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
        RaiseException('Sentinel firewall rollback could not start. The program files have been retained for recovery.');
      if ResultCode <> 0 then
        RaiseException('Sentinel firewall rollback failed. The program files have been retained for recovery. Repair the firewall policy or run --restore-firewall as administrator, then retry uninstall.');
      Sleep(800);
    end;

    Taskkill := SysNative('taskkill.exe');
    Exec(Taskkill, '/F /IM "Sentinel.Service.exe"', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Exec(Taskkill, '/F /IM "Sentinel.Agent.exe"', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Exec(Taskkill, '/F /IM "NanoAV.exe"', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Sleep(1000);

    // Remove IPSec policy and firewall rule created by Sentinel
    Exec(ExpandConstant('{sys}\netsh.exe'), 'ipsec static delete policy name=GSecurity', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Exec(ExpandConstant('{sys}\netsh.exe'), 'advfirewall firewall delete rule name="Sentinel-Block-Remote-RPC-Ephemeral"', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);

    // Remove agent autorun key
    RegDeleteValue(HKLM, 'SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'SentinelAgent');
    RegDeleteValue(HKCU, 'SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'NanoAV');
  end;
end;
