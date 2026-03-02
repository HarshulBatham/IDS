[Setup]
AppName=AeroGuard IDS
AppVersion=1.0.0
AppPublisher=AeroGuard Security
AppPublisherURL=https://aereguard.io
DefaultDirName={pf}\AeroGuard
DefaultGroupName=AeroGuard IDS
LicenseFile=LICENSE.txt
OutputBaseFilename=AeroGuard_IDS_Installer
OutputDir=dist
Compression=lzma
SolidCompression=yes
PrivilegesRequired=admin
ArchitecturesAllowed=x64
ArchitecturesInstallIn64BitMode=x64

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Components]
Name: "core"; Description: "AeroGuard IDS Core (ML + UI)"; Types: full compact custom; Flags: fixed
Name: "ollama"; Description: "Local Ollama LLM + Model (~2.5GB)"; Types: full; Flags: disablenouninstallwarning
Name: "backend"; Description: "FastAPI Backend Service"; Types: full; Flags: disablenouninstallwarning
Name: "wireshark"; Description: "Wireshark Integration (Optional)"; Types: full; Flags: disablenouninstallwarning

[Types]
Name: "full"; Description: "Full Installation (All Components)"
Name: "compact"; Description: "Compact Installation (UI Only - Cloud LLM)"
Name: "custom"; Description: "Custom Installation"

[Files]
; Core executable
Source: "dist\AeroGuard.exe"; DestDir: "{app}"; Components: core; Flags: ignoreversion

; Configuration files
Source: "config.json"; DestDir: "{app}"; Flags: ignoreversion
Source: "whitelist.json"; DestDir: "{app}"; Flags: ignoreversion
Source: "README.md"; DestDir: "{app}"; Flags: ignoreversion isreadme

; Model files
Source: "nstream_model.pkl"; DestDir: "{app}"; Flags: ignoreversion
Source: "nstream_scaler.pkl"; DestDir: "{app}"; Flags: ignoreversion
Source: "nstream_features.pkl"; DestDir: "{app}"; Flags: ignoreversion
Source: "nstream_app_encoder.pkl"; DestDir: "{app}"; Flags: ignoreversion

; Capture files
Source: "dummy.pcap"; DestDir: "{app}"; Flags: ignoreversion
Source: "live_capture.pcap"; DestDir: "{app}"; Flags: ignoreversion

; Ollama (only if selected)
Source: "ollama_installer.exe"; DestDir: "{tmp}"; Components: ollama; Flags: deleteafterinstall

; Backend files (if selected)
Source: "backend_api.py"; DestDir: "{app}\backend"; Components: backend; Flags: ignoreversion
Source: "requirements-backend.txt"; DestDir: "{app}\backend"; Components: backend; Flags: ignoreversion

[Icons]
Name: "{group}\AeroGuard IDS"; Filename: "{app}\AeroGuard.exe"; WorkingDir: "{app}"
Name: "{group}\Uninstall"; Filename: "{uninstallexe}"
Name: "{commondesktop}\AeroGuard IDS"; Filename: "{app}\AeroGuard.exe"; WorkingDir: "{app}"; IconIndex: 0

[Run]
; Install Ollama if selected
Filename: "{tmp}\ollama_installer.exe"; Components: ollama; Flags: waituntilterminated

; Install backend dependencies if selected
Filename: "cmd.exe"; Parameters: "/c pip install -r requirements-backend.txt"; WorkingDir: "{app}\backend"; Components: backend; Flags: skipifdoesntexist runhidden

; Start AeroGuard after installation
Filename: "{app}\AeroGuard.exe"; Description: "Launch AeroGuard IDS"; Flags: nowait postinstall skipifsilent

[UninstallDelete]
Type: filesandordirs; Name: "{app}"

[Registry]
; Register uninstall info
Root: HKLM; Subkey: "Software\Microsoft\Windows\CurrentVersion\Uninstall\AeroGuard IDS"; ValueType: string; ValueName: "DisplayName"; ValueData: "AeroGuard IDS"; Flags: uninsdeletevalue
Root: HKLM; Subkey: "Software\Microsoft\Windows\CurrentVersion\Uninstall\AeroGuard IDS"; ValueType: string; ValueName: "UninstallString"; ValueData: "{uninstallexe}"; Flags: uninsdeletevalue
Root: HKLM; Subkey: "Software\Microsoft\Windows\CurrentVersion\Uninstall\AeroGuard IDS"; ValueType: dword; ValueName: "NoModify"; ValueData: "1"
Root: HKLM; Subkey: "Software\Microsoft\Windows\CurrentVersion\Uninstall\AeroGuard IDS"; ValueType: dword; ValueName: "NoRepair"; ValueData: "1"

[Code]
procedure CurPageChanged(CurPageID: Integer);
begin
  if CurPageID = wpSelectComponents then
  begin
    MsgBox('Select installation components:' + #13 +
           '• Core: AeroGuard UI and ML engine (required)' + #13 +
           '• Ollama: Local LLM for offline analysis (~2.5GB)' + #13 +
           '• Backend: FastAPI service for cloud deployment' + #13 +
           '• Wireshark: Integration for packet analysis', mbInformation, MB_OK);
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usPostUninstall then
  begin
    // Optional: Remove user data
    if MsgBox('Remove saved configurations and models?', mbConfirmation, MB_YESNO) = IDYES then
    begin
      DelTree(ExpandConstant('{userappdata}\AeroGuard'), True, True, True);
    end;
  end;
end;

function ShouldSkipPage(PageID: Integer): Boolean;
begin
  Result := False;
end;

function InitializeSetup(): Boolean;
begin
  Result := True;
  // Check if running on Windows 7 or later
  if GetWindowsVersion < $06010000 then
  begin
    MsgBox('AeroGuard IDS requires Windows 7 or later.', mbCriticalError, MB_OK);
    Result := False;
  end;
end;
