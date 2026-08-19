#define MyAppVersion GetEnv("MYTAIL_VERSION")
#define MyBinary GetEnv("MYTAIL_BINARY")

[Setup]
AppId={{D35187F7-B247-47E5-85E1-5E909F98B530}
AppName=MyTail Consent Agent
AppVersion={#MyAppVersion}
AppPublisher=Hirable AI Agents
AppPublisherURL=https://suporte.hirableaiagents.com
DefaultDirName={autopf}\MyTail
DefaultGroupName=MyTail
OutputDir=output
OutputBaseFilename=MyTail-Setup-Windows-x64
Compression=lzma2
SolidCompression=yes
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=admin
UninstallDisplayName=MyTail Consent Agent
WizardStyle=modern

[Languages]
Name: "brazilianportuguese"; MessagesFile: "compiler:Languages\BrazilianPortuguese.isl"

[Files]
Source: "{#MyBinary}"; DestDir: "{app}"; DestName: "mytail-agent.exe"; Flags: ignoreversion

[Icons]
Name: "{group}\Abrir painel do MyTail"; Filename: "http://127.0.0.1:8787"
Name: "{group}\Desinstalar MyTail"; Filename: "{uninstallexe}"

[Registry]
Root: HKLM; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "MyTailAgent"; ValueData: """{app}\mytail-agent.exe"""; Flags: uninsdeletevalue

[Run]
Filename: "{app}\mytail-agent.exe"; Parameters: "--open"; Description: "Iniciar e configurar o MyTail"; Flags: nowait postinstall skipifsilent runasoriginaluser

[UninstallRun]
Filename: "{sys}\taskkill.exe"; Parameters: "/F /IM mytail-agent.exe"; Flags: runhidden waituntilterminated; RunOnceId: "StopAgent"

[Code]
function InitializeSetup(): Boolean;
begin
  Result := MsgBox(
    'O MyTail instalará um agente iniciado com o Windows. Ele envia identificação da máquina e status ao servidor configurado, mostra autorizações no painel local e não executa comandos nem cria túneis nesta versão.' + #13#10 + #13#10 +
    'Deseja continuar?', mbConfirmation, MB_YESNO) = IDYES;
end;
