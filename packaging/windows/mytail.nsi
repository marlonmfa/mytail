Unicode True
RequestExecutionLevel admin
Name "MyTail Remote Support"
OutFile "..\..\dist\MyTail-Setup-Windows-x64.exe"
InstallDir "$PROGRAMFILES64\MyTail"
SetCompressor /SOLID lzma

!include "MUI2.nsh"
!include "nsDialogs.nsh"
!include "LogicLib.nsh"

Var ServerURL
Var MachineToken
Var ServerField
Var TokenField
Var ConsentCheckbox
Var ConsentAccepted

Function .onInit
  SetShellVarContext all
FunctionEnd

Function un.onInit
  SetShellVarContext all
FunctionEnd

Page custom ExplainPage ExplainPageLeave
Page custom ConfigurePage ConfigurePageLeave
Page directory
Page instfiles
Page custom ConnectivityPage
UninstPage uninstConfirm
UninstPage instfiles

Function ExplainPage
  nsDialogs::Create 1018
  Pop $0
  ${NSD_CreateLabel} 0 0 100% 32u "Acesso administrativo transparente"
  Pop $0
  ${NSD_CreateLabel} 0 38u 100% 92u "O MyTail será executado como SYSTEM e poderá abrir uma sessão administrativa somente após aprovação explícita e por tempo limitado.$\r$\n$\r$\nO instalador adiciona o cliente OpenSSH se necessário, gera uma chave exclusiva do dispositivo, inicia uma tarefa privilegiada no boot e testa HTTPS, TCP e autenticação SSH.$\r$\n$\r$\nNenhuma chave do operador é salva permanentemente. O endpoint SSH local escuta apenas em 127.0.0.1."
  Pop $0
  ${NSD_CreateCheckbox} 0 140u 100% 18u "Entendi e autorizo essas alterações administrativas"
  Pop $ConsentCheckbox
  nsDialogs::Show
FunctionEnd

Function ExplainPageLeave
  ${NSD_GetState} $ConsentCheckbox $ConsentAccepted
  ${If} $ConsentAccepted != ${BST_CHECKED}
    MessageBox MB_OK|MB_ICONSTOP "É necessário confirmar as alterações administrativas para continuar."
    Abort
  ${EndIf}
FunctionEnd

Function ConfigurePage
  nsDialogs::Create 1018
  Pop $0
  ${NSD_CreateLabel} 0 0 100% 16u "Servidor HTTPS do MyTail"
  Pop $0
  ${NSD_CreateText} 0 18u 100% 13u "https://broker-suporte.hirableaiagents.com"
  Pop $ServerField
  ${NSD_CreateLabel} 0 48u 100% 16u "Token de inscrição fornecido pelo suporte"
  Pop $0
  ${NSD_CreatePassword} 0 66u 100% 13u ""
  Pop $TokenField
  ${NSD_CreateLabel} 0 96u 100% 45u "Depois da cópia dos arquivos, o instalador testará o controle HTTPS, o relay, a autenticação da chave do dispositivo e o endpoint administrativo local."
  Pop $0
  nsDialogs::Show
FunctionEnd

Function ConfigurePageLeave
  ${NSD_GetText} $ServerField $ServerURL
  ${NSD_GetText} $TokenField $MachineToken
  ${If} $ServerURL == ""
  ${OrIf} $MachineToken == ""
    MessageBox MB_OK|MB_ICONSTOP "Informe o servidor e o token de inscrição."
    Abort
  ${EndIf}
FunctionEnd

Function ConnectivityPage
  nsDialogs::Create 1018
  Pop $0
  ${NSD_CreateLabel} 0 0 100% 30u "Testando conectividade com o servidor e o relay..."
  Pop $1
  ExecWait '"$INSTDIR\mytail-agent.exe" --test-only' $2
  ${If} $2 == 0
    ${NSD_SetText} $1 "Conectividade confirmada: HTTPS, relay TCP, autenticação SSH e endpoint administrativo local estão funcionando."
  ${Else}
    ${NSD_SetText} $1 "O teste de conectividade falhou (código $2). A instalação foi mantida, mas o acesso remoto não será iniciado. Revise o servidor, token, rede e execute novamente o instalador."
  ${EndIf}
  nsExec::ExecToLog 'schtasks.exe /Create /TN "MyTail Agent" /SC ONSTART /RU SYSTEM /RL HIGHEST /TR "$\"$INSTDIR\mytail-agent.exe$\"" /F'
  nsExec::ExecToLog 'schtasks.exe /Run /TN "MyTail Agent"'
  nsDialogs::Show
FunctionEnd

Section "Instalar"
  SetOutPath "$INSTDIR"
  File /oname=mytail-agent.exe "..\..\dist\mytail-agent-windows-amd64.exe"
  File /oname=cloudflared.exe "..\..\dist\cloudflared-windows-amd64.exe"
  CreateDirectory "$APPDATA\MyTail"
  FileOpen $0 "$APPDATA\MyTail\config.json" w
  FileWrite $0 '{$\r$\n  $\"server_url$\": $\"$ServerURL$\",$\r$\n  $\"machine_token$\": $\"$MachineToken$\",$\r$\n  $\"paused$\": false$\r$\n}$\r$\n'
  FileClose $0
  nsExec::ExecToLog 'icacls "$APPDATA\MyTail" /inheritance:r /grant "SYSTEM:(OI)(CI)F" /grant "Administrators:(OI)(CI)F"'
  nsExec::ExecToLog 'powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "if (-not (Get-Command ssh.exe -ErrorAction SilentlyContinue)) { Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0 | Out-Null }"'
  WriteUninstaller "$INSTDIR\Uninstall.exe"
  CreateDirectory "$SMPROGRAMS\MyTail"
  CreateShortcut "$SMPROGRAMS\MyTail\Abrir painel do MyTail.lnk" "http://127.0.0.1:8787"
  CreateShortcut "$SMPROGRAMS\MyTail\Desinstalar MyTail.lnk" "$INSTDIR\Uninstall.exe"
SectionEnd

Section "Uninstall"
  nsExec::ExecToLog 'schtasks.exe /End /TN "MyTail Agent"'
  nsExec::ExecToLog 'schtasks.exe /Delete /TN "MyTail Agent" /F'
  Delete "$SMPROGRAMS\MyTail\Abrir painel do MyTail.lnk"
  Delete "$SMPROGRAMS\MyTail\Desinstalar MyTail.lnk"
  RMDir "$SMPROGRAMS\MyTail"
  Delete "$INSTDIR\mytail-agent.exe"
  Delete "$INSTDIR\cloudflared.exe"
  Delete "$INSTDIR\Uninstall.exe"
  RMDir "$INSTDIR"
  MessageBox MB_YESNO "Remover também a configuração e a chave exclusiva deste dispositivo?" IDNO keepconfig
  RMDir /r "$APPDATA\MyTail"
keepconfig:
SectionEnd
