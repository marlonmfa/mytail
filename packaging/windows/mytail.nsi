Unicode True
RequestExecutionLevel user
Name "MyTail Consent Agent"
OutFile "..\..\dist\MyTail-Setup-Windows-x64.exe"
InstallDir "$LOCALAPPDATA\Programs\MyTail"
SetCompressor /SOLID lzma

Page custom ExplainPage
Page directory
Page instfiles
UninstPage uninstConfirm
UninstPage instfiles

Function ExplainPage
  MessageBox MB_OK|MB_ICONINFORMATION "O MyTail instala um agente iniciado com o Windows.$\r$\n$\r$\nEle envia a identificação da máquina e o status ao servidor que você configurar, mostra autorizações no painel local e pode ser pausado.$\r$\n$\r$\nEsta versão alfa NÃO executa comandos e NÃO cria túneis de rede."
FunctionEnd

Section "Instalar"
  SetOutPath "$INSTDIR"
  File /oname=mytail-agent.exe "..\..\dist\mytail-agent-windows-amd64.exe"
  WriteUninstaller "$INSTDIR\Uninstall.exe"
  CreateDirectory "$SMPROGRAMS\MyTail"
  CreateShortcut "$SMPROGRAMS\MyTail\Abrir painel do MyTail.lnk" "http://127.0.0.1:8787"
  CreateShortcut "$SMPROGRAMS\MyTail\Desinstalar MyTail.lnk" "$INSTDIR\Uninstall.exe"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Run" "MyTailAgent" '"$INSTDIR\mytail-agent.exe"'
  Exec '"$INSTDIR\mytail-agent.exe" --open'
SectionEnd

Section "Uninstall"
  ExecWait 'taskkill /F /IM mytail-agent.exe'
  DeleteRegValue HKCU "Software\Microsoft\Windows\CurrentVersion\Run" "MyTailAgent"
  Delete "$SMPROGRAMS\MyTail\Abrir painel do MyTail.lnk"
  Delete "$SMPROGRAMS\MyTail\Desinstalar MyTail.lnk"
  RMDir "$SMPROGRAMS\MyTail"
  Delete "$INSTDIR\mytail-agent.exe"
  Delete "$INSTDIR\Uninstall.exe"
  RMDir "$INSTDIR"
SectionEnd
