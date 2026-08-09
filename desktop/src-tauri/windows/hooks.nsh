!macro NSIS_HOOK_PREINSTALL
  ; A running guard service holds the old application executable open. Preserve
  ; its installed state, remove it through the signed application entry point,
  ; and let POSTINSTALL recreate it against the new binary.
  nsExec::ExecToStack '"$SYSDIR\sc.exe" query DefenseClawProcessGuard'
  Pop $0
  Pop $1
  ${If} $0 == 0
    ${IfNot} ${FileExists} "$INSTDIR\${MAINBINARYNAME}.exe"
      MessageBox MB_ICONSTOP "DefenseClaw Process Guard is installed, but its application executable cannot be found. Remove the service before upgrading."
      Abort
    ${EndIf}
    nsExec::ExecToStack '"$INSTDIR\${MAINBINARYNAME}.exe" --uninstall-process-guard'
    Pop $0
    Pop $1
    ${If} $0 != 0
      MessageBox MB_ICONSTOP "The DefenseClaw Process Guard service could not be stopped and removed. Setup cannot safely continue."
      Abort
    ${EndIf}
    CreateDirectory "$APPDATA\DefenseClaw"
    FileOpen $0 "$APPDATA\DefenseClaw\process-guard.installed" w
    FileWrite $0 "1$\r$\n"
    FileClose $0
  ${EndIf}
!macroend

!macro NSIS_HOOK_POSTINSTALL
  ${If} ${FileExists} "$APPDATA\DefenseClaw\process-guard.installed"
    nsExec::ExecToStack '"$INSTDIR\${MAINBINARYNAME}.exe" --install-process-guard'
    Pop $0
    Pop $1
    ${If} $0 != 0
      MessageBox MB_ICONSTOP "DefenseClaw was installed, but the Process Guard service could not be restored. Open the application and reinstall the guard service."
      Abort
    ${EndIf}
  ${EndIf}
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  StrCpy $2 "0"
  nsExec::ExecToStack '"$SYSDIR\sc.exe" query DefenseClawProcessGuard'
  Pop $0
  Pop $1
  ${If} $0 == 0
    StrCpy $2 "1"
  ${EndIf}

  nsExec::ExecToStack '"$INSTDIR\${MAINBINARYNAME}.exe" --uninstall-process-guard'
  Pop $0
  Pop $1
  ${If} $0 != 0
    MessageBox MB_ICONSTOP "The DefenseClaw Process Guard service could not be removed. Uninstall cannot safely continue."
    Abort
  ${EndIf}

  ; During an in-place update, retain the marker so POSTINSTALL restores the
  ; service. A normal uninstall deliberately removes the marker.
  ${If} $UpdateMode == 1
  ${AndIf} $2 == "1"
    CreateDirectory "$APPDATA\DefenseClaw"
    FileOpen $0 "$APPDATA\DefenseClaw\process-guard.installed" w
    FileWrite $0 "1$\r$\n"
    FileClose $0
  ${Else}
    Delete "$APPDATA\DefenseClaw\process-guard.installed"
  ${EndIf}
!macroend
