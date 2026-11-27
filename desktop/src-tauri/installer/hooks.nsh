; Stop a running backend before files are replaced or removed. Agents' state is in the database, so a running
; mission is marked interrupted and can be resumed after the upgrade. User data in %LOCALAPPDATA%\AIFusionOSPro is
; never touched by install, upgrade or uninstall.
!macro NSIS_HOOK_PREINSTALL
  IfFileExists "$INSTDIR\backend\python\python.exe" 0 +2
    nsExec::Exec '"$INSTDIR\backend\python\python.exe" -I -m fusion_os desktop-stop'
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  IfFileExists "$INSTDIR\backend\python\python.exe" 0 +2
    nsExec::Exec '"$INSTDIR\backend\python\python.exe" -I -m fusion_os desktop-stop'
!macroend
