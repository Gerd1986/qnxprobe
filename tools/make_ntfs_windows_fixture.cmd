@echo off
rem Builds a small NTFS volume in a VHD holding known data: WOF-compressed files in each
rem algorithm, an NTFS-compressed file, sparse files, hard links and cloud placeholders.
rem Everything it does is in make_ntfs_windows_fixture.ps1; results land beside this file.
rem Run it on Windows from an ordinary prompt (it asks to be elevated: diskpart needs it),
rem then run tools/finish_ntfs_windows_fixture.py on the folder it wrote into.
net session >nul 2>&1
if errorlevel 1 (
  powershell -NoProfile -Command "Start-Process -FilePath 'cmd.exe' -ArgumentList '/c %~f0' -Verb RunAs"
  exit /b
)
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0make_ntfs_windows_fixture.ps1" > "%~dp0run_console.txt" 2>&1
echo done >> "%~dp0run_console.txt"
