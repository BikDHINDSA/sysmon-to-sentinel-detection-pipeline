# SAFE SIMULATION: creates a Run key pointing to notepad.exe (harmless),
# demonstrating the persistence TECHNIQUE without any real payload.

reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v LabPersistenceTest /t REG_SZ /d "C:\Windows\System32\notepad.exe"