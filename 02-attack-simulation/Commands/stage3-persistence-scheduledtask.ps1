# SAFE SIMULATION: scheduled task that would launch calc.exe on boot — harmless binary, real technique.

schtasks /create /tn "LabPersistenceTask" /tr "C:\Windows\System32\calc.exe" /sc onstart /ru System