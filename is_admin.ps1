# Check if running as Administrator and display execution policy settings
$IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Write-Output "IsAdministrator: $IsAdmin"
Get-ExecutionPolicy -List | Format-Table -AutoSize

# To run the unsigned script, bypass the execution policy
PowerShell -ExecutionPolicy Bypass -File .\check_authenticode.ps1
