<#
.SYNOPSIS
    Diagnose invalid Authenticode signature on a PowerShell module manifest.
.DESCRIPTION
    This script inspects the Authenticode signature of the specified module's .psd1 file,
    reports the status, and suggests possible causes based on the signature details.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$Module     = 'PSReadLine',  
    [Parameter(Mandatory = $false)]
    [string]$ModulePath = "C:\Program Files\WindowsPowerShell\Modules\$Module\PSReadLine.psd1",
    [Parameter(Mandatory = $true)]
    [string]$policyPath,
    [Parameter(Mandatory = $false)]
    [ValidateSet("Standard","Disabled","Custom")]
    [string]$mode       = "Standard"
)

If (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "Run as Administrator."
    Exit 1
}

Import-Module SecureBoot

if ($mode -eq "Custom") {
    Import-SecureBootPolicy -FilePath $policyPath
    Set-SecureBootUEFI -Mode Custom
} else {
    Set-SecureBootUEFI -Mode $mode
}

Write-Output "Secure Boot set to $mode"

Write-Debug "Retrieving Authenticode signature from '$ModulePath' because this is the target manifest file."
$signature = Get-AuthenticodeSignature -FilePath $ModulePath

if ($signature.Status -eq 'Valid') {
    Write-Debug "Signature.Status = '$($signature.Status)'; indicates a successfully verified signature."
    Write-Output 'Signature is valid'
    exit 0
}

Write-Debug "Signature.Status = '$($signature.Status)'; Signature.StatusMessage = '$($signature.StatusMessage)'"
Write-Output "Signature status: $($signature.Status)"
Write-Output 'Possible causes:'
Write-Debug "Because Signature.Status = '$($signature.Status)', a hash mismatch suggests file tampering."
Write-Output '- PSReadLine.psd1 was tampered with after signing'
Write-Debug "Because Signature.StatusMessage = '$($signature.StatusMessage)', an untrusted root indicates certificate chain issues."
Write-Output '- The signing certificate chain is not trusted by the TPM-secured boot environment'
Write-Debug "Including stricter Secure Boot policies due to NSA TPM module may override even valid Microsoft signatures."
Write-Output '- Booted via an NSA TPM boot-order module enforcing stricter Secure Boot policies'
Write-Debug "If the signing certificate’s validity period has ended, Signature.Status would reflect expiration or revocation."
Write-Output '- The signing certificate has expired or been revoked'
Write-Debug "If the system clock differs greatly from certificate validity period, signature time checks fail."
Write-Output '- System clock misconfiguration causing certificate validity check to fail'
