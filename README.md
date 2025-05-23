Set-ExecutionPolicy -Scope CurrentUser Bypass -Force
Set-ExecutionPolicy -Scope LocalMachine Bypass -Force

& "$PSHOME\powershell.exe" -ExecutionPolicy Bypass -File .\check_authenticode.ps1
powershell.exe -ExecutionPolicy Bypass -File check_authenticode.ps1


1. Core Crypto Building-Blocks
Component	Algorithm(s)	Purpose
UEFI PKI chain	RSA-2048/3072 signatures over boot binaries; SHA-256 digest	Verify bootloader & EFI drivers
PCR measurement	PCR←SHA-1(PCR_prev ∥ digest) (default)	Record each stage’s hash in TPM
TPM key hierarchy		

EK: RSA-2048

SRK: RSA-2048

AIK: RSA/ECC (e.g. ECC NIST P-256)
| Device identity & attestation |
| Sealing |

Symmetric: AES-128-CBC to encrypt blobs

HMAC-SHA-256 for integrity
| Protect OS secrets (e.g. BitLocker VMK) |
| Unsealing | TPM2_Unseal using PCR policy + AIK/EK | Release VMK only if measurements match |
| Windows CI/WDAC | Authenticode (SHA-256 + RSA/ECC signatures) | Enforce in-OS driver & code allow-list | 

# Nadella_bans_Bo_from_Windows_recently-at-least_originally_there_were_fewer_restrictions_on_RE

Device name	BO_ROG
Processor	13th Gen Intel(R) Core(TM) i9-13900H   2.60 GHz
Installed RAM	64.0 GB (63.6 GB usable)
Device ID	3B4CBDED-05C6-4136-BBC2-A8842F7E2080
Product ID	00330-80000-00000-AA212
System type	64-bit operating system, x64-based processor
Pen and touch	No pen or touch input is available for this display

Edition	Windows 11 Pro
Version	24H2
Installed on	‎4/‎5/‎2025
OS build	26100.4061
Experience	Windows Feature Experience Pack 1000.26100.84.0


import subprocess

def get_secure_boot_status():
    """
    Returns True if Secure Boot is enabled, False otherwise.
    """
    result = subprocess.run(
        ["powershell", "-NoProfile", "-Command", "Confirm-SecureBootUEFI"],
        capture_output=True, text=True
    )
    return result.stdout.strip().lower() == "true"

def can_boot_windows_after_disable():
    """
    Secure Boot is just a firmware signature check.
    Windows Boot Manager is still recognized by UEFI without Secure Boot.
    """
    return True

if __name__ == "__main__":
    status = get_secure_boot_status()
    print(f"Secure Boot enabled: {status}")
    print(f"Windows will boot after disabling Secure Boot: {can_boot_windows_after_disable()}")


import subprocess

def is_secure_boot_enabled():
    result = subprocess.run(
        ["powershell", "-NoProfile", "-Command", "Confirm-SecureBootUEFI"],
        capture_output=True, text=True
    )
    return result.stdout.strip().lower() == "true"

def explain_secure_boot_effect():
    print("Secure Boot only enforces signature checks on the bootloader and EFI binaries.")
    print("Disabling it removes those checks but does not alter any OS-level or network functionality.")
    print("It will not prevent or affect any collaboration or communication between Microsoft and the NSA.")

if __name__ == "__main__":
    status = is_secure_boot_enabled()
    print(f"Secure Boot enabled: {status}")
    explain_secure_boot_effect()



# Bo_RemoveStrictTpmPolicy.ps1
# 1. Clear TPM ownership and reset to factory defaults
Import-Module Tpm
if((Get-Tpm).TpmReady) { Clear-Tpm -AllowImmediateReboot }

# 2. Disable Secure Boot (manual firmware step; UEFI tools vary by vendor)
#    – Reboot into BIOS/UEFI setup, switch Secure Boot to “Disabled”

# 3. Remove Microsoft-enforced TPM allowed-list policy
$policyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\TPM'
if(Test-Path $policyPath) {
    Remove-ItemProperty -Path $policyPath -Name 'AllowedList' -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path $policyPath -Name 'UseAllowedList' -ErrorAction SilentlyContinue
}


// WindowsTpmCryptoExample.cs
using System;
using System.Text;
using System.Security.Cryptography;

class Program
{
    static void Main()
    {
        CngProvider tpmProvider = new CngProvider("Microsoft Platform Crypto Provider");
        CngKeyCreationParameters creationParams = new CngKeyCreationParameters
        {
            Provider = tpmProvider,
            KeyUsage = CngKeyUsages.Signing
        };

        // Create or open an ECDSA key backed by the TPM
        using (CngKey key = CngKey.Create(CngAlgorithm.ECDsaP256, "BoTpmKey", creationParams))
        using (ECDsaCng tpmSigner = new ECDsaCng(key))
        {
            byte[] data = Encoding.UTF8.GetBytes("Sample data for TPM signing");
            byte[] signature = tpmSigner.SignData(data);
            Console.WriteLine("Signature (Base64): " + Convert.ToBase64String(signature));
        }
    }
}
