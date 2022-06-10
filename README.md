# Why

To understand how can we dump Windows Secrets internally.<br/>
Powershell implementation of [Secretsdump](<https://github.com/SecureAuthCorp/impacket/blob/master/examples/secretsdump.py>) and [Pypykatz](<https://github.com/skelsec/pypykatz>).<br/>
The script work on a local Windows machine: Powershell v2 to latest / Windows NT 6.0 to latest.<br/>
It is not intended to bypass AVs and you have to be administrator on the computer.<br/>
It is commented to understand each process. Currently It can:<br/>
   * Dump BootKey
   * Compute Hashed BootKey
   * Dump SAM
   * Dump LSA Secrets
      *	$MACHINE.ACC = Machine account password in clear text if computer is joined to a domain<br/>
      * DefaultPassword = Clear text password when autologon is configured for an account<br/>
      * NL$KM = Secret key in clear text for decrypting Cached Domain Credentials<br/>
      * DPAPI_SYSTEM = System User PreKey and System Machine PreKey in clear text for decrypting System User MasterKey files and System Machine MasterKey files (DPAPI)<br/>
      * \_SC\_&lt;ServiceName&gt; = Service account password in clear text<br/>
      * ASPNET_WP_PASSWORD = Password for .NET services in clear text<br/>
      * L$_SQSA_S-&lt;SID&gt; = Clear text answers for Windows Security Questions
   * Dump Cached Domain Credentials
   * Dump DPAPI Secrets<br/>
      * Wi-Fi passwords<br/>
      * <del>Chrome cookies/passwords</del> (Removed because It required loading ChilkatDotNet2 and System.Data.SQLite DLLs)<br/>
      * Vault Credential Manager passwords (VPOL and VCRD files)
   * Dump VNC passwords (RealVNC, TightVNC, TigerVNC, UltraVNC)
   * Dump NTDS.dit (Shadow Copy and parsing as ESE format)
   * Dump LSASS (ProcOpen and DupHandle methods)
   * List Session Tokens and Impersonate

# How it works

Download the script on target and from Powershell:
```
. <Path>\Get-WindowsSecrets.ps1;
Get-WindowsSecrets -Creds <User1>:<Pwd1>:<User2>:<Pwd2>
Get-WindowsSecrets -NTHashes <User>:<NTHash>
Get-WindowsSecrets -Creds <User>:<Pwd> -NTHashes <User1>:<NTHash1>/<User2>:<NTHash2>
Get-WindowsSecrets -SkipDPAPI $True
Get-WindowsSecrets
Get-WindowsSecrets -Impersonate <SID>
```

Creds and NTHashes parameters helped for DPAPI only (If you compromised these secrets for a user).
