# Why

To be able to really understand how can we dump Windows Secrets internally.<br/>
The script work on a local Windows machine (Powershell v2 to latest). It is not intended to bypass AVs.<br/>
It is commented to understand each process. Currently It can :<br/>
   * Dump BootKey
   * Compute Hashed BootKey
   * Dump LSA Secrets
      *	$MACHINE.ACC = Machine account password in clear text if computer is joined to a domain<br/>
      * DefaultPassword = Clear text password when autologon is configured for an account<br/>
      * NL$KM = Secret key in clear text for decrypting Cached Domain Credentials<br/>
      * DPAPI_SYSTEM = System User MasterKey and System Machine MasterKey in clear text for decrypting System User MasterKey files and System Machine MasterKey files (DPAPI)<br/>
      * _SC_<ServiceName> = Service account password in clear text<br/>
      * ASPNET_WP_PASSWORD = Password for .NET services in clear text<br/>
      * L$_SQSA_S-<SID> = Clear text answers for Windows Security Questions
   * Cached Domain Credentials
   * DPAPI Secrets<br/>
      * Wi-Fi passwords<br/>
      * Chrome cookies/passwords<br/>

It is clearly inspired from Secretsdump (<https://github.com/SecureAuthCorp/impacket/blob/master/examples/secretsdump.py>) and Pypykatz (<https://github.com/skelsec/pypykatz>).
	
Check script to learn, sorry for coding style and hardcoded B64 DLL (ChiklatDotNet2 <https://www.chilkatsoft.com/downloads_DotNet.asp> and System.Data.SQLite <https://system.data.sqlite.org/index.html/doc/trunk/www/downloads.wiki>) ...

# How it works

Download the script on target and from Powershell:
```
. <Path>\Get-WindowsSecrets.ps1; Get-WindowsSecrets -Creds <User1>:<Pwd1>:<User2>:<Pwd2>
. <Path>\Get-WindowsSecrets.ps1; Get-WindowsSecrets -NTHashes <User>:<NTHash>
. <Path>\Get-WindowsSecrets.ps1; Get-WindowsSecrets -Creds <User>:<Pwd> -NTHashes <User1>:<NTHash1>/<User2>:<NTHash2>
. <Path>\Get-WindowsSecrets.ps1; Get-WindowsSecrets
```
