# Why

To be able to really understand how can we dump Windows Secrets internally.
The script work on a local Windows machine. It is not intended to bypass AVs.
It is commented to understand each process. Currently It can :
	- Dump BootKey
	- Compute Hashed BootKey
	- Dump LSA Secrets
		- $MACHINE.ACC = Machine account password in clear text if computer is joined to a domain
		- DefaultPassword = Clear text password when autologon is configured for an account
		- NL$KM = Secret key in clear text for decrypting Cached Domain Credentials
		- DPAPI_SYSTEM = System User MasterKey and System Machine MasterKey in clear text for decrypting System User MasterKey files and System Machine MasterKey files (DPAPI)
		- _SC_<ServiceName> = Service account password in clear text
		- ASPNET_WP_PASSWORD = Password for .NET services in clear text
		- L$_SQSA_S-<SID> = Clear text answers for Windows Security Questions
	- DPAPI Secrets
		- Wi-Fi passwords
		- Chrome cookies/passwords

It is clearly inspired from Secretsdump (<https://github.com/SecureAuthCorp/impacket/blob/master/examples/secretsdump.py>) and Pypykatz (<https://github.com/skelsec/pypykatz>).

Sorry for my coding style.

# How it works

From PowerShell:

```
. <Path>\Get-WindowsSecrets.ps1; Get-WindowsSecrets -Creds <User1>:<Pwd1>:<User2>:<Pwd2>
. <Path>\Get-WindowsSecrets.ps1; Get-WindowsSecrets -NTHashes <User>:<NTHash>
. <Path>\Get-WindowsSecrets.ps1; Get-WindowsSecrets -Creds <User>:<Pwd> - NTHashes <User1>:<NTHash1>/<User2>:<NTHash2>
. <Path>\Get-WindowsSecrets.ps1; Get-WindowsSecrets
```
