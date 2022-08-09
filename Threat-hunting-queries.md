# Threat Hunting with Crowdstrike

Here I'll share some queries that will help threat hunters to find malicious activity. Most of them are custom queries, but others you can find them in the excellent subreddit [/crowdstrike](https://www.reddit.com/r/crowdstrike/)

You can try them, add the necesary FP and then add them to Scheduled Searches.

### Detecting Port Scanner tools
```
(event_simpleName=NetworkConnectIP4 AND RPort<10000) OR event_simpleName=ProcessRollup2 
| eval falconPID=coalesce(TargetProcessId_decimal, ContextProcessId_decimal)
| stats values(company), dc(event_simpleName) as eventCount, values(FileName) as fileName, values(CommandLine) as cmdLine, values(UserName) as userName, values(UserSid_readable) as userSID, dc(RPort) as uniquePortCount, values(RPort) as remotePorts, dc(RemoteAddressIP4) as remoteIPcount by aid, ComputerName, falconPID 
| where eventCount>1
| where uniquePortCount>10
| sort - uniquePortCount
| table company, ComputerName, falconPID, userName, userSID, fileName, cmdLine, remoteIPcount, uniquePortCount, remotePorts
```
### Malicious activity related with Kerberos
```
	
index=main event_platform=win sourcetype=ProcessRollup2* event_simpleName=ProcessRollup2
| search ImageFileName=*\\Users\\* OR ImageFileName=*\\ProgramData\\*
[ search index=main event_platform=win sourcetype IN (NetworkConnectIP6*, NetworkConnectIP4*) event_simpleName IN (NetworkConnectIP6, NetworkConnectIP4) 
| search RemotePort_decimal=389 RemoteIP!=127.0.0.1 
| where LPort > 49151 
| rename ContextProcessId_decimal as TargetProcessId_decimal 
| fields aid TargetProcessId_decimal] 
| table _time company ComputerName UserName ParentBaseFileName FilePath FileName CommandLine 
```
### LNK delivering DLL
```
event_platform=win event_simpleName=ProcessRollup2 LinkName!=C:\\*  FileName=rundll32.exe
| rex field=LinkName "(?<lnkFileLocation>.*\\\)(?<lnkFile>.*\.lnk)"
| table _time company ComputerName UserName ParentBaseFileName FileName lnkFile lnkFileLocation LinkName CommandLine
```
### Abnormal/Tunneled RDP connections
```
index=main event_simpleName=ProcessRollup2 (ImageFileName!="\\Device\\HarddiskVolume*\\Windows\\System32\\mstsc.exe" AND ImageFileName!="\\Device\\HarddiskVolume*\\Program Files\\Mozilla Firefox\\firefox.exe" AND ImageFileName!="\\Device\\HarddiskVolume*\\Program Files*\\Google\\Chrome\\Application\\chrome.exe" AND ImageFileName!="\\Device\\HarddiskVolume*\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe" AND ImageFileName!="\\Device\\HarddiskVolume*\\Users\\*\\AppData\\Local\\Google\\Chrome\\Application\\chrome.exe" AND ImageFileName!="\\Device\\HarddiskVolume*\\Users\\*\\AppData\\Local\\Mozilla Firefox\\firefox.exe" AND ImageFileName!="\\Device\\HarddiskVolume*\\Program Files*\\Royal TS V5\\RoyalTS.exe" AND ImageFileName!="\\Device\\HarddiskVolume*\\Program Files (x86)\\mRemoteNG\\mRemoteNG.exe" AND ImageFileName!="*\\Program Files (x86)\\Devolutions\\Remote Desktop Manager\\RemoteDesktopManager64.exe") ParentBaseFileName!=AgentPackageNetworkDiscovery.exe
[search (event_simpleName=NetworkConnectIP6 OR event_simpleName=NetworkConnectIP4) RemotePort_decimal=3389  
| rename ContextProcessId_decimal as TargetProcessId_decimal 
| fields aid TargetProcessId_decimal] 
| table  _time company ComputerName ParentBaseFileName ImageFileName CommandLine UserName
```
### LNK to Powershell
```
event_platform=win event_simpleName=ProcessRollup2 LinkName=* (ImageFileName=*\\powershell.exe OR *\\cmd.exe) CommandLine=*/c* OR *iwr* OR *FromBase64String* OR *curl*  
| rex field=LinkName "(?<lnkFileLocation>.*\\\)(?<lnkFile>.*\.lnk)"  
| table  _time company ComputerName UserName ParentBaseFileName FileName lnkFile lnkFileLocation LinkName CommandLine 
```
### Detect KrbRelayUp
```
index=main event_platform=win sourcetype=ProcessRollup2* event_simpleName=ProcessRollup2 
| search ImageFileName!=*\\Windows\\System32\\lsass.exe 
[ search index=main event_platform=win sourcetype IN (NetworkConnectIP6*, NetworkConnectIP4*) event_simpleName IN (NetworkConnectIP6, NetworkConnectIP4) 
| search RemotePort_decimal=88 RemoteIP!=127.0.0.1 
| where LPort > 49151 
| rename ContextProcessId_decimal as TargetProcessId_decimal 
| fields aid TargetProcessId_decimal] 
| table _time company ComputerName UserName ParentBaseFileName FileName CommandLine
```
### LOLBINs doing network requests to public IP
```
index=main event_simpleName=ProcessRollup2 (FileName=powershell.exe OR FileName=rundll32.exe OR FileName=cscript.exe OR FileName=wscript.exe OR FileName=mshta.exe OR FileName=cmd.exe OR FileName=regsvr32.exe OR FileName=msdt.exe OR FileName=powershell_ise.exe) [search (event_simpleName=NetworkConnectIP6 OR event_simpleName=NetworkConnectIP4 OR event_simpleName=DnsRequest) (DomainName=*) (DomainName!=*microsoft.com) 
| regex RemoteIP!="(^127\.)|(^10\.)|(^172\.1[6-9]\.)|(^172\.2[0-9]\.)|(^172\.3[0-1]\.)|(^192\.168\.)|(^100\.20\.)|(^200\.10\.10\.)|(^100\.114\.)|(^100\.65\.)|(31.14.161.42)|(90.69.80.90)" 
| rename ContextProcessId_decimal as TargetProcessId_decimal  
| fields aid TargetProcessId_decimal]   
| table  _time company ComputerName ParentBaseFileName FileName CommandLine UserName
```
### Logins from external IP
```
event_simpleName=UserLogon RemoteIP=* ComputerName!=build76cd9069-1
| regex RemoteIP!="(^127\.)|(^10\.)|(^172\.1[6-9]\.)|(^172\.2[0-9]\.)|(^172\.3[0-1]\.)|(^192\.168\.)|(^100\.20\.)|(^200\.10\.10\.)|(^100\.114\.)|(^100\.65\.)"
| Table _time event_simpleName company ComputerName UserName LogonType_decimal RemoteIP
```
