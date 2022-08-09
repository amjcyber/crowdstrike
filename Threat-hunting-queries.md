# Threat Hunting with Crowdstrike

Here I'll share some queries that will help threat hunters to find malicious activity. Most of them are custom queries, but others you can find them in the excellent subreddit [/crowdstrike](https://www.reddit.com/r/crowdstrike/)

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
