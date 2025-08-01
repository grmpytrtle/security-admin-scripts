# Microsoft Defender for Endpoint - Advanced Hunting Queries

Useful queries for everyday functions.

---

## MDE AV Active / Passive Mode

The query shows all enrolled devices with Microsoft Defender in Active/Passive mode.

```kusto
let avmodetable = DeviceTvmSecureConfigurationAssessment
| where ConfigurationId == "scid-2010" and isnotnull(Context)
| extend avdata=parsejson(Context)
| extend AVMode = iif(tostring(avdata[0][0]) == '0', 'Active' , iif(tostring(avdata[0][0]) == '1', 'Passive' ,iif(tostring(avdata[0][0]) == '4', 'EDR Blocked' ,'Unknown')))
| project DeviceId, AVMode;
DeviceTvmSecureConfigurationAssessment
| where ConfigurationId == "scid-2011" and isnotnull(Context)
| extend avdata=parsejson(Context)
| extend AVSigVersion = tostring(avdata[0][0])
| extend AVEngineVersion = tostring(avdata[0][1])
| extend AVSigLastUpdateTime = tostring(avdata[0][2])
| project DeviceId, DeviceName, OSPlatform, AVSigVersion, AVEngineVersion, AVSigLastUpdateTime, IsCompliant, IsApplicable
| join avmodetable on DeviceId
| project-away DeviceId1
```
---

## Local Admin rights logon

Users that logon with local admin rights.

```kusto
DeviceLogonEvents
| where IsLocalAdmin == 1
//| extend locallogon = extractjson(“$.IsLocalLogon”, AdditionalFields, typeof(string))
| extend parsed = parse_json(AdditionalFields)
| extend LocalLogon=tostring(parsed.IsLocalLogon) 
| project Timestamp , DeviceName, AccountDomain, AccountName , LogonType, ActionType, LocalLogon
// summarize by user
| summarize LogonCount=count() by AccountName, DeviceName, AccountDomain
```
---

## Top 50 most downloaded EXE / MSI

The 50 most downloaded executables by count, this is to audit genuine files for AppLocker or MDE Indicator exclusions.

```kusto
DeviceProcessEvents
| where FolderPath has "AppData\\Local\\Downloads\\"
| where FileName endswith ".exe" or FileName endswith ".msi"
| extend FilePrefix = substring(FileName, 0, 8)
| summarize Count = count(), ExampleFileName = any(FileName) by substring(FileName, 0, 8)
| top 50 by Count desc
| project ExampleFileName, Count
```
---
