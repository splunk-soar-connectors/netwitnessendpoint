[comment]: # "Auto-generated SOAR connector documentation"
# NetWitness Endpoint

Publisher: Splunk  
Connector Version: 2\.0\.5  
Product Vendor: RSA  
Product Name: NetWitness Endpoint  
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 4\.10\.0\.40961  

This app supports executing various endpoint\-based investigative and containment actions on RSA NetWitness Endpoint

[comment]: # " File: readme.md"
[comment]: # "  Copyright (c) 2018-2022 Splunk Inc."
[comment]: # ""
[comment]: # "Licensed under the Apache License, Version 2.0 (the 'License');"
[comment]: # "you may not use this file except in compliance with the License."
[comment]: # "You may obtain a copy of the License at"
[comment]: # ""
[comment]: # "    http://www.apache.org/licenses/LICENSE-2.0"
[comment]: # ""
[comment]: # "Unless required by applicable law or agreed to in writing, software distributed under"
[comment]: # "the License is distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,"
[comment]: # "either express or implied. See the License for the specific language governing permissions"
[comment]: # "and limitations under the License."
[comment]: # ""
To enable users to efficiently prioritize suspicious endpoints and investigate, **RSA Netwitness
Endpoint** provides a scoring mechanism based on the behavior that was seen. Each endpoint will have
an aggregated suspect score, which is calculated based on the suspect scores of all modules found on
that endpoint. The suspect scores are calculated based on the IOCs that are triggered on the
endpoint.  
  
There are different levels of IOCs based on how suspicious the behavior is considered. IOCs have
four possible levels, ranging from 0 to 3. Below are the details of each IOC level:  
  

|           |          |                                             |                 |
|-----------|----------|---------------------------------------------|-----------------|
| IOC Level | Severity | Description                                 | IOC Score Range |
| 0         | Critical | Confirmed infection                         | 1024-1024       |
| 1         | High     | Highly suspicious activity                  | 128-1023        |
| 2         | Medium   | Activity might be suspicious                | 8-127           |
| 3         | Low      | More informational, but could be suspicious | 1-7             |


### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a NetWitness Endpoint asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**url** |  required  | string | Server URL \(e\.g\. https\://10\.10\.10\.10\:9443\)
**verify\_server\_cert** |  optional  | boolean | Verify server certificate
**username** |  required  | string | Username
**password** |  required  | password | Password
**max\_ioc\_level** |  required  | string | Maximum IOC level of modules to retrieve \(Default\: 2\)
**max\_ioc\_for\_scheduled\_poll** |  required  | numeric | Maximum Container \(IOC\) to ingest for the scheduled poll \(Default\: 5\)

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate credentials provided for connectivity  
[blocklist domain](#action-blocklist-domain) - Blocklist the domain  
[blocklist ip](#action-blocklist-ip) - Blocklist the IP  
[list endpoints](#action-list-endpoints) - Lists all the windows endpoints configured on NetWitness Endpoint  
[get system info](#action-get-system-info) - Get information about an endpoint  
[scan endpoint](#action-scan-endpoint) - Scan an endpoint  
[get scan data](#action-get-scan-data) - Get scan data of an endpoint  
[on poll](#action-on-poll) - Action to ingest endpoint related information  
[list ioc](#action-list-ioc) - List the IOC  
[get ioc](#action-get-ioc) - Get the IOC  

## action: 'test connectivity'
Validate credentials provided for connectivity

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'blocklist domain'
Blocklist the domain

Type: **contain**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**domain** |  required  | Domain to blocklist | string |  `domain`  `url` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.domain | string |  `domain`  `url` 
action\_result\.data\.\*\.domain | string |  `domain` 
action\_result\.message | string | 
action\_result\.summary\.domain | string | 
action\_result\.summary | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'blocklist ip'
Blocklist the IP

Type: **contain**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** |  required  | IP to blocklist | string |  `ip`  `ipv6` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.ip | string |  `ip`  `ipv6` 
action\_result\.data\.\*\.ip | string |  `ip`  `ipv6` 
action\_result\.message | string | 
action\_result\.summary | string | 
action\_result\.summary\.ip | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'list endpoints'
Lists all the windows endpoints configured on NetWitness Endpoint

Type: **investigate**  
Read only: **True**

If the <b>limit</b> parameter is 0 or not specified, the action will fetch all the windows endpoints\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**iocscore\_gte** |  optional  | Filter all machines whose IOC score is greater than or equal to this value \(Default\: 0\) | numeric | 
**iocscore\_lte** |  optional  | Filter all machines whose IOC score is less than or equal to this value \(Default\: 1024\) | numeric | 
**limit** |  optional  | Maximum number of endpoints to retrieve \(Default\: 50\) | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.iocscore\_gte | numeric | 
action\_result\.parameter\.iocscore\_lte | numeric | 
action\_result\.parameter\.limit | numeric | 
action\_result\.data\.\*\.Items\.\*\.Id | string |  `nwe machine guid` 
action\_result\.data\.\*\.Items\.\*\.Links\.\*\.href | string |  `url` 
action\_result\.data\.\*\.Items\.\*\.Links\.\*\.rel | string | 
action\_result\.data\.\*\.Items\.\*\.Name | string | 
action\_result\.data\.\*\.Items\.\*\.Properties\.Name | string | 
action\_result\.summary\.total\_endpoints | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get system info'
Get information about an endpoint

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**guid** |  required  | Machine GUID | string |  `nwe machine guid` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.guid | string |  `nwe machine guid` 
action\_result\.data\.\*\.Machine\.AdminStatus | string | 
action\_result\.data\.\*\.Machine\.AgentID | string |  `nwe machine guid` 
action\_result\.data\.\*\.Machine\.AllowAccessDataSourceDomain | string | 
action\_result\.data\.\*\.Machine\.AllowDisplayMixedContent | string | 
action\_result\.data\.\*\.Machine\.AntiVirusDisabled | string | 
action\_result\.data\.\*\.Machine\.BIOS | string | 
action\_result\.data\.\*\.Machine\.BadCertificateWarningDisabled | string | 
action\_result\.data\.\*\.Machine\.BlockingActive | string | 
action\_result\.data\.\*\.Machine\.BootTime | string | 
action\_result\.data\.\*\.Machine\.ChassisType | string | 
action\_result\.data\.\*\.Machine\.Comment | string | 
action\_result\.data\.\*\.Machine\.ConnectionTime | string | 
action\_result\.data\.\*\.Machine\.ContainmentStatus | string | 
action\_result\.data\.\*\.Machine\.ContainmentSupported | string | 
action\_result\.data\.\*\.Machine\.CookiesCleanupDisabled | string | 
action\_result\.data\.\*\.Machine\.Country | string | 
action\_result\.data\.\*\.Machine\.CrosssiteScriptFilterDisabled | string | 
action\_result\.data\.\*\.Machine\.DNS | string |  `ip` 
action\_result\.data\.\*\.Machine\.DebuggerAttachedToProcess | string | 
action\_result\.data\.\*\.Machine\.DomainName | string |  `domain` 
action\_result\.data\.\*\.Machine\.DomainRole | string | 
action\_result\.data\.\*\.Machine\.DriverErrorCode | string | 
action\_result\.data\.\*\.Machine\.DriverMonitorModule | string | 
action\_result\.data\.\*\.Machine\.ECATDriverCompileTime | string | 
action\_result\.data\.\*\.Machine\.ECATPackageTime | string | 
action\_result\.data\.\*\.Machine\.ECATServerName | string | 
action\_result\.data\.\*\.Machine\.ECATServiceCompileTime | string | 
action\_result\.data\.\*\.Machine\.EarlyStart | string | 
action\_result\.data\.\*\.Machine\.ErrorLogModule | string | 
action\_result\.data\.\*\.Machine\.FirewallDisabled | string | 
action\_result\.data\.\*\.Machine\.Gateway | string |  `ip` 
action\_result\.data\.\*\.Machine\.Group | string | 
action\_result\.data\.\*\.Machine\.HTTPSFallbackMode | string | 
action\_result\.data\.\*\.Machine\.IEDepDisabled | string | 
action\_result\.data\.\*\.Machine\.IEEnhancedSecurityDisabled | string | 
action\_result\.data\.\*\.Machine\.IIOCLevel0 | string | 
action\_result\.data\.\*\.Machine\.IIOCLevel1 | string | 
action\_result\.data\.\*\.Machine\.IIOCLevel2 | string | 
action\_result\.data\.\*\.Machine\.IIOCLevel3 | string | 
action\_result\.data\.\*\.Machine\.IIOCScore | string | 
action\_result\.data\.\*\.Machine\.Idle | string | 
action\_result\.data\.\*\.Machine\.ImageMonitorModule | string | 
action\_result\.data\.\*\.Machine\.IncludedinMonitoring | string | 
action\_result\.data\.\*\.Machine\.IncludedinScanSchedule | string | 
action\_result\.data\.\*\.Machine\.InstallTime | string | 
action\_result\.data\.\*\.Machine\.InstallationFailed | string | 
action\_result\.data\.\*\.Machine\.IntranetZoneNotificationDisabled | string | 
action\_result\.data\.\*\.Machine\.KernelDebuggerDetected | string | 
action\_result\.data\.\*\.Machine\.LUADisabled | string | 
action\_result\.data\.\*\.Machine\.Language | string | 
action\_result\.data\.\*\.Machine\.LastScan | string | 
action\_result\.data\.\*\.Machine\.LastSeen | string | 
action\_result\.data\.\*\.Machine\.LoadedModuleModule | string | 
action\_result\.data\.\*\.Machine\.LocalIP | string |  `ip` 
action\_result\.data\.\*\.Machine\.LowLevelReaderModule | string | 
action\_result\.data\.\*\.Machine\.MAC | string |  `mac address` 
action\_result\.data\.\*\.Machine\.MachineID | string | 
action\_result\.data\.\*\.Machine\.MachineName | string | 
action\_result\.data\.\*\.Machine\.MachineStatus | string | 
action\_result\.data\.\*\.Machine\.Manufacturer | string | 
action\_result\.data\.\*\.Machine\.Model | string | 
action\_result\.data\.\*\.Machine\.NetworkAdapterPromiscMode | string | 
action\_result\.data\.\*\.Machine\.NetworkSegment | string |  `ip` 
action\_result\.data\.\*\.Machine\.NoAntivirusNotificationDisabled | string | 
action\_result\.data\.\*\.Machine\.NoFirewallNotificationDisabled | string | 
action\_result\.data\.\*\.Machine\.NoUACNotificationDisabled | string | 
action\_result\.data\.\*\.Machine\.NoWindowsUpdateDisabled | string | 
action\_result\.data\.\*\.Machine\.NotifyRoutineModule | string | 
action\_result\.data\.\*\.Machine\.NotifyShutdownModule | string | 
action\_result\.data\.\*\.Machine\.OSBuildNumber | string | 
action\_result\.data\.\*\.Machine\.ObjectMonitorModule | string | 
action\_result\.data\.\*\.Machine\.Online | string | 
action\_result\.data\.\*\.Machine\.OperatingSystem | string | 
action\_result\.data\.\*\.Machine\.OrganizationUnit | string | 
action\_result\.data\.\*\.Machine\.Platform | string | 
action\_result\.data\.\*\.Machine\.ProcessModule | string | 
action\_result\.data\.\*\.Machine\.ProcessMonitorModule | string | 
action\_result\.data\.\*\.Machine\.ProcessorArchitecture | string | 
action\_result\.data\.\*\.Machine\.ProcessorCount | string | 
action\_result\.data\.\*\.Machine\.ProcessorIs32bits | string | 
action\_result\.data\.\*\.Machine\.ProcessorName | string | 
action\_result\.data\.\*\.Machine\.Processoris64 | string | 
action\_result\.data\.\*\.Machine\.RegistryToolsDisabled | string | 
action\_result\.data\.\*\.Machine\.RemoteIP | string |  `ip` 
action\_result\.data\.\*\.Machine\.RoamingAgentsRelaySystemActive | string | 
action\_result\.data\.\*\.Machine\.ScanStartTime | string | 
action\_result\.data\.\*\.Machine\.Scanning | string | 
action\_result\.data\.\*\.Machine\.Serial | string | 
action\_result\.data\.\*\.Machine\.ServicePackOS | string | 
action\_result\.data\.\*\.Machine\.SmartscreenFilterDisabled | string | 
action\_result\.data\.\*\.Machine\.StartTime | string | 
action\_result\.data\.\*\.Machine\.SystemRestoreDisabled | string | 
action\_result\.data\.\*\.Machine\.TaskManagerDisabled | string | 
action\_result\.data\.\*\.Machine\.TdiMonitorModule | string | 
action\_result\.data\.\*\.Machine\.ThreadMonitorModule | string | 
action\_result\.data\.\*\.Machine\.TimeZone | string | 
action\_result\.data\.\*\.Machine\.TotalPhysicalMemory | string | 
action\_result\.data\.\*\.Machine\.TrackingCreateProcessMonitor | string | 
action\_result\.data\.\*\.Machine\.TrackingFileBlockMonitor | string | 
action\_result\.data\.\*\.Machine\.TrackingFileMonitor | string | 
action\_result\.data\.\*\.Machine\.TrackingHardLinkMonitor | string | 
action\_result\.data\.\*\.Machine\.TrackingModule | string | 
action\_result\.data\.\*\.Machine\.TrackingNetworkMonitor | string | 
action\_result\.data\.\*\.Machine\.TrackingObjectMonitor | string | 
action\_result\.data\.\*\.Machine\.TrackingRegistryMonitor | string | 
action\_result\.data\.\*\.Machine\.TrackingRemoteThreadMonitor | string | 
action\_result\.data\.\*\.Machine\.Type | string | 
action\_result\.data\.\*\.Machine\.UACDisabled | string | 
action\_result\.data\.\*\.Machine\.UnloadedDriverModule | string | 
action\_result\.data\.\*\.Machine\.UserID | string | 
action\_result\.data\.\*\.Machine\.UserName | string |  `user name` 
action\_result\.data\.\*\.Machine\.VersionInfo | string | 
action\_result\.data\.\*\.Machine\.WarningOnZoneCrossingDisabled | string | 
action\_result\.data\.\*\.Machine\.WarningPostRedirectionDisabled | string | 
action\_result\.data\.\*\.Machine\.WindowsDirectory | string |  `file path` 
action\_result\.data\.\*\.Machine\.WindowsHooksModule | string | 
action\_result\.data\.\*\.Machine\.WorkerThreadModule | string | 
action\_result\.summary\.iiocscore | string | 
action\_result\.summary\.machine\_name | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'scan endpoint'
Scan an endpoint

Type: **investigate**  
Read only: **True**

Typical values for <b>scan\_category</b> parameter are\: <ul><li>None</li><li>Drivers</li><li>Processes</li><li>Kernel Hooks</li><li>Windows Hooks</li><li>Autoruns</li><li>Network</li><li>Services</li><li>Image Hooks</li><li>Files</li><li>Registry Discrepancies</li><li>Dlls</li><li>Security Products</li><li>Network Shares</li><li>Current Users</li><li>Loaded Files</li><li>Tasks</li><li>Hosts</li><li>Suspicious Threads</li><li>Windows Patches</li><li>All</li></ul>

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**guid** |  required  | Machine GUID | string |  `nwe machine guid` 
**scan\_category** |  optional  | Scan category \(Default\: All\) | string | 
**filter\_hooks** |  optional  | Filter hooks \(Default\: Signed Modules\) | string | 
**cpu\_max** |  optional  | Max % of CPU \(Default\: 95\) | numeric | 
**cpu\_max\_vm** |  optional  | Max % of CPU for VM \(Default\: 25\) | numeric | 
**cpu\_min** |  optional  | Min % of CPU \(Default\: 20\) | numeric | 
**capture\_floating\_code** |  optional  | Capture floating code during scan | boolean | 
**all\_network\_connections** |  optional  | Retrieve all network connections | boolean | 
**reset\_agent\_network\_cache** |  optional  | Reset the agent's network cache | boolean | 
**retrieve\_master\_boot\_record** |  optional  | Retrieve the master boot record | boolean | 
**notify** |  optional  | Notify upon reception | boolean | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.all\_network\_connections | boolean | 
action\_result\.parameter\.capture\_floating\_code | boolean | 
action\_result\.parameter\.cpu\_max | numeric | 
action\_result\.parameter\.cpu\_max\_vm | numeric | 
action\_result\.parameter\.cpu\_min | numeric | 
action\_result\.parameter\.filter\_hooks | string | 
action\_result\.parameter\.guid | string |  `nwe machine guid` 
action\_result\.parameter\.notify | boolean | 
action\_result\.parameter\.reset\_agent\_network\_cache | boolean | 
action\_result\.parameter\.retrieve\_master\_boot\_record | boolean | 
action\_result\.parameter\.scan\_category | string | 
action\_result\.data\.\*\.AlreadyScanning | boolean | 
action\_result\.data\.\*\.IsScanningCancelled | boolean | 
action\_result\.message | string | 
action\_result\.summary | string | 
action\_result\.summary\.guid | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get scan data'
Get scan data of an endpoint

Type: **investigate**  
Read only: **True**

This action will return the latest scan results\. If the latest scan was done with a specific category, the resulting scan results may not contain data for all categories\. If the <b>limit</b> parameter is 0 or not specified, the action will fetch complete data of all categories and for any other valid value, the action will fetch data equal to the limit specified for each category\. For a particular category, if the limit specified is greater than the available data, the action will fetch all data for that category\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**guid** |  required  | Machine GUID | string |  `nwe machine guid` 
**limit** |  optional  | Maximum number of records to retrieve for each category \(Default\: 50\) | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.guid | string |  `nwe machine guid` 
action\_result\.parameter\.limit | numeric | 
action\_result\.data\.\*\.AutoRuns\.\*\.ADS | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.AVDefinitionHash | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.AVDescription | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.AVFirstThreat | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.AVScanResult | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.AVVersion | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.AccessNetwork | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.AnalysisTime | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.AppDataLocal | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.AppDataRoaming | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.Arguments | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.AutoStartCategory | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.AutomaticBiasStatusAssignment | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.Autorun | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.AutorunAppInit | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.AutorunBoot | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.AutorunBootExecute | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.AutorunCodecs | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.AutorunDrivers | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.AutorunExplorer | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.AutorunImageHijack | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.AutorunInternetExplorer | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.AutorunKnownDLLs | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.AutorunLSAProviders | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.AutorunLogon | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.AutorunNetworkProviders | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.AutorunPrintMonitors | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.AutorunSafeBootMinimal | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.AutorunSafeBootNetwork | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.AutorunScheduledTask | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.AutorunServiceDLL | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.AutorunServices | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.AutorunStartupFolder | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.AutorunWinlogon | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.AutorunWinsockProviders | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.Beacon | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.BlacklistCategory | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.Blacklisted | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.BlockingStatus | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.BytesSentRatio | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.CertBiasStatus | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.CertModuleCount | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.CodeSectionWritable | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.CompanyName | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.CompanyNameCount | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.CompileTime | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.CreateProcess | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.CreateProcessNotification | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.CreateRemoteThread | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.CreateThreadNotification | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.CustomerOccurrences | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.DateBlocked | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.DaysSinceCompilation | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.DaysSinceCreation | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.DeleteExecutable | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.Description | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.Desktop | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.Downloaded | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.DownloadedTime | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.DuplicationSectionName | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.EmptySectionName | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.EncryptedDirectory | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.Entropy | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.FakeStartAddress | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.FileAccessDenied | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.FileAccessTime | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.FileAttributes | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.FileCreationTime | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.FileEncrypted | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.FileHiddenAttributes | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.FileHiddenXView | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.FileModificationTime | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.FileName | string |  `file name` 
action\_result\.data\.\*\.AutoRuns\.\*\.FileNameCount | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.FileOccurrences | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.FirewallAuthorized | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.FirstSeenDate | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.FirstSeenName | string |  `file name` 
action\_result\.data\.\*\.AutoRuns\.\*\.FirstTimeSeen | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.Floating | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.FolderCie | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.FolderExecutables | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.FolderFolder | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.FolderNonExecutables | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.Found | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.FullPath | string |  `file path` 
action\_result\.data\.\*\.AutoRuns\.\*\.Graylisted | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.HashLookup | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.HiddenAttributes | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.HiddenDirectory | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.HiddenFile | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.HiddenXView | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.HookEAT | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.HookIAT | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.HookInline | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.HookModule | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.HookType | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.Hooking | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.IIOCLevel0 | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.IIOCLevel1 | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.IIOCLevel2 | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.IIOCLevel3 | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.IIOCScore | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.IconPresent | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.ImageHidden | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.ImageMismatch | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.ImportedDLLCount | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.ImportedDLLs | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.InstallerDirectory | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.LikelyPacked | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.Listen | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.LiveConnectLastUpdated | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.LiveConnectRiskEnum | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.LiveConnectRiskReason | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.Loaded | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.MD5 | string |  `md5` 
action\_result\.data\.\*\.AutoRuns\.\*\.MD5Collision | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.MachineCount | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.ModifyBadCertificateWarningSetting | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.ModifyFirewallPolicy | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.ModifyInternetZoneSettings | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.ModifyIntranetZoneBrowsingNotificationSetting | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.ModifyLUASetting | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.ModifyRegistryEditorSetting | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.ModifySecurityCenterConfiguration | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.ModifyServicesImagePath | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.ModifyTaskManagerSetting | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.ModifyWindowsSystemPolicy | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.ModifyZoneCrossingWarningSetting | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.ModuleMemoryHash | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.ModuleName | string |  `file name` 
action\_result\.data\.\*\.AutoRuns\.\*\.NativeSubsystem | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.Net | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.Neutral | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.NoIcon | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.NoVersionInfo | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.NotFound | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.NotificationRegistered | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.NotificationRegisteredType | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.OpenBrowserProcess | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.OpenLogicalDrive | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.OpenOSProcess | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.OpenPhysicalDrive | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.OpenProcess | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.OriginalFileName | string |  `file name` 
action\_result\.data\.\*\.AutoRuns\.\*\.Packed | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.Path | string |  `file path` 
action\_result\.data\.\*\.AutoRuns\.\*\.Platform | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.ProcessAccessDenied | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.ProgramData | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.ProgramFiles | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.ReadDocument | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.RecordModifiedTime | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.RegistryPath | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.RelativeFileName | string |  `file name` 
action\_result\.data\.\*\.AutoRuns\.\*\.RelativePath | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.RemoteFileName | string |  `file name` 
action\_result\.data\.\*\.AutoRuns\.\*\.RemotePath | string |  `file path` 
action\_result\.data\.\*\.AutoRuns\.\*\.RenametoExecutable | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.ReservedName | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.RiskScore | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.SHA1 | string |  `sha1` 
action\_result\.data\.\*\.AutoRuns\.\*\.SHA256 | string |  `sha256` 
action\_result\.data\.\*\.AutoRuns\.\*\.SectionsNames | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.Signature | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.SignatureExpired | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.SignaturePresent | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.SignatureThumbprint | string |  `sha1` 
action\_result\.data\.\*\.AutoRuns\.\*\.SignatureTimeStamp | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.SignatureValid | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.SignedbyMicrosoft | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.SizeInBytes | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.Status | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.StatusComment | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.SysWOW64 | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.System32 | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.Temporary | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.TooManyConnections | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.Type | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.User | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.VersionInfoPresent | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.WFP | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.Whitelisted | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.Windows | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.WritetoExecutable | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.YaraDefinitionHash | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.YaraScanDescription | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.YaraScanFirstThreat | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.YaraScanresult | string | 
action\_result\.data\.\*\.AutoRuns\.\*\.YaraVersion | string | 
action\_result\.data\.\*\.Dlls\.\*\.ADS | string | 
action\_result\.data\.\*\.Dlls\.\*\.AVDefinitionHash | string | 
action\_result\.data\.\*\.Dlls\.\*\.AVDescription | string | 
action\_result\.data\.\*\.Dlls\.\*\.AVFirstThreat | string | 
action\_result\.data\.\*\.Dlls\.\*\.AVScanResult | string | 
action\_result\.data\.\*\.Dlls\.\*\.AVVersion | string | 
action\_result\.data\.\*\.Dlls\.\*\.AccessNetwork | string | 
action\_result\.data\.\*\.Dlls\.\*\.AnalysisTime | string | 
action\_result\.data\.\*\.Dlls\.\*\.AppDataLocal | string | 
action\_result\.data\.\*\.Dlls\.\*\.AppDataRoaming | string | 
action\_result\.data\.\*\.Dlls\.\*\.AutoStartCategory | string | 
action\_result\.data\.\*\.Dlls\.\*\.AutomaticBiasStatusAssignment | string | 
action\_result\.data\.\*\.Dlls\.\*\.Autorun | string | 
action\_result\.data\.\*\.Dlls\.\*\.AutorunAppInit | string | 
action\_result\.data\.\*\.Dlls\.\*\.AutorunBoot | string | 
action\_result\.data\.\*\.Dlls\.\*\.AutorunBootExecute | string | 
action\_result\.data\.\*\.Dlls\.\*\.AutorunCodecs | string | 
action\_result\.data\.\*\.Dlls\.\*\.AutorunDrivers | string | 
action\_result\.data\.\*\.Dlls\.\*\.AutorunExplorer | string | 
action\_result\.data\.\*\.Dlls\.\*\.AutorunImageHijack | string | 
action\_result\.data\.\*\.Dlls\.\*\.AutorunInternetExplorer | string | 
action\_result\.data\.\*\.Dlls\.\*\.AutorunKnownDLLs | string | 
action\_result\.data\.\*\.Dlls\.\*\.AutorunLSAProviders | string | 
action\_result\.data\.\*\.Dlls\.\*\.AutorunLogon | string | 
action\_result\.data\.\*\.Dlls\.\*\.AutorunNetworkProviders | string | 
action\_result\.data\.\*\.Dlls\.\*\.AutorunPrintMonitors | string | 
action\_result\.data\.\*\.Dlls\.\*\.AutorunSafeBootMinimal | string | 
action\_result\.data\.\*\.Dlls\.\*\.AutorunSafeBootNetwork | string | 
action\_result\.data\.\*\.Dlls\.\*\.AutorunScheduledTask | string | 
action\_result\.data\.\*\.Dlls\.\*\.AutorunServiceDLL | string | 
action\_result\.data\.\*\.Dlls\.\*\.AutorunServices | string | 
action\_result\.data\.\*\.Dlls\.\*\.AutorunStartupFolder | string | 
action\_result\.data\.\*\.Dlls\.\*\.AutorunWinlogon | string | 
action\_result\.data\.\*\.Dlls\.\*\.AutorunWinsockProviders | string | 
action\_result\.data\.\*\.Dlls\.\*\.Beacon | string | 
action\_result\.data\.\*\.Dlls\.\*\.BlacklistCategory | string | 
action\_result\.data\.\*\.Dlls\.\*\.Blacklisted | string | 
action\_result\.data\.\*\.Dlls\.\*\.BlockingStatus | string | 
action\_result\.data\.\*\.Dlls\.\*\.BytesSentRatio | string | 
action\_result\.data\.\*\.Dlls\.\*\.CertBiasStatus | string | 
action\_result\.data\.\*\.Dlls\.\*\.CertModuleCount | string | 
action\_result\.data\.\*\.Dlls\.\*\.CodeSectionWritable | string | 
action\_result\.data\.\*\.Dlls\.\*\.CompanyName | string | 
action\_result\.data\.\*\.Dlls\.\*\.CompanyNameCount | string | 
action\_result\.data\.\*\.Dlls\.\*\.CompileTime | string | 
action\_result\.data\.\*\.Dlls\.\*\.CreateProcess | string | 
action\_result\.data\.\*\.Dlls\.\*\.CreateProcessNotification | string | 
action\_result\.data\.\*\.Dlls\.\*\.CreateRemoteThread | string | 
action\_result\.data\.\*\.Dlls\.\*\.CreateThreadNotification | string | 
action\_result\.data\.\*\.Dlls\.\*\.CustomerOccurrences | string | 
action\_result\.data\.\*\.Dlls\.\*\.DateBlocked | string | 
action\_result\.data\.\*\.Dlls\.\*\.DaysSinceCompilation | string | 
action\_result\.data\.\*\.Dlls\.\*\.DaysSinceCreation | string | 
action\_result\.data\.\*\.Dlls\.\*\.DeleteExecutable | string | 
action\_result\.data\.\*\.Dlls\.\*\.Description | string | 
action\_result\.data\.\*\.Dlls\.\*\.Desktop | string | 
action\_result\.data\.\*\.Dlls\.\*\.Downloaded | string | 
action\_result\.data\.\*\.Dlls\.\*\.DownloadedTime | string | 
action\_result\.data\.\*\.Dlls\.\*\.DuplicationSectionName | string | 
action\_result\.data\.\*\.Dlls\.\*\.EPROCESS | string | 
action\_result\.data\.\*\.Dlls\.\*\.EProcess | string | 
action\_result\.data\.\*\.Dlls\.\*\.EmptySectionName | string | 
action\_result\.data\.\*\.Dlls\.\*\.EncryptedDirectory | string | 
action\_result\.data\.\*\.Dlls\.\*\.Entropy | string | 
action\_result\.data\.\*\.Dlls\.\*\.FakeStartAddress | string | 
action\_result\.data\.\*\.Dlls\.\*\.FileAccessDenied | string | 
action\_result\.data\.\*\.Dlls\.\*\.FileAccessTime | string | 
action\_result\.data\.\*\.Dlls\.\*\.FileAttributes | string | 
action\_result\.data\.\*\.Dlls\.\*\.FileCreationTime | string | 
action\_result\.data\.\*\.Dlls\.\*\.FileEncrypted | string | 
action\_result\.data\.\*\.Dlls\.\*\.FileHiddenAttributes | string | 
action\_result\.data\.\*\.Dlls\.\*\.FileHiddenXView | string | 
action\_result\.data\.\*\.Dlls\.\*\.FileModificationTime | string | 
action\_result\.data\.\*\.Dlls\.\*\.FileName | string |  `file name` 
action\_result\.data\.\*\.Dlls\.\*\.FileNameCount | string | 
action\_result\.data\.\*\.Dlls\.\*\.FileOccurrences | string | 
action\_result\.data\.\*\.Dlls\.\*\.FirewallAuthorized | string | 
action\_result\.data\.\*\.Dlls\.\*\.FirstSeenDate | string | 
action\_result\.data\.\*\.Dlls\.\*\.FirstSeenName | string |  `file name` 
action\_result\.data\.\*\.Dlls\.\*\.FirstTimeSeen | string | 
action\_result\.data\.\*\.Dlls\.\*\.Floating | string | 
action\_result\.data\.\*\.Dlls\.\*\.FolderCie | string | 
action\_result\.data\.\*\.Dlls\.\*\.FolderExecutables | string | 
action\_result\.data\.\*\.Dlls\.\*\.FolderFolder | string | 
action\_result\.data\.\*\.Dlls\.\*\.FolderNonExecutables | string | 
action\_result\.data\.\*\.Dlls\.\*\.Found | string | 
action\_result\.data\.\*\.Dlls\.\*\.FullPath | string |  `file path` 
action\_result\.data\.\*\.Dlls\.\*\.Graylisted | string | 
action\_result\.data\.\*\.Dlls\.\*\.HashLookup | string | 
action\_result\.data\.\*\.Dlls\.\*\.HiddenAttributes | string | 
action\_result\.data\.\*\.Dlls\.\*\.HiddenDirectory | string | 
action\_result\.data\.\*\.Dlls\.\*\.HiddenFile | string | 
action\_result\.data\.\*\.Dlls\.\*\.HiddenXView | string | 
action\_result\.data\.\*\.Dlls\.\*\.HookEAT | string | 
action\_result\.data\.\*\.Dlls\.\*\.HookIAT | string | 
action\_result\.data\.\*\.Dlls\.\*\.HookInline | string | 
action\_result\.data\.\*\.Dlls\.\*\.HookModule | string | 
action\_result\.data\.\*\.Dlls\.\*\.HookType | string | 
action\_result\.data\.\*\.Dlls\.\*\.Hooking | string | 
action\_result\.data\.\*\.Dlls\.\*\.IIOCLevel0 | string | 
action\_result\.data\.\*\.Dlls\.\*\.IIOCLevel1 | string | 
action\_result\.data\.\*\.Dlls\.\*\.IIOCLevel2 | string | 
action\_result\.data\.\*\.Dlls\.\*\.IIOCLevel3 | string | 
action\_result\.data\.\*\.Dlls\.\*\.IIOCScore | string | 
action\_result\.data\.\*\.Dlls\.\*\.IconPresent | string | 
action\_result\.data\.\*\.Dlls\.\*\.ImageBase | string | 
action\_result\.data\.\*\.Dlls\.\*\.ImageEnd | string | 
action\_result\.data\.\*\.Dlls\.\*\.ImageHidden | string | 
action\_result\.data\.\*\.Dlls\.\*\.ImageMismatch | string | 
action\_result\.data\.\*\.Dlls\.\*\.ImageSize | string | 
action\_result\.data\.\*\.Dlls\.\*\.ImportedDLLCount | string | 
action\_result\.data\.\*\.Dlls\.\*\.ImportedDLLs | string | 
action\_result\.data\.\*\.Dlls\.\*\.InstallerDirectory | string | 
action\_result\.data\.\*\.Dlls\.\*\.LikelyPacked | string | 
action\_result\.data\.\*\.Dlls\.\*\.Listen | string | 
action\_result\.data\.\*\.Dlls\.\*\.LiveConnectLastUpdated | string | 
action\_result\.data\.\*\.Dlls\.\*\.LiveConnectRiskEnum | string | 
action\_result\.data\.\*\.Dlls\.\*\.LiveConnectRiskReason | string | 
action\_result\.data\.\*\.Dlls\.\*\.Loaded | string | 
action\_result\.data\.\*\.Dlls\.\*\.MD5 | string |  `md5` 
action\_result\.data\.\*\.Dlls\.\*\.MD5Collision | string | 
action\_result\.data\.\*\.Dlls\.\*\.MachineCount | string | 
action\_result\.data\.\*\.Dlls\.\*\.ModifyBadCertificateWarningSetting | string | 
action\_result\.data\.\*\.Dlls\.\*\.ModifyFirewallPolicy | string | 
action\_result\.data\.\*\.Dlls\.\*\.ModifyInternetZoneSettings | string | 
action\_result\.data\.\*\.Dlls\.\*\.ModifyIntranetZoneBrowsingNotificationSetting | string | 
action\_result\.data\.\*\.Dlls\.\*\.ModifyLUASetting | string | 
action\_result\.data\.\*\.Dlls\.\*\.ModifyRegistryEditorSetting | string | 
action\_result\.data\.\*\.Dlls\.\*\.ModifySecurityCenterConfiguration | string | 
action\_result\.data\.\*\.Dlls\.\*\.ModifyServicesImagePath | string | 
action\_result\.data\.\*\.Dlls\.\*\.ModifyTaskManagerSetting | string | 
action\_result\.data\.\*\.Dlls\.\*\.ModifyWindowsSystemPolicy | string | 
action\_result\.data\.\*\.Dlls\.\*\.ModifyZoneCrossingWarningSetting | string | 
action\_result\.data\.\*\.Dlls\.\*\.ModuleMemoryHash | string | 
action\_result\.data\.\*\.Dlls\.\*\.ModuleName | string |  `file name` 
action\_result\.data\.\*\.Dlls\.\*\.NativeSubsystem | string | 
action\_result\.data\.\*\.Dlls\.\*\.Net | string | 
action\_result\.data\.\*\.Dlls\.\*\.Neutral | string | 
action\_result\.data\.\*\.Dlls\.\*\.NoIcon | string | 
action\_result\.data\.\*\.Dlls\.\*\.NoVersionInfo | string | 
action\_result\.data\.\*\.Dlls\.\*\.NotFound | string | 
action\_result\.data\.\*\.Dlls\.\*\.NotificationRegistered | string | 
action\_result\.data\.\*\.Dlls\.\*\.NotificationRegisteredType | string | 
action\_result\.data\.\*\.Dlls\.\*\.OpenBrowserProcess | string | 
action\_result\.data\.\*\.Dlls\.\*\.OpenLogicalDrive | string | 
action\_result\.data\.\*\.Dlls\.\*\.OpenOSProcess | string | 
action\_result\.data\.\*\.Dlls\.\*\.OpenPhysicalDrive | string | 
action\_result\.data\.\*\.Dlls\.\*\.OpenProcess | string | 
action\_result\.data\.\*\.Dlls\.\*\.OriginalFileName | string |  `file name` 
action\_result\.data\.\*\.Dlls\.\*\.PID | string |  `pid` 
action\_result\.data\.\*\.Dlls\.\*\.Packed | string | 
action\_result\.data\.\*\.Dlls\.\*\.Path | string |  `file path` 
action\_result\.data\.\*\.Dlls\.\*\.Platform | string | 
action\_result\.data\.\*\.Dlls\.\*\.ProcessAccessDenied | string | 
action\_result\.data\.\*\.Dlls\.\*\.ProcessContext | string | 
action\_result\.data\.\*\.Dlls\.\*\.ProcessCreationTime | string | 
action\_result\.data\.\*\.Dlls\.\*\.ProgramData | string | 
action\_result\.data\.\*\.Dlls\.\*\.ProgramFiles | string | 
action\_result\.data\.\*\.Dlls\.\*\.ReadDocument | string | 
action\_result\.data\.\*\.Dlls\.\*\.RecordModifiedTime | string | 
action\_result\.data\.\*\.Dlls\.\*\.RelativeFileName | string |  `file name` 
action\_result\.data\.\*\.Dlls\.\*\.RelativePath | string | 
action\_result\.data\.\*\.Dlls\.\*\.RemoteFileName | string |  `file name` 
action\_result\.data\.\*\.Dlls\.\*\.RemotePath | string |  `file path` 
action\_result\.data\.\*\.Dlls\.\*\.RenametoExecutable | string | 
action\_result\.data\.\*\.Dlls\.\*\.ReservedName | string | 
action\_result\.data\.\*\.Dlls\.\*\.RiskScore | string | 
action\_result\.data\.\*\.Dlls\.\*\.SHA1 | string |  `sha1` 
action\_result\.data\.\*\.Dlls\.\*\.SHA256 | string |  `sha256` 
action\_result\.data\.\*\.Dlls\.\*\.SectionsNames | string | 
action\_result\.data\.\*\.Dlls\.\*\.Signature | string | 
action\_result\.data\.\*\.Dlls\.\*\.SignatureExpired | string | 
action\_result\.data\.\*\.Dlls\.\*\.SignaturePresent | string | 
action\_result\.data\.\*\.Dlls\.\*\.SignatureThumbprint | string |  `sha1` 
action\_result\.data\.\*\.Dlls\.\*\.SignatureTimeStamp | string | 
action\_result\.data\.\*\.Dlls\.\*\.SignatureValid | string | 
action\_result\.data\.\*\.Dlls\.\*\.SignedbyMicrosoft | string | 
action\_result\.data\.\*\.Dlls\.\*\.SizeInBytes | string | 
action\_result\.data\.\*\.Dlls\.\*\.Status | string | 
action\_result\.data\.\*\.Dlls\.\*\.StatusComment | string | 
action\_result\.data\.\*\.Dlls\.\*\.SysWOW64 | string | 
action\_result\.data\.\*\.Dlls\.\*\.System32 | string | 
action\_result\.data\.\*\.Dlls\.\*\.Temporary | string | 
action\_result\.data\.\*\.Dlls\.\*\.TooManyConnections | string | 
action\_result\.data\.\*\.Dlls\.\*\.User | string | 
action\_result\.data\.\*\.Dlls\.\*\.VersionInfoPresent | string | 
action\_result\.data\.\*\.Dlls\.\*\.WFP | string | 
action\_result\.data\.\*\.Dlls\.\*\.Whitelisted | string | 
action\_result\.data\.\*\.Dlls\.\*\.Windows | string | 
action\_result\.data\.\*\.Dlls\.\*\.WritetoExecutable | string | 
action\_result\.data\.\*\.Dlls\.\*\.YaraDefinitionHash | string | 
action\_result\.data\.\*\.Dlls\.\*\.YaraScanDescription | string | 
action\_result\.data\.\*\.Dlls\.\*\.YaraScanFirstThreat | string | 
action\_result\.data\.\*\.Dlls\.\*\.YaraScanresult | string | 
action\_result\.data\.\*\.Dlls\.\*\.YaraVersion | string | 
action\_result\.data\.\*\.Drivers\.\*\.ADS | string | 
action\_result\.data\.\*\.Drivers\.\*\.AVDefinitionHash | string | 
action\_result\.data\.\*\.Drivers\.\*\.AVDescription | string | 
action\_result\.data\.\*\.Drivers\.\*\.AVFirstThreat | string | 
action\_result\.data\.\*\.Drivers\.\*\.AVScanResult | string | 
action\_result\.data\.\*\.Drivers\.\*\.AVVersion | string | 
action\_result\.data\.\*\.Drivers\.\*\.AccessNetwork | string | 
action\_result\.data\.\*\.Drivers\.\*\.AnalysisTime | string | 
action\_result\.data\.\*\.Drivers\.\*\.AppDataLocal | string | 
action\_result\.data\.\*\.Drivers\.\*\.AppDataRoaming | string | 
action\_result\.data\.\*\.Drivers\.\*\.AutoStartCategory | string | 
action\_result\.data\.\*\.Drivers\.\*\.AutomaticBiasStatusAssignment | string | 
action\_result\.data\.\*\.Drivers\.\*\.Autorun | string | 
action\_result\.data\.\*\.Drivers\.\*\.AutorunAppInit | string | 
action\_result\.data\.\*\.Drivers\.\*\.AutorunBoot | string | 
action\_result\.data\.\*\.Drivers\.\*\.AutorunBootExecute | string | 
action\_result\.data\.\*\.Drivers\.\*\.AutorunCodecs | string | 
action\_result\.data\.\*\.Drivers\.\*\.AutorunDrivers | string | 
action\_result\.data\.\*\.Drivers\.\*\.AutorunExplorer | string | 
action\_result\.data\.\*\.Drivers\.\*\.AutorunImageHijack | string | 
action\_result\.data\.\*\.Drivers\.\*\.AutorunInternetExplorer | string | 
action\_result\.data\.\*\.Drivers\.\*\.AutorunKnownDLLs | string | 
action\_result\.data\.\*\.Drivers\.\*\.AutorunLSAProviders | string | 
action\_result\.data\.\*\.Drivers\.\*\.AutorunLogon | string | 
action\_result\.data\.\*\.Drivers\.\*\.AutorunNetworkProviders | string | 
action\_result\.data\.\*\.Drivers\.\*\.AutorunPrintMonitors | string | 
action\_result\.data\.\*\.Drivers\.\*\.AutorunSafeBootMinimal | string | 
action\_result\.data\.\*\.Drivers\.\*\.AutorunSafeBootNetwork | string | 
action\_result\.data\.\*\.Drivers\.\*\.AutorunScheduledTask | string | 
action\_result\.data\.\*\.Drivers\.\*\.AutorunServiceDLL | string | 
action\_result\.data\.\*\.Drivers\.\*\.AutorunServices | string | 
action\_result\.data\.\*\.Drivers\.\*\.AutorunStartupFolder | string | 
action\_result\.data\.\*\.Drivers\.\*\.AutorunWinlogon | string | 
action\_result\.data\.\*\.Drivers\.\*\.AutorunWinsockProviders | string | 
action\_result\.data\.\*\.Drivers\.\*\.Beacon | string | 
action\_result\.data\.\*\.Drivers\.\*\.BlacklistCategory | string | 
action\_result\.data\.\*\.Drivers\.\*\.Blacklisted | string | 
action\_result\.data\.\*\.Drivers\.\*\.BlockingStatus | string | 
action\_result\.data\.\*\.Drivers\.\*\.BytesSentRatio | string | 
action\_result\.data\.\*\.Drivers\.\*\.CertBiasStatus | string | 
action\_result\.data\.\*\.Drivers\.\*\.CertModuleCount | string | 
action\_result\.data\.\*\.Drivers\.\*\.CodeSectionWritable | string | 
action\_result\.data\.\*\.Drivers\.\*\.CompanyName | string | 
action\_result\.data\.\*\.Drivers\.\*\.CompanyNameCount | string | 
action\_result\.data\.\*\.Drivers\.\*\.CompileTime | string | 
action\_result\.data\.\*\.Drivers\.\*\.CreateProcess | string | 
action\_result\.data\.\*\.Drivers\.\*\.CreateProcessNotification | string | 
action\_result\.data\.\*\.Drivers\.\*\.CreateRemoteThread | string | 
action\_result\.data\.\*\.Drivers\.\*\.CreateThreadNotification | string | 
action\_result\.data\.\*\.Drivers\.\*\.CustomerOccurrences | string | 
action\_result\.data\.\*\.Drivers\.\*\.DateBlocked | string | 
action\_result\.data\.\*\.Drivers\.\*\.DaysSinceCompilation | string | 
action\_result\.data\.\*\.Drivers\.\*\.DaysSinceCreation | string | 
action\_result\.data\.\*\.Drivers\.\*\.DeleteExecutable | string | 
action\_result\.data\.\*\.Drivers\.\*\.Description | string | 
action\_result\.data\.\*\.Drivers\.\*\.Desktop | string | 
action\_result\.data\.\*\.Drivers\.\*\.Downloaded | string | 
action\_result\.data\.\*\.Drivers\.\*\.DownloadedTime | string | 
action\_result\.data\.\*\.Drivers\.\*\.DuplicationSectionName | string | 
action\_result\.data\.\*\.Drivers\.\*\.EmptySectionName | string | 
action\_result\.data\.\*\.Drivers\.\*\.EncryptedDirectory | string | 
action\_result\.data\.\*\.Drivers\.\*\.Entropy | string | 
action\_result\.data\.\*\.Drivers\.\*\.FakeStartAddress | string | 
action\_result\.data\.\*\.Drivers\.\*\.FileAccessDenied | string | 
action\_result\.data\.\*\.Drivers\.\*\.FileAccessTime | string | 
action\_result\.data\.\*\.Drivers\.\*\.FileAttributes | string | 
action\_result\.data\.\*\.Drivers\.\*\.FileCreationTime | string | 
action\_result\.data\.\*\.Drivers\.\*\.FileEncrypted | string | 
action\_result\.data\.\*\.Drivers\.\*\.FileHiddenAttributes | string | 
action\_result\.data\.\*\.Drivers\.\*\.FileHiddenXView | string | 
action\_result\.data\.\*\.Drivers\.\*\.FileModificationTime | string | 
action\_result\.data\.\*\.Drivers\.\*\.FileName | string |  `file name` 
action\_result\.data\.\*\.Drivers\.\*\.FileNameCount | string | 
action\_result\.data\.\*\.Drivers\.\*\.FileOccurrences | string | 
action\_result\.data\.\*\.Drivers\.\*\.FirewallAuthorized | string | 
action\_result\.data\.\*\.Drivers\.\*\.FirstSeenDate | string | 
action\_result\.data\.\*\.Drivers\.\*\.FirstSeenName | string |  `file name` 
action\_result\.data\.\*\.Drivers\.\*\.FirstTimeSeen | string | 
action\_result\.data\.\*\.Drivers\.\*\.Floating | string | 
action\_result\.data\.\*\.Drivers\.\*\.FolderCie | string | 
action\_result\.data\.\*\.Drivers\.\*\.FolderExecutables | string | 
action\_result\.data\.\*\.Drivers\.\*\.FolderFolder | string | 
action\_result\.data\.\*\.Drivers\.\*\.FolderNonExecutables | string | 
action\_result\.data\.\*\.Drivers\.\*\.Found | string | 
action\_result\.data\.\*\.Drivers\.\*\.FullPath | string |  `file path` 
action\_result\.data\.\*\.Drivers\.\*\.Graylisted | string | 
action\_result\.data\.\*\.Drivers\.\*\.HashLookup | string | 
action\_result\.data\.\*\.Drivers\.\*\.HiddenAttributes | string | 
action\_result\.data\.\*\.Drivers\.\*\.HiddenDirectory | string | 
action\_result\.data\.\*\.Drivers\.\*\.HiddenFile | string | 
action\_result\.data\.\*\.Drivers\.\*\.HiddenXView | string | 
action\_result\.data\.\*\.Drivers\.\*\.HookEAT | string | 
action\_result\.data\.\*\.Drivers\.\*\.HookIAT | string | 
action\_result\.data\.\*\.Drivers\.\*\.HookInline | string | 
action\_result\.data\.\*\.Drivers\.\*\.HookModule | string | 
action\_result\.data\.\*\.Drivers\.\*\.HookType | string | 
action\_result\.data\.\*\.Drivers\.\*\.Hooking | string | 
action\_result\.data\.\*\.Drivers\.\*\.IIOCLevel0 | string | 
action\_result\.data\.\*\.Drivers\.\*\.IIOCLevel1 | string | 
action\_result\.data\.\*\.Drivers\.\*\.IIOCLevel2 | string | 
action\_result\.data\.\*\.Drivers\.\*\.IIOCLevel3 | string | 
action\_result\.data\.\*\.Drivers\.\*\.IIOCScore | string | 
action\_result\.data\.\*\.Drivers\.\*\.IconPresent | string | 
action\_result\.data\.\*\.Drivers\.\*\.ImageBase | string | 
action\_result\.data\.\*\.Drivers\.\*\.ImageHidden | string | 
action\_result\.data\.\*\.Drivers\.\*\.ImageMismatch | string | 
action\_result\.data\.\*\.Drivers\.\*\.ImageSize | string | 
action\_result\.data\.\*\.Drivers\.\*\.ImportedDLLCount | string | 
action\_result\.data\.\*\.Drivers\.\*\.ImportedDLLs | string | 
action\_result\.data\.\*\.Drivers\.\*\.InstallerDirectory | string | 
action\_result\.data\.\*\.Drivers\.\*\.LikelyPacked | string | 
action\_result\.data\.\*\.Drivers\.\*\.Listen | string | 
action\_result\.data\.\*\.Drivers\.\*\.LiveConnectLastUpdated | string | 
action\_result\.data\.\*\.Drivers\.\*\.LiveConnectRiskEnum | string | 
action\_result\.data\.\*\.Drivers\.\*\.LiveConnectRiskReason | string | 
action\_result\.data\.\*\.Drivers\.\*\.Loaded | string | 
action\_result\.data\.\*\.Drivers\.\*\.MD5 | string |  `md5` 
action\_result\.data\.\*\.Drivers\.\*\.MD5Collision | string | 
action\_result\.data\.\*\.Drivers\.\*\.MachineCount | string | 
action\_result\.data\.\*\.Drivers\.\*\.ModifyBadCertificateWarningSetting | string | 
action\_result\.data\.\*\.Drivers\.\*\.ModifyFirewallPolicy | string | 
action\_result\.data\.\*\.Drivers\.\*\.ModifyInternetZoneSettings | string | 
action\_result\.data\.\*\.Drivers\.\*\.ModifyIntranetZoneBrowsingNotificationSetting | string | 
action\_result\.data\.\*\.Drivers\.\*\.ModifyLUASetting | string | 
action\_result\.data\.\*\.Drivers\.\*\.ModifyRegistryEditorSetting | string | 
action\_result\.data\.\*\.Drivers\.\*\.ModifySecurityCenterConfiguration | string | 
action\_result\.data\.\*\.Drivers\.\*\.ModifyServicesImagePath | string | 
action\_result\.data\.\*\.Drivers\.\*\.ModifyTaskManagerSetting | string | 
action\_result\.data\.\*\.Drivers\.\*\.ModifyWindowsSystemPolicy | string | 
action\_result\.data\.\*\.Drivers\.\*\.ModifyZoneCrossingWarningSetting | string | 
action\_result\.data\.\*\.Drivers\.\*\.ModuleMemoryHash | string | 
action\_result\.data\.\*\.Drivers\.\*\.ModuleName | string |  `file name` 
action\_result\.data\.\*\.Drivers\.\*\.NativeSubsystem | string | 
action\_result\.data\.\*\.Drivers\.\*\.Net | string | 
action\_result\.data\.\*\.Drivers\.\*\.Neutral | string | 
action\_result\.data\.\*\.Drivers\.\*\.NoIcon | string | 
action\_result\.data\.\*\.Drivers\.\*\.NoVersionInfo | string | 
action\_result\.data\.\*\.Drivers\.\*\.NotFound | string | 
action\_result\.data\.\*\.Drivers\.\*\.NotificationRegistered | string | 
action\_result\.data\.\*\.Drivers\.\*\.NotificationRegisteredType | string | 
action\_result\.data\.\*\.Drivers\.\*\.OpenBrowserProcess | string | 
action\_result\.data\.\*\.Drivers\.\*\.OpenLogicalDrive | string | 
action\_result\.data\.\*\.Drivers\.\*\.OpenOSProcess | string | 
action\_result\.data\.\*\.Drivers\.\*\.OpenPhysicalDrive | string | 
action\_result\.data\.\*\.Drivers\.\*\.OpenProcess | string | 
action\_result\.data\.\*\.Drivers\.\*\.OriginalFileName | string |  `file name` 
action\_result\.data\.\*\.Drivers\.\*\.Packed | string | 
action\_result\.data\.\*\.Drivers\.\*\.Path | string |  `file path` 
action\_result\.data\.\*\.Drivers\.\*\.Platform | string | 
action\_result\.data\.\*\.Drivers\.\*\.ProcessAccessDenied | string | 
action\_result\.data\.\*\.Drivers\.\*\.ProgramData | string | 
action\_result\.data\.\*\.Drivers\.\*\.ProgramFiles | string | 
action\_result\.data\.\*\.Drivers\.\*\.ReadDocument | string | 
action\_result\.data\.\*\.Drivers\.\*\.RecordModifiedTime | string | 
action\_result\.data\.\*\.Drivers\.\*\.RelativeFileName | string |  `file name` 
action\_result\.data\.\*\.Drivers\.\*\.RelativePath | string | 
action\_result\.data\.\*\.Drivers\.\*\.RemoteFileName | string |  `file name` 
action\_result\.data\.\*\.Drivers\.\*\.RemotePath | string |  `file path` 
action\_result\.data\.\*\.Drivers\.\*\.RenametoExecutable | string | 
action\_result\.data\.\*\.Drivers\.\*\.ReservedName | string | 
action\_result\.data\.\*\.Drivers\.\*\.RiskScore | string | 
action\_result\.data\.\*\.Drivers\.\*\.SHA1 | string |  `sha1` 
action\_result\.data\.\*\.Drivers\.\*\.SHA256 | string |  `sha256` 
action\_result\.data\.\*\.Drivers\.\*\.SectionsNames | string | 
action\_result\.data\.\*\.Drivers\.\*\.Signature | string | 
action\_result\.data\.\*\.Drivers\.\*\.SignatureExpired | string | 
action\_result\.data\.\*\.Drivers\.\*\.SignaturePresent | string | 
action\_result\.data\.\*\.Drivers\.\*\.SignatureThumbprint | string |  `sha1` 
action\_result\.data\.\*\.Drivers\.\*\.SignatureTimeStamp | string | 
action\_result\.data\.\*\.Drivers\.\*\.SignatureValid | string | 
action\_result\.data\.\*\.Drivers\.\*\.SignedbyMicrosoft | string | 
action\_result\.data\.\*\.Drivers\.\*\.SizeInBytes | string | 
action\_result\.data\.\*\.Drivers\.\*\.Status | string | 
action\_result\.data\.\*\.Drivers\.\*\.StatusComment | string | 
action\_result\.data\.\*\.Drivers\.\*\.SysWOW64 | string | 
action\_result\.data\.\*\.Drivers\.\*\.System32 | string | 
action\_result\.data\.\*\.Drivers\.\*\.Temporary | string | 
action\_result\.data\.\*\.Drivers\.\*\.TooManyConnections | string | 
action\_result\.data\.\*\.Drivers\.\*\.User | string | 
action\_result\.data\.\*\.Drivers\.\*\.VersionInfoPresent | string | 
action\_result\.data\.\*\.Drivers\.\*\.WFP | string | 
action\_result\.data\.\*\.Drivers\.\*\.Whitelisted | string | 
action\_result\.data\.\*\.Drivers\.\*\.Windows | string | 
action\_result\.data\.\*\.Drivers\.\*\.WritetoExecutable | string | 
action\_result\.data\.\*\.Drivers\.\*\.YaraDefinitionHash | string | 
action\_result\.data\.\*\.Drivers\.\*\.YaraScanDescription | string | 
action\_result\.data\.\*\.Drivers\.\*\.YaraScanFirstThreat | string | 
action\_result\.data\.\*\.Drivers\.\*\.YaraScanresult | string | 
action\_result\.data\.\*\.Drivers\.\*\.YaraVersion | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.ADS | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.AVDefinitionHash | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.AVDescription | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.AVFirstThreat | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.AVScanResult | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.AVVersion | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.AccessNetwork | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.AnalysisTime | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.AppDataLocal | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.AppDataRoaming | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.Assigned | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.AutoStartCategory | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.AutomaticAssignment | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.AutomaticBiasStatusAssignment | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.Autorun | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.AutorunAppInit | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.AutorunBoot | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.AutorunBootExecute | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.AutorunCodecs | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.AutorunDrivers | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.AutorunExplorer | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.AutorunImageHijack | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.AutorunInternetExplorer | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.AutorunKnownDLLs | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.AutorunLSAProviders | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.AutorunLogon | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.AutorunNetworkProviders | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.AutorunPrintMonitors | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.AutorunSafeBootMinimal | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.AutorunSafeBootNetwork | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.AutorunScheduledTask | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.AutorunServiceDLL | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.AutorunServices | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.AutorunStartupFolder | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.AutorunWinlogon | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.AutorunWinsockProviders | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.Beacon | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.BlacklistCategory | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.Blacklisted | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.BlockingStatus | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.BytesSentRatio | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.CertBiasStatus | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.CertModuleCount | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.CodeSectionWritable | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.CompanyName | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.CompanyNameCount | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.CompileTime | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.CreateProcess | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.CreateProcessNotification | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.CreateRemoteThread | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.CreateThreadNotification | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.CurrentBytes | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.CurrentBytesCount | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.CustomerOccurrences | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.DateBlocked | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.DaysSinceCompilation | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.DaysSinceCreation | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.DeleteExecutable | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.Description | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.Desktop | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.Downloaded | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.DownloadedTime | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.DuplicationSectionName | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.EmptySectionName | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.EncryptedDirectory | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.Entropy | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.FakeStartAddress | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.FileAccessDenied | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.FileAccessTime | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.FileAttributes | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.FileCreationTime | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.FileEncrypted | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.FileHiddenAttributes | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.FileHiddenXView | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.FileModificationTime | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.FileNameCount | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.FileOccurrences | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.FinalEPROCESS | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.FinalProcessCreationTime | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.FinalProcessID | string |  `pid` 
action\_result\.data\.\*\.ImageHooks\.\*\.FinalTarget | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.FirewallAuthorized | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.FirstSeenDate | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.FirstSeenName | string |  `file name` 
action\_result\.data\.\*\.ImageHooks\.\*\.FirstTimeSeen | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.Floating | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.FolderCie | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.FolderExecutables | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.FolderFolder | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.FolderNonExecutables | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.Found | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.FullPath | string |  `file path` 
action\_result\.data\.\*\.ImageHooks\.\*\.Graylisted | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.HashLookup | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.HiddenAttributes | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.HiddenDirectory | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.HiddenFile | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.HiddenXView | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.HookEAT | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.HookIAT | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.HookInline | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.HookModule | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.HookType | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.HookedAddress | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.HookedEPROCESS | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.HookedFunction | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.HookedImageBase | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.HookedModuleFileName | string |  `file name` 
action\_result\.data\.\*\.ImageHooks\.\*\.HookedModulePath | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.HookedProcess | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.HookedProcessCreationTime | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.HookedProcessFileName | string |  `file name` 
action\_result\.data\.\*\.ImageHooks\.\*\.HookedProcessID | string |  `pid` 
action\_result\.data\.\*\.ImageHooks\.\*\.HookedProcessPath | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.HookedSection | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.HookedSectionBase | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.HookedSymbol | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.HookedSymbolOffset | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.HookerModuleFileName | string |  `file name` 
action\_result\.data\.\*\.ImageHooks\.\*\.HookerModulePath | string |  `file path` 
action\_result\.data\.\*\.ImageHooks\.\*\.Hooking | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.IIOCLevel0 | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.IIOCLevel1 | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.IIOCLevel2 | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.IIOCLevel3 | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.IIOCScore | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.IconPresent | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.ImageHidden | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.ImageHookType | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.ImageMismatch | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.ImportedDLLCount | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.ImportedDLLs | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.InitialTarget | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.InstallerDirectory | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.JumpCount | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.LikelyPacked | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.Listen | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.LiveConnectLastUpdated | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.LiveConnectRiskEnum | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.LiveConnectRiskReason | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.Loaded | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.MD5 | string |  `md5` 
action\_result\.data\.\*\.ImageHooks\.\*\.MD5Collision | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.MachineCount | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.ModifyBadCertificateWarningSetting | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.ModifyFirewallPolicy | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.ModifyInternetZoneSettings | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.ModifyIntranetZoneBrowsingNotificationSetting | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.ModifyLUASetting | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.ModifyRegistryEditorSetting | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.ModifySecurityCenterConfiguration | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.ModifyServicesImagePath | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.ModifyTaskManagerSetting | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.ModifyWindowsSystemPolicy | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.ModifyZoneCrossingWarningSetting | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.ModuleMemoryHash | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.ModuleName | string |  `file name` 
action\_result\.data\.\*\.ImageHooks\.\*\.NativeSubsystem | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.Net | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.Neutral | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.NoIcon | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.NoVersionInfo | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.NotFound | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.NotificationRegistered | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.NotificationRegisteredType | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.OpenBrowserProcess | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.OpenLogicalDrive | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.OpenOSProcess | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.OpenPhysicalDrive | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.OpenProcess | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.OriginalBytes | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.OriginalBytesCount | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.OriginalFileName | string |  `file name` 
action\_result\.data\.\*\.ImageHooks\.\*\.Packed | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.Platform | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.ProcessAccessDenied | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.ProgramData | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.ProgramFiles | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.ReadDocument | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.RecordModifiedTime | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.RelativeFileName | string |  `file name` 
action\_result\.data\.\*\.ImageHooks\.\*\.RelativePath | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.RemoteFileName | string |  `file name` 
action\_result\.data\.\*\.ImageHooks\.\*\.RemotePath | string |  `file path` 
action\_result\.data\.\*\.ImageHooks\.\*\.RenametoExecutable | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.ReservedName | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.RiskScore | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.SHA1 | string |  `sha1` 
action\_result\.data\.\*\.ImageHooks\.\*\.SHA256 | string |  `sha256` 
action\_result\.data\.\*\.ImageHooks\.\*\.SectionsNames | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.Signature | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.SignatureExpired | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.SignaturePresent | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.SignatureThumbprint | string |  `sha1` 
action\_result\.data\.\*\.ImageHooks\.\*\.SignatureTimeStamp | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.SignatureValid | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.SignedbyMicrosoft | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.SizeInBytes | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.Status | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.StatusComment | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.SysWOW64 | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.System32 | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.Temporary | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.TooManyConnections | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.User | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.VersionInfoPresent | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.WFP | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.Whitelisted | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.Windows | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.WritetoExecutable | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.YaraDefinitionHash | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.YaraScanDescription | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.YaraScanFirstThreat | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.YaraScanresult | string | 
action\_result\.data\.\*\.ImageHooks\.\*\.YaraVersion | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.ADS | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.AVDefinitionHash | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.AVDescription | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.AVFirstThreat | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.AVScanResult | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.AVVersion | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.AccessNetwork | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.AnalysisTime | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.AppDataLocal | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.AppDataRoaming | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.Assigned | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.AutoStartCategory | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.AutomaticAssignment | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.AutomaticBiasStatusAssignment | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.Autorun | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.AutorunAppInit | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.AutorunBoot | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.AutorunBootExecute | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.AutorunCodecs | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.AutorunDrivers | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.AutorunExplorer | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.AutorunImageHijack | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.AutorunInternetExplorer | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.AutorunKnownDLLs | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.AutorunLSAProviders | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.AutorunLogon | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.AutorunNetworkProviders | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.AutorunPrintMonitors | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.AutorunSafeBootMinimal | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.AutorunSafeBootNetwork | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.AutorunScheduledTask | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.AutorunServiceDLL | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.AutorunServices | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.AutorunStartupFolder | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.AutorunWinlogon | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.AutorunWinsockProviders | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.Beacon | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.BlacklistCategory | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.Blacklisted | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.BlockingStatus | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.BytesSentRatio | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.CertBiasStatus | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.CertModuleCount | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.CodeSectionWritable | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.CompanyName | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.CompanyNameCount | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.CompileTime | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.CreateProcess | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.CreateProcessNotification | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.CreateRemoteThread | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.CreateThreadNotification | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.CustomerOccurrences | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.DateBlocked | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.DaysSinceCompilation | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.DaysSinceCreation | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.DeleteExecutable | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.Description | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.Desktop | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.Downloaded | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.DownloadedTime | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.DuplicationSectionName | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.EmptySectionName | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.EncryptedDirectory | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.Entropy | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.FakeStartAddress | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.FileAccessDenied | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.FileAccessTime | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.FileAttributes | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.FileCreationTime | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.FileEncrypted | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.FileHiddenAttributes | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.FileHiddenXView | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.FileModificationTime | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.FileNameCount | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.FileOccurrences | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.FinalAddress | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.FirewallAuthorized | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.FirstSeenDate | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.FirstSeenName | string |  `file name` 
action\_result\.data\.\*\.KernelHooks\.\*\.FirstTimeSeen | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.Floating | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.FolderCie | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.FolderExecutables | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.FolderFolder | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.FolderNonExecutables | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.Found | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.FullPath | string |  `file path` 
action\_result\.data\.\*\.KernelHooks\.\*\.FunctionName | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.Graylisted | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.HashLookup | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.HiddenAttributes | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.HiddenDirectory | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.HiddenFile | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.HiddenXView | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.HookEAT | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.HookIAT | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.HookInline | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.HookModule | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.HookType | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.HookerModuleFileName | string |  `file name` 
action\_result\.data\.\*\.KernelHooks\.\*\.HookerModulePath | string |  `file path` 
action\_result\.data\.\*\.KernelHooks\.\*\.Hooking | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.IIOCLevel0 | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.IIOCLevel1 | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.IIOCLevel2 | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.IIOCLevel3 | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.IIOCScore | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.IconPresent | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.ImageHidden | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.ImageMismatch | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.ImportedDLLCount | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.ImportedDLLs | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.InitialAddress | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.InstallerDirectory | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.KernelHookType | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.LikelyPacked | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.Listen | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.LiveConnectLastUpdated | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.LiveConnectRiskEnum | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.LiveConnectRiskReason | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.Loaded | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.MD5 | string |  `md5` 
action\_result\.data\.\*\.KernelHooks\.\*\.MD5Collision | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.MachineCount | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.ModifyBadCertificateWarningSetting | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.ModifyFirewallPolicy | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.ModifyInternetZoneSettings | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.ModifyIntranetZoneBrowsingNotificationSetting | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.ModifyLUASetting | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.ModifyRegistryEditorSetting | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.ModifySecurityCenterConfiguration | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.ModifyServicesImagePath | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.ModifyTaskManagerSetting | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.ModifyWindowsSystemPolicy | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.ModifyZoneCrossingWarningSetting | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.ModuleMemoryHash | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.ModuleName | string |  `file name` 
action\_result\.data\.\*\.KernelHooks\.\*\.NativeSubsystem | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.Net | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.Neutral | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.NoIcon | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.NoVersionInfo | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.NotFound | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.NotificationRegistered | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.NotificationRegisteredType | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.ObjectName | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.OpenBrowserProcess | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.OpenLogicalDrive | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.OpenOSProcess | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.OpenPhysicalDrive | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.OpenProcess | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.OriginalFileName | string |  `file name` 
action\_result\.data\.\*\.KernelHooks\.\*\.Packed | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.Path | string |  `file path` 
action\_result\.data\.\*\.KernelHooks\.\*\.Platform | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.ProcessAccessDenied | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.ProgramData | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.ProgramFiles | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.ReadDocument | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.RecordModifiedTime | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.RelativeFileName | string |  `file name` 
action\_result\.data\.\*\.KernelHooks\.\*\.RelativePath | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.RemoteFileName | string |  `file name` 
action\_result\.data\.\*\.KernelHooks\.\*\.RemotePath | string |  `file path` 
action\_result\.data\.\*\.KernelHooks\.\*\.RenametoExecutable | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.ReservedName | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.RiskScore | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.SHA1 | string |  `sha1` 
action\_result\.data\.\*\.KernelHooks\.\*\.SHA256 | string |  `sha256` 
action\_result\.data\.\*\.KernelHooks\.\*\.SectionsNames | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.Signature | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.SignatureExpired | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.SignaturePresent | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.SignatureThumbprint | string |  `sha1` 
action\_result\.data\.\*\.KernelHooks\.\*\.SignatureTimeStamp | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.SignatureValid | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.SignedbyMicrosoft | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.SizeInBytes | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.Status | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.StatusComment | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.SysWOW64 | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.System32 | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.Temporary | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.TooManyConnections | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.User | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.VersionInfoPresent | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.WFP | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.Whitelisted | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.Windows | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.WritetoExecutable | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.YaraDefinitionHash | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.YaraScanDescription | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.YaraScanFirstThreat | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.YaraScanresult | string | 
action\_result\.data\.\*\.KernelHooks\.\*\.YaraVersion | string | 
action\_result\.data\.\*\.Network\.\*\.ADS | string | 
action\_result\.data\.\*\.Network\.\*\.AVDefinitionHash | string | 
action\_result\.data\.\*\.Network\.\*\.AVDescription | string | 
action\_result\.data\.\*\.Network\.\*\.AVFirstThreat | string | 
action\_result\.data\.\*\.Network\.\*\.AVScanResult | string | 
action\_result\.data\.\*\.Network\.\*\.AVVersion | string | 
action\_result\.data\.\*\.Network\.\*\.AccessNetwork | string | 
action\_result\.data\.\*\.Network\.\*\.AnalysisTime | string | 
action\_result\.data\.\*\.Network\.\*\.AppDataLocal | string | 
action\_result\.data\.\*\.Network\.\*\.AppDataRoaming | string | 
action\_result\.data\.\*\.Network\.\*\.Assigned | string | 
action\_result\.data\.\*\.Network\.\*\.AutoStartCategory | string | 
action\_result\.data\.\*\.Network\.\*\.AutomaticBiasStatusAssignment | string | 
action\_result\.data\.\*\.Network\.\*\.Autorun | string | 
action\_result\.data\.\*\.Network\.\*\.AutorunAppInit | string | 
action\_result\.data\.\*\.Network\.\*\.AutorunBoot | string | 
action\_result\.data\.\*\.Network\.\*\.AutorunBootExecute | string | 
action\_result\.data\.\*\.Network\.\*\.AutorunCodecs | string | 
action\_result\.data\.\*\.Network\.\*\.AutorunDrivers | string | 
action\_result\.data\.\*\.Network\.\*\.AutorunExplorer | string | 
action\_result\.data\.\*\.Network\.\*\.AutorunImageHijack | string | 
action\_result\.data\.\*\.Network\.\*\.AutorunInternetExplorer | string | 
action\_result\.data\.\*\.Network\.\*\.AutorunKnownDLLs | string | 
action\_result\.data\.\*\.Network\.\*\.AutorunLSAProviders | string | 
action\_result\.data\.\*\.Network\.\*\.AutorunLogon | string | 
action\_result\.data\.\*\.Network\.\*\.AutorunNetworkProviders | string | 
action\_result\.data\.\*\.Network\.\*\.AutorunPrintMonitors | string | 
action\_result\.data\.\*\.Network\.\*\.AutorunSafeBootMinimal | string | 
action\_result\.data\.\*\.Network\.\*\.AutorunSafeBootNetwork | string | 
action\_result\.data\.\*\.Network\.\*\.AutorunScheduledTask | string | 
action\_result\.data\.\*\.Network\.\*\.AutorunServiceDLL | string | 
action\_result\.data\.\*\.Network\.\*\.AutorunServices | string | 
action\_result\.data\.\*\.Network\.\*\.AutorunStartupFolder | string | 
action\_result\.data\.\*\.Network\.\*\.AutorunWinlogon | string | 
action\_result\.data\.\*\.Network\.\*\.AutorunWinsockProviders | string | 
action\_result\.data\.\*\.Network\.\*\.BadDomain | string | 
action\_result\.data\.\*\.Network\.\*\.BadIP | string | 
action\_result\.data\.\*\.Network\.\*\.Beacon | string | 
action\_result\.data\.\*\.Network\.\*\.BlacklistCategory | string | 
action\_result\.data\.\*\.Network\.\*\.Blacklisted | string | 
action\_result\.data\.\*\.Network\.\*\.BlockingStatus | string | 
action\_result\.data\.\*\.Network\.\*\.BurstCount | string | 
action\_result\.data\.\*\.Network\.\*\.BurstIntervalDeviation | string | 
action\_result\.data\.\*\.Network\.\*\.BurstIntervalMean | string | 
action\_result\.data\.\*\.Network\.\*\.BytesSentRatio | string | 
action\_result\.data\.\*\.Network\.\*\.CertBiasStatus | string | 
action\_result\.data\.\*\.Network\.\*\.CertModuleCount | string | 
action\_result\.data\.\*\.Network\.\*\.CodeSectionWritable | string | 
action\_result\.data\.\*\.Network\.\*\.CompanyName | string | 
action\_result\.data\.\*\.Network\.\*\.CompanyNameCount | string | 
action\_result\.data\.\*\.Network\.\*\.CompileTime | string | 
action\_result\.data\.\*\.Network\.\*\.ConnectionCount | string | 
action\_result\.data\.\*\.Network\.\*\.CreateProcess | string | 
action\_result\.data\.\*\.Network\.\*\.CreateProcessNotification | string | 
action\_result\.data\.\*\.Network\.\*\.CreateRemoteThread | string | 
action\_result\.data\.\*\.Network\.\*\.CreateThreadNotification | string | 
action\_result\.data\.\*\.Network\.\*\.CustomerOccurrences | string | 
action\_result\.data\.\*\.Network\.\*\.DateBlocked | string | 
action\_result\.data\.\*\.Network\.\*\.DaysSinceCompilation | string | 
action\_result\.data\.\*\.Network\.\*\.DaysSinceCreation | string | 
action\_result\.data\.\*\.Network\.\*\.DeleteExecutable | string | 
action\_result\.data\.\*\.Network\.\*\.Description | string | 
action\_result\.data\.\*\.Network\.\*\.Desktop | string | 
action\_result\.data\.\*\.Network\.\*\.Domain | string |  `domain` 
action\_result\.data\.\*\.Network\.\*\.Domains | string |  `domain` 
action\_result\.data\.\*\.Network\.\*\.Downloaded | string | 
action\_result\.data\.\*\.Network\.\*\.DownloadedTime | string | 
action\_result\.data\.\*\.Network\.\*\.DuplicationSectionName | string | 
action\_result\.data\.\*\.Network\.\*\.EPROCESS | string | 
action\_result\.data\.\*\.Network\.\*\.ETHREAD | string | 
action\_result\.data\.\*\.Network\.\*\.EmptySectionName | string | 
action\_result\.data\.\*\.Network\.\*\.EncryptedDirectory | string | 
action\_result\.data\.\*\.Network\.\*\.Entropy | string | 
action\_result\.data\.\*\.Network\.\*\.FailConnectCount | string | 
action\_result\.data\.\*\.Network\.\*\.FakeStartAddress | string | 
action\_result\.data\.\*\.Network\.\*\.FileAccessDenied | string | 
action\_result\.data\.\*\.Network\.\*\.FileAccessTime | string | 
action\_result\.data\.\*\.Network\.\*\.FileAttributes | string | 
action\_result\.data\.\*\.Network\.\*\.FileCreationTime | string | 
action\_result\.data\.\*\.Network\.\*\.FileEncrypted | string | 
action\_result\.data\.\*\.Network\.\*\.FileHiddenAttributes | string | 
action\_result\.data\.\*\.Network\.\*\.FileHiddenXView | string | 
action\_result\.data\.\*\.Network\.\*\.FileModificationTime | string | 
action\_result\.data\.\*\.Network\.\*\.FileName | string |  `file name` 
action\_result\.data\.\*\.Network\.\*\.FileNameCount | string | 
action\_result\.data\.\*\.Network\.\*\.FileOccurrences | string | 
action\_result\.data\.\*\.Network\.\*\.FirewallAuthorized | string | 
action\_result\.data\.\*\.Network\.\*\.FirstActivity | string | 
action\_result\.data\.\*\.Network\.\*\.FirstSeenDate | string | 
action\_result\.data\.\*\.Network\.\*\.FirstSeenName | string |  `file name` 
action\_result\.data\.\*\.Network\.\*\.FirstTimeSeen | string | 
action\_result\.data\.\*\.Network\.\*\.Floating | string | 
action\_result\.data\.\*\.Network\.\*\.FolderCie | string | 
action\_result\.data\.\*\.Network\.\*\.FolderExecutables | string | 
action\_result\.data\.\*\.Network\.\*\.FolderFolder | string | 
action\_result\.data\.\*\.Network\.\*\.FolderNonExecutables | string | 
action\_result\.data\.\*\.Network\.\*\.Found | string | 
action\_result\.data\.\*\.Network\.\*\.FullPath | string |  `file path` 
action\_result\.data\.\*\.Network\.\*\.Graylisted | string | 
action\_result\.data\.\*\.Network\.\*\.HashLookup | string | 
action\_result\.data\.\*\.Network\.\*\.HiddenAttributes | string | 
action\_result\.data\.\*\.Network\.\*\.HiddenDirectory | string | 
action\_result\.data\.\*\.Network\.\*\.HiddenFile | string | 
action\_result\.data\.\*\.Network\.\*\.HiddenXView | string | 
action\_result\.data\.\*\.Network\.\*\.HookEAT | string | 
action\_result\.data\.\*\.Network\.\*\.HookIAT | string | 
action\_result\.data\.\*\.Network\.\*\.HookInline | string | 
action\_result\.data\.\*\.Network\.\*\.HookModule | string | 
action\_result\.data\.\*\.Network\.\*\.HookType | string | 
action\_result\.data\.\*\.Network\.\*\.Hooking | string | 
action\_result\.data\.\*\.Network\.\*\.IIOCLevel0 | string | 
action\_result\.data\.\*\.Network\.\*\.IIOCLevel1 | string | 
action\_result\.data\.\*\.Network\.\*\.IIOCLevel2 | string | 
action\_result\.data\.\*\.Network\.\*\.IIOCLevel3 | string | 
action\_result\.data\.\*\.Network\.\*\.IIOCScore | string | 
action\_result\.data\.\*\.Network\.\*\.IP | string |  `ip` 
action\_result\.data\.\*\.Network\.\*\.IconPresent | string | 
action\_result\.data\.\*\.Network\.\*\.ImageHidden | string | 
action\_result\.data\.\*\.Network\.\*\.ImageMismatch | string | 
action\_result\.data\.\*\.Network\.\*\.ImportedDLLCount | string | 
action\_result\.data\.\*\.Network\.\*\.ImportedDLLs | string | 
action\_result\.data\.\*\.Network\.\*\.InstallerDirectory | string | 
action\_result\.data\.\*\.Network\.\*\.LastActivity | string | 
action\_result\.data\.\*\.Network\.\*\.LaunchArguments | string | 
action\_result\.data\.\*\.Network\.\*\.LikelyPacked | string | 
action\_result\.data\.\*\.Network\.\*\.Listen | string | 
action\_result\.data\.\*\.Network\.\*\.LiveConnectLastUpdated | string | 
action\_result\.data\.\*\.Network\.\*\.LiveConnectRiskEnum | string | 
action\_result\.data\.\*\.Network\.\*\.LiveConnectRiskReason | string | 
action\_result\.data\.\*\.Network\.\*\.Loaded | string | 
action\_result\.data\.\*\.Network\.\*\.MD5 | string |  `md5` 
action\_result\.data\.\*\.Network\.\*\.MD5Collision | string | 
action\_result\.data\.\*\.Network\.\*\.MachineCount | string | 
action\_result\.data\.\*\.Network\.\*\.MachineName | string | 
action\_result\.data\.\*\.Network\.\*\.ModifyBadCertificateWarningSetting | string | 
action\_result\.data\.\*\.Network\.\*\.ModifyFirewallPolicy | string | 
action\_result\.data\.\*\.Network\.\*\.ModifyInternetZoneSettings | string | 
action\_result\.data\.\*\.Network\.\*\.ModifyIntranetZoneBrowsingNotificationSetting | string | 
action\_result\.data\.\*\.Network\.\*\.ModifyLUASetting | string | 
action\_result\.data\.\*\.Network\.\*\.ModifyRegistryEditorSetting | string | 
action\_result\.data\.\*\.Network\.\*\.ModifySecurityCenterConfiguration | string | 
action\_result\.data\.\*\.Network\.\*\.ModifyServicesImagePath | string | 
action\_result\.data\.\*\.Network\.\*\.ModifyTaskManagerSetting | string | 
action\_result\.data\.\*\.Network\.\*\.ModifyWindowsSystemPolicy | string | 
action\_result\.data\.\*\.Network\.\*\.ModifyZoneCrossingWarningSetting | string | 
action\_result\.data\.\*\.Network\.\*\.ModuleMemoryHash | string | 
action\_result\.data\.\*\.Network\.\*\.ModuleName | string |  `file name` 
action\_result\.data\.\*\.Network\.\*\.NativeSubsystem | string | 
action\_result\.data\.\*\.Network\.\*\.Net | string | 
action\_result\.data\.\*\.Network\.\*\.NetworkSegment | string |  `ip` 
action\_result\.data\.\*\.Network\.\*\.Neutral | string | 
action\_result\.data\.\*\.Network\.\*\.NoIcon | string | 
action\_result\.data\.\*\.Network\.\*\.NoVersionInfo | string | 
action\_result\.data\.\*\.Network\.\*\.NotFound | string | 
action\_result\.data\.\*\.Network\.\*\.NotificationRegistered | string | 
action\_result\.data\.\*\.Network\.\*\.NotificationRegisteredType | string | 
action\_result\.data\.\*\.Network\.\*\.OffHourTraffic | string | 
action\_result\.data\.\*\.Network\.\*\.OpenBrowserProcess | string | 
action\_result\.data\.\*\.Network\.\*\.OpenLogicalDrive | string | 
action\_result\.data\.\*\.Network\.\*\.OpenOSProcess | string | 
action\_result\.data\.\*\.Network\.\*\.OpenPhysicalDrive | string | 
action\_result\.data\.\*\.Network\.\*\.OpenProcess | string | 
action\_result\.data\.\*\.Network\.\*\.OriginalFileName | string |  `file name` 
action\_result\.data\.\*\.Network\.\*\.PID | string |  `pid` 
action\_result\.data\.\*\.Network\.\*\.Packed | string | 
action\_result\.data\.\*\.Network\.\*\.Path | string |  `file path` 
action\_result\.data\.\*\.Network\.\*\.Platform | string | 
action\_result\.data\.\*\.Network\.\*\.Port | string | 
action\_result\.data\.\*\.Network\.\*\.PrivateAddress | string | 
action\_result\.data\.\*\.Network\.\*\.Process | string |  `process name` 
action\_result\.data\.\*\.Network\.\*\.ProcessAccessDenied | string | 
action\_result\.data\.\*\.Network\.\*\.ProcessContext | string | 
action\_result\.data\.\*\.Network\.\*\.ProgramData | string | 
action\_result\.data\.\*\.Network\.\*\.ProgramFiles | string | 
action\_result\.data\.\*\.Network\.\*\.Protocol | string | 
action\_result\.data\.\*\.Network\.\*\.ReadDocument | string | 
action\_result\.data\.\*\.Network\.\*\.RecordModifiedTime | string | 
action\_result\.data\.\*\.Network\.\*\.RelativeFileName | string |  `file name` 
action\_result\.data\.\*\.Network\.\*\.RelativePath | string | 
action\_result\.data\.\*\.Network\.\*\.RemoteFileName | string |  `file name` 
action\_result\.data\.\*\.Network\.\*\.RemotePath | string |  `file path` 
action\_result\.data\.\*\.Network\.\*\.RenametoExecutable | string | 
action\_result\.data\.\*\.Network\.\*\.ReservedName | string | 
action\_result\.data\.\*\.Network\.\*\.RiskScore | string | 
action\_result\.data\.\*\.Network\.\*\.SHA1 | string |  `sha1` 
action\_result\.data\.\*\.Network\.\*\.SHA256 | string |  `sha256` 
action\_result\.data\.\*\.Network\.\*\.SectionsNames | string | 
action\_result\.data\.\*\.Network\.\*\.Signature | string | 
action\_result\.data\.\*\.Network\.\*\.SignatureExpired | string | 
action\_result\.data\.\*\.Network\.\*\.SignaturePresent | string | 
action\_result\.data\.\*\.Network\.\*\.SignatureThumbprint | string |  `sha1` 
action\_result\.data\.\*\.Network\.\*\.SignatureTimeStamp | string | 
action\_result\.data\.\*\.Network\.\*\.SignatureValid | string | 
action\_result\.data\.\*\.Network\.\*\.SignedbyMicrosoft | string | 
action\_result\.data\.\*\.Network\.\*\.SizeInBytes | string | 
action\_result\.data\.\*\.Network\.\*\.Status | string | 
action\_result\.data\.\*\.Network\.\*\.StatusComment | string | 
action\_result\.data\.\*\.Network\.\*\.SysWOW64 | string | 
action\_result\.data\.\*\.Network\.\*\.System32 | string | 
action\_result\.data\.\*\.Network\.\*\.Temporary | string | 
action\_result\.data\.\*\.Network\.\*\.TooManyConnections | string | 
action\_result\.data\.\*\.Network\.\*\.TotalReceived | string | 
action\_result\.data\.\*\.Network\.\*\.TotalSent | string | 
action\_result\.data\.\*\.Network\.\*\.TrustedDomain | string | 
action\_result\.data\.\*\.Network\.\*\.User | string | 
action\_result\.data\.\*\.Network\.\*\.UserAgent | string | 
action\_result\.data\.\*\.Network\.\*\.VersionInfoPresent | string | 
action\_result\.data\.\*\.Network\.\*\.WFP | string | 
action\_result\.data\.\*\.Network\.\*\.Whitelisted | string | 
action\_result\.data\.\*\.Network\.\*\.Windows | string | 
action\_result\.data\.\*\.Network\.\*\.WritetoExecutable | string | 
action\_result\.data\.\*\.Network\.\*\.YaraDefinitionHash | string | 
action\_result\.data\.\*\.Network\.\*\.YaraScanDescription | string | 
action\_result\.data\.\*\.Network\.\*\.YaraScanFirstThreat | string | 
action\_result\.data\.\*\.Network\.\*\.YaraScanresult | string | 
action\_result\.data\.\*\.Network\.\*\.YaraVersion | string | 
action\_result\.data\.\*\.Processes\.\*\.ADS | string | 
action\_result\.data\.\*\.Processes\.\*\.AVDefinitionHash | string | 
action\_result\.data\.\*\.Processes\.\*\.AVDescription | string | 
action\_result\.data\.\*\.Processes\.\*\.AVFirstThreat | string | 
action\_result\.data\.\*\.Processes\.\*\.AVScanResult | string | 
action\_result\.data\.\*\.Processes\.\*\.AVVersion | string | 
action\_result\.data\.\*\.Processes\.\*\.AccessNetwork | string | 
action\_result\.data\.\*\.Processes\.\*\.AnalysisTime | string | 
action\_result\.data\.\*\.Processes\.\*\.AppDataLocal | string | 
action\_result\.data\.\*\.Processes\.\*\.AppDataRoaming | string | 
action\_result\.data\.\*\.Processes\.\*\.AutoStartCategory | string | 
action\_result\.data\.\*\.Processes\.\*\.AutomaticBiasStatusAssignment | string | 
action\_result\.data\.\*\.Processes\.\*\.Autorun | string | 
action\_result\.data\.\*\.Processes\.\*\.AutorunAppInit | string | 
action\_result\.data\.\*\.Processes\.\*\.AutorunBoot | string | 
action\_result\.data\.\*\.Processes\.\*\.AutorunBootExecute | string | 
action\_result\.data\.\*\.Processes\.\*\.AutorunCodecs | string | 
action\_result\.data\.\*\.Processes\.\*\.AutorunDrivers | string | 
action\_result\.data\.\*\.Processes\.\*\.AutorunExplorer | string | 
action\_result\.data\.\*\.Processes\.\*\.AutorunImageHijack | string | 
action\_result\.data\.\*\.Processes\.\*\.AutorunInternetExplorer | string | 
action\_result\.data\.\*\.Processes\.\*\.AutorunKnownDLLs | string | 
action\_result\.data\.\*\.Processes\.\*\.AutorunLSAProviders | string | 
action\_result\.data\.\*\.Processes\.\*\.AutorunLogon | string | 
action\_result\.data\.\*\.Processes\.\*\.AutorunNetworkProviders | string | 
action\_result\.data\.\*\.Processes\.\*\.AutorunPrintMonitors | string | 
action\_result\.data\.\*\.Processes\.\*\.AutorunSafeBootMinimal | string | 
action\_result\.data\.\*\.Processes\.\*\.AutorunSafeBootNetwork | string | 
action\_result\.data\.\*\.Processes\.\*\.AutorunScheduledTask | string | 
action\_result\.data\.\*\.Processes\.\*\.AutorunServiceDLL | string | 
action\_result\.data\.\*\.Processes\.\*\.AutorunServices | string | 
action\_result\.data\.\*\.Processes\.\*\.AutorunStartupFolder | string | 
action\_result\.data\.\*\.Processes\.\*\.AutorunWinlogon | string | 
action\_result\.data\.\*\.Processes\.\*\.AutorunWinsockProviders | string | 
action\_result\.data\.\*\.Processes\.\*\.Beacon | string | 
action\_result\.data\.\*\.Processes\.\*\.BlacklistCategory | string | 
action\_result\.data\.\*\.Processes\.\*\.Blacklisted | string | 
action\_result\.data\.\*\.Processes\.\*\.BlockingStatus | string | 
action\_result\.data\.\*\.Processes\.\*\.BytesSentRatio | string | 
action\_result\.data\.\*\.Processes\.\*\.CertBiasStatus | string | 
action\_result\.data\.\*\.Processes\.\*\.CertModuleCount | string | 
action\_result\.data\.\*\.Processes\.\*\.CodeSectionWritable | string | 
action\_result\.data\.\*\.Processes\.\*\.CompanyName | string | 
action\_result\.data\.\*\.Processes\.\*\.CompanyNameCount | string | 
action\_result\.data\.\*\.Processes\.\*\.CompileTime | string | 
action\_result\.data\.\*\.Processes\.\*\.CreateProcess | string | 
action\_result\.data\.\*\.Processes\.\*\.CreateProcessNotification | string | 
action\_result\.data\.\*\.Processes\.\*\.CreateRemoteThread | string | 
action\_result\.data\.\*\.Processes\.\*\.CreateThreadNotification | string | 
action\_result\.data\.\*\.Processes\.\*\.CustomerOccurrences | string | 
action\_result\.data\.\*\.Processes\.\*\.DateBlocked | string | 
action\_result\.data\.\*\.Processes\.\*\.DaysSinceCompilation | string | 
action\_result\.data\.\*\.Processes\.\*\.DaysSinceCreation | string | 
action\_result\.data\.\*\.Processes\.\*\.DebuggerAttached | string | 
action\_result\.data\.\*\.Processes\.\*\.DeleteExecutable | string | 
action\_result\.data\.\*\.Processes\.\*\.Dep | string | 
action\_result\.data\.\*\.Processes\.\*\.DepPermanent | string | 
action\_result\.data\.\*\.Processes\.\*\.Description | string | 
action\_result\.data\.\*\.Processes\.\*\.Desktop | string | 
action\_result\.data\.\*\.Processes\.\*\.Downloaded | string | 
action\_result\.data\.\*\.Processes\.\*\.DownloadedTime | string | 
action\_result\.data\.\*\.Processes\.\*\.DuplicationSectionName | string | 
action\_result\.data\.\*\.Processes\.\*\.EPROCESS | string | 
action\_result\.data\.\*\.Processes\.\*\.EmptySectionName | string | 
action\_result\.data\.\*\.Processes\.\*\.EncryptedDirectory | string | 
action\_result\.data\.\*\.Processes\.\*\.Entropy | string | 
action\_result\.data\.\*\.Processes\.\*\.FakeStartAddress | string | 
action\_result\.data\.\*\.Processes\.\*\.FileAccessDenied | string | 
action\_result\.data\.\*\.Processes\.\*\.FileAccessTime | string | 
action\_result\.data\.\*\.Processes\.\*\.FileAttributes | string | 
action\_result\.data\.\*\.Processes\.\*\.FileCreationTime | string | 
action\_result\.data\.\*\.Processes\.\*\.FileEncrypted | string | 
action\_result\.data\.\*\.Processes\.\*\.FileHiddenAttributes | string | 
action\_result\.data\.\*\.Processes\.\*\.FileHiddenXView | string | 
action\_result\.data\.\*\.Processes\.\*\.FileModificationTime | string | 
action\_result\.data\.\*\.Processes\.\*\.FileName | string |  `file name` 
action\_result\.data\.\*\.Processes\.\*\.FileNameCount | string | 
action\_result\.data\.\*\.Processes\.\*\.FileOccurrences | string | 
action\_result\.data\.\*\.Processes\.\*\.FirewallAuthorized | string | 
action\_result\.data\.\*\.Processes\.\*\.FirstSeenDate | string | 
action\_result\.data\.\*\.Processes\.\*\.FirstSeenName | string |  `file name` 
action\_result\.data\.\*\.Processes\.\*\.FirstTimeSeen | string | 
action\_result\.data\.\*\.Processes\.\*\.FloatThreadCount | string | 
action\_result\.data\.\*\.Processes\.\*\.Floating | string | 
action\_result\.data\.\*\.Processes\.\*\.FolderCie | string | 
action\_result\.data\.\*\.Processes\.\*\.FolderExecutables | string | 
action\_result\.data\.\*\.Processes\.\*\.FolderFolder | string | 
action\_result\.data\.\*\.Processes\.\*\.FolderNonExecutables | string | 
action\_result\.data\.\*\.Processes\.\*\.Found | string | 
action\_result\.data\.\*\.Processes\.\*\.FullPath | string |  `file path` 
action\_result\.data\.\*\.Processes\.\*\.Graylisted | string | 
action\_result\.data\.\*\.Processes\.\*\.HashLookup | string | 
action\_result\.data\.\*\.Processes\.\*\.HiddenAttributes | string | 
action\_result\.data\.\*\.Processes\.\*\.HiddenDirectory | string | 
action\_result\.data\.\*\.Processes\.\*\.HiddenFile | string | 
action\_result\.data\.\*\.Processes\.\*\.HiddenXView | string | 
action\_result\.data\.\*\.Processes\.\*\.HookEAT | string | 
action\_result\.data\.\*\.Processes\.\*\.HookIAT | string | 
action\_result\.data\.\*\.Processes\.\*\.HookInline | string | 
action\_result\.data\.\*\.Processes\.\*\.HookModule | string | 
action\_result\.data\.\*\.Processes\.\*\.HookType | string | 
action\_result\.data\.\*\.Processes\.\*\.Hooking | string | 
action\_result\.data\.\*\.Processes\.\*\.IIOCLevel0 | string | 
action\_result\.data\.\*\.Processes\.\*\.IIOCLevel1 | string | 
action\_result\.data\.\*\.Processes\.\*\.IIOCLevel2 | string | 
action\_result\.data\.\*\.Processes\.\*\.IIOCLevel3 | string | 
action\_result\.data\.\*\.Processes\.\*\.IIOCScore | string | 
action\_result\.data\.\*\.Processes\.\*\.IconPresent | string | 
action\_result\.data\.\*\.Processes\.\*\.ImageBase | string | 
action\_result\.data\.\*\.Processes\.\*\.ImageHidden | string | 
action\_result\.data\.\*\.Processes\.\*\.ImageMismatch | string | 
action\_result\.data\.\*\.Processes\.\*\.ImageSize | string | 
action\_result\.data\.\*\.Processes\.\*\.ImportedDLLCount | string | 
action\_result\.data\.\*\.Processes\.\*\.ImportedDLLs | string | 
action\_result\.data\.\*\.Processes\.\*\.InstallerDirectory | string | 
action\_result\.data\.\*\.Processes\.\*\.Integrity | string | 
action\_result\.data\.\*\.Processes\.\*\.LaunchArguments | string | 
action\_result\.data\.\*\.Processes\.\*\.LikelyPacked | string | 
action\_result\.data\.\*\.Processes\.\*\.Listen | string | 
action\_result\.data\.\*\.Processes\.\*\.LiveConnectLastUpdated | string | 
action\_result\.data\.\*\.Processes\.\*\.LiveConnectRiskEnum | string | 
action\_result\.data\.\*\.Processes\.\*\.LiveConnectRiskReason | string | 
action\_result\.data\.\*\.Processes\.\*\.Loaded | string | 
action\_result\.data\.\*\.Processes\.\*\.MD5 | string |  `md5` 
action\_result\.data\.\*\.Processes\.\*\.MD5Collision | string | 
action\_result\.data\.\*\.Processes\.\*\.MachineCount | string | 
action\_result\.data\.\*\.Processes\.\*\.ModifyBadCertificateWarningSetting | string | 
action\_result\.data\.\*\.Processes\.\*\.ModifyFirewallPolicy | string | 
action\_result\.data\.\*\.Processes\.\*\.ModifyInternetZoneSettings | string | 
action\_result\.data\.\*\.Processes\.\*\.ModifyIntranetZoneBrowsingNotificationSetting | string | 
action\_result\.data\.\*\.Processes\.\*\.ModifyLUASetting | string | 
action\_result\.data\.\*\.Processes\.\*\.ModifyRegistryEditorSetting | string | 
action\_result\.data\.\*\.Processes\.\*\.ModifySecurityCenterConfiguration | string | 
action\_result\.data\.\*\.Processes\.\*\.ModifyServicesImagePath | string | 
action\_result\.data\.\*\.Processes\.\*\.ModifyTaskManagerSetting | string | 
action\_result\.data\.\*\.Processes\.\*\.ModifyWindowsSystemPolicy | string | 
action\_result\.data\.\*\.Processes\.\*\.ModifyZoneCrossingWarningSetting | string | 
action\_result\.data\.\*\.Processes\.\*\.ModuleMemoryHash | string | 
action\_result\.data\.\*\.Processes\.\*\.ModuleName | string |  `file name` 
action\_result\.data\.\*\.Processes\.\*\.NativeSubsystem | string | 
action\_result\.data\.\*\.Processes\.\*\.Net | string | 
action\_result\.data\.\*\.Processes\.\*\.Neutral | string | 
action\_result\.data\.\*\.Processes\.\*\.NoIcon | string | 
action\_result\.data\.\*\.Processes\.\*\.NoVersionInfo | string | 
action\_result\.data\.\*\.Processes\.\*\.NotFound | string | 
action\_result\.data\.\*\.Processes\.\*\.NotificationRegistered | string | 
action\_result\.data\.\*\.Processes\.\*\.NotificationRegisteredType | string | 
action\_result\.data\.\*\.Processes\.\*\.OpenBrowserProcess | string | 
action\_result\.data\.\*\.Processes\.\*\.OpenLogicalDrive | string | 
action\_result\.data\.\*\.Processes\.\*\.OpenOSProcess | string | 
action\_result\.data\.\*\.Processes\.\*\.OpenPhysicalDrive | string | 
action\_result\.data\.\*\.Processes\.\*\.OpenProcess | string | 
action\_result\.data\.\*\.Processes\.\*\.OriginalFileName | string |  `file name` 
action\_result\.data\.\*\.Processes\.\*\.PID | string |  `pid` 
action\_result\.data\.\*\.Processes\.\*\.Packed | string | 
action\_result\.data\.\*\.Processes\.\*\.ParentFileName | string |  `file name` 
action\_result\.data\.\*\.Processes\.\*\.ParentFullpath | string |  `file path` 
action\_result\.data\.\*\.Processes\.\*\.ParentPID | string |  `pid` 
action\_result\.data\.\*\.Processes\.\*\.Path | string |  `file path` 
action\_result\.data\.\*\.Processes\.\*\.Platform | string | 
action\_result\.data\.\*\.Processes\.\*\.Process | string | 
action\_result\.data\.\*\.Processes\.\*\.ProcessAccessDenied | string | 
action\_result\.data\.\*\.Processes\.\*\.ProcessCreationTime | string | 
action\_result\.data\.\*\.Processes\.\*\.ProgramData | string | 
action\_result\.data\.\*\.Processes\.\*\.ProgramFiles | string | 
action\_result\.data\.\*\.Processes\.\*\.ReadDocument | string | 
action\_result\.data\.\*\.Processes\.\*\.RecordModifiedTime | string | 
action\_result\.data\.\*\.Processes\.\*\.RelativeFileName | string |  `file name` 
action\_result\.data\.\*\.Processes\.\*\.RelativePath | string | 
action\_result\.data\.\*\.Processes\.\*\.RemoteFileName | string |  `file name` 
action\_result\.data\.\*\.Processes\.\*\.RemotePath | string |  `file path` 
action\_result\.data\.\*\.Processes\.\*\.RenametoExecutable | string | 
action\_result\.data\.\*\.Processes\.\*\.ReservedName | string | 
action\_result\.data\.\*\.Processes\.\*\.RiskScore | string | 
action\_result\.data\.\*\.Processes\.\*\.SHA1 | string |  `sha1` 
action\_result\.data\.\*\.Processes\.\*\.SHA256 | string |  `sha256` 
action\_result\.data\.\*\.Processes\.\*\.SectionsNames | string | 
action\_result\.data\.\*\.Processes\.\*\.Session | string | 
action\_result\.data\.\*\.Processes\.\*\.Signature | string | 
action\_result\.data\.\*\.Processes\.\*\.SignatureExpired | string | 
action\_result\.data\.\*\.Processes\.\*\.SignaturePresent | string | 
action\_result\.data\.\*\.Processes\.\*\.SignatureThumbprint | string |  `sha1` 
action\_result\.data\.\*\.Processes\.\*\.SignatureTimeStamp | string | 
action\_result\.data\.\*\.Processes\.\*\.SignatureValid | string | 
action\_result\.data\.\*\.Processes\.\*\.SignedbyMicrosoft | string | 
action\_result\.data\.\*\.Processes\.\*\.SizeInBytes | string | 
action\_result\.data\.\*\.Processes\.\*\.Status | string | 
action\_result\.data\.\*\.Processes\.\*\.StatusComment | string | 
action\_result\.data\.\*\.Processes\.\*\.SysWOW64 | string | 
action\_result\.data\.\*\.Processes\.\*\.System32 | string | 
action\_result\.data\.\*\.Processes\.\*\.Temporary | string | 
action\_result\.data\.\*\.Processes\.\*\.ThreadCount | string | 
action\_result\.data\.\*\.Processes\.\*\.TooManyConnections | string | 
action\_result\.data\.\*\.Processes\.\*\.User | string | 
action\_result\.data\.\*\.Processes\.\*\.UserName | string |  `user name` 
action\_result\.data\.\*\.Processes\.\*\.VersionInfoPresent | string | 
action\_result\.data\.\*\.Processes\.\*\.Virtualized | string | 
action\_result\.data\.\*\.Processes\.\*\.WFP | string | 
action\_result\.data\.\*\.Processes\.\*\.Whitelisted | string | 
action\_result\.data\.\*\.Processes\.\*\.WindowTitle | string | 
action\_result\.data\.\*\.Processes\.\*\.Windows | string | 
action\_result\.data\.\*\.Processes\.\*\.WritetoExecutable | string | 
action\_result\.data\.\*\.Processes\.\*\.YaraDefinitionHash | string | 
action\_result\.data\.\*\.Processes\.\*\.YaraScanDescription | string | 
action\_result\.data\.\*\.Processes\.\*\.YaraScanFirstThreat | string | 
action\_result\.data\.\*\.Processes\.\*\.YaraScanresult | string | 
action\_result\.data\.\*\.Processes\.\*\.YaraVersion | string | 
action\_result\.data\.\*\.RegistryDiscrepencies\.\*\.BiasStatus | string | 
action\_result\.data\.\*\.RegistryDiscrepencies\.\*\.Comment | string | 
action\_result\.data\.\*\.RegistryDiscrepencies\.\*\.Data | string | 
action\_result\.data\.\*\.RegistryDiscrepencies\.\*\.DataType | string | 
action\_result\.data\.\*\.RegistryDiscrepencies\.\*\.Discrepancy | string | 
action\_result\.data\.\*\.RegistryDiscrepencies\.\*\.Hive | string | 
action\_result\.data\.\*\.RegistryDiscrepencies\.\*\.Path | string |  `file path` 
action\_result\.data\.\*\.RegistryDiscrepencies\.\*\.RawData | string | 
action\_result\.data\.\*\.RegistryDiscrepencies\.\*\.RawDataType | string | 
action\_result\.data\.\*\.Services\.\*\.ADS | string | 
action\_result\.data\.\*\.Services\.\*\.AVDefinitionHash | string | 
action\_result\.data\.\*\.Services\.\*\.AVDescription | string | 
action\_result\.data\.\*\.Services\.\*\.AVFirstThreat | string | 
action\_result\.data\.\*\.Services\.\*\.AVScanResult | string | 
action\_result\.data\.\*\.Services\.\*\.AVVersion | string | 
action\_result\.data\.\*\.Services\.\*\.AccessNetwork | string | 
action\_result\.data\.\*\.Services\.\*\.AnalysisTime | string | 
action\_result\.data\.\*\.Services\.\*\.AppDataLocal | string | 
action\_result\.data\.\*\.Services\.\*\.AppDataRoaming | string | 
action\_result\.data\.\*\.Services\.\*\.AutoStartCategory | string | 
action\_result\.data\.\*\.Services\.\*\.AutomaticBiasStatusAssignment | string | 
action\_result\.data\.\*\.Services\.\*\.Autorun | string | 
action\_result\.data\.\*\.Services\.\*\.AutorunAppInit | string | 
action\_result\.data\.\*\.Services\.\*\.AutorunBoot | string | 
action\_result\.data\.\*\.Services\.\*\.AutorunBootExecute | string | 
action\_result\.data\.\*\.Services\.\*\.AutorunCodecs | string | 
action\_result\.data\.\*\.Services\.\*\.AutorunDrivers | string | 
action\_result\.data\.\*\.Services\.\*\.AutorunExplorer | string | 
action\_result\.data\.\*\.Services\.\*\.AutorunImageHijack | string | 
action\_result\.data\.\*\.Services\.\*\.AutorunInternetExplorer | string | 
action\_result\.data\.\*\.Services\.\*\.AutorunKnownDLLs | string | 
action\_result\.data\.\*\.Services\.\*\.AutorunLSAProviders | string | 
action\_result\.data\.\*\.Services\.\*\.AutorunLogon | string | 
action\_result\.data\.\*\.Services\.\*\.AutorunNetworkProviders | string | 
action\_result\.data\.\*\.Services\.\*\.AutorunPrintMonitors | string | 
action\_result\.data\.\*\.Services\.\*\.AutorunSafeBootMinimal | string | 
action\_result\.data\.\*\.Services\.\*\.AutorunSafeBootNetwork | string | 
action\_result\.data\.\*\.Services\.\*\.AutorunScheduledTask | string | 
action\_result\.data\.\*\.Services\.\*\.AutorunServiceDLL | string | 
action\_result\.data\.\*\.Services\.\*\.AutorunServices | string | 
action\_result\.data\.\*\.Services\.\*\.AutorunStartupFolder | string | 
action\_result\.data\.\*\.Services\.\*\.AutorunWinlogon | string | 
action\_result\.data\.\*\.Services\.\*\.AutorunWinsockProviders | string | 
action\_result\.data\.\*\.Services\.\*\.Beacon | string | 
action\_result\.data\.\*\.Services\.\*\.BlacklistCategory | string | 
action\_result\.data\.\*\.Services\.\*\.Blacklisted | string | 
action\_result\.data\.\*\.Services\.\*\.BlockingStatus | string | 
action\_result\.data\.\*\.Services\.\*\.BytesSentRatio | string | 
action\_result\.data\.\*\.Services\.\*\.CertBiasStatus | string | 
action\_result\.data\.\*\.Services\.\*\.CertModuleCount | string | 
action\_result\.data\.\*\.Services\.\*\.CodeSectionWritable | string | 
action\_result\.data\.\*\.Services\.\*\.CompanyName | string | 
action\_result\.data\.\*\.Services\.\*\.CompanyNameCount | string | 
action\_result\.data\.\*\.Services\.\*\.CompileTime | string | 
action\_result\.data\.\*\.Services\.\*\.CreateProcess | string | 
action\_result\.data\.\*\.Services\.\*\.CreateProcessNotification | string | 
action\_result\.data\.\*\.Services\.\*\.CreateRemoteThread | string | 
action\_result\.data\.\*\.Services\.\*\.CreateThreadNotification | string | 
action\_result\.data\.\*\.Services\.\*\.CustomerOccurrences | string | 
action\_result\.data\.\*\.Services\.\*\.DateBlocked | string | 
action\_result\.data\.\*\.Services\.\*\.DaysSinceCompilation | string | 
action\_result\.data\.\*\.Services\.\*\.DaysSinceCreation | string | 
action\_result\.data\.\*\.Services\.\*\.DeleteExecutable | string | 
action\_result\.data\.\*\.Services\.\*\.Description | string | 
action\_result\.data\.\*\.Services\.\*\.Desktop | string | 
action\_result\.data\.\*\.Services\.\*\.DisplayName | string | 
action\_result\.data\.\*\.Services\.\*\.Downloaded | string | 
action\_result\.data\.\*\.Services\.\*\.DownloadedTime | string | 
action\_result\.data\.\*\.Services\.\*\.DuplicationSectionName | string | 
action\_result\.data\.\*\.Services\.\*\.EmptySectionName | string | 
action\_result\.data\.\*\.Services\.\*\.EncryptedDirectory | string | 
action\_result\.data\.\*\.Services\.\*\.Entropy | string | 
action\_result\.data\.\*\.Services\.\*\.FakeStartAddress | string | 
action\_result\.data\.\*\.Services\.\*\.FileAccessDenied | string | 
action\_result\.data\.\*\.Services\.\*\.FileAccessTime | string | 
action\_result\.data\.\*\.Services\.\*\.FileAttributes | string | 
action\_result\.data\.\*\.Services\.\*\.FileCreationTime | string | 
action\_result\.data\.\*\.Services\.\*\.FileEncrypted | string | 
action\_result\.data\.\*\.Services\.\*\.FileHiddenAttributes | string | 
action\_result\.data\.\*\.Services\.\*\.FileHiddenXView | string | 
action\_result\.data\.\*\.Services\.\*\.FileModificationTime | string | 
action\_result\.data\.\*\.Services\.\*\.FileName | string |  `file name` 
action\_result\.data\.\*\.Services\.\*\.FileNameCount | string | 
action\_result\.data\.\*\.Services\.\*\.FileOccurrences | string | 
action\_result\.data\.\*\.Services\.\*\.FirewallAuthorized | string | 
action\_result\.data\.\*\.Services\.\*\.FirstSeenDate | string | 
action\_result\.data\.\*\.Services\.\*\.FirstSeenName | string |  `file name` 
action\_result\.data\.\*\.Services\.\*\.FirstTimeSeen | string | 
action\_result\.data\.\*\.Services\.\*\.Floating | string | 
action\_result\.data\.\*\.Services\.\*\.FolderCie | string | 
action\_result\.data\.\*\.Services\.\*\.FolderExecutables | string | 
action\_result\.data\.\*\.Services\.\*\.FolderFolder | string | 
action\_result\.data\.\*\.Services\.\*\.FolderNonExecutables | string | 
action\_result\.data\.\*\.Services\.\*\.Found | string | 
action\_result\.data\.\*\.Services\.\*\.FoundServiceName | string | 
action\_result\.data\.\*\.Services\.\*\.FoundfromRegistry | string | 
action\_result\.data\.\*\.Services\.\*\.FoundfromService | string | 
action\_result\.data\.\*\.Services\.\*\.FullPath | string |  `file path` 
action\_result\.data\.\*\.Services\.\*\.GotConfigQuery | string | 
action\_result\.data\.\*\.Services\.\*\.Graylisted | string | 
action\_result\.data\.\*\.Services\.\*\.HashLookup | string | 
action\_result\.data\.\*\.Services\.\*\.Hidden | string | 
action\_result\.data\.\*\.Services\.\*\.HiddenAttributes | string | 
action\_result\.data\.\*\.Services\.\*\.HiddenDirectory | string | 
action\_result\.data\.\*\.Services\.\*\.HiddenFile | string | 
action\_result\.data\.\*\.Services\.\*\.HiddenXView | string | 
action\_result\.data\.\*\.Services\.\*\.HookEAT | string | 
action\_result\.data\.\*\.Services\.\*\.HookIAT | string | 
action\_result\.data\.\*\.Services\.\*\.HookInline | string | 
action\_result\.data\.\*\.Services\.\*\.HookModule | string | 
action\_result\.data\.\*\.Services\.\*\.HookType | string | 
action\_result\.data\.\*\.Services\.\*\.Hooking | string | 
action\_result\.data\.\*\.Services\.\*\.IIOCLevel0 | string | 
action\_result\.data\.\*\.Services\.\*\.IIOCLevel1 | string | 
action\_result\.data\.\*\.Services\.\*\.IIOCLevel2 | string | 
action\_result\.data\.\*\.Services\.\*\.IIOCLevel3 | string | 
action\_result\.data\.\*\.Services\.\*\.IIOCScore | string | 
action\_result\.data\.\*\.Services\.\*\.IconPresent | string | 
action\_result\.data\.\*\.Services\.\*\.ImageHidden | string | 
action\_result\.data\.\*\.Services\.\*\.ImageMismatch | string | 
action\_result\.data\.\*\.Services\.\*\.ImportedDLLCount | string | 
action\_result\.data\.\*\.Services\.\*\.ImportedDLLs | string | 
action\_result\.data\.\*\.Services\.\*\.InstallerDirectory | string | 
action\_result\.data\.\*\.Services\.\*\.LaunchArguments | string | 
action\_result\.data\.\*\.Services\.\*\.LikelyPacked | string | 
action\_result\.data\.\*\.Services\.\*\.Listen | string | 
action\_result\.data\.\*\.Services\.\*\.LiveConnectLastUpdated | string | 
action\_result\.data\.\*\.Services\.\*\.LiveConnectRiskEnum | string | 
action\_result\.data\.\*\.Services\.\*\.LiveConnectRiskReason | string | 
action\_result\.data\.\*\.Services\.\*\.LoadOrder | string | 
action\_result\.data\.\*\.Services\.\*\.Loaded | string | 
action\_result\.data\.\*\.Services\.\*\.MD5 | string |  `md5` 
action\_result\.data\.\*\.Services\.\*\.MD5Collision | string | 
action\_result\.data\.\*\.Services\.\*\.MachineCount | string | 
action\_result\.data\.\*\.Services\.\*\.Mode | string | 
action\_result\.data\.\*\.Services\.\*\.ModifyBadCertificateWarningSetting | string | 
action\_result\.data\.\*\.Services\.\*\.ModifyFirewallPolicy | string | 
action\_result\.data\.\*\.Services\.\*\.ModifyInternetZoneSettings | string | 
action\_result\.data\.\*\.Services\.\*\.ModifyIntranetZoneBrowsingNotificationSetting | string | 
action\_result\.data\.\*\.Services\.\*\.ModifyLUASetting | string | 
action\_result\.data\.\*\.Services\.\*\.ModifyRegistryEditorSetting | string | 
action\_result\.data\.\*\.Services\.\*\.ModifySecurityCenterConfiguration | string | 
action\_result\.data\.\*\.Services\.\*\.ModifyServicesImagePath | string | 
action\_result\.data\.\*\.Services\.\*\.ModifyTaskManagerSetting | string | 
action\_result\.data\.\*\.Services\.\*\.ModifyWindowsSystemPolicy | string | 
action\_result\.data\.\*\.Services\.\*\.ModifyZoneCrossingWarningSetting | string | 
action\_result\.data\.\*\.Services\.\*\.ModuleMemoryHash | string | 
action\_result\.data\.\*\.Services\.\*\.ModuleName | string |  `file name` 
action\_result\.data\.\*\.Services\.\*\.NativeSubsystem | string | 
action\_result\.data\.\*\.Services\.\*\.Net | string | 
action\_result\.data\.\*\.Services\.\*\.Neutral | string | 
action\_result\.data\.\*\.Services\.\*\.NoIcon | string | 
action\_result\.data\.\*\.Services\.\*\.NoVersionInfo | string | 
action\_result\.data\.\*\.Services\.\*\.NotFound | string | 
action\_result\.data\.\*\.Services\.\*\.NotificationRegistered | string | 
action\_result\.data\.\*\.Services\.\*\.NotificationRegisteredType | string | 
action\_result\.data\.\*\.Services\.\*\.Open | string | 
action\_result\.data\.\*\.Services\.\*\.OpenBrowserProcess | string | 
action\_result\.data\.\*\.Services\.\*\.OpenLogicalDrive | string | 
action\_result\.data\.\*\.Services\.\*\.OpenOSProcess | string | 
action\_result\.data\.\*\.Services\.\*\.OpenPhysicalDrive | string | 
action\_result\.data\.\*\.Services\.\*\.OpenProcess | string | 
action\_result\.data\.\*\.Services\.\*\.OriginalFileName | string |  `file name` 
action\_result\.data\.\*\.Services\.\*\.PID | string |  `pid` 
action\_result\.data\.\*\.Services\.\*\.Packed | string | 
action\_result\.data\.\*\.Services\.\*\.Path | string |  `file path` 
action\_result\.data\.\*\.Services\.\*\.PathfromEventLog | string | 
action\_result\.data\.\*\.Services\.\*\.Platform | string | 
action\_result\.data\.\*\.Services\.\*\.ProcessAccessDenied | string | 
action\_result\.data\.\*\.Services\.\*\.ProgramData | string | 
action\_result\.data\.\*\.Services\.\*\.ProgramFiles | string | 
action\_result\.data\.\*\.Services\.\*\.ReadDocument | string | 
action\_result\.data\.\*\.Services\.\*\.RecordModifiedTime | string | 
action\_result\.data\.\*\.Services\.\*\.RegistryInfoMatch | string | 
action\_result\.data\.\*\.Services\.\*\.RegistryKeyFound | string | 
action\_result\.data\.\*\.Services\.\*\.RegistrySafeModeMinimal | string | 
action\_result\.data\.\*\.Services\.\*\.RegistrySafeModeNetword | string | 
action\_result\.data\.\*\.Services\.\*\.RelativeFileName | string |  `file name` 
action\_result\.data\.\*\.Services\.\*\.RelativePath | string | 
action\_result\.data\.\*\.Services\.\*\.RemoteFileName | string |  `file name` 
action\_result\.data\.\*\.Services\.\*\.RemotePath | string |  `file path` 
action\_result\.data\.\*\.Services\.\*\.RenametoExecutable | string | 
action\_result\.data\.\*\.Services\.\*\.ReservedName | string | 
action\_result\.data\.\*\.Services\.\*\.RiskScore | string | 
action\_result\.data\.\*\.Services\.\*\.SHA1 | string |  `sha1` 
action\_result\.data\.\*\.Services\.\*\.SHA256 | string |  `sha256` 
action\_result\.data\.\*\.Services\.\*\.SectionsNames | string | 
action\_result\.data\.\*\.Services\.\*\.ServiceDLLEntryPoint | string | 
action\_result\.data\.\*\.Services\.\*\.ServiceDescription | string | 
action\_result\.data\.\*\.Services\.\*\.Signature | string | 
action\_result\.data\.\*\.Services\.\*\.SignatureExpired | string | 
action\_result\.data\.\*\.Services\.\*\.SignaturePresent | string | 
action\_result\.data\.\*\.Services\.\*\.SignatureThumbprint | string |  `sha1` 
action\_result\.data\.\*\.Services\.\*\.SignatureTimeStamp | string | 
action\_result\.data\.\*\.Services\.\*\.SignatureValid | string | 
action\_result\.data\.\*\.Services\.\*\.SignedbyMicrosoft | string | 
action\_result\.data\.\*\.Services\.\*\.SizeInBytes | string | 
action\_result\.data\.\*\.Services\.\*\.State | string | 
action\_result\.data\.\*\.Services\.\*\.Status | string | 
action\_result\.data\.\*\.Services\.\*\.StatusComment | string | 
action\_result\.data\.\*\.Services\.\*\.SysWOW64 | string | 
action\_result\.data\.\*\.Services\.\*\.System32 | string | 
action\_result\.data\.\*\.Services\.\*\.Temporary | string | 
action\_result\.data\.\*\.Services\.\*\.TooManyConnections | string | 
action\_result\.data\.\*\.Services\.\*\.Type | string | 
action\_result\.data\.\*\.Services\.\*\.User | string | 
action\_result\.data\.\*\.Services\.\*\.UserName | string |  `user name` 
action\_result\.data\.\*\.Services\.\*\.VersionInfoPresent | string | 
action\_result\.data\.\*\.Services\.\*\.WFP | string | 
action\_result\.data\.\*\.Services\.\*\.Whitelisted | string | 
action\_result\.data\.\*\.Services\.\*\.Win32ErrorCode | string | 
action\_result\.data\.\*\.Services\.\*\.Windows | string | 
action\_result\.data\.\*\.Services\.\*\.WritetoExecutable | string | 
action\_result\.data\.\*\.Services\.\*\.YaraDefinitionHash | string | 
action\_result\.data\.\*\.Services\.\*\.YaraScanDescription | string | 
action\_result\.data\.\*\.Services\.\*\.YaraScanFirstThreat | string | 
action\_result\.data\.\*\.Services\.\*\.YaraScanresult | string | 
action\_result\.data\.\*\.Services\.\*\.YaraVersion | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.ADS | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.AVDefinitionHash | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.AVDescription | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.AVFirstThreat | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.AVScanResult | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.AVVersion | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.AccessNetwork | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.AnalysisTime | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.AppDataLocal | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.AppDataRoaming | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.Assigned | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.AutoStartCategory | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.AutomaticAssignment | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.AutomaticBiasStatusAssignment | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.Autorun | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.AutorunAppInit | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.AutorunBoot | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.AutorunBootExecute | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.AutorunCodecs | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.AutorunDrivers | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.AutorunExplorer | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.AutorunImageHijack | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.AutorunInternetExplorer | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.AutorunKnownDLLs | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.AutorunLSAProviders | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.AutorunLogon | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.AutorunNetworkProviders | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.AutorunPrintMonitors | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.AutorunSafeBootMinimal | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.AutorunSafeBootNetwork | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.AutorunScheduledTask | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.AutorunServiceDLL | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.AutorunServices | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.AutorunStartupFolder | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.AutorunWinlogon | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.AutorunWinsockProviders | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.Beacon | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.Behavior | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.BlacklistCategory | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.Blacklisted | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.BlockingStatus | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.BytesSentRatio | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.CertBiasStatus | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.CertModuleCount | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.CodeSectionWritable | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.CompanyName | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.CompanyNameCount | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.CompileTime | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.CreateProcess | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.CreateProcessNotification | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.CreateRemoteThread | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.CreateThreadNotification | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.CreationTime | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.CustomerOccurrences | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.DateBlocked | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.DaysSinceCompilation | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.DaysSinceCreation | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.DeleteExecutable | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.Description | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.Desktop | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.Downloaded | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.DownloadedTime | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.DuplicationSectionName | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.EPROCESS | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.ETHREAD | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.EmptySectionName | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.EncryptedDirectory | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.Entropy | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.EnvironmentBlock | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.FakeStartAddress | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.FileAccessDenied | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.FileAccessTime | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.FileAttributes | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.FileCreationTime | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.FileEncrypted | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.FileHiddenAttributes | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.FileHiddenXView | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.FileModificationTime | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.FileName | string |  `file name` 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.FileNameCount | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.FileOccurrences | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.FinalAddress | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.FinalEPROCESS | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.FinalProcessID | string |  `pid` 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.FirewallAuthorized | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.FirstSeenDate | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.FirstSeenName | string |  `file name` 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.FirstTimeSeen | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.Floating | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.FolderCie | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.FolderExecutables | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.FolderFolder | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.FolderNonExecutables | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.Found | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.FullPath | string |  `file path` 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.Graylisted | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.HashLookup | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.HiddenAttributes | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.HiddenDirectory | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.HiddenFile | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.HiddenXView | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.HookEAT | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.HookIAT | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.HookInline | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.HookModule | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.HookType | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.Hooking | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.IIOCLevel0 | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.IIOCLevel1 | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.IIOCLevel2 | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.IIOCLevel3 | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.IIOCScore | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.IconPresent | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.ImageHidden | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.ImageMismatch | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.ImportedDLLCount | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.ImportedDLLs | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.InstallerDirectory | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.LikelyPacked | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.Listen | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.LiveConnectLastUpdated | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.LiveConnectRiskEnum | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.LiveConnectRiskReason | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.Loaded | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.MD5 | string |  `md5` 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.MD5Collision | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.MachineCount | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.ModifyBadCertificateWarningSetting | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.ModifyFirewallPolicy | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.ModifyInternetZoneSettings | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.ModifyIntranetZoneBrowsingNotificationSetting | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.ModifyLUASetting | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.ModifyRegistryEditorSetting | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.ModifySecurityCenterConfiguration | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.ModifyServicesImagePath | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.ModifyTaskManagerSetting | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.ModifyWindowsSystemPolicy | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.ModifyZoneCrossingWarningSetting | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.ModuleMemoryHash | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.ModuleName | string |  `file name` 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.NativeSubsystem | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.Net | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.Neutral | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.NoIcon | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.NoVersionInfo | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.NotFound | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.NotificationRegistered | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.NotificationRegisteredType | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.OpenBrowserProcess | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.OpenLogicalDrive | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.OpenOSProcess | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.OpenPhysicalDrive | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.OpenProcess | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.OriginalFileName | string |  `file name` 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.Packed | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.Path | string |  `file path` 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.Platform | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.ProcessAccessDenied | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.ProcessContext | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.ProcessID | string |  `pid` 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.ProgramData | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.ProgramFiles | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.ReadDocument | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.RecordModifiedTime | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.RelativeFileName | string |  `file name` 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.RelativePath | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.RemoteFileName | string |  `file name` 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.RemotePath | string |  `file path` 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.RenametoExecutable | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.ReservedName | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.RiskScore | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.SHA1 | string |  `sha1` 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.SHA256 | string |  `sha256` 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.SectionsNames | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.Signature | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.SignatureExpired | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.SignaturePresent | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.SignatureThumbprint | string |  `sha1` 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.SignatureTimeStamp | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.SignatureValid | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.SignedbyMicrosoft | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.SizeInBytes | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.StartAddress | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.Status | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.StatusComment | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.SysWOW64 | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.System32 | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.Temporary | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.ThreadID | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.ThreadState | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.TooManyConnections | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.User | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.VersionInfoPresent | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.WFP | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.Whitelisted | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.Windows | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.WritetoExecutable | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.YaraDefinitionHash | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.YaraScanDescription | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.YaraScanFirstThreat | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.YaraScanresult | string | 
action\_result\.data\.\*\.SuspiciousThreads\.\*\.YaraVersion | string | 
action\_result\.data\.\*\.Tasks\.\*\.ADS | string | 
action\_result\.data\.\*\.Tasks\.\*\.AVDefinitionHash | string | 
action\_result\.data\.\*\.Tasks\.\*\.AVDescription | string | 
action\_result\.data\.\*\.Tasks\.\*\.AVFirstThreat | string | 
action\_result\.data\.\*\.Tasks\.\*\.AVScanResult | string | 
action\_result\.data\.\*\.Tasks\.\*\.AVVersion | string | 
action\_result\.data\.\*\.Tasks\.\*\.AccessNetwork | string | 
action\_result\.data\.\*\.Tasks\.\*\.Account | string | 
action\_result\.data\.\*\.Tasks\.\*\.AnalysisTime | string | 
action\_result\.data\.\*\.Tasks\.\*\.AppDataLocal | string | 
action\_result\.data\.\*\.Tasks\.\*\.AppDataRoaming | string | 
action\_result\.data\.\*\.Tasks\.\*\.Arguments | string | 
action\_result\.data\.\*\.Tasks\.\*\.AutoStartCategory | string | 
action\_result\.data\.\*\.Tasks\.\*\.AutomaticBiasStatusAssignment | string | 
action\_result\.data\.\*\.Tasks\.\*\.Autorun | string | 
action\_result\.data\.\*\.Tasks\.\*\.AutorunAppInit | string | 
action\_result\.data\.\*\.Tasks\.\*\.AutorunBoot | string | 
action\_result\.data\.\*\.Tasks\.\*\.AutorunBootExecute | string | 
action\_result\.data\.\*\.Tasks\.\*\.AutorunCodecs | string | 
action\_result\.data\.\*\.Tasks\.\*\.AutorunDrivers | string | 
action\_result\.data\.\*\.Tasks\.\*\.AutorunExplorer | string | 
action\_result\.data\.\*\.Tasks\.\*\.AutorunImageHijack | string | 
action\_result\.data\.\*\.Tasks\.\*\.AutorunInternetExplorer | string | 
action\_result\.data\.\*\.Tasks\.\*\.AutorunKnownDLLs | string | 
action\_result\.data\.\*\.Tasks\.\*\.AutorunLSAProviders | string | 
action\_result\.data\.\*\.Tasks\.\*\.AutorunLogon | string | 
action\_result\.data\.\*\.Tasks\.\*\.AutorunNetworkProviders | string | 
action\_result\.data\.\*\.Tasks\.\*\.AutorunPrintMonitors | string | 
action\_result\.data\.\*\.Tasks\.\*\.AutorunSafeBootMinimal | string | 
action\_result\.data\.\*\.Tasks\.\*\.AutorunSafeBootNetwork | string | 
action\_result\.data\.\*\.Tasks\.\*\.AutorunScheduledTask | string | 
action\_result\.data\.\*\.Tasks\.\*\.AutorunServiceDLL | string | 
action\_result\.data\.\*\.Tasks\.\*\.AutorunServices | string | 
action\_result\.data\.\*\.Tasks\.\*\.AutorunStartupFolder | string | 
action\_result\.data\.\*\.Tasks\.\*\.AutorunWinlogon | string | 
action\_result\.data\.\*\.Tasks\.\*\.AutorunWinsockProviders | string | 
action\_result\.data\.\*\.Tasks\.\*\.Beacon | string | 
action\_result\.data\.\*\.Tasks\.\*\.BlacklistCategory | string | 
action\_result\.data\.\*\.Tasks\.\*\.Blacklisted | string | 
action\_result\.data\.\*\.Tasks\.\*\.BlockingStatus | string | 
action\_result\.data\.\*\.Tasks\.\*\.BytesSentRatio | string | 
action\_result\.data\.\*\.Tasks\.\*\.CertBiasStatus | string | 
action\_result\.data\.\*\.Tasks\.\*\.CertModuleCount | string | 
action\_result\.data\.\*\.Tasks\.\*\.CodeSectionWritable | string | 
action\_result\.data\.\*\.Tasks\.\*\.CompanyName | string | 
action\_result\.data\.\*\.Tasks\.\*\.CompanyNameCount | string | 
action\_result\.data\.\*\.Tasks\.\*\.CompileTime | string | 
action\_result\.data\.\*\.Tasks\.\*\.CreateProcess | string | 
action\_result\.data\.\*\.Tasks\.\*\.CreateProcessNotification | string | 
action\_result\.data\.\*\.Tasks\.\*\.CreateRemoteThread | string | 
action\_result\.data\.\*\.Tasks\.\*\.CreateThreadNotification | string | 
action\_result\.data\.\*\.Tasks\.\*\.Creator | string | 
action\_result\.data\.\*\.Tasks\.\*\.CustomerOccurrences | string | 
action\_result\.data\.\*\.Tasks\.\*\.DateBlocked | string | 
action\_result\.data\.\*\.Tasks\.\*\.DaysSinceCompilation | string | 
action\_result\.data\.\*\.Tasks\.\*\.DaysSinceCreation | string | 
action\_result\.data\.\*\.Tasks\.\*\.DeleteExecutable | string | 
action\_result\.data\.\*\.Tasks\.\*\.Description | string | 
action\_result\.data\.\*\.Tasks\.\*\.Desktop | string | 
action\_result\.data\.\*\.Tasks\.\*\.Downloaded | string | 
action\_result\.data\.\*\.Tasks\.\*\.DownloadedTime | string | 
action\_result\.data\.\*\.Tasks\.\*\.DuplicationSectionName | string | 
action\_result\.data\.\*\.Tasks\.\*\.EmptySectionName | string | 
action\_result\.data\.\*\.Tasks\.\*\.EncryptedDirectory | string | 
action\_result\.data\.\*\.Tasks\.\*\.Entropy | string | 
action\_result\.data\.\*\.Tasks\.\*\.FakeStartAddress | string | 
action\_result\.data\.\*\.Tasks\.\*\.FileAccessDenied | string | 
action\_result\.data\.\*\.Tasks\.\*\.FileAccessTime | string | 
action\_result\.data\.\*\.Tasks\.\*\.FileAttributes | string | 
action\_result\.data\.\*\.Tasks\.\*\.FileCreationTime | string | 
action\_result\.data\.\*\.Tasks\.\*\.FileEncrypted | string | 
action\_result\.data\.\*\.Tasks\.\*\.FileHiddenAttributes | string | 
action\_result\.data\.\*\.Tasks\.\*\.FileHiddenXView | string | 
action\_result\.data\.\*\.Tasks\.\*\.FileModificationTime | string | 
action\_result\.data\.\*\.Tasks\.\*\.FileName | string |  `file name` 
action\_result\.data\.\*\.Tasks\.\*\.FileNameCount | string | 
action\_result\.data\.\*\.Tasks\.\*\.FileOccurrences | string | 
action\_result\.data\.\*\.Tasks\.\*\.FirewallAuthorized | string | 
action\_result\.data\.\*\.Tasks\.\*\.FirstSeenDate | string | 
action\_result\.data\.\*\.Tasks\.\*\.FirstSeenName | string |  `file name` 
action\_result\.data\.\*\.Tasks\.\*\.FirstTimeSeen | string | 
action\_result\.data\.\*\.Tasks\.\*\.Flag | string | 
action\_result\.data\.\*\.Tasks\.\*\.Floating | string | 
action\_result\.data\.\*\.Tasks\.\*\.FolderCie | string | 
action\_result\.data\.\*\.Tasks\.\*\.FolderExecutables | string | 
action\_result\.data\.\*\.Tasks\.\*\.FolderFolder | string | 
action\_result\.data\.\*\.Tasks\.\*\.FolderNonExecutables | string | 
action\_result\.data\.\*\.Tasks\.\*\.Found | string | 
action\_result\.data\.\*\.Tasks\.\*\.FullPath | string |  `file path` 
action\_result\.data\.\*\.Tasks\.\*\.Graylisted | string | 
action\_result\.data\.\*\.Tasks\.\*\.HashLookup | string | 
action\_result\.data\.\*\.Tasks\.\*\.HiddenAttributes | string | 
action\_result\.data\.\*\.Tasks\.\*\.HiddenDirectory | string | 
action\_result\.data\.\*\.Tasks\.\*\.HiddenFile | string | 
action\_result\.data\.\*\.Tasks\.\*\.HiddenXView | string | 
action\_result\.data\.\*\.Tasks\.\*\.HookEAT | string | 
action\_result\.data\.\*\.Tasks\.\*\.HookIAT | string | 
action\_result\.data\.\*\.Tasks\.\*\.HookInline | string | 
action\_result\.data\.\*\.Tasks\.\*\.HookModule | string | 
action\_result\.data\.\*\.Tasks\.\*\.HookType | string | 
action\_result\.data\.\*\.Tasks\.\*\.Hooking | string | 
action\_result\.data\.\*\.Tasks\.\*\.IIOCLevel0 | string | 
action\_result\.data\.\*\.Tasks\.\*\.IIOCLevel1 | string | 
action\_result\.data\.\*\.Tasks\.\*\.IIOCLevel2 | string | 
action\_result\.data\.\*\.Tasks\.\*\.IIOCLevel3 | string | 
action\_result\.data\.\*\.Tasks\.\*\.IIOCScore | string | 
action\_result\.data\.\*\.Tasks\.\*\.IconPresent | string | 
action\_result\.data\.\*\.Tasks\.\*\.ImageHidden | string | 
action\_result\.data\.\*\.Tasks\.\*\.ImageMismatch | string | 
action\_result\.data\.\*\.Tasks\.\*\.ImportedDLLCount | string | 
action\_result\.data\.\*\.Tasks\.\*\.ImportedDLLs | string | 
action\_result\.data\.\*\.Tasks\.\*\.InstallerDirectory | string | 
action\_result\.data\.\*\.Tasks\.\*\.LastRunTime | string | 
action\_result\.data\.\*\.Tasks\.\*\.LikelyPacked | string | 
action\_result\.data\.\*\.Tasks\.\*\.Listen | string | 
action\_result\.data\.\*\.Tasks\.\*\.LiveConnectLastUpdated | string | 
action\_result\.data\.\*\.Tasks\.\*\.LiveConnectRiskEnum | string | 
action\_result\.data\.\*\.Tasks\.\*\.LiveConnectRiskReason | string | 
action\_result\.data\.\*\.Tasks\.\*\.Loaded | string | 
action\_result\.data\.\*\.Tasks\.\*\.MD5 | string |  `md5` 
action\_result\.data\.\*\.Tasks\.\*\.MD5Collision | string | 
action\_result\.data\.\*\.Tasks\.\*\.MachineCount | string | 
action\_result\.data\.\*\.Tasks\.\*\.ModifyBadCertificateWarningSetting | string | 
action\_result\.data\.\*\.Tasks\.\*\.ModifyFirewallPolicy | string | 
action\_result\.data\.\*\.Tasks\.\*\.ModifyInternetZoneSettings | string | 
action\_result\.data\.\*\.Tasks\.\*\.ModifyIntranetZoneBrowsingNotificationSetting | string | 
action\_result\.data\.\*\.Tasks\.\*\.ModifyLUASetting | string | 
action\_result\.data\.\*\.Tasks\.\*\.ModifyRegistryEditorSetting | string | 
action\_result\.data\.\*\.Tasks\.\*\.ModifySecurityCenterConfiguration | string | 
action\_result\.data\.\*\.Tasks\.\*\.ModifyServicesImagePath | string | 
action\_result\.data\.\*\.Tasks\.\*\.ModifyTaskManagerSetting | string | 
action\_result\.data\.\*\.Tasks\.\*\.ModifyWindowsSystemPolicy | string | 
action\_result\.data\.\*\.Tasks\.\*\.ModifyZoneCrossingWarningSetting | string | 
action\_result\.data\.\*\.Tasks\.\*\.ModuleMemoryHash | string | 
action\_result\.data\.\*\.Tasks\.\*\.ModuleName | string |  `file name` 
action\_result\.data\.\*\.Tasks\.\*\.Name | string | 
action\_result\.data\.\*\.Tasks\.\*\.NativeSubsystem | string | 
action\_result\.data\.\*\.Tasks\.\*\.Net | string | 
action\_result\.data\.\*\.Tasks\.\*\.Neutral | string | 
action\_result\.data\.\*\.Tasks\.\*\.NextRunTime | string | 
action\_result\.data\.\*\.Tasks\.\*\.NoIcon | string | 
action\_result\.data\.\*\.Tasks\.\*\.NoVersionInfo | string | 
action\_result\.data\.\*\.Tasks\.\*\.NotFound | string | 
action\_result\.data\.\*\.Tasks\.\*\.NotificationRegistered | string | 
action\_result\.data\.\*\.Tasks\.\*\.NotificationRegisteredType | string | 
action\_result\.data\.\*\.Tasks\.\*\.OpenBrowserProcess | string | 
action\_result\.data\.\*\.Tasks\.\*\.OpenLogicalDrive | string | 
action\_result\.data\.\*\.Tasks\.\*\.OpenOSProcess | string | 
action\_result\.data\.\*\.Tasks\.\*\.OpenPhysicalDrive | string | 
action\_result\.data\.\*\.Tasks\.\*\.OpenProcess | string | 
action\_result\.data\.\*\.Tasks\.\*\.OriginalFileName | string |  `file name` 
action\_result\.data\.\*\.Tasks\.\*\.Packed | string | 
action\_result\.data\.\*\.Tasks\.\*\.Path | string |  `file path` 
action\_result\.data\.\*\.Tasks\.\*\.Platform | string | 
action\_result\.data\.\*\.Tasks\.\*\.ProcessAccessDenied | string | 
action\_result\.data\.\*\.Tasks\.\*\.ProgramData | string | 
action\_result\.data\.\*\.Tasks\.\*\.ProgramFiles | string | 
action\_result\.data\.\*\.Tasks\.\*\.ReadDocument | string | 
action\_result\.data\.\*\.Tasks\.\*\.RecordModifiedTime | string | 
action\_result\.data\.\*\.Tasks\.\*\.RelativeFileName | string |  `file name` 
action\_result\.data\.\*\.Tasks\.\*\.RelativePath | string | 
action\_result\.data\.\*\.Tasks\.\*\.RemoteFileName | string |  `file name` 
action\_result\.data\.\*\.Tasks\.\*\.RemotePath | string |  `file path` 
action\_result\.data\.\*\.Tasks\.\*\.RenametoExecutable | string | 
action\_result\.data\.\*\.Tasks\.\*\.ReservedName | string | 
action\_result\.data\.\*\.Tasks\.\*\.RiskScore | string | 
action\_result\.data\.\*\.Tasks\.\*\.SHA1 | string |  `sha1` 
action\_result\.data\.\*\.Tasks\.\*\.SHA256 | string |  `sha256` 
action\_result\.data\.\*\.Tasks\.\*\.SectionsNames | string | 
action\_result\.data\.\*\.Tasks\.\*\.Signature | string | 
action\_result\.data\.\*\.Tasks\.\*\.SignatureExpired | string | 
action\_result\.data\.\*\.Tasks\.\*\.SignaturePresent | string | 
action\_result\.data\.\*\.Tasks\.\*\.SignatureThumbprint | string |  `sha1` 
action\_result\.data\.\*\.Tasks\.\*\.SignatureTimeStamp | string | 
action\_result\.data\.\*\.Tasks\.\*\.SignatureValid | string | 
action\_result\.data\.\*\.Tasks\.\*\.SignedbyMicrosoft | string | 
action\_result\.data\.\*\.Tasks\.\*\.SizeInBytes | string | 
action\_result\.data\.\*\.Tasks\.\*\.Status | string | 
action\_result\.data\.\*\.Tasks\.\*\.StatusComment | string | 
action\_result\.data\.\*\.Tasks\.\*\.SysWOW64 | string | 
action\_result\.data\.\*\.Tasks\.\*\.System32 | string | 
action\_result\.data\.\*\.Tasks\.\*\.TaskStatus | string | 
action\_result\.data\.\*\.Tasks\.\*\.Temporary | string | 
action\_result\.data\.\*\.Tasks\.\*\.TooManyConnections | string | 
action\_result\.data\.\*\.Tasks\.\*\.Trigger | string | 
action\_result\.data\.\*\.Tasks\.\*\.User | string | 
action\_result\.data\.\*\.Tasks\.\*\.VersionInfoPresent | string | 
action\_result\.data\.\*\.Tasks\.\*\.WFP | string | 
action\_result\.data\.\*\.Tasks\.\*\.Whitelisted | string | 
action\_result\.data\.\*\.Tasks\.\*\.Windows | string | 
action\_result\.data\.\*\.Tasks\.\*\.WritetoExecutable | string | 
action\_result\.data\.\*\.Tasks\.\*\.YaraDefinitionHash | string | 
action\_result\.data\.\*\.Tasks\.\*\.YaraScanDescription | string | 
action\_result\.data\.\*\.Tasks\.\*\.YaraScanFirstThreat | string | 
action\_result\.data\.\*\.Tasks\.\*\.YaraScanresult | string | 
action\_result\.data\.\*\.Tasks\.\*\.YaraVersion | string | 
action\_result\.data\.\*\.Tracking\.\*\.Detail | string | 
action\_result\.data\.\*\.Tracking\.\*\.Event | string | 
action\_result\.data\.\*\.Tracking\.\*\.EventTime | string | 
action\_result\.data\.\*\.Tracking\.\*\.EventType | string | 
action\_result\.data\.\*\.Tracking\.\*\.HashLookup | string | 
action\_result\.data\.\*\.Tracking\.\*\.IIOCScore | string | 
action\_result\.data\.\*\.Tracking\.\*\.IpAddress | string |  `ip` 
action\_result\.data\.\*\.Tracking\.\*\.MachineName | string | 
action\_result\.data\.\*\.Tracking\.\*\.PID | string |  `pid` 
action\_result\.data\.\*\.Tracking\.\*\.SignatureValid | string | 
action\_result\.data\.\*\.Tracking\.\*\.SourceCommandLine | string | 
action\_result\.data\.\*\.Tracking\.\*\.SourceFileName | string |  `file name` 
action\_result\.data\.\*\.Tracking\.\*\.SourcePath | string | 
action\_result\.data\.\*\.Tracking\.\*\.SourceSHA256 | string |  `sha256` 
action\_result\.data\.\*\.Tracking\.\*\.Status | string | 
action\_result\.data\.\*\.Tracking\.\*\.Target | string | 
action\_result\.data\.\*\.Tracking\.\*\.TargetCommandLine | string | 
action\_result\.data\.\*\.Tracking\.\*\.TargetFileName | string |  `file name` 
action\_result\.data\.\*\.Tracking\.\*\.TargetPath | string | 
action\_result\.data\.\*\.Tracking\.\*\.TargetSHA256 | string |  `sha256` 
action\_result\.data\.\*\.Tracking\.\*\.UserName | string |  `user name` 
action\_result\.data\.\*\.WindowsHooks\.\*\.ADS | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.AVDefinitionHash | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.AVDescription | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.AVFirstThreat | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.AVScanResult | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.AVVersion | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.AccessNetwork | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.AnalysisTime | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.AppDataLocal | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.AppDataRoaming | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.Assigned | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.AutoStartCategory | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.AutomaticAssignment | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.AutomaticBiasStatusAssignment | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.Autorun | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.AutorunAppInit | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.AutorunBoot | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.AutorunBootExecute | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.AutorunCodecs | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.AutorunDrivers | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.AutorunExplorer | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.AutorunImageHijack | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.AutorunInternetExplorer | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.AutorunKnownDLLs | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.AutorunLSAProviders | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.AutorunLogon | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.AutorunNetworkProviders | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.AutorunPrintMonitors | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.AutorunSafeBootMinimal | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.AutorunSafeBootNetwork | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.AutorunScheduledTask | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.AutorunServiceDLL | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.AutorunServices | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.AutorunStartupFolder | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.AutorunWinlogon | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.AutorunWinsockProviders | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.Beacon | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.BlacklistCategory | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.Blacklisted | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.BlockingStatus | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.BytesSentRatio | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.CertBiasStatus | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.CertModuleCount | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.CodeSectionWritable | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.CompanyName | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.CompanyNameCount | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.CompileTime | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.CreateProcess | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.CreateProcessNotification | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.CreateRemoteThread | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.CreateThreadNotification | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.CustomerOccurrences | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.DateBlocked | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.DaysSinceCompilation | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.DaysSinceCreation | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.DeleteExecutable | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.Description | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.Desktop | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.Downloaded | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.DownloadedTime | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.DuplicationSectionName | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.EmptySectionName | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.EncryptedDirectory | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.Entropy | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.FakeStartAddress | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.FileAccessDenied | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.FileAccessTime | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.FileAttributes | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.FileCreationTime | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.FileEncrypted | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.FileHiddenAttributes | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.FileHiddenXView | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.FileModificationTime | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.FileName | string |  `file name` 
action\_result\.data\.\*\.WindowsHooks\.\*\.FileNameCount | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.FileOccurrences | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.FirewallAuthorized | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.FirstSeenDate | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.FirstSeenName | string |  `file name` 
action\_result\.data\.\*\.WindowsHooks\.\*\.FirstTimeSeen | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.Floating | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.FolderCie | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.FolderExecutables | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.FolderFolder | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.FolderNonExecutables | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.Found | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.FullPath | string |  `file path` 
action\_result\.data\.\*\.WindowsHooks\.\*\.Graylisted | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.HashLookup | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.HiddenAttributes | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.HiddenDirectory | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.HiddenFile | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.HiddenXView | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.HookEAT | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.HookIAT | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.HookInline | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.HookModule | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.HookType | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.HookedEPROCESS | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.HookedPID | string |  `pid` 
action\_result\.data\.\*\.WindowsHooks\.\*\.HookedProcess | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.HookedProcessPath | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.HookerEPROCESS | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.HookerETHREAD | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.HookerPID | string |  `pid` 
action\_result\.data\.\*\.WindowsHooks\.\*\.Hooking | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.IIOCLevel0 | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.IIOCLevel1 | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.IIOCLevel2 | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.IIOCLevel3 | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.IIOCScore | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.IconPresent | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.ImageHidden | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.ImageMismatch | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.ImportedDLLCount | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.ImportedDLLs | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.InstallerDirectory | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.LikelyPacked | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.Listen | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.LiveConnectLastUpdated | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.LiveConnectRiskEnum | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.LiveConnectRiskReason | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.Loaded | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.MD5 | string |  `md5` 
action\_result\.data\.\*\.WindowsHooks\.\*\.MD5Collision | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.MachineCount | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.ModifyBadCertificateWarningSetting | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.ModifyFirewallPolicy | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.ModifyInternetZoneSettings | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.ModifyIntranetZoneBrowsingNotificationSetting | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.ModifyLUASetting | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.ModifyRegistryEditorSetting | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.ModifySecurityCenterConfiguration | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.ModifyServicesImagePath | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.ModifyTaskManagerSetting | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.ModifyWindowsSystemPolicy | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.ModifyZoneCrossingWarningSetting | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.ModuleMemoryHash | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.ModuleName | string |  `file name` 
action\_result\.data\.\*\.WindowsHooks\.\*\.NativeSubsystem | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.Net | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.Neutral | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.NoIcon | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.NoVersionInfo | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.NotFound | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.NotificationRegistered | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.NotificationRegisteredType | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.OpenBrowserProcess | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.OpenLogicalDrive | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.OpenOSProcess | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.OpenPhysicalDrive | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.OpenProcess | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.OriginalFileName | string |  `file name` 
action\_result\.data\.\*\.WindowsHooks\.\*\.Packed | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.Path | string |  `file path` 
action\_result\.data\.\*\.WindowsHooks\.\*\.Platform | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.ProcessAccessDenied | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.ProgramData | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.ProgramFiles | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.ReadDocument | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.RecordModifiedTime | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.RelativeFileName | string |  `file name` 
action\_result\.data\.\*\.WindowsHooks\.\*\.RelativePath | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.RemoteFileName | string |  `file name` 
action\_result\.data\.\*\.WindowsHooks\.\*\.RemotePath | string |  `file path` 
action\_result\.data\.\*\.WindowsHooks\.\*\.RenametoExecutable | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.ReservedName | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.RiskScore | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.SHA1 | string |  `sha1` 
action\_result\.data\.\*\.WindowsHooks\.\*\.SHA256 | string |  `sha256` 
action\_result\.data\.\*\.WindowsHooks\.\*\.SectionsNames | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.Signature | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.SignatureExpired | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.SignaturePresent | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.SignatureThumbprint | string |  `sha1` 
action\_result\.data\.\*\.WindowsHooks\.\*\.SignatureTimeStamp | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.SignatureValid | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.SignedbyMicrosoft | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.SizeInBytes | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.Status | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.StatusComment | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.SysWOW64 | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.System32 | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.Temporary | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.TooManyConnections | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.User | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.VersionInfoPresent | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.WFP | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.Whitelisted | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.Windows | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.WindowsHookType | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.WritetoExecutable | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.YaraDefinitionHash | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.YaraScanDescription | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.YaraScanFirstThreat | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.YaraScanresult | string | 
action\_result\.data\.\*\.WindowsHooks\.\*\.YaraVersion | string | 
action\_result\.summary\.autoruns | numeric | 
action\_result\.summary\.dlls | numeric | 
action\_result\.summary\.drivers | numeric | 
action\_result\.summary\.imagehooks | numeric | 
action\_result\.summary\.kernelhooks | numeric | 
action\_result\.summary\.network | numeric | 
action\_result\.summary\.processes | numeric | 
action\_result\.summary\.registrydiscrepencies | numeric | 
action\_result\.summary\.services | numeric | 
action\_result\.summary\.suspiciousthreads | numeric | 
action\_result\.summary\.tasks | numeric | 
action\_result\.summary\.tracking | numeric | 
action\_result\.summary\.windowshooks | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'on poll'
Action to ingest endpoint related information

Type: **ingest**  
Read only: **True**

This action ingests all the IOCs having OS type "Windows", IOC level <b>max\_ioc\_level</b> and lower and whose machine count and module count are greater than 0\. The IOCs fetched are ordered concerning time\. Containers are uniquely identified by IOC Description and its OS type\. The information of affected machines and modules of an IOC is ingested as artifacts\. During manual polling, the number of IOCs to be ingested can be controlled by <b>container\_count</b>, and during scheduled polling, the number of IOCs to be ingested in each cycle can be controlled by <b>max\_ioc\_for\_scheduled\_poll</b>\.<br></p><table><tbody><tr class='plain'><th>IOC</th><th>Artifact Name</th><th>CEF Field</th></tr><tr><td>File</td><td>File Artifact</td><td>fileHashMd5, fileHashSha1, fileHashSha256, fileName, iiocScore, riskScore</td></tr><tr><td>Endpoint Details</td><td>Endpoint Artifact</td><td>nweMachineGuid, sourceAddress, remoteAddress, sourceUserName, sourceMacAddress, iiocScore, machineName</td></tr><tr><td>Instant IOC Details</td><td>Instant IOC Artifact</td><td>instantIocName, iocLevel, iocType, lastExecutedTime, osType</td></tr></tbody></table>

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**container\_id** |  optional  | Comma \(,\) separated container IDs | string | 
**container\_count** |  optional  | Maximum number of containers to ingest | numeric | 
**start\_time** |  optional  | Parameter ignored in this app | numeric | 
**artifact\_count** |  optional  | Parameter ignored in this app | numeric | 
**end\_time** |  optional  | Parameter ignored in this app | numeric | 

#### Action Output
No Output  

## action: 'list ioc'
List the IOC

Type: **investigate**  
Read only: **True**

This action lists all IOCs having OS type "Windows"\.<br>The results are always sorted in ascending order based on their IOC level to place the most critical IOCs at the top\. For example, to get the top 10 critical IOCs that matched the filter, specify the <b>limit</b> as 10\. If the <b>limit</b> is zero, then all matching IOCs will be returned\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**machine\_count** |  optional  | Minimum IOC machines \(Default\: 0\) | numeric | 
**module\_count** |  optional  | Minimum IOC modules \(Default\: 0\) | numeric | 
**max\_ioc\_level** |  optional  | Maximum IOC level of modules \(Default\: 2\) | string | 
**limit** |  optional  | Maximum number of IOCs to retrieve \(Default\: 50\) | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.limit | numeric | 
action\_result\.parameter\.machine\_count | numeric | 
action\_result\.parameter\.max\_ioc\_level | string | 
action\_result\.parameter\.module\_count | numeric | 
action\_result\.data\.\*\.Active | string | 
action\_result\.data\.\*\.Alertable | string | 
action\_result\.data\.\*\.BlacklistedCount | string | 
action\_result\.data\.\*\.Description | string | 
action\_result\.data\.\*\.ErrorMessage | string | 
action\_result\.data\.\*\.EvaluationMachineCount | string | 
action\_result\.data\.\*\.GraylistedCount | string | 
action\_result\.data\.\*\.IOCLevel | string | 
action\_result\.data\.\*\.LastEvaluationDuration | string | 
action\_result\.data\.\*\.LastExecuted | string | 
action\_result\.data\.\*\.LastExecutionDuration | string | 
action\_result\.data\.\*\.MachineCount | string | 
action\_result\.data\.\*\.ModuleCount | string | 
action\_result\.data\.\*\.Name | string |  `nwe ioc name` 
action\_result\.data\.\*\.Persistent | string | 
action\_result\.data\.\*\.Priority | string | 
action\_result\.data\.\*\.Query | string | 
action\_result\.data\.\*\.Type | string | 
action\_result\.data\.\*\.UserDefined | string | 
action\_result\.data\.\*\.WhitelistedCount | string | 
action\_result\.summary\.available\_iocs | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get ioc'
Get the IOC

Type: **investigate**  
Read only: **True**

This action will fetch details of only windows machines whose modules are having IOC level <b>max\_ioc\_level</b> and lower and are related to the given IOC name\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**name** |  required  | Name of IOC | string |  `nwe ioc name` 
**max\_ioc\_level** |  optional  | Maximum IOC level of modules to ingest \(Default\: 2\) | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.max\_ioc\_level | string | 
action\_result\.parameter\.name | string |  `nwe ioc name` 
action\_result\.data\.\*\.iocMachines\.\*\.AdminStatus | string | 
action\_result\.data\.\*\.iocMachines\.\*\.AgentID | string | 
action\_result\.data\.\*\.iocMachines\.\*\.AllowAccessDataSourceDomain | string | 
action\_result\.data\.\*\.iocMachines\.\*\.AllowDisplayMixedContent | string | 
action\_result\.data\.\*\.iocMachines\.\*\.AntiVirusDisabled | string | 
action\_result\.data\.\*\.iocMachines\.\*\.BIOS | string | 
action\_result\.data\.\*\.iocMachines\.\*\.BadCertificateWarningDisabled | string | 
action\_result\.data\.\*\.iocMachines\.\*\.BlockingActive | string | 
action\_result\.data\.\*\.iocMachines\.\*\.BootTime | string | 
action\_result\.data\.\*\.iocMachines\.\*\.CategorySaveFailed | string | 
action\_result\.data\.\*\.iocMachines\.\*\.ChassisType | string | 
action\_result\.data\.\*\.iocMachines\.\*\.Comment | string | 
action\_result\.data\.\*\.iocMachines\.\*\.ConnectionTime | string | 
action\_result\.data\.\*\.iocMachines\.\*\.ContainmentStatus | string | 
action\_result\.data\.\*\.iocMachines\.\*\.ContainmentSupported | string | 
action\_result\.data\.\*\.iocMachines\.\*\.CookiesCleanupDisabled | string | 
action\_result\.data\.\*\.iocMachines\.\*\.Country | string | 
action\_result\.data\.\*\.iocMachines\.\*\.CrosssiteScriptFilterDisabled | string | 
action\_result\.data\.\*\.iocMachines\.\*\.DNS | string |  `ip` 
action\_result\.data\.\*\.iocMachines\.\*\.DebuggerAttachedToProcess | string | 
action\_result\.data\.\*\.iocMachines\.\*\.DomainName | string |  `domain` 
action\_result\.data\.\*\.iocMachines\.\*\.DomainRole | string | 
action\_result\.data\.\*\.iocMachines\.\*\.DriverErrorCode | string | 
action\_result\.data\.\*\.iocMachines\.\*\.DriverMonitorModule | string | 
action\_result\.data\.\*\.iocMachines\.\*\.ECATDriverCompileTime | string | 
action\_result\.data\.\*\.iocMachines\.\*\.ECATPackageTime | string | 
action\_result\.data\.\*\.iocMachines\.\*\.ECATServerName | string | 
action\_result\.data\.\*\.iocMachines\.\*\.ECATServiceCompileTime | string | 
action\_result\.data\.\*\.iocMachines\.\*\.EarlyStart | string | 
action\_result\.data\.\*\.iocMachines\.\*\.ErrorLogModule | string | 
action\_result\.data\.\*\.iocMachines\.\*\.FirewallDisabled | string | 
action\_result\.data\.\*\.iocMachines\.\*\.Gateway | string |  `ip` 
action\_result\.data\.\*\.iocMachines\.\*\.Group | string | 
action\_result\.data\.\*\.iocMachines\.\*\.HTTPSFallbackMode | string | 
action\_result\.data\.\*\.iocMachines\.\*\.IEDepDisabled | string | 
action\_result\.data\.\*\.iocMachines\.\*\.IEEnhancedSecurityDisabled | string | 
action\_result\.data\.\*\.iocMachines\.\*\.IIOCLevel0 | string | 
action\_result\.data\.\*\.iocMachines\.\*\.IIOCLevel1 | string | 
action\_result\.data\.\*\.iocMachines\.\*\.IIOCLevel2 | string | 
action\_result\.data\.\*\.iocMachines\.\*\.IIOCLevel3 | string | 
action\_result\.data\.\*\.iocMachines\.\*\.IIOCScore | string | 
action\_result\.data\.\*\.iocMachines\.\*\.Idle | string | 
action\_result\.data\.\*\.iocMachines\.\*\.ImageMonitorModule | string | 
action\_result\.data\.\*\.iocMachines\.\*\.IncludedinMonitoring | string | 
action\_result\.data\.\*\.iocMachines\.\*\.IncludedinScanSchedule | string | 
action\_result\.data\.\*\.iocMachines\.\*\.InstallTime | string | 
action\_result\.data\.\*\.iocMachines\.\*\.InstallationFailed | string | 
action\_result\.data\.\*\.iocMachines\.\*\.IntranetZoneNotificationDisabled | string | 
action\_result\.data\.\*\.iocMachines\.\*\.KernelDebuggerDetected | string | 
action\_result\.data\.\*\.iocMachines\.\*\.LUADisabled | string | 
action\_result\.data\.\*\.iocMachines\.\*\.Language | string | 
action\_result\.data\.\*\.iocMachines\.\*\.LastScan | string | 
action\_result\.data\.\*\.iocMachines\.\*\.LastSeen | string | 
action\_result\.data\.\*\.iocMachines\.\*\.LoadedModuleModule | string | 
action\_result\.data\.\*\.iocMachines\.\*\.LocalIP | string |  `ip` 
action\_result\.data\.\*\.iocMachines\.\*\.LowLevelReaderModule | string | 
action\_result\.data\.\*\.iocMachines\.\*\.MAC | string |  `mac address` 
action\_result\.data\.\*\.iocMachines\.\*\.MachineID | string | 
action\_result\.data\.\*\.iocMachines\.\*\.MachineName | string | 
action\_result\.data\.\*\.iocMachines\.\*\.MachineStatus | string | 
action\_result\.data\.\*\.iocMachines\.\*\.Manufacturer | string | 
action\_result\.data\.\*\.iocMachines\.\*\.Model | string | 
action\_result\.data\.\*\.iocMachines\.\*\.NTFSPartitionDrive | string | 
action\_result\.data\.\*\.iocMachines\.\*\.NTFSPhysicalDrive | string | 
action\_result\.data\.\*\.iocMachines\.\*\.NetworkAdapterPromiscMode | string | 
action\_result\.data\.\*\.iocMachines\.\*\.NetworkSegment | string |  `ip` 
action\_result\.data\.\*\.iocMachines\.\*\.NoAntivirusNotificationDisabled | string | 
action\_result\.data\.\*\.iocMachines\.\*\.NoFirewallNotificationDisabled | string | 
action\_result\.data\.\*\.iocMachines\.\*\.NoUACNotificationDisabled | string | 
action\_result\.data\.\*\.iocMachines\.\*\.NoWindowsUpdateDisabled | string | 
action\_result\.data\.\*\.iocMachines\.\*\.NotifyRoutineModule | string | 
action\_result\.data\.\*\.iocMachines\.\*\.NotifyShutdownModule | string | 
action\_result\.data\.\*\.iocMachines\.\*\.NtfsLowLevelReads | string | 
action\_result\.data\.\*\.iocMachines\.\*\.OSBuildNumber | string | 
action\_result\.data\.\*\.iocMachines\.\*\.ObjectMonitorModule | string | 
action\_result\.data\.\*\.iocMachines\.\*\.Online | string | 
action\_result\.data\.\*\.iocMachines\.\*\.OperatingSystem | string | 
action\_result\.data\.\*\.iocMachines\.\*\.OrganizationUnit | string | 
action\_result\.data\.\*\.iocMachines\.\*\.Platform | string | 
action\_result\.data\.\*\.iocMachines\.\*\.ProcessModule | string | 
action\_result\.data\.\*\.iocMachines\.\*\.ProcessMonitorModule | string | 
action\_result\.data\.\*\.iocMachines\.\*\.ProcessingIOCEvaluation | string | 
action\_result\.data\.\*\.iocMachines\.\*\.ProcessorArchitecture | string | 
action\_result\.data\.\*\.iocMachines\.\*\.ProcessorCount | string | 
action\_result\.data\.\*\.iocMachines\.\*\.ProcessorIs32bits | string | 
action\_result\.data\.\*\.iocMachines\.\*\.ProcessorName | string | 
action\_result\.data\.\*\.iocMachines\.\*\.Processoris64 | string | 
action\_result\.data\.\*\.iocMachines\.\*\.RegistryToolsDisabled | string | 
action\_result\.data\.\*\.iocMachines\.\*\.RemoteIP | string |  `ip` 
action\_result\.data\.\*\.iocMachines\.\*\.RoamingAgentsRelaySystemActive | string | 
action\_result\.data\.\*\.iocMachines\.\*\.ScanStartTime | string | 
action\_result\.data\.\*\.iocMachines\.\*\.Scanning | string | 
action\_result\.data\.\*\.iocMachines\.\*\.Serial | string | 
action\_result\.data\.\*\.iocMachines\.\*\.ServicePackOS | string | 
action\_result\.data\.\*\.iocMachines\.\*\.SmartscreenFilterDisabled | string | 
action\_result\.data\.\*\.iocMachines\.\*\.StartTime | string | 
action\_result\.data\.\*\.iocMachines\.\*\.SystemRestoreDisabled | string | 
action\_result\.data\.\*\.iocMachines\.\*\.TaskManagerDisabled | string | 
action\_result\.data\.\*\.iocMachines\.\*\.TdiMonitorModule | string | 
action\_result\.data\.\*\.iocMachines\.\*\.ThreadMonitorModule | string | 
action\_result\.data\.\*\.iocMachines\.\*\.TimeZone | string | 
action\_result\.data\.\*\.iocMachines\.\*\.TotalPhysicalMemory | string | 
action\_result\.data\.\*\.iocMachines\.\*\.TrackingCreateProcessMonitor | string | 
action\_result\.data\.\*\.iocMachines\.\*\.TrackingFileBlockMonitor | string | 
action\_result\.data\.\*\.iocMachines\.\*\.TrackingFileMonitor | string | 
action\_result\.data\.\*\.iocMachines\.\*\.TrackingHardLinkMonitor | string | 
action\_result\.data\.\*\.iocMachines\.\*\.TrackingModule | string | 
action\_result\.data\.\*\.iocMachines\.\*\.TrackingNetworkMonitor | string | 
action\_result\.data\.\*\.iocMachines\.\*\.TrackingObjectMonitor | string | 
action\_result\.data\.\*\.iocMachines\.\*\.TrackingRegistryMonitor | string | 
action\_result\.data\.\*\.iocMachines\.\*\.TrackingRemoteThreadMonitor | string | 
action\_result\.data\.\*\.iocMachines\.\*\.Type | string | 
action\_result\.data\.\*\.iocMachines\.\*\.UACDisabled | string | 
action\_result\.data\.\*\.iocMachines\.\*\.UnloadedDriverModule | string | 
action\_result\.data\.\*\.iocMachines\.\*\.UserID | string | 
action\_result\.data\.\*\.iocMachines\.\*\.UserName | string |  `user name` 
action\_result\.data\.\*\.iocMachines\.\*\.VersionInfo | string | 
action\_result\.data\.\*\.iocMachines\.\*\.WarningOnZoneCrossingDisabled | string | 
action\_result\.data\.\*\.iocMachines\.\*\.WarningPostRedirectionDisabled | string | 
action\_result\.data\.\*\.iocMachines\.\*\.WindowsDirectory | string |  `file path` 
action\_result\.data\.\*\.iocMachines\.\*\.WindowsHooksModule | string | 
action\_result\.data\.\*\.iocMachines\.\*\.WorkerThreadModule | string | 
action\_result\.data\.\*\.iocModules\.\*\.ADS | string | 
action\_result\.data\.\*\.iocModules\.\*\.AVDefinitionHash | string | 
action\_result\.data\.\*\.iocModules\.\*\.AVDescription | string | 
action\_result\.data\.\*\.iocModules\.\*\.AVFirstThreat | string | 
action\_result\.data\.\*\.iocModules\.\*\.AVScanResult | string | 
action\_result\.data\.\*\.iocModules\.\*\.AVVersion | string | 
action\_result\.data\.\*\.iocModules\.\*\.AccessNetwork | string | 
action\_result\.data\.\*\.iocModules\.\*\.Active | string | 
action\_result\.data\.\*\.iocModules\.\*\.Alertable | string | 
action\_result\.data\.\*\.iocModules\.\*\.AnalysisTime | string | 
action\_result\.data\.\*\.iocModules\.\*\.AppDataLocal | string | 
action\_result\.data\.\*\.iocModules\.\*\.AppDataRoaming | string | 
action\_result\.data\.\*\.iocModules\.\*\.AutoStartCategory | string | 
action\_result\.data\.\*\.iocModules\.\*\.AutomaticBiasStatusAssignment | string | 
action\_result\.data\.\*\.iocModules\.\*\.Autorun | string | 
action\_result\.data\.\*\.iocModules\.\*\.AutorunAppInit | string | 
action\_result\.data\.\*\.iocModules\.\*\.AutorunBoot | string | 
action\_result\.data\.\*\.iocModules\.\*\.AutorunBootExecute | string | 
action\_result\.data\.\*\.iocModules\.\*\.AutorunCodecs | string | 
action\_result\.data\.\*\.iocModules\.\*\.AutorunDrivers | string | 
action\_result\.data\.\*\.iocModules\.\*\.AutorunExplorer | string | 
action\_result\.data\.\*\.iocModules\.\*\.AutorunImageHijack | string | 
action\_result\.data\.\*\.iocModules\.\*\.AutorunInternetExplorer | string | 
action\_result\.data\.\*\.iocModules\.\*\.AutorunKnownDLLs | string | 
action\_result\.data\.\*\.iocModules\.\*\.AutorunLSAProviders | string | 
action\_result\.data\.\*\.iocModules\.\*\.AutorunLogon | string | 
action\_result\.data\.\*\.iocModules\.\*\.AutorunNetworkProviders | string | 
action\_result\.data\.\*\.iocModules\.\*\.AutorunPrintMonitors | string | 
action\_result\.data\.\*\.iocModules\.\*\.AutorunSafeBootMinimal | string | 
action\_result\.data\.\*\.iocModules\.\*\.AutorunSafeBootNetwork | string | 
action\_result\.data\.\*\.iocModules\.\*\.AutorunScheduledTask | string | 
action\_result\.data\.\*\.iocModules\.\*\.AutorunServiceDLL | string | 
action\_result\.data\.\*\.iocModules\.\*\.AutorunServices | string | 
action\_result\.data\.\*\.iocModules\.\*\.AutorunStartupFolder | string | 
action\_result\.data\.\*\.iocModules\.\*\.AutorunWinlogon | string | 
action\_result\.data\.\*\.iocModules\.\*\.AutorunWinsockProviders | string | 
action\_result\.data\.\*\.iocModules\.\*\.Beacon | string | 
action\_result\.data\.\*\.iocModules\.\*\.BlacklistCategory | string | 
action\_result\.data\.\*\.iocModules\.\*\.Blacklisted | string | 
action\_result\.data\.\*\.iocModules\.\*\.BlockingStatus | string | 
action\_result\.data\.\*\.iocModules\.\*\.BytesSentRatio | string | 
action\_result\.data\.\*\.iocModules\.\*\.CertBiasStatus | string | 
action\_result\.data\.\*\.iocModules\.\*\.CertModuleCount | string | 
action\_result\.data\.\*\.iocModules\.\*\.CodeSectionWritable | string | 
action\_result\.data\.\*\.iocModules\.\*\.CompanyName | string | 
action\_result\.data\.\*\.iocModules\.\*\.CompanyNameCount | string | 
action\_result\.data\.\*\.iocModules\.\*\.CompileTime | string | 
action\_result\.data\.\*\.iocModules\.\*\.CreateProcess | string | 
action\_result\.data\.\*\.iocModules\.\*\.CreateProcessNotification | string | 
action\_result\.data\.\*\.iocModules\.\*\.CreateRemoteThread | string | 
action\_result\.data\.\*\.iocModules\.\*\.CreateThreadNotification | string | 
action\_result\.data\.\*\.iocModules\.\*\.CustomerOccurrences | string | 
action\_result\.data\.\*\.iocModules\.\*\.DateBlocked | string | 
action\_result\.data\.\*\.iocModules\.\*\.DaysSinceCompilation | string | 
action\_result\.data\.\*\.iocModules\.\*\.DeleteExecutable | string | 
action\_result\.data\.\*\.iocModules\.\*\.Description | string | 
action\_result\.data\.\*\.iocModules\.\*\.Desktop | string | 
action\_result\.data\.\*\.iocModules\.\*\.Downloaded | string | 
action\_result\.data\.\*\.iocModules\.\*\.DownloadedTime | string | 
action\_result\.data\.\*\.iocModules\.\*\.DuplicationSectionName | string | 
action\_result\.data\.\*\.iocModules\.\*\.EmptySectionName | string | 
action\_result\.data\.\*\.iocModules\.\*\.EncryptedDirectory | string | 
action\_result\.data\.\*\.iocModules\.\*\.Entropy | string | 
action\_result\.data\.\*\.iocModules\.\*\.FakeStartAddress | string | 
action\_result\.data\.\*\.iocModules\.\*\.FileAccessDenied | string | 
action\_result\.data\.\*\.iocModules\.\*\.FileEncrypted | string | 
action\_result\.data\.\*\.iocModules\.\*\.FileHiddenAttributes | string | 
action\_result\.data\.\*\.iocModules\.\*\.FileHiddenXView | string | 
action\_result\.data\.\*\.iocModules\.\*\.FileName | string |  `file name` 
action\_result\.data\.\*\.iocModules\.\*\.FileNameCount | string | 
action\_result\.data\.\*\.iocModules\.\*\.FileOccurrences | string | 
action\_result\.data\.\*\.iocModules\.\*\.FirstSeenDate | string | 
action\_result\.data\.\*\.iocModules\.\*\.FirstSeenName | string |  `file name` 
action\_result\.data\.\*\.iocModules\.\*\.FirstTimeSeen | string | 
action\_result\.data\.\*\.iocModules\.\*\.Floating | string | 
action\_result\.data\.\*\.iocModules\.\*\.Found | string | 
action\_result\.data\.\*\.iocModules\.\*\.Graylisted | string | 
action\_result\.data\.\*\.iocModules\.\*\.HashLookup | string | 
action\_result\.data\.\*\.iocModules\.\*\.HiddenAttributes | string | 
action\_result\.data\.\*\.iocModules\.\*\.HiddenDirectory | string | 
action\_result\.data\.\*\.iocModules\.\*\.HiddenFile | string | 
action\_result\.data\.\*\.iocModules\.\*\.HiddenXView | string | 
action\_result\.data\.\*\.iocModules\.\*\.HookEAT | string | 
action\_result\.data\.\*\.iocModules\.\*\.HookIAT | string | 
action\_result\.data\.\*\.iocModules\.\*\.HookInline | string | 
action\_result\.data\.\*\.iocModules\.\*\.HookModule | string | 
action\_result\.data\.\*\.iocModules\.\*\.HookType | string | 
action\_result\.data\.\*\.iocModules\.\*\.Hooking | string | 
action\_result\.data\.\*\.iocModules\.\*\.IIOCLevel0 | string | 
action\_result\.data\.\*\.iocModules\.\*\.IIOCLevel1 | string | 
action\_result\.data\.\*\.iocModules\.\*\.IIOCLevel2 | string | 
action\_result\.data\.\*\.iocModules\.\*\.IIOCLevel3 | string | 
action\_result\.data\.\*\.iocModules\.\*\.IIOCScore | string | 
action\_result\.data\.\*\.iocModules\.\*\.IOCDescription | string | 
action\_result\.data\.\*\.iocModules\.\*\.IOCLevel | string | 
action\_result\.data\.\*\.iocModules\.\*\.IOCName | string | 
action\_result\.data\.\*\.iocModules\.\*\.IconPresent | string | 
action\_result\.data\.\*\.iocModules\.\*\.ImageHidden | string | 
action\_result\.data\.\*\.iocModules\.\*\.ImageMismatch | string | 
action\_result\.data\.\*\.iocModules\.\*\.ImportedDLLCount | string | 
action\_result\.data\.\*\.iocModules\.\*\.ImportedDLLs | string | 
action\_result\.data\.\*\.iocModules\.\*\.LastExecuted | string | 
action\_result\.data\.\*\.iocModules\.\*\.LikelyPacked | string | 
action\_result\.data\.\*\.iocModules\.\*\.Listen | string | 
action\_result\.data\.\*\.iocModules\.\*\.LiveConnectLastUpdated | string | 
action\_result\.data\.\*\.iocModules\.\*\.LiveConnectRiskEnum | string | 
action\_result\.data\.\*\.iocModules\.\*\.LiveConnectRiskReason | string | 
action\_result\.data\.\*\.iocModules\.\*\.MD5 | string |  `md5` 
action\_result\.data\.\*\.iocModules\.\*\.MD5Collision | string | 
action\_result\.data\.\*\.iocModules\.\*\.MachineCount | string | 
action\_result\.data\.\*\.iocModules\.\*\.ModifyBadCertificateWarningSetting | string | 
action\_result\.data\.\*\.iocModules\.\*\.ModifyFirewallPolicy | string | 
action\_result\.data\.\*\.iocModules\.\*\.ModifyInternetZoneSettings | string | 
action\_result\.data\.\*\.iocModules\.\*\.ModifyIntranetZoneBrowsingNotificationSetting | string | 
action\_result\.data\.\*\.iocModules\.\*\.ModifyLUASetting | string | 
action\_result\.data\.\*\.iocModules\.\*\.ModifyRegistryEditorSetting | string | 
action\_result\.data\.\*\.iocModules\.\*\.ModifySecurityCenterConfiguration | string | 
action\_result\.data\.\*\.iocModules\.\*\.ModifyServicesImagePath | string | 
action\_result\.data\.\*\.iocModules\.\*\.ModifyTaskManagerSetting | string | 
action\_result\.data\.\*\.iocModules\.\*\.ModifyWindowsSystemPolicy | string | 
action\_result\.data\.\*\.iocModules\.\*\.ModifyZoneCrossingWarningSetting | string | 
action\_result\.data\.\*\.iocModules\.\*\.ModuleMemoryHash | string | 
action\_result\.data\.\*\.iocModules\.\*\.NativeSubsystem | string | 
action\_result\.data\.\*\.iocModules\.\*\.Net | string | 
action\_result\.data\.\*\.iocModules\.\*\.Neutral | string | 
action\_result\.data\.\*\.iocModules\.\*\.NoIcon | string | 
action\_result\.data\.\*\.iocModules\.\*\.NoVersionInfo | string | 
action\_result\.data\.\*\.iocModules\.\*\.NotFound | string | 
action\_result\.data\.\*\.iocModules\.\*\.NotificationRegistered | string | 
action\_result\.data\.\*\.iocModules\.\*\.NotificationRegisteredType | string | 
action\_result\.data\.\*\.iocModules\.\*\.OpenBrowserProcess | string | 
action\_result\.data\.\*\.iocModules\.\*\.OpenLogicalDrive | string | 
action\_result\.data\.\*\.iocModules\.\*\.OpenOSProcess | string | 
action\_result\.data\.\*\.iocModules\.\*\.OpenPhysicalDrive | string | 
action\_result\.data\.\*\.iocModules\.\*\.OpenProcess | string | 
action\_result\.data\.\*\.iocModules\.\*\.OriginalFileName | string |  `file name` 
action\_result\.data\.\*\.iocModules\.\*\.Packed | string | 
action\_result\.data\.\*\.iocModules\.\*\.Platform | string | 
action\_result\.data\.\*\.iocModules\.\*\.Priority | string | 
action\_result\.data\.\*\.iocModules\.\*\.ProcessAccessDenied | string | 
action\_result\.data\.\*\.iocModules\.\*\.ProgramData | string | 
action\_result\.data\.\*\.iocModules\.\*\.ProgramFiles | string | 
action\_result\.data\.\*\.iocModules\.\*\.Query | string | 
action\_result\.data\.\*\.iocModules\.\*\.ReadDocument | string | 
action\_result\.data\.\*\.iocModules\.\*\.RelativeFileName | string |  `file name` 
action\_result\.data\.\*\.iocModules\.\*\.RelativePath | string | 
action\_result\.data\.\*\.iocModules\.\*\.RemoteFileName | string | 
action\_result\.data\.\*\.iocModules\.\*\.RemotePath | string |  `file path` 
action\_result\.data\.\*\.iocModules\.\*\.RenametoExecutable | string | 
action\_result\.data\.\*\.iocModules\.\*\.RiskScore | string | 
action\_result\.data\.\*\.iocModules\.\*\.SHA1 | string |  `sha1` 
action\_result\.data\.\*\.iocModules\.\*\.SHA256 | string |  `sha256` 
action\_result\.data\.\*\.iocModules\.\*\.SectionsNames | string | 
action\_result\.data\.\*\.iocModules\.\*\.Signature | string | 
action\_result\.data\.\*\.iocModules\.\*\.SignatureExpired | string | 
action\_result\.data\.\*\.iocModules\.\*\.SignaturePresent | string | 
action\_result\.data\.\*\.iocModules\.\*\.SignatureThumbprint | string |  `sha1` 
action\_result\.data\.\*\.iocModules\.\*\.SignatureTimeStamp | string | 
action\_result\.data\.\*\.iocModules\.\*\.SignatureValid | string | 
action\_result\.data\.\*\.iocModules\.\*\.SignedbyMicrosoft | string | 
action\_result\.data\.\*\.iocModules\.\*\.SizeInBytes | string | 
action\_result\.data\.\*\.iocModules\.\*\.Status | string | 
action\_result\.data\.\*\.iocModules\.\*\.StatusComment | string | 
action\_result\.data\.\*\.iocModules\.\*\.SysWOW64 | string | 
action\_result\.data\.\*\.iocModules\.\*\.System32 | string | 
action\_result\.data\.\*\.iocModules\.\*\.Temporary | string | 
action\_result\.data\.\*\.iocModules\.\*\.TooManyConnections | string | 
action\_result\.data\.\*\.iocModules\.\*\.Type | string | 
action\_result\.data\.\*\.iocModules\.\*\.User | string | 
action\_result\.data\.\*\.iocModules\.\*\.VersionInfoPresent | string | 
action\_result\.data\.\*\.iocModules\.\*\.WFP | string | 
action\_result\.data\.\*\.iocModules\.\*\.Whitelisted | string | 
action\_result\.data\.\*\.iocModules\.\*\.Windows | string | 
action\_result\.data\.\*\.iocModules\.\*\.WritetoExecutable | string | 
action\_result\.data\.\*\.iocModules\.\*\.YaraDefinitionHash | string | 
action\_result\.data\.\*\.iocModules\.\*\.YaraScanDescription | string | 
action\_result\.data\.\*\.iocModules\.\*\.YaraScanFirstThreat | string | 
action\_result\.data\.\*\.iocModules\.\*\.YaraScanresult | string | 
action\_result\.data\.\*\.iocModules\.\*\.YaraVersion | string | 
action\_result\.data\.\*\.iocQuery\.Active | string | 
action\_result\.data\.\*\.iocQuery\.Alertable | string | 
action\_result\.data\.\*\.iocQuery\.BlacklistedCount | string | 
action\_result\.data\.\*\.iocQuery\.Description | string | 
action\_result\.data\.\*\.iocQuery\.ErrorMessage | string | 
action\_result\.data\.\*\.iocQuery\.EvaluationMachineCount | string | 
action\_result\.data\.\*\.iocQuery\.GraylistedCount | string | 
action\_result\.data\.\*\.iocQuery\.IOCLevel | string | 
action\_result\.data\.\*\.iocQuery\.LastEvaluationDuration | string | 
action\_result\.data\.\*\.iocQuery\.LastExecuted | string | 
action\_result\.data\.\*\.iocQuery\.LastExecutionDuration | string | 
action\_result\.data\.\*\.iocQuery\.MachineCount | string | 
action\_result\.data\.\*\.iocQuery\.ModuleCount | string | 
action\_result\.data\.\*\.iocQuery\.Name | string |  `nwe ioc name` 
action\_result\.data\.\*\.iocQuery\.Persistent | string | 
action\_result\.data\.\*\.iocQuery\.Priority | string | 
action\_result\.data\.\*\.iocQuery\.Query | string | 
action\_result\.data\.\*\.iocQuery\.Type | string | 
action\_result\.data\.\*\.iocQuery\.UserDefined | string | 
action\_result\.data\.\*\.iocQuery\.WhitelistedCount | string | 
action\_result\.data\.\*\.iocType | string | 
action\_result\.summary\.ioc\_level | string | 
action\_result\.summary\.machine\_count | numeric | 
action\_result\.summary\.module\_count | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 