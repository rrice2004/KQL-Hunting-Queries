
<kbd>Industries: Transportation, Food, Manufacturing, Construction, Marketing, Hardware, Nature </kbd>
<kbd>Targeted Countries: United States of America , Italy , United Kingdom of Great Britain and Northern Ireland , Portugal , France , India , Switzerland </kbd>
<kbd>Malware Families: CACTUS , Cactus  </kbd>


## Query Information

Description:
This query uses hashes, external doamins, file names/pathcs and email address to locate IOC's for the Qlik Sense CVE's that utilize Cactus Ransomware. 
CVE-2023-41266, CVE-2023-41265,CVE-2023-48365




```sh
// Cactus Ransomware IOCs
// Based on https://otx.alienvault.com/pulse/64ba02ecb2d2743614f9606a 
// https://arcticwolf.com/resources/blog/qlik-sense-exploited-in-cactus-ransomware-campaign/
//
let MD5_IOCs = dynamic(['e28db6a65da2ebcf304873c9a5ed086d', 'eba1596272ff695a1219b1380468293a','de6ce47e28337d28b6d29ff61980b2e9','949d9523269604db26065f002feef9ae','5737cb3a9a6d22e957cf747986eeb1b3','2611833c12aa97d3b14d2ed541df06b2','1add9766eb649496bc2fa516902a5965']);
let SHA1_IOCs = dynamic (['173f9b0db97097676a028b4b877630adc7281d2f', 'cb570234349507a204c558fc8c4ecf713e2c0ac3']);
let SHA256_IOCs = dynamic(['78c16de9fc07f1d0375a093903f86583a4e32037a7da8aa2f90ecb15c4862c17', 
'c52ad663ff29e146de6b7b20d834304202de7120e93a93de1de1cb1d56190bfd',
'90b009b15eb1b5bc4a990ecdd86375fa25eaa67a8515ae6c6b3b58815d46fa82',
'3ac8308a7378dfe047eacd393c861d32df34bb47535972eb0a35631ab964d14d',
'6cb87cad36f56aefcefbe754605c00ac92e640857fd7ca5faab7b9542ef80c96',
'828e81aa16b2851561fff6d3127663ea2d1d68571f06cbd732fdf5672086924d']);
let Domain_IOCs = dynamic(['sonarmsng5vzwqezlvtu2iiwwdn3dxkhotftikhowpfjuzg7p3ca5eid.onion',
'cactusbloguuodvqjmnzlwetjlpj6aggc6iocwhuupb47laukux7ckid.onion',
'sonarmsng5vzwqezlvtu2iiwwdn3dxkhotftikhowpfjuzg7p3ca5eid.onion/contact/Cactus_Support',
'zohoservice.net','zohoservice.net/putty.zip','216.107.136.46/Qliksens_update.zip','zohoservice.net/qlik-sens-Patch.zip','zohoservice.net/qlik-sens-nov.zip']);
let IP_IOCs = dynamic (['45.61.147.176','216.107.136.46','144.172.122.30']);
let Email_IOCs = dynamic(['cactus787835@proton.me']);
let FileName_IOCs = dynamic(['file.exe','anydesk.zip','AcRes.exe','any.exe','putty.zip','Qlik_sense_enterprise.zip','qlik-sens-nov.zip','qlik-sens-Patch.zip','Qliksens.exe','Qliksens_updated.zip','Qliksens_update.zip']);
let FilePath_IOCs = dynamic(['C:\\Users\\Public\\svchost.exe','c:\\windows\\temp\\file.exe','c:\\windows\\temp\\putty.exe','c:\\windows\\temp\\Qliksens.exe',
'c:\\windows\\temp\\any.exe','C:\\temp\\putty.exe','C:\\Windows\\appcompat\\AcRes.exe']);
(union isfuzzy=true
     (DeviceFileEvents
     | where FolderPath has_any (FilePath_IOCs)),
     (DeviceFileEvents 
      | where InitiatingProcessVersionInfoOriginalFileName has_any (FileName_IOCs)),  
     (DeviceNetworkEvents
     | where RemoteUrl has_any (IP_IOCs)),
     (EmailEvents 
     | where RecipientEmailAddress   has_any (Email_IOCs)),
     (DeviceNetworkEvents
     | where RemoteUrl  has_any (Domain_IOCs)),
     (DeviceFileEvents
     | where MD5 has_any (MD5_IOCs)),
     (DeviceFileEvents
     | where SHA1 has_any (SHA1_IOCs)),
     (DeviceFileEvents
     | where SHA256 has_any (SHA256_IOCs))
)


```


