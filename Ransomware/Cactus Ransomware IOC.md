
<kbd>Industries: Transportation, Food, Manufacturing, Construction, Marketing, Hardware, Nature </kbd>
<kbd>Targeted Countries: United States of America , Italy , United Kingdom of Great Britain and Northern Ireland , Portugal , France , India , Switzerland </kbd>
<kbd>Malware Families: CACTUS , Cactus  </kbd>


## Query Information

Description:
This query uses hashes, external doamins and email address. This is used to search your environment for hash, outgoing email and outgoing internet connections.




```sh
// Cactus Ransomware IOCs
// Based on https://otx.alienvault.com/pulse/64ba02ecb2d2743614f9606a 
let MD5_IOCs = dynamic(['e28db6a65da2ebcf304873c9a5ed086d', 'eba1596272ff695a1219b1380468293a','de6ce47e28337d28b6d29ff61980b2e9','949d9523269604db26065f002feef9ae','5737cb3a9a6d22e957cf747986eeb1b3','2611833c12aa97d3b14d2ed541df06b2','1add9766eb649496bc2fa516902a5965']);
let SHA1_IOCs = dynamic (['173f9b0db97097676a028b4b877630adc7281d2f', 'cb570234349507a204c558fc8c4ecf713e2c0ac3']);
let SHA256_IOCs = dynamic(['78c16de9fc07f1d0375a093903f86583a4e32037a7da8aa2f90ecb15c4862c17', 
'c52ad663ff29e146de6b7b20d834304202de7120e93a93de1de1cb1d56190bfd']);
let Domain_IOCs = dynamic(['sonarmsng5vzwqezlvtu2iiwwdn3dxkhotftikhowpfjuzg7p3ca5eid.onion','cactusbloguuodvqjmnzlwetjlpj6aggc6iocwhuupb47laukux7ckid.onion','http://sonarmsng5vzwqezlvtu2iiwwdn3dxkhotftikhowpfjuzg7p3ca5eid.onion/contact/Cactus_Support']);
let Email_IOCs = dynamic(['cactus787835@proton.me']);
(union isfuzzy=true
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


