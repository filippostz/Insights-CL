# Insights-CL
insightsCL.py offers a terminal interface that enables users to search for specific cyber threat campaigns or profiles and download associated IOCs leveraging Trellix Insights APIs.
Insights is a comprehensive and regularly updated threat intelligence database.
```
# ./insightsCL.py
usage: insightsCL.py [-h] [--search KEYWORD] [--sortby SORTBY] [--limit LIMIT] [--get-iocs CAMPID]
                          [--ioc-type IOCTYPE] [--get-info IDCAMP] [--output FORMAT]

examples of usage:
 insightsCL.py --search apt29
 insightsCL.py --search all --sortby updated-on --limit 5
 insightsCL.py --search 1ef9c42efe6e9a08b7ebb16913fa0228
 insightsCL.py --get-info 6c2ef20f-7c2c-417c-8f5e-73e4b9936a72
 insightsCL.py --get-iocs 6c2ef20f-7c2c-417c-8f5e-73e4b9936a72
 insightsCL.py --get-iocs 6c2ef20f-7c2c-417c-8f5e-73e4b9936a72 --ioc-type domain

optional arguments:
  -h, --help          show this help message and exit
  --search KEYWORD    search | values:["keyword","all", "type:md5", "type:sha256"]
  --sortby SORTBY     sort results from search Campaigns | values:[created-on|updated-on]
  --limit LIMIT       number of results | default: 10
  --get-iocs CAMPID   get IOCs | arg ex. 6c2ef20f-7c2c-417c-8f5e-73e4b9936a72
  --ioc-type IOCTYPE  IOC type | values:["md5","sha256", "ip", "url", "domain"]
  --get-info IDCAMP   get Tools and MITRE | arg ex. 6c2ef20f-7c2c-417c-8f5e-73e4b9936a72
  --output FORMAT     IOCs print format | values:["newline","kibana"]
```
## Prerequisites
the script requires api key, client id and token available to Trellix customers, more info here: https://developer.manage.trellix.com<br />
Modify the following variables in the insightsCL.py script<br />
```
api_key = 'your_api_key_here'
client_id = 'your_client_id_here'
client_token = 'your_client_token_here'
```
## Examples
Search the latest 3 updated campaigns with keyword "blackcat"
```
insightsCL.py --search blackcat --sortby updated-on --limit 3   

Created    | *Updated   | Id                                   | Level  | Name                            
2023-05-22 |            | 5e18ad88-3638-43fb-8702-6b28f82e8f03 | Low    | BlackCat Ransomware Deploys New Signed Kernel Driver                    
2022-01-25 | 2023-04-11 | 5e2d477d-f0ad-494e-917c-dbe4c0514bd6 | Medium | BlackCat - Rust Ransomware-As-A-Service                                 
2022-03-02 | 2023-04-11 | e1e0a1fa-f65b-43c8-91d0-621e951e3e68 | Medium | The BlackCat And LockBit Ransomware Connection
```
Get the IP indicators associated to the campaign with id e1e0a1fa-f65b-43c8-91d0-621e951e3e68
```
insightsCL.py --get-iocs e1e0a1fa-f65b-43c8-91d0-621e951e3e68 --ioc-type ip 
141.136.44.54
188.120.247.108
45.9.190.135
185.43.7.120
```
