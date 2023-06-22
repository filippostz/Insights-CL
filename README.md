# Insights-CL
insightsCL.py offers a terminal interface that enables users to search for specific cyber threat campaigns or profiles and download associated IOCs leveraging Trellix Insights APIs.
Insights is a comprehensive and regularly updated threat intelligence database.
```
usage: insightsCL.py [-h] [--search KEYWORD] [--sortby SORTBY] [--limit LIMIT] [--get-iocs CAMPID] [--ioc-type IOCTYPE] [--get-info IDCAMP] [--output FORMAT]

Insights CL v0.6 - A Trellix Insights command line tool - Community Project
examplese:
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
