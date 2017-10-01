# GetWT

## Description
The tool is designed to query the [PassiveTotal - Get Passive DNS](http://api.passivetotal.org/api/docs/#api-Passive_DNS-GetV2DnsPassive) and [VirusTotal - IP Address Report](https://developers.virustotal.com/v2.0/reference#ip-address-report) APIs to return all domains associated with an IP. Then each site is retrieved live to attempt to detect web technologies in use on each record. The web technology detection is based on a python port of [Wappalyzer](https://wappalyzer.com/) that has been modified to work with Python 3.6.2.

**Warning:** This will reach out to all domains associated with an IP, including possibily malicious domains. Use with caution.
To reduce the number of malicious domains, the `MALWARE` config can be set to False to remove VirusTotal's "detected urls."

*Note:* PassiveTotal's Community API only supports 15 lookups a day. VirusTotal's Public API caps at 4 queries a minute.

## Inputs
* IP or List of IPs
* Job ID for tracking

## Outputs
Web Technologies in use on domains seens in passive DNS records for each IP

Up-to-date apps.json:
    https://raw.githubusercontent.com/AliasIO/Wappalyzer/master/src/apps.json
    
## Install
1. Install Python 3.6.2 
2. pip3 install six
3. pip3 install requests
4. pip3 install flask
5. Update configs.cfg with API keys
6. python3 getwt.py
7. Web browse to the IP and Port configured in configs


### Code Structure
```
clues.py
data_gather.py
detection.py
group.py
output.py
README.md
thirdeye.py
tools.py
etc
--apps.json
--config.cfg
--passive_dns.db
static
--css
----bootstrap-grid.css
----bootstrap-grid.css.map
----bootstrap-grid.min.css
----bootstrap-grid.min.css.map
----bootstrap-reboot.css
----bootstrap-reboot.css.map
----bootstrap-reboot.min.css
----bootstrap-reboot.min.css.map
----bootstrap.css
----bootstrap.css.map
----bootstrap.min.css
----bootstrap.min.css.map
--js
----bootstrap.js
----bootstrap.min.js
----jquery-3.2.1.min.js
templates
--job.html
--result.html
utils
--create_db.py
```

### Modules in Use
* Python
  * Version: 3.6.2
  * Use: Code Base
* flask
  * Version: 0.12.2
  * Use: User Interface
* sqlite3
  * Version: 2.6.0
  * Use: Backend Database
* [wad](https://pypi.python.org/pypi/wad)
  * Version: Custom modified
  * Use: Web technology scanner
  * Notes: Modified to work with Python 3.6.2
* six
  * Version: 1.10.0
* requests
  * Version 2.18.4
  * Use: Retrieve online apps.json
 
#### TODO:
* Convert legacy WAD code to beautifulSoup/requests
* Support other databases
* Handle sites with tarpit-style responses
* Add [PassiveTotal - Host_Attributes - Get Components](http://api.passivetotal.org/api/docs/#api-Host_Attributes-GetV2HostAttributesComponents) Integration
* Add support for "Last Seen Date"

