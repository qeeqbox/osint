<p align="center"> <img src="https://raw.githubusercontent.com/qeeqbox/osint/main/readme/osint_logo.png"></p>

Build custom OSINT tools and APIs with this python package - It includes different OSINT modules (Ping, Traceroute, Scans, Archives, DNS, Scrape, Whois, Metadata) for performing reconnaissance on the target, and a built-in database for mapping and visuialzing some of the reconnaissance results. 

The final results is a json output that can be intergrated with other projects

## Install
```bash
pip3 install osint
```

## Usage Example - Scan ips or domains for http and https
```python
#Remember you need higher privileges

from osint import QBDns, QBScan
targets = QBDns().convert_to_ips(["http://test.com","1.2.3.4"] )
targets = QBScan().run(targets,[80,443])
print(targets)
```

## Usage Example - Extract text from domains
```python
#Remember you need higher privileges

from osint import QBDns, QBHost, QBExtract
targets = QBDns().convert_to_ips(["http://test.com"] )
targets = QBHost().run(targets)
targets = QBExtract().run(targets,function="text")
print(targets)
```

## Usage Example - Interact with the built-in database
```python
from osint import QBGetInfo
print(QBGetInfo().cursor.execute(("SELECT * FROM ports WHERE port=?"),(80,)).fetchone())
```

## Current modules
#### QBDns() - Dns lookups
```python
QBDns().convert_to_ips(targets)
```
- `targets` List of target domains or ips, the results is needed for the rest of modules e.g. ["http://test...","1.2.3.4"] 

#### QBHost() - Extract host information and cert
```python
QBHost().run(targets, function)
```
- `targets` from QBDns().convert_to_ips() function
- `function` all, cert or content

#### QBCached() - Check archive.org from snapshots
```python
QBCached().run(targets, from_date_in, to_date_in)
```

- `targets` from QBDns().convert_to_ips() function
- `from_date_in`   #start date as month/year e.g. 12/2020
- `to_date_in`     #end date as month/year e.g. 12/2021 

#### QBExtract() - Extract text from pages
```python
QBExtract().run(targets, function)
```
- `targets` from QBDns().convert_to_ips() function
- `function` all, text, metadata, links, image or language

#### QBScan() - Extract text from pages
```python
QBScan.run(targets, ports, function)
```
- `targets` from QBDns().convert_to_ips() function
- `ports` ports to scan e.g. [80,443]
- `function` all, sync, tcp, xmas, fin, null, ack, window or udp

#### QBTraceRoute() - Extract text from pages
```python
QBTraceRoute.run(targets)
```
- `targets` from QBDns().convert_to_ips() function

#### QBPing() - Ping host
```python
QBPing.run(targets, function)
```
- `targets` from QBDns().convert_to_ips() function
function       #all, arp, icmp or udp

#### QBWhois() - Whois information
```python
QBWhois.run(targets)
```
- `targest` from QBDns().convert_to_ips() function

#### QBICS() - Industrial Control Systems Scanning
```python
QBICS.run(targets)
```
- `targets` from QBDns().convert_to_ips() function

QBICS() module is not available and currently under testing

## Built-in Database
```
countries_ids (country text, ctry text, cntry text, cid int, latitude int, longitude int, flag text)
countries_ips (ipfrom bigint, ipto bigint, registry text, assigned int, ctry text, cntry text, country text)
dns_servers (dns text, description text)
languages (ctry text, language text)
ports (port int, protocol text, service text, description text)
reserved_ips (ipfrom bigint, ipto bigint, description text)
temp_emails (email text, description text, blocked boolean)
url_shorteners (URL text, description text)
```

## acknowledgement
By using this framework, you are accepting the license terms of all these packages: `scapy tld netifaces dnspython beautifulsoup4 requests pyOpenSSL lxml langdetect`

## Other Projects
[![](https://github.com/qeeqbox/.github/blob/main/data/social-analyzer.png)](https://github.com/qeeqbox/social-analyzer) [![](https://github.com/qeeqbox/.github/blob/main/data/analyzer.png)](https://github.com/qeeqbox/analyzer) [![](https://github.com/qeeqbox/.github/blob/main/data/chameleon.png)](https://github.com/qeeqbox/chameleon) [![](https://github.com/qeeqbox/.github/blob/main/data/url-sandbox.png)](https://github.com/qeeqbox/url-sandbox) [![](https://github.com/qeeqbox/.github/blob/main/data/mitre-visualizer.png)](https://github.com/qeeqbox/mitre-visualizer) [![](https://github.com/qeeqbox/.github/blob/main/data/woodpecker.png)](https://github.com/qeeqbox/woodpecker) [![](https://github.com/qeeqbox/.github/blob/main/data/docker-images.png)](https://github.com/qeeqbox/docker-images) [![](https://github.com/qeeqbox/.github/blob/main/data/seahorse.png)](https://github.com/qeeqbox/seahorse) [![](https://github.com/qeeqbox/.github/blob/main/data/rhino.png)](https://github.com/qeeqbox/rhino)
