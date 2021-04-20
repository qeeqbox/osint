.. image:: https://raw.githubusercontent.com/qeeqbox/osint/main/readme/osint_logo.png

Build your custom OSINT tools and APIs with this python package! It includes different OSINT modules for performing reconnaissance on the target, and a built-in database for mapping and visuialzing the some of the reconnaissance results. 

The final results is a json file that can be intergrated with other projects

Install
-------
.. code:: bash

    sudo pip3 install osint

Usage Example - Test target
---------------------------
.. code:: bash

    sudo python3 -m osint --test "https://test.."

Usage Example - Scan ips or domains for http and https
------------------------------------------------------
.. code:: python

    from osint import QBDns, QBScan
    targets = QBDns().convert_to_ips(["http://test...","1.2.3.4"] )
    targets = QBScan().run(targets,[80,443])
    print(targets)

Usage Example - Extract text from domains
------------------------------------------------------
.. code:: python

    targets = QBDns().convert_to_ips(["http://test..."] )
    targets = QBHost(headers=headers).run(targets)
    targets = QBExtract().run(targets,function="text")
    print(targets)

Usage Example - Interact with the built-in database
------------------------------------------------------
.. code:: python

    print(QBGetInfo().cursor.execute(("SELECT * FROM ports WHERE port=?"),(80,)).fetchone())

Current modules
---------------
QBDns() - Dns lookups
---------------------
.. code:: python

    QBDns().convert_to_ips(targets)

- **target** List of target domains or ips, the results is needed for the rest of modules e.g. ["http://test...","1.2.3.4"] 

QBHost() - Extract host information and cert
--------------------------------------------
.. code:: python

    QBHost().run(targets, function)

- **target** from QBDns().convert_to_ips() function
- **function** all, cert or content

QBCached() - Check archive.org from snapshots
---------------------------------------------
.. code:: python

    QBCached().run(targets, from_date_in, to_date_in)

- **target** from QBDns().convert_to_ips() function
- **from_date_in**   #start date as month/year e.g. 12/2020
- **to_date_in**     #end date as month/year e.g. 12/2021 

QBExtract() - Extract text from pages
-------------------------------------
.. code:: python

    QBExtract().run(targets, function)

- **target** from QBDns().convert_to_ips() function
- **function** all, text, metadata, links, image or language

QBScan() - Extract text from pages
----------------------------------
.. code:: python

    QBScan.run(targets, ports, function)

- **target** from QBDns().convert_to_ips() function
- **ports** ports to scan e.g. [80,443]
- **function** all, sync, tcp, xmas, fin, null, ack, window or udp

QBTraceRoute() - Extract text from pages
----------------------------------------
.. code:: python

    QBTraceRoute.run(targets)

- **target** from QBDns().convert_to_ips() function

QBPing() - Ping host
---------------------------------------------------
.. code:: python

    QBPing.run(targets, function)

- **target** from QBDns().convert_to_ips() function
- **function**       #all, arp, icmp or udp

QBWhois() - Whois information
-----------------------------
.. code:: python

    QBWhois.run(targets)

- **target** from QBDns().convert_to_ips() function

QBICS() - Industrial Control Systems Scanning
---------------------------------------------
.. code:: python

    QBICS.run(targets)

- **target** from QBDns().convert_to_ips() function

QBICS() module is not available and currently under testing

Built-in Database
-----------------
countries_ids (country text, ctry text, cntry text, cid int, latitude int, longitude int, flag text)
countries_ips (ipfrom bigint, ipto bigint, registry text, assigned int, ctry text, cntry text, country text)
dns_servers (dns text, description text)
languages (ctry text, language text)
ports (port int, protocol text, service text, description text)
reserved_ips (ipfrom bigint, ipto bigint, description text)
temp_emails (email text, description text, blocked boolean)
url_shorteners (URL text, description text)

Acknowledgement
---------------
By using this framework, you are accepting the license terms of all these packages: **scapy tld netifaces dnspython beautifulsoup4 requests pyOpenSSL lxml langdetect**
