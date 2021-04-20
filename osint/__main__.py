#!/usr/bin/env python

"""
//  -------------------------------------------------------------
//  author        Giga
//  project       qeeqbox/osint
//  email         gigaqeeq@gmail.com
//  description   app.py (CLI)
//  licensee      AGPL-3.0
//  -------------------------------------------------------------
//  contributors list qeeqbox/osint/graphs/contributors
//  -------------------------------------------------------------
"""

from osint import QBDns, QBGetInfo, QBExtract, QBHost, QBScan, QBTraceRoute, QBPing, QBWhois, QBCached
from argparse import ArgumentParser
from json import dumps

headers = {"User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:84.0) Gecko/20100101 Firefox/84.0"}


def msg():
    return """\npython3 -m osint --test --targets "https://www.test.com" --ports "21,22,80"\n"""


ARG_PARSER = ArgumentParser(description="Qeeqbox/osint Build your own custom OSINT tools and APIs with this python package", usage=msg())
ARG_PARSER.add_argument("--test", action="store_true", help="enable testing")
ARG_PARSER.add_argument("--targets", help="target ips or domains separated by comma", metavar="", default="")
ARG_PARSER.add_argument("--ports", help="target ports separated by comma", metavar="", default="80,443")
ARGV = ARG_PARSER.parse_args()

if __name__ == "__main__":
    if ARGV.targets and ARGV.ports and ARGV.test:
        _targets = ARGV.targets.split(',')
        _ports = [int(n) for n in ARGV.ports.split(',')]
        if (len(_ports) > 0 and len(_targets)):
            qbgetinfo = QBGetInfo()
            qbdns = QBDns()
            targets = qbdns.convert_to_ips(_targets)
            if len(targets) > 0:
                print("\nTargets:\n")
                print(targets)
                targets = QBScan().run(targets, _ports)
                targets = QBTraceRoute().run(targets)
                targets = QBHost(headers=headers).run(targets)
                targets = QBPing().run(targets)
                targets = QBWhois().run(targets)
                targets = QBExtract().run(targets)
                targets = QBCached().run(targets)
                print("\nosint results:\n")
                print(dumps(targets, indent=4))
                print("\nTest database results:\n")
            print(QBGetInfo().cursor.execute(("SELECT * FROM ports WHERE port=?"), (80,)).fetchone())
