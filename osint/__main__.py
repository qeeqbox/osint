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

from warnings import filterwarnings
filterwarnings(action='ignore', module='.*OpenSSL.*')
filterwarnings('ignore', category=RuntimeWarning, module='runpy')

headers = {"User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:84.0) Gecko/20100101 Firefox/84.0"}

def main_logic():
    from osint import QBDns, QBGetInfo, QBExtract, QBHost, QBScan, QBTraceRoute, QBPing, QBWhois, QBCached
    from argparse import ArgumentParser, SUPPRESS
    from json import dumps

    class _ArgumentParser(ArgumentParser):
        def error(self, message):
            self.exit(2, 'Error: %s\n' % (message))

    ARG_PARSER = _ArgumentParser(description="Qeeqbox/osint Build your own custom OSINT tools and APIs with this python package", usage=SUPPRESS)
    ARG_PARSER.add_argument("--test", action="store_true", help="enable testing")
    ARG_PARSER.add_argument("--targets", help="target ips or domains separated by comma", metavar="", default="")
    ARG_PARSER.add_argument("--ports", help="target ports separated by comma", metavar="", default="80,443")
    ARGV = ARG_PARSER.parse_args()

    if ARGV.targets and ARGV.ports and ARGV.test:
        _targets = ARGV.targets.split(',')
        _ports = [int(n) for n in ARGV.ports.split(',')]
        if (len(_ports) > 0 and len(_targets)):
            qbgetinfo = QBGetInfo()
            qbdns = QBDns()
            targets = qbdns.convert_to_ips(_targets)
            if len(targets) > 0:
                print("[+] Running QBScan")
                targets = QBScan().run(targets, _ports)
                print("[+] Running QBTraceRoute")
                targets = QBTraceRoute().run(targets)
                print("[+] Running QBHost")
                targets = QBHost(headers=headers).run(targets)
                print("[+] Running QBPing")
                targets = QBPing().run(targets)
                print("[+] Running QBWhois")
                targets = QBWhois().run(targets)
                print("[+] Running QBExtract")
                targets = QBExtract().run(targets)
                print("[+] Running QBCached")
                targets = QBCached().run(targets)
                print("[+] osint results")
                print(dumps(targets, indent=4))
                print("\nTest database results:\n")
            print(QBGetInfo().cursor.execute(("SELECT * FROM ports WHERE port=?"), (80,)).fetchone())

if __name__ == "__main__":
    main_logic()