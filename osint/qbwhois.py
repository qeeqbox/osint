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

from socket import socket, AF_INET, SOCK_STREAM
from re import match as rematch
from concurrent.futures import ThreadPoolExecutor, as_completed


class QBWhois:
    def __init__(self, workers=30, options=['hop', 'ip', 'info', 'domain', 'time', 'flag']):
        self.options = options
        self.workers = workers

    def whois_request_threads(self, targets, timeout=1):
        results = []
        with ThreadPoolExecutor(max_workers=self.workers) as executor:
            futures = (executor.submit(self.whois_request, target) for target in targets)
            for future in as_completed(futures):
                _temp, __temp = future.result()
                if __temp != []:
                    results.append({"uuid": _temp["uuid"], "results": __temp})
        return results

    def find(self, v, l):
        for i, d in enumerate(l):
            if d["uuid"] == v:
                return i
        return -1

    def parse_reply(self, data):
        results = []
        for line in data.splitlines():
            try:
                temp_line = line.split()
                if temp_line[0].endswith(":"):
                    matched = rematch("^([^:\n]+): *(.*?) *$", line)
                    if matched:
                        if matched.group(1) != "" and matched.group(2) != "":
                            results.append({matched.group(1): matched.group(2)})
            except BaseException:
                pass
        return results

    def whois_request(self, target):
        for whois in ["whois.arin.net", "whois.lacnic.net", "whois.apnic.net", "whois.ripe.net"]:
            response = b""
            try:
                sock = socket(AF_INET, SOCK_STREAM)
                sock.connect((whois, 43))
                sock.send((target['ip'] + "\r\n").encode())
                while True:
                    data = sock.recv(4096)
                    response += data
                    if not data:
                        break
                sock.close()
            except BaseException:
                pass
            if len(response) > 0:
                return target, self.parse_reply(response.decode())
        return target, []

    def run(self, targets):
        results = []
        if len(targets) > 0:
            results = self.whois_request_threads(targets)
        if len(results) > 0:
            for item in results:
                index = self.find(item["uuid"], targets)
                if index >= 0 and "results" in item:
                    targets[index].update({"whois": item["results"]})
        return targets
