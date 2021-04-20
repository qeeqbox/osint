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

from scapy.all import ARP, Ether, sr1, srp1
from scapy.layers.inet import IP, ICMP, UDP
from contextlib import suppress
from concurrent.futures import ThreadPoolExecutor, as_completed


class QBPing:
    def __init__(self, workers=30, options=['status', 'mac']):
        self.options = options
        self.workers = workers

    def find(self, v, l):
        for i, d in enumerate(l):
            if d["uuid"] == v:
                return i
        return -1

    def ping_threads(self, ping, targets, timeout=1):
        results = []
        with ThreadPoolExecutor(max_workers=self.workers) as executor:
            futures = (executor.submit(getattr(self, ping), target) for target in targets)
            for future in as_completed(futures):
                _temp, __temp = future.result()
                if __temp != {}:
                    results.append({"uuid": _temp["uuid"], "results": {ping.replace("_ping", ""): __temp}})
        return results

    def arp_ping(self, target, ret=None):
        temp_value = {}
        status = "down"
        mac_address = "unknown"
        answer = srp1(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target['ip']), iface_hint=target['ip'], timeout=1, verbose=False)
        if answer is not None:
            status = "up"
            mac_address = answer[ARP].hwsrc
        temp_value.update({"status": status, "mac": mac_address})
        return target, temp_value

    def icmp_ping(self, target, ttl=20, ret=None):
        temp_value = {}
        status = "down"
        mac_address = "unknown"
        with suppress(Exception):
            answer = sr1(IP(dst=target['ip'], ttl=ttl) / ICMP(), timeout=1, verbose=False)
            if answer is not None:
                if (int(answer.getlayer(ICMP).type) == 3 and int(answer.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]):
                    status = "filtered"
                status = "up"
        temp_value.update({"status": status, "mac": mac_address})
        return target, temp_value

    def udp_ping(self, target, ttl=20, port=0, ret=None):
        temp_value = {}
        status = "down"
        mac_address = "unknown"
        with suppress(Exception):
            answer = sr1(IP(dst=target['ip'], ttl=ttl) / UDP(dport=port), timeout=1, verbose=False)
            if answer is not None:
                status = "up"
        temp_value.update({"status": status, "mac": mac_address})
        return target, temp_value

    def run(self, targets, function="all"):
        results = []
        if len(targets) > 0:
            if function == "arp" or function == "all":
                results.extend(self.ping_threads("arp_ping", targets))
            if function == "icmp" or function == "all":
                results.extend(self.ping_threads("icmp_ping", targets))
            if function == "udp" or function == "all":
                results.extend(self.ping_threads("udp_ping", targets))
        if len(results) > 0:
            for item in results:
                index = self.find(item["uuid"], targets)
                if index >= 0 and "results" in item:
                    targets[index].update(item["results"])
        return targets
