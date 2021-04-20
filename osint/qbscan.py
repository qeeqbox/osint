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

from scapy.all import sr, RandShort, sr1
from scapy.layers.inet import IP, ICMP, TCP, UDP
from contextlib import suppress
from concurrent.futures import ThreadPoolExecutor, as_completed
from copy import deepcopy
from .qbgetinfo import QBGetInfo


class QBScan():
    def __init__(self, workers=30, options=['port', 'status', 'service', 'description'], qbgetinfo=None):
        self.options = options
        self.qbgetinfo = qbgetinfo or QBGetInfo()
        self.workers = workers

    def find(self, v, l):
        for i, d in enumerate(l):
            if d["uuid"] == v:
                return i
        return -1

    def clean_up_and_add_info(self, dict_in):
        if self.qbgetinfo:
            dict_in_temp = deepcopy(dict_in)
            for scan in dict_in_temp.keys():
                for i, port_scan in enumerate(dict_in_temp[scan]):
                    if 'service' in self.options or 'description' in self.options:
                        temp_value = self.qbgetinfo.find_port(dict_in_temp[scan][i]['port'])
                        service = "unknown"
                        description = "unknown"
                        if temp_value is not None:
                            service = temp_value[2]
                            description = temp_value[3]
                        dict_in[scan][i].update({"service": service, "description": description})
                for key, value in dict_in_temp[scan][i].items():
                    if key not in self.options:
                        del dict_in[scan][i][key]
        return dict_in

    def scan_threads(self, scan, ip, ports, timeout=1):
        results = []
        with ThreadPoolExecutor(max_workers=self.workers) as executor:
            scan_port = (executor.submit(getattr(self, scan), ip, port, timeout) for port in ports)
            for future in as_completed(scan_port):
                results.append(future.result())
        return results

    def sync_scan(self, ip, port, timeout=1):
        random_port = RandShort()
        status = "unknown"
        response = sr1(IP(dst=ip) / TCP(sport=random_port, dport=port, flags="S"), timeout=timeout, verbose=False)
        with suppress(Exception):
            if response is not None:
                if TCP in response:
                    if response[TCP].flags == 0x12:
                        sr(IP(dst=ip) / TCP(sport=random_port, dport=port, flags="AR"), timeout=timeout, verbose=False)
                        status = "open"
                    elif response[TCP].flags == 0x14:
                        status = "closed"
                    else:
                        status = "filtered"
                elif ICMP in response:
                    status = "filtered"
            else:
                status = "closed"
        return {"port": port, "status": status}

    def tcp_scan(self, ip, port, timeout=1):
        random_port = RandShort()
        status = "unknown"
        response = sr1(IP(dst=ip) / TCP(sport=random_port, dport=port, flags="S"), timeout=timeout, verbose=False)
        with suppress(Exception):
            if response is not None:
                if TCP in response:
                    if response[TCP].flags == 0x12:
                        sr(IP(dst=ip) / TCP(sport=random_port, dport=port, flags="R"), timeout=timeout, verbose=False)
                        status = "open"
                    elif response[TCP].flags == 0x14:
                        status = "closed"
                    else:
                        status = "filtered"
                elif ICMP in response:
                    status = "filtered"
            else:
                status = "filtered"
        return {"port": port, "status": status}

    def xmas_scan(self, ip, port, timeout=1):
        random_port = RandShort()
        status = "unknown"
        response = sr1(IP(dst=ip) / TCP(sport=random_port, dport=port, flags="FPU"), timeout=timeout, verbose=False)
        with suppress(Exception):
            if response is not None:
                if TCP in response:
                    if response[TCP].flags == 0x14:
                        status = "closed"
                elif ICMP in response:
                    status = "filtered"
            else:
                status = "open | filtered"
        return {"port": port, "status": status}

    def fin_scan(self, ip, port, timeout=1):
        random_port = RandShort()
        status = "unknown"
        response = sr1(IP(dst=ip) / TCP(sport=random_port, dport=port, flags="F"), timeout=timeout, verbose=False)
        with suppress(Exception):
            if response is not None:
                if TCP in response:
                    if response[TCP].flags == 0x14:
                        status = "closed"
                elif ICMP in response:
                    status = "filtered"
            else:
                status = "open | filtered"
        return {"port": port, "status": status}

    def null_scan(self, ip, port, timeout=1):
        random_port = RandShort()
        status = "unknown"
        response = sr1(IP(dst=ip) / TCP(sport=random_port, dport=port, flags=""), timeout=timeout, verbose=False)
        with suppress(Exception):
            if response is not None:
                if TCP in response:
                    if response[TCP].flags == 0x14:
                        status = "closed"
                elif ICMP in response:
                    status = "filtered"
            else:
                status = "open | filtered"
        return {"port": port, "status": status}

    def ack_scan(self, ip, port, timeout=1):
        random_port = RandShort()
        status = "unknown"
        response = sr1(IP(dst=ip) / TCP(sport=random_port, dport=port, flags="A"), timeout=timeout, verbose=False)
        with suppress(Exception):
            if response is not None:
                if TCP in response:
                    if response[TCP].flags == 0x4:
                        status = "open"
                elif ICMP in response:
                    status = "filtered"
            else:
                status = "filtered"
        return {"port": port, "status": status}

    def window_scan(self, ip, port, timeout=1):
        random_port = RandShort()
        status = "unknown"
        response = sr1(IP(dst=ip) / TCP(sport=random_port, dport=port, flags="A"), timeout=timeout, verbose=False)
        with suppress(Exception):
            if response is not None:
                if TCP in response:
                    if response[TCP].window > 0:
                        status = "open"
                    else:
                        status = "closed"
                elif ICMP in response:
                    status = "filtered"
            else:
                status = "unknown"
        return {"port": port, "status": status}

    def udp_scan(self, ip, port, timeout=1):
        random_port = RandShort()
        status = "unknown"
        response = sr1(IP(dst=ip) / UDP(sport=random_port, dport=port), timeout=timeout, verbose=False)
        with suppress(Exception):
            if response is not None:
                if UDP in response:
                    status = "open"
                elif ICMP in response:
                    status = "closed"
            else:
                status = "open | filtered"
        return {"port": port, "status": status}

    def run(self, targets, ports, function="all"):
        results = []
        if len(targets) > 0:
            for target in targets:
                temp_value = {}
                if function == "sync_scan" or function == "all":
                    temp_value.update({"sync": self.scan_threads("sync_scan", target['ip'], ports)})
                if function == "tcp_scan" or function == "all":
                    temp_value.update({"tcp": self.scan_threads("tcp_scan", target['ip'], ports)})
                if function == "xmas_scan" or function == "all":
                    temp_value.update({"xmas": self.scan_threads("xmas_scan", target['ip'], ports)})
                if function == "fin_scan" or function == "all":
                    temp_value.update({"fin": self.scan_threads("fin_scan", target['ip'], ports)})
                if function == "null_scan" or function == "all":
                    temp_value.update({"null": self.scan_threads("null_scan", target['ip'], ports)})
                if function == "ack_scan" or function == "all":
                    temp_value.update({"ack": self.scan_threads("ack_scan", target['ip'], ports)})
                if function == "window_scan" or function == "all":
                    temp_value.update({"window": self.scan_threads("window_scan", target['ip'], ports)})
                if function == "udp_scan" or function == "all":
                    temp_value.update({"udp": self.scan_threads("udp_scan", target['ip'], ports)})
                target.update({"scan": self.clean_up_and_add_info(temp_value)})
                results.append(target)
        return results
