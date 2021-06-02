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

from scapy.all import sr1, ICMP, RandShort
from scapy.layers.inet import IP
from logging import getLogger, ERROR
from time import time
from contextlib import suppress
from ipaddress import IPv4Address
from concurrent.futures import ThreadPoolExecutor, as_completed
from copy import deepcopy
from .qbdns import QBDns
from .qbgetinfo import QBGetInfo

getLogger("scapy").setLevel(ERROR)


class QBTraceRoute():
    def __init__(self, minttl=1, maxttl=30, retry=1, timeout=2, workers=30, gateway=None, options=['hop', 'ip', 'info', 'domain', 'time', 'flag'], qbgetinfo=None, qbdns=None):
        self.minttl = minttl
        self.maxttl = maxttl
        self.timeout = timeout
        self.retry = retry
        self.gateway = gateway
        self.qbgetinfo = QBGetInfo()
        self.qbdns = qbdns or QBDns()
        self.options = options
        self.workers = workers

    def find(self, v, l):
        for i, d in enumerate(l):
            if d["uuid"] == v:
                return i
        return -1

    def clean_up_and_add_info(self, dict_in):
        if self.qbgetinfo:
            dict_in_temp = deepcopy(dict_in)
            for i, route in enumerate(dict_in_temp):
                country = "unknown"
                alpha_2_code = None
                flag_base64 = ""
                if dict_in_temp[i]["ip"] != "unknown":
                    temp_value = self.qbgetinfo.find_ip(dict_in_temp[i]["ip"])
                    if temp_value is not None:
                        country = temp_value[6]
                        alpha_2_code = temp_value[4]
                        if alpha_2_code != "ZZ":
                            temp_value = self.qbgetinfo.find_country(alpha_2_code)
                            if temp_value is not None:
                                flag_base64 = temp_value[6]
                dict_in[i].update({"info": country, "flag": flag_base64})
                for key, value in dict_in_temp[i].items():
                    if key not in self.options:
                        del dict_in[i][key]
        return dict_in

    def traceroute_threads(self, targets, timeout=1):
        results = []
        with ThreadPoolExecutor(max_workers=self.workers) as executor:
            futures = (executor.submit(self.traceroute, target) for target in targets)
            for future in as_completed(futures):
                _temp, __temp = future.result()
                if __temp != []:
                    results.append({"uuid": _temp["uuid"], "results": __temp})
        return results

    def traceroute(self, target):
        temp_results = []
        with suppress(Exception):
            for ttl in range(self.minttl, self.maxttl):
                time_start = time()
                response = sr1(IP(dst=target['ip'], ttl=ttl, id=RandShort()) / ICMP(), retry=self.retry, timeout=self.timeout, verbose=False)
                time_end = time()
                if response:
                    if response.src != self.qbdns.gateway:
                        domain = self.qbdns.reverse_dns_wrapper(response.src)
                    else:
                        domain = "gateway"
                    if response.type == 3 or response.src == target['ip']:
                        temp_results.append({"hop": ttl, "ip": response.src, "domain": domain, "time": round((time_end - time_start) * 1000, 3)})
                        break
                    else:
                        if self.qbdns.gateway == response.src:
                            temp_results.append({"hop": ttl, "ip": response.src, "domain": domain, "time": round((time_end - time_start) * 1000, 3)})
                        else:
                            temp_results.append({"hop": ttl, "ip": response.src, "domain": domain, "time": round((time_end - time_start) * 1000, 3)})
                else:
                    temp_results.append({"hop": ttl, "ip": "unknown", "domain": "unknown", "time": round((time_end - time_start) * 1000, 3)})
        return target, temp_results

    def run(self, targets):
        results = []
        if len(targets) > 0:
            results = self.traceroute_threads(targets)
        if len(results) > 0:
            for item in results:
                index = self.find(item["uuid"], targets)
                if index >= 0 and "results" in item:
                    x = self.clean_up_and_add_info(item["results"])
                    targets[index].update({"traceroute": x})
        return targets
