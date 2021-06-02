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

from scapy.layers.dns import DNSRR, DNSQR, DNS
from scapy.all import RandShort, sr1
from scapy.layers.inet import IP, UDP
from re import match as rematch
from tld import get_fld
from socket import gethostbyaddr
from netifaces import gateways, AF_INET
from contextlib import suppress
from dns.resolver import resolve
from ipaddress import IPv4Address
from uuid import uuid4
from copy import deepcopy
from .qbgetinfo import QBGetInfo


class QBDns():
    def __init__(self, gateway=None, interface=None, dns="8.8.8.8", options=["ip", "domain", "type", "method", "flag", "info", "uuid"], qbgetinfo=None):
        self.dns = dns
        self.gateway = gateway
        self.interface = interface
        self.qbgetinfo = qbgetinfo or QBGetInfo()
        self.options = options
        self.ip_regex = "^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$"
        self.get_network_settings()

    def get_dns(self, targets, method="any"):
        temp_dict = []
        for target in targets:
            with suppress(Exception):
                temp_list = []
                if method in "any" or method == target['method']:
                    host = get_fld(target['domain'], fix_protocol=True, fail_silently=True)
                    if host:
                        for records in ['A', 'AAAA', 'CNAME', 'MX', 'SRV', 'TXT', 'SOA', 'NS']:
                            with suppress(Exception):
                                answer = resolve(host, records, raise_on_no_answer=False)
                                if answer.rrset is not None:
                                    temp_list.append({records: answer.rrset.to_text()})
                    temp_dict.append({"domain": target['domain'], "dns": temp_list})
        return temp_dict

    def clean_up_and_add_info(self, list_in):
        if self.qbgetinfo:
            dict_in_temp = deepcopy(list_in)
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
                list_in[i].update({"info": country, "flag": flag_base64})
                for key, value in dict_in_temp[i].items():
                    if key not in self.options:
                        del list_in[i][key]
        return list_in

    def resolve_dns(self, host):
        with suppress(Exception):
            host = get_fld(host, fix_protocol=True, fail_silently=True)
            if host:
                response = sr1(IP(dst=self.dns) / UDP(sport=RandShort(), dport=53) / DNS(rd=1, qd=DNSQR(qname=host)), verbose=False)
                for record in range(response[DNS].ancount):
                    if response[DNSRR][record].type == 1:
                        return response[DNSRR][record].rdata
        return None

    def check_if_valid_ip_old(self, ip):
        if rematch(self.ip_regex, ip):
            return True
        return False

    def get_network_settings(self):
        with suppress(Exception):
            self.interface = gateways()['default'][AF_INET][1]
        with suppress(Exception):
            self.gateway = gateways()['default'][AF_INET][0]

    def reverse_dns_lookup_scapy(self, ip):
        with suppress(Exception):
            response = sr1(IP(dst=self.dns) / UDP(sport=RandShort(), dport=53) / DNS(rd=1, qd=DNSQR(qname="{}.in-addr.arpa".format(ip), qtype='PTR')), verbose=False)
            return response["DNS"].an.rdata[:-1].decode()
        return None

    def reverse_dns_lookup(self, ip):
        with suppress(Exception):
            return gethostbyaddr(ip)[0]
        return None

    def check_public_ip(self, ip):
        with suppress(Exception):
            add = IPv4Address(ip)
            if add.is_private:
                return False
            else:
                return True
        return False

    def reverse_dns_wrapper(self, ip):
        with suppress(Exception):
            if self.check_public_ip(ip):
                domain = self.reverse_dns_lookup(ip)
                if domain is None:
                    domain = self.reverse_dns_lookup_scapy(ip)
                    if domain is None:
                        return ip
                return domain
        return ip

    def convert_to_ip(self, host, ret=None):
        with suppress(Exception):
            if self.check_if_valid_ip(host) == False:
                host = self.resolve_dns(host)
            if host is not None:
                return host
        return ret

    def convert_to_ips(self, targets):
        temp_hosts = []
        for target in targets:
            ip_type = None
            domain = None
            with suppress(Exception):
                add = IPv4Address(target)
                if add.is_private:
                    ip_type = "private"
                else:
                    domain = self.reverse_dns_wrapper(str(add))
                    ip_type = "public"
                if ip_type:
                    temp_hosts.append({"ip": str(add), "domain": domain, "type": ip_type, "method": "reverse", "uuid": str(uuid4())})
            if ip_type is None:
                with suppress(Exception):
                    add = self.resolve_dns(target)
                    add = IPv4Address(add)
                    temp_hosts.append({"ip": str(add), "domain": target, "type": "public", "method": "resolve", "uuid": str(uuid4())})
        return self.clean_up_and_add_info(temp_hosts)
