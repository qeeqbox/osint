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
from requests import get as rget
from requests import Session
from requests.packages.urllib3.connection import VerifiedHTTPSConnection
from concurrent.futures import ThreadPoolExecutor, as_completed
from ssl import get_server_certificate
from OpenSSL import crypto
from contextlib import suppress
from urllib3 import disable_warnings

filterwarnings("ignore", category=DeprecationWarning)
filterwarnings('ignore', message='Unverified HTTPS request')
disable_warnings()


class QBHost:
    def __init__(self, headers=None, proxies=None, workers=30, options=[]):
        self.options = options
        self.workers = workers
        self.headers = headers
        self.proxies = proxies

    def find(self, v, l):
        for i, d in enumerate(l):
            if d["uuid"] == v:
                return i
        return -1

    def get_cert_threads(self, targets, timeout=1):
        results = []
        with ThreadPoolExecutor(max_workers=self.workers) as executor:
            futures = (executor.submit(self.get_cert, target) for target in targets)
            for future in as_completed(futures):
                _temp, __temp = future.result()
                if __temp != {}:
                    results.append({"uuid": _temp["uuid"], "results": {"cert": __temp}})
        return results

    def get_content_threads(self, targets, method, timeout=1):
        results = []
        with ThreadPoolExecutor(max_workers=self.workers) as executor:
            futures = (executor.submit(self.get_content, target, method) for target in targets)
            for future in as_completed(futures):
                _temp, __temp = future.result()
                if __temp != {}:
                    results.append({"uuid": _temp["uuid"], "results": __temp})
        return results

    def get_cert(self, target):
        List_ = {}
        mapped = {b'CN': b'Common Name', b'OU': b'Organizational Unit', b'O': b'Organization', b'L': b'Locality', b'ST': b'State Or Province Name', b'C': b'Country Name'}
        with suppress(Exception):
            cert = get_server_certificate((target['ip'], 443))
            X509 = crypto.load_certificate(crypto.FILETYPE_PEM, cert)
            List_['Subjects'] = []
            for subject in X509.get_subject().get_components():
                try:
                    List_['Subjects'].append({mapped[subject[0]].decode('utf-8'): subject[1].decode('utf-8')})
                except BaseException:
                    pass
            List_['Subject Hash'] = X509.get_subject().hash()
            List_['Issuer'] = []
            for issuer in X509.get_issuer().get_components():
                try:
                    List_['Issuer'].append({mapped[issuer[0]].decode('utf-8'): issuer[1].decode('utf-8')})
                except BaseException:
                    pass
            List_['Issuer Hash'] = X509.get_issuer().hash()
            List_['Extensions'] = []
            for extension in range(X509.get_extension_count()):
                List_['Extensions'].append({X509.get_extension(extension).get_short_name().decode('utf-8'): X509.get_extension(extension).__str__()})
            List_['Expired'] = X509.has_expired()
            List_['Valid From'] = X509.get_notBefore().decode('utf-8')
            List_['Valid Until'] = X509.get_notAfter().decode('utf-8')
            List_['Signature Algorithm'] = X509.get_signature_algorithm().decode('utf-8')
            List_['Serial Number'] = X509.get_serial_number()
            List_['MD5 Digest'] = X509.digest('md5').decode('utf-8')
            List_['SHA1 Digest'] = X509.digest('sha1').decode('utf-8')
            List_['SHA224 Digest'] = X509.digest('sha224').decode('utf-8')
            List_['SHA256 Digest'] = X509.digest('sha256').decode('utf-8')
            List_['SHA384 Digest'] = X509.digest('sha384').decode('utf-8')
            List_['SHA512 Digest'] = X509.digest('sha512').decode('utf-8')
        return target, List_

    def get_cert_old(self, target):
        List_ = {}
        mapped = {b'CN': b'Common Name', b'OU': b'Organizational Unit', b'O': b'Organization', b'L': b'Locality', b'ST': b'State Or Province Name', b'C': b'Country Name'}
        original_connect = VerifiedHTTPSConnection.connect

        def hooked_connect(self):
            global X509
            original_connect(self)
            X509 = self.sock.connection.get_peer_certificate()
        VerifiedHTTPSConnection.connect = hooked_connect
        if self.headers or self.proxies:
            if self.proxies and self.headers:
                rget(target['domain'], proxies=self.proxies, headers=self.proxies, timeout=2)
            elif self.proxies:
                rget(target['domain'], proxies=self.proxies, timeout=2)
            elif self.headers:
                rget(target['domain'], headers=self.headers, timeout=2)
        else:
            rget(target['domain'], timeout=2)
        List_['Subjects'] = []
        for subject in X509.get_subject().get_components():
            try:
                List_['Subjects'].append({mapped[subject[0]].decode('utf-8'): subject[1].decode('utf-8')})
            except BaseException:
                pass
        List_['Subject Hash'] = X509.get_subject().hash()
        List_['Issuer'] = []
        for issuer in X509.get_issuer().get_components():
            try:
                List_['Issuer'].append({mapped[issuer[0]].decode('utf-8'): issuer[1].decode('utf-8')})
            except BaseException:
                pass
        List_['Issuer Hash'] = X509.get_issuer().hash()
        List_['Extensions'] = []
        for extension in range(X509.get_extension_count()):
            List_['Extensions'].append({X509.get_extension(extension).get_short_name().decode('utf-8'): X509.get_extension(extension).__str__()})
        List_['Expired'] = X509.has_expired()
        List_['Valid From'] = X509.get_notBefore().decode('utf-8')
        List_['Valid Until'] = X509.get_notAfter().decode('utf-8')
        List_['Signature Algorithm'] = X509.get_signature_algorithm().decode('utf-8')
        List_['Serial Number'] = X509.get_serial_number()
        List_['MD5 Digest'] = X509.digest('md5').decode('utf-8')
        List_['SHA1 Digest'] = X509.digest('sha1').decode('utf-8')
        List_['SHA224 Digest'] = X509.digest('sha224').decode('utf-8')
        List_['SHA256 Digest'] = X509.digest('sha256').decode('utf-8')
        List_['SHA384 Digest'] = X509.digest('sha384').decode('utf-8')
        List_['SHA512 Digest'] = X509.digest('sha512').decode('utf-8')
        return target, List_

    def get_content(self, target, method):
        temp_value = {"response": [], "source": "", "base_url": ""}
        with suppress(Exception):
            if method == "normal":
                if target["domain"]:
                    session = Session()
                    if self.headers:
                        session.headers.update(self.headers)
                    if self.proxies:
                        session.proxies.update(self.proxies)
                    response = session.get(target["domain"], timeout=5, verify=False)
                    temp_value["source"] = response.text
                    temp_value["base_url"] = response.url
                    temp_value["response"] = dict((k.lower(), v.lower()) for k, v in response.headers.items())
                    session.close()
        return target, temp_value

    def run(self, targets, function="all"):
        results = []
        if len(targets) > 0:
            if function == "cert" or function == "all":
                results.extend(self.get_cert_threads(targets))
            if function == "content" or function == "all":
                results.extend(self.get_content_threads(targets, "normal"))
        if len(results) > 0:
            for item in results:
                index = self.find(item["uuid"], targets)
                if index >= 0 and "results" in item:
                    targets[index].update(item["results"])
        return targets
