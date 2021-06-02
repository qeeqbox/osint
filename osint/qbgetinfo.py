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

from sqlite3 import connect
from os import path
from contextlib import suppress
from requests import get
from ipaddress import IPv4Address


class QBGetInfo:
    def __init__(self, name="qbosint.sqlite", db=None, cursor=None):
        self.sqlite_name = path.join(path.dirname(__file__), "data", "qbosint.sqlite")
        self.db = db
        self.cursor = cursor
        self.structure = []
        self.load_file(name,self.sqlite_name,"https://raw.githubusercontent.com/qeeqbox/osint/main/osint/data/qbosint.sqlite")
        self.setup_connection()
        self.get_structure()

    def load_file(self, name, path_to_check, url_download):
        ret = None
        try:
            if path.exists(path_to_check) == False:
                #print("[init] Downloading {} from {}".format(name, url_download))
                file = get(url_download, allow_redirects=True)
                with open(path_to_check, 'wb') as f:
                    f.write(file.content)
            if path.exists(path_to_check) == True:
                pass
                #print("[init] {} looks good!".format(name))
            else:
                exit()
        except Exception as e:
            exit()
            #print("[!] {} Does not exist! cannot be downloaded...".format(name))
        return ret

    def setup_connection(self):
        self.db = connect(self.sqlite_name, check_same_thread=False)
        self.cursor = self.db.cursor()

    def get_structure(self):
        for table in self.cursor.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall():
            cols = self.cursor.execute('PRAGMA table_info ({})'.format(table[0])).fetchall()
            for col in cols:
                self.structure.append({"table":table[0],"name":col[1],"type":col[2]})

    def search_all(self, value):
        ret = []
        with suppress(Exception):
            if len(self.structure) > 0:
                for col in self.structure:
                    temp_value = None
                    items = self.cursor.execute(("SELECT * FROM {} WHERE {} LIKE ?".format(col["table"],col["name"])), (value,)).fetchall()
                    for item in items:
                        if item not in ret:
                            ret.append(item)
                with suppress(Exception):
                    temp_ip = self.find_ip(value)
                    if temp_ip:
                        ret.append(temp_ip)
        return ret


    def find_ip(self, ip, ret=None):
        with suppress(Exception):
            self.cursor.execute(("SELECT * FROM countries_ips WHERE (ipfrom <= ? AND ipto >= ?)"), (int(IPv4Address(value)), int(IPv4Address(value)),))
            temp_item = self.cursor.fetchone()
            if temp_item is not None:
                return temp_item
        return ret

    def find_country(self, ctry, ret=None):
        with suppress(Exception):
            self.cursor.execute(("SELECT * FROM countries_ids WHERE ctry=?"), (ctry,))
            temp_item = self.cursor.fetchone()
            if temp_item is not None:
                return temp_item
        return ret

    def find_language(self, ctry, ret=None):
        self.cursor.execute(("SELECT * FROM languages WHERE ctry=?"), (ctry,))
        temp_item = self.cursor.fetchone()
        if temp_item is not None:
            return temp_item
        return ret

    def find_port(self, port, ret=None):
        with suppress(Exception):
            self.cursor.execute(("SELECT * FROM ports WHERE port=?"), (port,))
            temp_item = self.cursor.fetchone()
            if temp_item is not None:
                return temp_item
        return ret

    def __exit__(self):
        with suppress(Exception):
            cursor.close()
        with suppress(Exception):
            db.close()
