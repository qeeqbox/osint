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


class QBGetInfo:
    def __init__(self, name="qbosint.sqlite", db=None, cursor=None):
        self.sqlite_name = path.join(path.dirname(__file__), "data", "qbosint.sqlite")
        self.db = db
        self.cursor = cursor
        self.setup_connection()

    def setup_connection(self):
        self.db = connect(self.sqlite_name, check_same_thread=False)
        self.cursor = self.db.cursor()

    def find_ip(self, ip, ret=None):
        with suppress(Exception):
            self.cursor.execute(("SELECT * FROM countries_ips WHERE (ipfrom <= ? AND ipto >= ?)"), (ip, ip,))
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
