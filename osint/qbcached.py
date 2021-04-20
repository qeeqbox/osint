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

from contextlib import suppress
from requests import get
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict


class QBCached():
    def __init__(self, headers=None, proxies=None, workers=30, options=[]):
        self.options = options
        self.workers = workers
        self.archive_org_args = "http://web.archive.org/cdx/search/cdx?url={}&matchType={}&output=json&fl=timestamp,original&fastLatest=true&filter=statuscode:200&collapse=original&from={}&to={}"
        self.cached = "http://web.archive.org/web/{}/{}"

    def find(self, v, l):
        for i, d in enumerate(l):
            if d["uuid"] == v:
                return i
        return -1

    def get_cached_threads(self, targets, from_date_in, to_date_in):
        results = []
        with ThreadPoolExecutor(max_workers=self.workers) as executor:
            futures = (executor.submit(self.get_cached, target, from_date_in, to_date_in) for target in targets)
            for future in as_completed(futures):
                _temp, __temp = future.result()
                if __temp != {}:
                    results.append({"uuid": _temp["uuid"], "results": {"cache": __temp}})
        return results

    def get_cached(self, target, from_date_in=None, to_date_in=None):
        temp_json = []
        results = {"snapshots": [], "random": []}
        cahced_all = defaultdict(list)
        from_date = ""
        to_date = ""
        with suppress(Exception):
            if from_date_in is None and to_date_in is not None:
                from_date = datetime.strftime(datetime.now() - timedelta(days=1 * 365), '%Y%m') + "01000000"
                to_date = datetime.strftime(datetime.strptime(to_date_in, '%m/%Y'), '%Y%m') + "01000000"
            elif from_date_in is not None and to_date_in is None:
                from_date = datetime.strftime(datetime.strptime(from_date_in, '%m/%Y'), '%Y%m') + "01000000"
                to_date = datetime.strftime(datetime.now(), '%Y%m') + "01000000"
            else:
                from_date = datetime.strftime(datetime.strptime(from_date_in, '%m/%Y'), '%Y%m') + "01000000"
                to_date = datetime.strftime(datetime.strptime(to_date_in, '%m/%Y'), '%Y%m') + "01000000"
            if from_date != "" and to_date != "":
                temp_json = get(self.archive_org_args.format(target["domain"], "domain", from_date, to_date)).json()
            if len(temp_json) > 1:
                for item in temp_json[1:]:
                    results["snapshots"].append({"time": str(datetime.strptime(item[0], '%Y%m%d%H%M%S')), "url": item[1], "cached": self.cached.format(item[0], item[1])})
            if len(results["snapshots"]) > 0:
                for s in results["snapshots"]:
                    k, v = s["time"].rsplit("-", 1)
                    cahced_all[k].append(s)
                for cached_item in cahced_all:
                    for sub_item in cahced_all[cached_item]:
                        if sub_item["url"] == target["base_url"]:
                            results["random"].append(sub_item)
                            break
                        elif sub_item["url"].rstrip('/') == target["base_url"].rstrip('/'):
                            results["random"].append(sub_item)
                            break
        if len(results["snapshots"]) == 0:
            del results["snapshots"]
        if len(results["random"]) == 0:
            del results["random"]
        return target, results

    def run(self, targets, from_date_in=None, to_date_in=None):
        results = []
        if len(targets) > 0:
            results.extend(self.get_cached_threads(targets, from_date_in, to_date_in))
        if len(results) > 0:
            for item in results:
                index = self.find(item["uuid"], targets)
                if index >= 0 and "results" in item:
                    targets[index].update(item["results"])
        return targets
