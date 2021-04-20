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
from bs4 import BeautifulSoup
from warnings import filterwarnings
from concurrent.futures import ThreadPoolExecutor, as_completed
from re import findall
from html import unescape
from langdetect import detect
from urllib.parse import urljoin
from re import sub as resub
from base64 import b64encode, b64decode
from requests import get
from PIL import Image
from io import BytesIO
from .qbgetinfo import QBGetInfo

filterwarnings("ignore", category=DeprecationWarning)


class QBExtract:
    def __init__(self, headers=None, proxies=None, workers=30, options=[], qbgetinfo=None):
        self.qbgetinfo = qbgetinfo or QBGetInfo()
        self.options = options
        self.workers = workers

    def find(self, v, l):
        for i, d in enumerate(l):
            if d["uuid"] == v:
                return i
        return -1

    def scrape_threads(self, targets, function, timeout=1):
        results = []
        with ThreadPoolExecutor(max_workers=self.workers) as executor:
            futures = (executor.submit(getattr(self, function), target) for target in targets)
            for future in as_completed(futures):
                _temp, __temp = future.result()
                if __temp != []:
                    results.append({"uuid": _temp["uuid"], "results": {function.replace("get_", ""): __temp}})
        return results

    def get_text(self, target):
        temp_text_list = []
        results = []
        with suppress(Exception):
            if "source" in target:
                soup = BeautifulSoup(target["source"], "html.parser")
                for item in soup.stripped_strings:
                    try:
                        if item not in temp_text_list:
                            temp_text_list.append(item)
                            results.append(repr(item).replace("'", ""))
                    except BaseException:
                        pass
        return target, results

    def get_metadata(self, target):
        temp_meta_list = []
        results = []
        with suppress(Exception):
            if "source" in target:
                soup = BeautifulSoup(target["source"], "lxml")
                for meta in soup.find_all('meta'):
                    try:
                        if meta not in temp_meta_list:
                            temp_meta_list.append(meta)
                            results.append(meta.attrs)
                    except BaseException:
                        pass
        return target, results

    def get_links(self, target):
        temp_link_list = []
        results = []
        with suppress(Exception):
            if "source" in target:
                soup = BeautifulSoup(target["source"], "lxml")
                for link in soup.find_all('a', href=True):
                    try:
                        if link not in temp_link_list:
                            results.append(urljoin(target["base_url"], link['href']))
                    except BaseException:
                        pass
                links = findall(r'https?://[^\s"\\]+', unescape(target["source"]))
                if len(links) > 0:
                    for link in links:
                        if link not in results:
                            results.append(link)
        return target, results

    def get_images(self, target):
        temp_images_list = []
        results = []
        with suppress(Exception):
            if "source" in target:
                soup = BeautifulSoup(target["source"], "html.parser")
                for image in soup.find_all('img'):
                    try:
                        if image not in temp_images_list:
                            if "data:image" in image['src']:
                                image['src'] = resub(r"^data:image\/[a-z]+;base64,", "", image['src'])
                                image_bytes = BytesIO(b64decode(image['src']))
                                img = Image.open(BytesIO(temp_image))
                                results.append({"format": img.format, "link": "Embedded", "base64": image['src']})
                            else:
                                temp_image = get(urljoin(target["base_url"], image['src'])).content
                                image_bytes = BytesIO(temp_image)
                                img = Image.open(BytesIO(temp_image))
                                results.append({"format": img.format, "link": urljoin(target["base_url"], image['src']), "base64": b64encode(temp_image).decode('utf-8')})
                    except BaseException:
                        pass
        return target, results

    def get_language(self, target):
        detected_lang = "unkwown"
        with suppress(Exception):
            if self.qbgetinfo:
                lang = BeautifulSoup(target["source"], "html.parser").find("html", attrs={"lang": True})["lang"]
                if lang and lang != "":
                    temp_value = self.qbgetinfo.find_language(lang)
                    if temp_value is not None:
                        detected_lang = temp_value[1]
                if detected_lang == "unkwown":
                    lang = detect(text)
                    if lang and lang != "":
                        temp_value = self.qbgetinfo().find_language(lang)
                        detected_lang = language
                        if temp_value is not None:
                            detected_lang += " (maybe)"
        return target, detected_lang

    def run(self, targets, function="all"):
        results = []
        if len(targets) > 0:
            if function == "text" or function == "all":
                results.extend(self.scrape_threads(targets, "get_text"))
            if function == "metadata" or function == "all":
                results.extend(self.scrape_threads(targets, "get_metadata"))
            if function == "links" or function == "all":
                results.extend(self.scrape_threads(targets, "get_links"))
            if function == "image" or function == "all":
                results.extend(self.scrape_threads(targets, "get_images"))
            if function == "language" or function == "all":
                results.extend(self.scrape_threads(targets, "get_language"))
        if len(results) > 0:
            for item in results:
                index = self.find(item["uuid"], targets)
                if index >= 0 and "results" in item:
                    targets[index].update(item["results"])
        return targets
