#!/usr/bin/python
# -*- coding: utf-8 -*-

from setuptools import setup

with open('README.rst', 'r') as fh:
    long_description = fh.read()

setup(
    name='osint',
    author='QeeqBox',
    author_email='gigaqeeq@gmail.com',
    description="Collection of Open Source Intelligence (OSINT) tools",
    long_description=long_description,
    version='0.5',
    license='AGPL-3.0',
    url='https://github.com/qeeqbox/osint',
    packages=['osint'],
    include_package_data=True,
    scripts=['osint/osint'],    
    install_requires=['scapy', 'tld', 'netifaces', 'dnspython', 'beautifulsoup4', 'requests', 'pyOpenSSL', 'lxml', 'langdetect', 'Pillow'],
    package_data={'osint': ['data/*']},
    python_requires='>=3',
)
