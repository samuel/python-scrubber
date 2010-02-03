#!/usr/bin/env python

from setuptools import setup

# Get the version, but make sure to create a fake BeautifulSoup module just
# in case it isn't installed.
import imp
import sys
mod = imp.new_module("BeautifulSoup")
mod.BeautifulSoup = None
mod.Comment = None
sys.modules["BeautifulSoup"] = mod
from scrubber import __version__ as version

try:
    long_description = open("README.rst").read()
except IOError:
    long_description = ""

setup(
    name = 'scrubber',
    version = version,
    description = 'A whitelisting HTML sanitizer',
    long_description = long_description,
    author = 'Samuel Stauffer',
    author_email = 'samuel@lefora.com',
    url = 'http://github.com/samuel/python-scrubber/tree/master',
    install_requires = ["BeautifulSoup"],
    packages = ['scrubber'],
    classifiers = [
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Topic :: Software Development',
        'Topic :: Software Development :: Libraries',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ],
)
