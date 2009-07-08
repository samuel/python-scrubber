#!/usr/bin/env python

from setuptools import setup

from scrubber import __version__ as version

setup(
    name = 'scrubber',
    version = version,
    description = 'A whitelisting HTML sanitizer',
    long_description = open("README.rst").read(),
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
