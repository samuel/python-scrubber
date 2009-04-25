#!/usr/bin/env python

from distutils.core import setup

setup(
    name = 'scrubber',
    version = '1.4.0',
    description = 'A whitelisting HTML sanitizer',
    author = 'Samuel Stauffer',
    author_email = 'samuel@lefora.com',
    url = 'http://github.com/samuel/python-scrubber/tree/master',
    packages = ['scrubber'],
    classifiers = [
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Topic :: Internet :: WWW/HTTP',
    ],
)
