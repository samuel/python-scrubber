========
Scrubber
========

Scrubber is a white-listing HTML sanitizer. It uses BeautifulSoup to parse an
HTML document and removes any tags and attributes that are not specifically
allowed. Some other features of scrubber include:

* normalizing of tags (``<b>`` to ``<strong>``, etc..)
* cleaning up markup to make it more consistent between browsers
* optional autolinking urls
* optional ``rel="nofollow"`` for anchor tags
* optional removal of comments

.. toctree::
    :maxdepth: 2

Installation
============

Stable releases of Scrubber can be installed using ``easy_install`` or
``pip``.

Source
======

You can find the latest version of scrubber at
http://github.com/samuel/python-scrubber

Example
=======

    >>> from scrubber import Scrubber
    >>> scrubber = Scrubber(autolink=True)
    >>> scrubber.scrub("<script>alert('foo');</script><p>bar, www.google.com</p>")
    u'<p>bar, <a href="http://www.google.com" rel="nofollow">www.google.com</a></p>'
    >>>

API
===

Module
------

The scrubber module has the following functions.

.. function:: scrubber.Scrubber(base_url=None, autolink=True, nofollow=True, remove_comments=True)

   Return a new Scrubber with the given settings. If *base_url* is given
   then all relative URLs are rewritten to be absolute.

Scrubber Objects
----------------

Scrubber objects have the following methods.

.. method:: scrubber.scrub(html)

   Return a sanitized version of *html*.
