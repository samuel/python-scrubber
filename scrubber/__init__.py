"""
Whitelisting HTML scrubber.
"""

__author__ = "Samuel Stauffer <samuel@descolada.com>"
__version__ = "1.1"
__license__ = "Python"

# 
# Useful links:
#   http://www.feedparser.org/docs/html-sanitization.html
#

import re
from urlparse import urljoin
from itertools import chain
from BeautifulSoup import BeautifulSoup

def urlize(text, trim_url_limit=None, nofollow=False, autoescape=False):
    """
    Borrowed from Django

    Converts any URLs in text into clickable links.

    If trim_url_limit is not None, the URLs in link text longer than this limit
    will truncated to trim_url_limit-3 characters and appended with an elipsis.

    If nofollow is True, the URLs in link text will get a rel="nofollow"
    attribute.

    If autoescape is True, the link text and URLs will get autoescaped.
    """
    from urllib import quote as urlquote
    
    LEADING_PUNCTUATION  = ['(', '<', '&lt;']
    TRAILING_PUNCTUATION = ['.', ',', ')', '>', '\n', '&gt;']
    
    word_split_re = re.compile(r'(\s+)')
    punctuation_re = re.compile('^(?P<lead>(?:%s)*)(?P<middle>.*?)(?P<trail>(?:%s)*)$' % \
        ('|'.join([re.escape(x) for x in LEADING_PUNCTUATION]),
        '|'.join([re.escape(x) for x in TRAILING_PUNCTUATION])))
    simple_email_re = re.compile(r'^\S+@[a-zA-Z0-9._-]+\.[a-zA-Z0-9._-]+$')
    del x # Temporary variable

    def escape(html):
        return html.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;').replace("'", '&#39;')
    
    trim_url = lambda x, limit=trim_url_limit: limit is not None and (len(x) > limit and ('%s...' % x[:max(0, limit - 3)])) or x
    safe_input = False#Todo, Strip this out
    words = word_split_re.split(text)
    nofollow_attr = nofollow and ' rel="nofollow"' or ''
    for i, word in enumerate(words):
        match = None
        if '.' in word or '@' in word or ':' in word:
            match = punctuation_re.match(word)
        if match:
            lead, middle, trail = match.groups()
            # Make URL we want to point to.
            url = None
            if middle.startswith('http://') or middle.startswith('https://'):
                url = urlquote(middle, safe='%/&=:;#?+*')
            elif middle.startswith('www.') or ('@' not in middle and \
                    middle and middle[0] in string.ascii_letters + string.digits and \
                    (middle.endswith('.org') or middle.endswith('.net') or middle.endswith('.com'))):
                url = urlquote('http://%s' % middle, safe='%/&=:;#?+*')
            elif '@' in middle and not ':' in middle and simple_email_re.match(middle):
                url = 'mailto:%s' % middle
                nofollow_attr = ''
            # Make link.
            if url:
                trimmed = trim_url(middle)
                if autoescape:
                    lead, trail = escape(lead), escape(trail)
                    url, trimmed = escape(url), escape(trimmed)
                middle = '<a href="%s"%s>%s</a>' % (url, nofollow_attr, trimmed)
                words[i] = '%s%s%s' % (lead, middle, trail)
            elif autoescape:
                words[i] = escape(word)
        elif autoescape:
            words[i] = escape(word)
    return u''.join(words)
    
class ScrubberWarning(object):
    pass

class Scrubber(object):
    def __init__(self, base_url=None):
        self.autolink = bool(urlize)
        self.nofollow = True
        self.base_url = base_url
        self.allowed_tags = set((
            'a', 'abbr', 'acronym', 'b', 'bdo', 'big', 'blockquote', 'br',
            'center', 'cite', 'code',
            'dd', 'del', 'dfn', 'div', 'dl', 'dt', 'em', 'embed', 'font',
            'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'hr', 'i', 'img', 'ins',
            'kbd', 'li', 'object', 'ol', 'param', 'pre', 'p', 'q',
            's', 'samp', 'small', 'span', 'strike', 'strong', 'sub', 'sup',
            'table', 'td', 'th', 'tr', 'tt', 'ul', 'u', 'var', 'wbr',
        ))
        self.disallowed_tags_save_content = set((
            'blink',
        ))
        self.allowed_attributes = set((
            'align', 'alt', 'border', 'cite', 'class', 'dir',
            'height', 'href', 'src', 'style', 'title', 'type', 'width',
            'face', 'size', # font tags
            'flashvars', # Not sure about flashvars - if any harm can come from it
            'classid', # FF needs the classid on object tags for flash
            'name', 'value', 'quality', 'data', # for flash embed param tags, could limit to just param if this is harmful
        )) # Bad attributes: 'allowscriptaccess', 'xmlns', 'target'
        self.normalized_tag_replacements = {'b': 'strong', 'i': 'em'}
        self.warnings = []

        # Find all _scrub_tab_<name> methods
        self.tag_scrubbers = {}
        for k in chain(*[cls.__dict__ for cls in self.__class__.__mro__]):
            if k.startswith('_scrub_tag_'):
                self.tag_scrubbers[k[11:]] = [getattr(self, k)]

    def autolink_soup(self, soup):
        def _autolink(node):
            if isinstance(node, basestring):
                text = node
                text2 = urlize(text, nofollow=self.nofollow)
                if text != text2:
                    node.replaceWith(text2)
            else:
                if node.name == "a":
                    return

                for child in node.contents:
                    _autolink(child)
        _autolink(soup)

    def strip_disallowed(self, soup):
        for node in soup.recursiveChildGenerator():
            if isinstance(node, basestring):
                continue
                
            # Remove disallowed tags
            if node.name not in self.allowed_tags:
                node.extract()

            # Remove disallowed attributes
            attrs = []
            for k, v in node.attrs:
                if not v:
                    continue

                if k.lower() not in self.allowed_attributes:
                    continue

                # TODO: This probably needs to be more robust
                v2 = v.lower()
                if any(x in v2 for x in ('javascript:', 'vbscript:', 'expression(')):
                    continue

                attrs.append((k,v))
            node.attrs = attrs

    def normalize_html(self, soup):
        for node in soup.findAll(self.normalized_tag_replacements.keys()):
            node.name = self.normalized_tag_replacements[node.name]
        # for node in soup.findAll('br', clear="all"):
        #     node.extract()

    def _clean_path(self, node, attrname):
        url = node.get(attrname)
        if url and '://' not in url:
            if url[0] not in ('/', '.'):
                node['href'] = "http://" + url
            elif self.base_url:
                node['href'] = urljoin(self.base_url, url)

    def _scrub_tag_a(self, a):
        if self.nofollow:
            a['rel'] = "nofollow"

        if not a.get('class', None):
            a['class'] = "external"

        self._clean_path(a, 'href')

    def _scrub_tag_img(self, img):
        try:
            if img['src'].lower().startswith('chrome://'):
                return True
        except KeyError:
            return True

        # Make sure images always have an 'alt' attribute
        img['alt'] = img.get('alt', '')

        self._clean_path(img, 'src')

    def _scrub_tag_font(self, node):
        attrs = []
        for k, v in node.attrs:
            if k.lower() == 'size' and v.startswith('+'):
                # Remove "size=+0"
                continue
            attrs.append((k, v))
        node.attrs = attrs

        if len(node.attrs) == 0:
            # IE renders font tags with no attributes differently then other browsers
            if node.contents:
                idx = node.parent.contents.index(node)
                for n in reversed(node.contents):
                    node.parent.insert(idx, n)
            node.extract()

    def _scrub_html_pre(self, html):
        return html

    def _scrub_html_post(self, html):
        return html

    def _scrub_soup(self, soup):
        self.strip_disallowed(soup)

        if self.autolink:
            self.autolink_soup(soup)

        for tag_name, scrubbers in self.tag_scrubbers.items():
            for node in soup(tag_name):
                for scrub in scrubbers:
                    if scrub(node):
                        # Remove the node from the tree
                        node.extract()
                        break

        self.normalize_html(soup)

    def scrub(self, html):
        self.warnings = []

        html = self._scrub_html_pre(html)
        soup = BeautifulSoup(html)
        self._scrub_soup(soup)
        html = unicode(soup)
        return self._scrub_html_post(html)

class UnapprovedJavascript(ScrubberWarning):
    def __init__(self, src):
        self.src = src
        self.path = src[:src.rfind('/')]

class SelectiveScriptScrubber(Scrubber):
    def __init__(self):
        super(SelectiveScriptScrubber, self).__init__()

        self.allowed_tags.add('script')
        self.allowed_tags.add('noscript')
        self.allowed_tags.add('iframe')
        self.allowed_attributes.add('scrolling')
        self.allowed_attributes.add('frameborder')

        self.allowed_script_srcs = set((
            'http://www.statcounter.com/counter/counter_xhtml.js',
            # 'http://www.google-analytics.com/urchin.js',
            'http://pub.mybloglog.com/',
            'http://rpc.bloglines.com/blogroll',
            'http://widget.blogrush.com/show.js',
            'http://re.adroll.com/',
            'http://widgetserver.com/',
            'http://pagead2.googlesyndication.com/pagead/show_ads.js', # are there pageadX for all kinds of numbers?
        ))

        self.allowed_script_line_res = set(re.compile(text) for text in (
             r"^(var )?sc_project\=\d+;$",
             r"^(var )?sc_invisible\=\d;$",
             r"^(var )?sc_partition\=\d+;$",
             r'^(var )?sc_security\="[A-Za-z0-9]+";$',
             # """^_uacct \= "[^"]+";$""",
             # """^urchinTracker\(\);$""",
             r'^blogrush_feed = "[^"]+";$',
             # """^!--$""",
             # """^//-->$""",
        ))

        self.allowed_iframe_srcs = set(re.compile(text) for text in (
            r'^http://www\.google\.com/calendar/embed\?[\w&;=\%]+$', # Google Calendar
        ))

    def _scrub_tag_script(self, script):
        src = script.get('src', None)
        if src:
            for asrc in self.allowed_script_srcs:
                # TODO: It could be dangerous to only check "start" of string
                #       as there could be browser bugs using crafted urls
                if src.startswith(asrc):
                    script.contents = []
                    break
            else:
                self.warnings.append(UnapprovedJavascript(src))
                script.extract()
        elif script.get('type', '') != 'text/javascript':
            script.extract()
        else:
            for line in script.string.splitlines():
                line = line.strip()
                if not line:
                    continue

                line_match = any(line_re.match(line) for line_re in self.allowed_script_line_res)

                if not line_match:
                    script.extract()
                    break

    def _scrub_tag_iframe(self, iframe):
        src = iframe.get('src', None)
        if not src or not any(asrc.match(src) for asrc in self.allowed_iframe_srcs):
            iframe.extract()
