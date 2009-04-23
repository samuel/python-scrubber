#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest
import BeautifulSoup

from scrubber import Scrubber, SelectiveScriptScrubber

class ScrubberTestCase(unittest.TestCase):
    tests = (
        ( # Invalid HTML
            """<div notRealAttribute="value\n"onmouseover="\nexecuteMe();\n"foo="bar">\nI will execute here, too, if you mouse over me\n</div>""",
            "" if BeautifulSoup.__version__.startswith('3.1') else """<div>\nI will execute here, too, if you mouse over me\n</div>"""
        ),
        ( # Autolink
            """www.example.com<br>""",
            """<a href="http://www.example.com" rel="nofollow">www.example.com</a><br />"""
        ),
        ( # No autolinking of existing links
            """<a href="http://www.example.com">Example</a>""",
            """<a href="http://www.example.com" rel="nofollow" class="external">Example</a>"""
        ),        
        ( # No enocoding of pre-encoded urls during autolink:
            """http://www.example.com/aaa%20bbb/test%20test.jpg<br/>""",
            """<a href="http://www.example.com/aaa%20bbb/test%20test.jpg" rel="nofollow">http://www.example.com/aaa%20bbb/test%20test.jpg</a><br />"""
        ),
        ( # Strip scripts
            """<div xmlns="http://www.w3.org/1999/xhtml">safe<script type="text/javascript">location.href='http:/'+'/example.com/';</script> description</div>""",
            """<div>safe description</div>""",
        ),
        ( # Remove target from links
            """<a href="www.google.com" target="_new">Google</a>""",
            """<a href="http://www.google.com" rel="nofollow" class="external">Google</a>"""
        ),
        ( # General cleaning (remove <br clear="all">, ...)
            """<br clear="all">""",
            """<br />"""
        ),
        ( # Converting b and i to strong and em
            """<b>strong</b> <i>em</i>""",
            """<strong>strong</strong> <em>em</em>"""
        ),
        ( # Encoded script (decimal)
            """<span style="&#97;&#110;&#121;&#58;&#32;&#101;&#120;&#112;&#114;&#101;&#115;&#115;&#105;&#111;&#110;&#40;&#119;&#105;&#110;&#100;&#111;&#119;&#46;&#108;&#111;&#99;&#97;&#116;&#105;&#111;&#110;&#61;&#39;&#104;&#116;&#116;&#112;&#58;&#47;&#47;&#101;&#120;&#97;&#109;&#112;&#108;&#101;&#46;&#111;&#114;&#103;&#47;&#39;&#41;">safe</span>""",
            """<span>safe</span>"""
        ),
        ( # Encoded script (hex)
            """<span style="&#x61;&#x6e;&#x79;&#x3a;&#x20;&#x65;&#x78;&#x70;&#x72;&#x65;&#x73;&#x73;&#x69;&#x6f;&#x6e;&#x28;&#x77;&#x69;&#x6e;&#x64;&#x6f;&#x77;&#x2e;&#x6c;&#x6f;&#x63;&#x61;&#x74;&#x69;&#x6f;&#x6e;&#x3d;&#x27;&#x68;&#x74;&#x74;&#x70;&#x3a;&#x2f;&#x2f;&#x65;&#x78;&#x61;&#x6d;&#x70;&#x6c;&#x65;&#x2e;&#x6f;&#x72;&#x67;&#x2f;&#x27;&#x29;">safe</span>""",
            """<span>safe</span>"""
        ),
        ( # Test unicode
            u"""Mitä kuuluu""",
            u"""Mitä kuuluu"""
        ),
        ( # Test embed
            """<embed src='http://videomedia.ign.com/ev/ev.swf' flashvars='object_ID=949610&downloadURL=http://pspmovies.ign.com/psp/video/article/852/852594/patapon_021508_flvlowwide.flv&allownetworking="all"' type='application/x-shockwave-flash' width='433' height='360' ></embed>""",
            """<embed src="http://videomedia.ign.com/ev/ev.swf" flashvars='object_ID=949610&amp;downloadURL=http://pspmovies.ign.com/psp/video/article/852/852594/patapon_021508_flvlowwide.flv&amp;allownetworking="all"' type="application/x-shockwave-flash" width="433" height="360"></embed>"""
        ),
        ( # Test evil code
            """<img src=""http://www.a.com/a.jpg<script type=text/javascript src="http://1.2.3.4:81/xss.js">" /><<img src=""http://www.a.com/a.jpg</script>""",
            "" if BeautifulSoup.__version__.startswith('3.1') else """<img src="" alt="" />"""
        ),
        ( # Bad font tags
            """<font size=+0>test</font> <font>wowzers</font> <font></font> <font><p>foo</p><i>bar</i></font>""",
            """test wowzers  <p>foo</p><em>bar</em>"""
        ),
        ( # Stripping empty attributed
            """<font style="">Foo</font> <span id="">Bar</span>""",
            """Foo <span>Bar</span>"""
        ),
        ( # a0 == nbsp
            u"""test\xa0www.this.com""",
            u"""test\xa0<a href="http://www.this.com" rel="nofollow">www.this.com</a>"""
        ),
        ( # Remove comments
            "Foo <!-- bar -->",
            "Foo "
        ),
        ( # Layered font tags
            """<div><font size=+0><font size=+0><a href="http://www.google.com">test</a></font><font>ing</font> 123</font> abc</div>""",
            """<div><a href="http://www.google.com" rel="nofollow" class="external">test</a>ing 123 abc</div>"""
        ),
        ( # Save contents of tags specified in 'disallowed_tags_save_content'
            "<blink>Foo</blink>",
            "Foo"
        ),
        ( # Character entities shouldn't get autolinked
            """http://www.google.com&nbsp;&nbsp;""",
            """<a href="http://www.google.com" rel="nofollow">http://www.google.com</a>&nbsp;&nbsp;"""
        ),
        ( # Test unicode with autolinker
            u"""http://www.google.com/?q=mitä""",
            u"""<a href="http://www.google.com/?q=mit%C3%A4" rel="nofollow">http://www.google.com/?q=mit\xe4</a>""",
        ),
    )

    def setUp(self):
        self.scrubber = Scrubber()

    def testScrubber(self):
        for html, expected in self.tests:
            self.failUnlessEqual(self.scrubber.scrub(html), expected)

class SelectiveScriptScrubberTestCase(unittest.TestCase):
    tests = (
        ( # Allowed src, remove body
            '<script type="text/javascript" src="http://www.statcounter.com/counter/counter_xhtml.js">fewfewfwe</script>',
            '<script type="text/javascript" src="http://www.statcounter.com/counter/counter_xhtml.js"></script>'
        ),
        ( # Disallowed src
            '<script type="text/javascript" src="http://www.example.com/evil.js">fewfewfwe</script>',
            ''
        ),
        ( # Allowed inline
            '<script type="text/javascript">var sc_project=123;</script>',
            True
        ),
        ( # Disallowed inline
            '<script type="text/javascript">alert(5);</script>',
            ''
        ),
        ( # Stat counter
            """<!-- Start of StatCounter Code --><script type="text/javascript">\nvar sc_project=1234; \nvar sc_invisible=0; \nvar sc_partition=12; \nvar sc_security="1234a5"; \n</script><script src="http://www.statcounter.com/counter/counter_xhtml.js" type="text/javascript"></script><noscript><div class="statcounter"><a href="http://www.statcounter.com/" class="statcounter" rel="nofollow"><img src="http://c37.statcounter.com/1234/0/020062e8/0/" alt="hit counter" class="statcounter" /></a></div></noscript><!-- End of StatCounter Code -->""",
            """<script type="text/javascript">\nvar sc_project=1234; \nvar sc_invisible=0; \nvar sc_partition=12; \nvar sc_security="1234a5"; \n</script><script src="http://www.statcounter.com/counter/counter_xhtml.js" type="text/javascript"></script><noscript><div class="statcounter"><a href="http://www.statcounter.com/" class="statcounter" rel="nofollow"><img src="http://c37.statcounter.com/1234/0/020062e8/0/" alt="hit counter" class="statcounter" /></a></div></noscript>"""
        ),
        ( # Google calendar
            """<iframe src="http://www.google.com/calendar/embed?title=test&amp;height=300&amp;wkst=1&amp;bgcolor=%23FFFFFF&amp;ctz=America%2FLos_Angeles" style=" border-width:0 " width="300" height="300" frameborder="0" scrolling="no"></iframe>""",
            True
        ),
    )

    def setUp(self):
        self.scrubber = SelectiveScriptScrubber()

    def testScrubber(self):
        for html, expected in self.tests:
            if expected is True:
                expected = html
            self.failUnlessEqual(self.scrubber.scrub(html), expected)

if __name__ == '__main__':
    unittest.main()
