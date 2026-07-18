# -*- coding: utf_8 -*-
"""Real-execution coverage tests for templatetags/ai_tags.py.

Pure template-helper functions exercised with real, crafted markdown-ish
text; ``ai_dashboard_ready``'s except branch is exercised with a real
fault: an MD5 string containing an embedded NUL byte, which PostgreSQL
genuinely rejects (a real ``ValueError``/``django.db.utils.Error`` from
the driver, not a mock).
"""
from django.test import SimpleTestCase, TestCase, override_settings

from mobinspect.StaticAnalyzer.templatetags.ai_tags import (
    ai_dashboard_ready,
    ai_inline,
    ai_richtext,
)


class AiInlineTests(SimpleTestCase):

    def test_falsy_value_returns_empty_string(self):
        # line 44.
        self.assertEqual(ai_inline(''), '')
        self.assertEqual(ai_inline(None), '')


class AiRichtextTests(SimpleTestCase):

    def test_falsy_value_returns_empty_string(self):
        # line 54.
        self.assertEqual(ai_richtext(''), '')
        self.assertEqual(ai_richtext(None), '')

    def test_bullet_list_flush_and_blank_line(self):
        # Bullet lines accumulate into `items` (lines 77-78), a blank
        # line flushes both para and list (lines 72-73), and the
        # non-empty list gets rendered + cleared (lines 65, 67).
        text = (
            'Intro paragraph.\n'
            '- first item\n'
            '- second item\n'
            '\n'
            'Trailing paragraph.'
        )
        html = ai_richtext(text)
        self.assertIn('<ul>', html)
        self.assertIn('<li>first item</li>', html)
        self.assertIn('<li>second item</li>', html)
        self.assertIn('Intro paragraph.', html)
        self.assertIn('Trailing paragraph.', html)

    def test_header_line_flushes_para_and_list(self):
        # A header line flushes both the current paragraph and any
        # pending list (lines 80-81) before emitting the header markup.
        text = (
            '- item one\n'
            '## A Header\n'
            'Body text after header.'
        )
        html = ai_richtext(text)
        self.assertIn('<li>item one</li>', html)
        self.assertIn('class="ai-h"', html)
        self.assertIn('A Header', html)
        self.assertIn('Body text after header.', html)


@override_settings(MOBINSPECT_AI_ENABLED=True)
class AiDashboardReadyTests(TestCase):

    def test_exception_branch_nul_byte_in_md5(self):
        # A real NUL byte in the MD5 string makes PostgreSQL/psycopg
        # genuinely reject the query -> except -> False (lines 104-105).
        result = ai_dashboard_ready('a\x00b')
        self.assertFalse(result)
