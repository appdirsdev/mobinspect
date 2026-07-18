# -*- coding: utf_8 -*-
"""Real-execution coverage tests for common/entropy.py (exclude() branches).

Pure function, direct real calls -- no mocking needed.
"""
from django.test import SimpleTestCase

from mobinspect.StaticAnalyzer.views.common.entropy import exclude


class ExcludeTests(SimpleTestCase):

    def test_starts_with_capital_l_and_slash_excluded(self):
        # line 42: Java/Kotlin type-descriptor-shaped strings.
        self.assertTrue(exclude('Lcom/example/MainActivity;'))

    def test_multiple_slashes_excluded_as_path(self):
        # line 47: more than one '/' -> treated as a URL/path.
        self.assertTrue(exclude('abc/def/ghijklmno'))

    def test_pure_alphabetic_excluded(self):
        # line 49: alphabetic-only string. Must avoid the 'excludes'
        # substrings ('abcdefghi', 'kotlin/') checked just before this,
        # or it would short-circuit at line 43-44 instead.
        self.assertTrue(exclude('SecurePasswordValueZZZ'))

    def test_real_secret_like_value_not_excluded(self):
        # Sanity check the negative case still works (no branch matches).
        self.assertFalse(exclude('aGVsbG93b3JsZDEyMzQ1Njc4OTA='))
