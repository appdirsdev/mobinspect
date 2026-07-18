# -*- coding: utf_8 -*-
"""Real-execution (no-mock) coverage tests for StaticAnalyzer/forms.py.

Drives the real Django form classes with real bound data -- no mocking.
"""
from django.test import SimpleTestCase

from mobinspect.StaticAnalyzer.forms import (
    APIChecks,
    ViewSourceAndroidApiForm,
    ViewSourceIOSForm,
)

VALID_MD5 = 'a' * 32
INVALID_BUT_RIGHT_LENGTH = 'z' * 32  # 32 chars, not valid hex -> not_md5


class APIChecksHashValidationTests(SimpleTestCase):

    def test_valid_md5_hash_passes_clean(self):
        form = APIChecks({'hash': VALID_MD5})
        self.assertTrue(form.is_valid())
        self.assertEqual(form.cleaned_data['hash'], VALID_MD5)

    def test_invalid_hash_raises_validation_error(self):
        # 32 chars (passes CharField length bounds) but not valid hex ->
        # is_md5() is False -> clean_hash() raises ValidationError (line 44).
        form = APIChecks({'hash': INVALID_BUT_RIGHT_LENGTH})
        self.assertFalse(form.is_valid())
        self.assertIn('hash', form.errors)
        self.assertIn('Invalid Hash', str(form.errors['hash']))


class WebChecksMd5ValidationTests(SimpleTestCase):

    def test_valid_md5_passes_clean(self):
        form = ViewSourceIOSForm({
            'file': 'AppDelegate.m', 'type': 'ios', 'md5': VALID_MD5})
        self.assertTrue(form.is_valid())
        self.assertEqual(form.cleaned_data['md5'], VALID_MD5)

    def test_invalid_md5_raises_validation_error(self):
        # 32 chars, not valid hex -> is_md5() False -> clean_md5() raises
        # ValidationError (line 55).
        form = ViewSourceIOSForm({
            'file': 'AppDelegate.m', 'type': 'ios',
            'md5': INVALID_BUT_RIGHT_LENGTH})
        self.assertFalse(form.is_valid())
        self.assertIn('md5', form.errors)
        self.assertIn('Invalid Hash', str(form.errors['md5']))


class ViewSourceAndroidApiFormTests(SimpleTestCase):
    """Sanity real-execution check of the composed multi-mixin form."""

    def test_valid_full_form(self):
        form = ViewSourceAndroidApiForm({
            'file': 'com/example/Main.java',
            'type': 'apk',
            'hash': VALID_MD5,
        })
        self.assertTrue(form.is_valid())
