# -*- coding: utf_8 -*-
"""Real-execution (no-mock) coverage tests for sbom_analysis.py.

Targets the three branches the rest of the suite (which exercises sbom()
indirectly through full code-analysis runs) never reaches: extract_
packages' exception branch, get_group_name's non-2-part else branch, and
android_sbom's per-file exception branch (via a real unreadable file).
"""
import os
import tempfile
from pathlib import Path

from django.test import TestCase

from mobinspect.StaticAnalyzer.views.android.sbom_analysis import (
    android_sbom,
    extract_packages,
    get_group_name,
)


class ExtractPackagesTests(TestCase):

    def test_exception_branch_non_string_content(self):
        # item[1] is None -> .split('\n') raises AttributeError for real.
        result = extract_packages([('path/to/File.java', None)])
        self.assertEqual(result, [])


class GetGroupNameTests(TestCase):

    def test_non_two_part_kotlinx_name(self):
        # 'kotlinx_coroutines_core' splits into 3 parts on '_' -> takes the
        # else branch; replace('_','-') + kotlinx- prefix check.
        group, name = get_group_name('kotlinx_coroutines_core', '')
        self.assertEqual(group, 'org.jetbrains.kotlinx')
        self.assertEqual(name, 'kotlinx-coroutines-core')

    def test_non_two_part_non_kotlinx_name_keeps_default_group(self):
        group, name = get_group_name('single', 'defaultgroup')
        self.assertEqual(group, 'defaultgroup')
        self.assertEqual(name, 'single')


class AndroidSbomTests(TestCase):

    def test_per_file_exception_is_swallowed(self):
        # A directory named '*.version' matches the rglob pattern, but
        # .read_text() on a directory raises a real IsADirectoryError.
        app_dir = Path(tempfile.mkdtemp())
        (app_dir / 'broken.version').mkdir()
        (app_dir / 'good_1_0.version').write_text('1.0')
        result = android_sbom(app_dir)
        # The broken entry is silently skipped; the good one still appears.
        self.assertTrue(any('1.0' in r for r in result))
