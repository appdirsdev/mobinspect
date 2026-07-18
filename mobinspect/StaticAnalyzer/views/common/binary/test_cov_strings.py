# -*- coding: utf_8 -*-
"""Real-execution coverage tests for common/binary/strings.py.

The real-binary success path (``strings`` present, a real target file) is
already exercised elsewhere via elf.py/macho.py's real Mach-O/ELF strings
extraction. These tests cover the remaining branches with real fault
injection, no mocking of return values:

* ``shutil.which('strings')`` returning None -- driven by really
  overriding ``PATH`` to a directory containing no ``strings`` binary for
  the duration of the call (not a mock of ``shutil.which`` itself).
* ``subprocess.check_output`` failing for real -- the real OS ``strings``
  binary genuinely exits non-zero against a real nonexistent target file.
* The pure-Python ``strings_util`` fallback genuinely raising
  ``FileNotFoundError`` when it tries to open the same nonexistent file.
"""
import os
import tempfile
from unittest import mock

from django.test import SimpleTestCase

from mobinspect.StaticAnalyzer.views.common.binary.strings import (
    get_os_strings,
    strings_on_binary,
)

NONEXISTENT = '/nonexistent/mobinspect/strings/test/target.bin'


class GetOsStringsTests(SimpleTestCase):

    def test_no_strings_binary_on_path_returns_none(self):
        # Real PATH override to an empty real directory -> shutil.which
        # genuinely finds no 'strings' executable -> returns None
        # (line 18). No function is mocked; PATH is real environment
        # state and shutil.which really searches it.
        empty_bin_dir = tempfile.mkdtemp()
        with mock.patch.dict(os.environ, {'PATH': empty_bin_dir}):
            result = get_os_strings('/bin/ls')
        self.assertIsNone(result)

    def test_subprocess_failure_on_missing_file_returns_none(self):
        # The real OS `strings` binary genuinely exits non-zero against a
        # real nonexistent file -> subprocess.CalledProcessError ->
        # except -> None (lines 21-22).
        result = get_os_strings(NONEXISTENT)
        self.assertIsNone(result)


class StringsOnBinaryTests(SimpleTestCase):

    def test_missing_file_falls_through_and_excepts(self):
        # get_os_strings(NONEXISTENT) genuinely returns None (real
        # subprocess failure, not a mock) -> falls through to the
        # strings_util(bin_path) fallback (line 34), whose generator
        # genuinely raises FileNotFoundError when iterated (real
        # io.open() on a real nonexistent path) -> caught -> [] (lines
        # 35-37).
        result = strings_on_binary(NONEXISTENT)
        self.assertEqual(result, [])
