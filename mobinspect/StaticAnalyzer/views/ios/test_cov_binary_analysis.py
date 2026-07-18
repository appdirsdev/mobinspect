# -*- coding: utf_8 -*-
"""Real-execution coverage tests for ios/binary_analysis.py.

Real files throughout: the committed test_files/macho.dylib (a genuine
universal/fat Mach-O binary whose FIRST header slice is 32-bit, real
armv7) drives the 32-bit branch of get_bin_info(); real .app directory
layouts (with and without a matching executable) drive
binary_analysis()'s path-resolution branches; a plain-text file standing
in for the executable makes the real macholib.MachO() parser genuinely
raise ValueError for the outer-exception branch.
"""
import os
import subprocess
import tempfile
from pathlib import Path

from django.conf import settings
from django.test import SimpleTestCase

from mobinspect.StaticAnalyzer.views.ios.binary_analysis import (
    binary_analysis,
    detect_bin_type,
    get_bin_info,
    ipa_macho_analysis,
)

SAMPLES_DIR = os.path.normpath(
    os.path.join(settings.BASE_DIR, '..', 'test_files'))
MACHO_DYLIB = os.path.join(SAMPLES_DIR, 'macho.dylib')


class DetectBinTypeTests(SimpleTestCase):

    def test_swift_library_present_returns_swift(self):
        # if-branch -> 'Swift' (line 34).
        self.assertEqual(
            detect_bin_type(['Foundation.dylib', 'libswiftCore.dylib']),
            'Swift')

    def test_no_swift_library_returns_objective_c(self):
        # else branch -> 'Objective C' (already covered elsewhere; kept
        # for completeness/documentation of the pairing).
        self.assertEqual(
            detect_bin_type(['Foundation.dylib', 'UIKit.dylib']),
            'Objective C')


class GetBinInfoTests(SimpleTestCase):

    def test_32bit_header_real_universal_binary(self):
        # macho.dylib is a real fat/universal binary whose first header
        # slice is 32-bit (armv7); get_bin_info() returns on the first
        # header (the 64-bit-branch's sibling 32-bit else, already
        # covered elsewhere -- kept here for documentation).
        info = get_bin_info(Path(MACHO_DYLIB))
        self.assertEqual(info['bit'], '32-bit')

    def test_64bit_header_real_macho_object(self):
        # A real Mach-O object file extracted from the committed static
        # lib (add.o) is a genuine single-arch, 64-bit x86_64 object ->
        # the first (only) header hits the 64-bit branch (line 45).
        tmp = tempfile.mkdtemp()
        subprocess.run(
            ['ar', 'x', os.path.join(SAMPLES_DIR, 'macho_static_lib.a')],
            cwd=tmp, check=True)
        info = get_bin_info(Path(tmp) / 'add.o')
        self.assertEqual(info['bit'], '64-bit')


class IpaMachoAnalysisTests(SimpleTestCase):

    def test_exception_branch_wrong_argument_type(self):
        # A plain string has no `.name` attribute -> the real
        # `logger.info('...', binary.name)` call genuinely raises
        # AttributeError -> caught (lines 73-74); default skeleton
        # returned.
        data = ipa_macho_analysis('not-a-path-object')
        self.assertEqual(data, {'checksec': {}, 'symbols': [], 'libraries': []})


class BinaryAnalysisTests(SimpleTestCase):

    def test_no_app_directory_found(self):
        # No .app directory anywhere under src -> lines 98-99.
        tmp = tempfile.mkdtemp()
        result = binary_analysis('a' * 32, tmp, tmp, tmp, '')
        self.assertEqual(result['bin_type'], '')
        self.assertIsNone(result['bin_path'])

    def test_executable_name_falsy_uses_app_stem(self):
        # executable_name falsy -> bin_name = dot_app_path.stem (line 104);
        # the stem-named file doesn't exist either -> warning branch
        # (lines 115-119).
        tmp = tempfile.mkdtemp()
        app_dir = Path(tmp) / 'MyApp.app'
        app_dir.mkdir(parents=True)
        result = binary_analysis('b' * 32, tmp, tmp, tmp, '')
        self.assertIsNone(result['bin_path'])

    def test_executable_name_given_but_missing_falls_back_to_stem(self):
        # executable_name given but the file doesn't exist under the
        # .app dir -> falls back to dot_app_path.stem (line 110); still
        # doesn't exist -> warning branch (lines 115-119) again, exercised
        # via a different code path.
        tmp = tempfile.mkdtemp()
        app_dir = Path(tmp) / 'MyApp.app'
        app_dir.mkdir(parents=True)
        result = binary_analysis(
            'c' * 32, tmp, tmp, tmp, 'NonexistentExecutable')
        self.assertIsNone(result['bin_path'])

    def test_outer_exception_invalid_macho_binary(self):
        # A real .app dir whose executable exists but is plain text (not
        # a real Mach-O) -> the real macholib.MachO() parser genuinely
        # raises ValueError('Unknown Mach-O header...') -> the function's
        # own outer except (lines 142-145).
        tmp = tempfile.mkdtemp()
        app_dir = Path(tmp) / 'BadApp.app'
        app_dir.mkdir(parents=True)
        (app_dir / 'BadApp').write_text('not a real mach-o binary at all')
        result = binary_analysis('d' * 32, tmp, tmp, tmp, '')
        self.assertEqual(result['bin_type'], '')
        self.assertIsNone(result['bin_path'])
