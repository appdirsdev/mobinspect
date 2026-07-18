# -*- coding: utf_8 -*-
"""Real-execution coverage tests for ios/icon_analysis.py.

STRICT: no mocks of the module under test. Real files on disk (crafted PNGs,
real .app directories), real subprocess execution (xcrun/pngcrush, the
committed CgbiPngFix_amd64/arm64/.exe binaries), and real fault injection
(missing PATH entries, architecture-mismatched binaries genuinely raising
``OSError: Exec format error`` on this host, missing destination
directories). ``platform.system``/``platform.machine`` are patched (a
narrow, single-call substitution, noted below) only to reach the
Windows/Linux code paths that cannot occur for real on this macOS host --
everything downstream of that patch (subprocess exec, exception handling,
file copies) still runs for real.
"""
import os
import subprocess
import tempfile
from pathlib import Path
from unittest import mock

from django.conf import settings
from django.test import SimpleTestCase, override_settings

from mobinspect.StaticAnalyzer.views.ios.icon_analysis import (
    get_icon_from_ipa,
    get_icon_source,
)


# A minimal (but real, valid) 1x1 PNG file body.
_PNG_BYTES = bytes.fromhex(
    '89504e470d0a1a0a0000000d49484452000000010000000108020000009077'
    '53de0000000c4944415478da6360606060000000050001a5f645400000000049454e44ae426082'
)


def _write_png(path):
    with open(path, 'wb') as fh:
        fh.write(_PNG_BYTES)


class GetIconFromIpaTests(SimpleTestCase):

    def _app_dict(self, tmp, extra=None):
        d = {
            'infoplist': {'bin': 'MyApp'},
            'md5_hash': 'a' * 32,
            'bin_dir': tmp,
        }
        if extra:
            d.update(extra)
        return d

    def test_bin_path_missing_returns_early(self):
        # bin_path (bin_dir/<binary>.app) does not exist -> lines 33-34.
        tmp = tempfile.mkdtemp()
        app_dict = self._app_dict(tmp)
        self.assertIsNone(get_icon_from_ipa(app_dict))
        self.assertEqual(app_dict.get('icon_path', ''), '')

    def test_no_icon_png_found_returns_early(self):
        # bin_path exists but has no AppIcon*.png -> lines 36-38 (already
        # covered elsewhere, exercised here too for completeness).
        tmp = tempfile.mkdtemp()
        os.makedirs(os.path.join(tmp, 'MyApp.app'))
        app_dict = self._app_dict(tmp)
        self.assertIsNone(get_icon_from_ipa(app_dict))

    def test_darwin_real_xcrun_no_libpng_error_in_stdout(self):
        # Real xcrun invocation (this host has no iphoneos SDK / pngcrush,
        # so xcrun exits non-zero writing to stderr, not stdout) -> the
        # try/if condition at lines 39-53 all execute; no exception raised
        # so the except body is NOT hit here (covered separately below).
        tmp = tempfile.mkdtemp()
        app_bundle = os.path.join(tmp, 'MyApp.app')
        os.makedirs(app_bundle)
        icon_path = os.path.join(app_bundle, 'AppIcon60x60.png')
        _write_png(icon_path)
        dwd = tempfile.mkdtemp()
        with override_settings(DWD_DIR=dwd):
            app_dict = self._app_dict(tmp)
            get_icon_from_ipa(app_dict)
        self.assertEqual(app_dict['icon_path'], f"{app_dict['md5_hash']}-icon.png")

    def test_darwin_xcrun_not_found_falls_back_to_copy(self):
        # Empty PATH -> the real 'xcrun' executable genuinely cannot be
        # found -> subprocess.run raises FileNotFoundError for real ->
        # except branch does a real shutil.copy2 fallback (lines 55-57).
        tmp = tempfile.mkdtemp()
        app_bundle = os.path.join(tmp, 'MyApp.app')
        os.makedirs(app_bundle)
        icon_path = os.path.join(app_bundle, 'AppIcon60x60.png')
        _write_png(icon_path)
        dwd = tempfile.mkdtemp()
        with override_settings(DWD_DIR=dwd), mock.patch.dict(
                os.environ, {'PATH': ''}):
            app_dict = self._app_dict(tmp)
            get_icon_from_ipa(app_dict)
        out_file = Path(dwd) / f"{app_dict['md5_hash']}-icon.png"
        self.assertTrue(out_file.exists())
        self.assertEqual(out_file.read_bytes(), _PNG_BYTES)

    def _non_darwin_case(self, system, machine, dwd):
        tmp = tempfile.mkdtemp()
        app_bundle = os.path.join(tmp, 'MyApp.app')
        os.makedirs(app_bundle)
        icon_path = os.path.join(app_bundle, 'AppIcon60x60.png')
        _write_png(icon_path)
        app_dict = self._app_dict(tmp)
        # Single, narrow patch of platform detection only -- every other
        # line (tools_dir resolution, the real subprocess exec attempt
        # against the real committed CgbiPngFix binary, the real
        # exec-format-error exception, the real shutil.copy2 fallback)
        # executes unmodified.
        with override_settings(DWD_DIR=dwd), \
                mock.patch('mobinspect.StaticAnalyzer.views.ios.'
                          'icon_analysis.platform.system',
                          return_value=system), \
                mock.patch('mobinspect.StaticAnalyzer.views.ios.'
                          'icon_analysis.platform.machine',
                          return_value=machine):
            get_icon_from_ipa(app_dict)
        return app_dict

    def test_darwin_pngcrush_reports_normal_png_raises_value_error(self):
        # Line 55 (raise ValueError('PNG is not CgBI')) only fires when the
        # real pngcrush tool decides the input PNG is not CgBI-crushed and
        # prints 'libpng error:' to stdout. pngcrush/the iphoneos SDK are
        # not installed on this host (confirmed: `xcrun --find pngcrush`
        # fails), so that exact tool output cannot be produced for real.
        # NARROW MONKEYPATCH (single call, noted per rule 1): patch only
        # subprocess.run's return value for this one call to carry the
        # real tool's documented 'libpng error:' stdout marker; the
        # raise/except/copy2 fallback that follows still executes for
        # real.
        tmp = tempfile.mkdtemp()
        app_bundle = os.path.join(tmp, 'MyApp.app')
        os.makedirs(app_bundle)
        icon_path = os.path.join(app_bundle, 'AppIcon60x60.png')
        _write_png(icon_path)
        dwd = tempfile.mkdtemp()
        fake_completed = subprocess.CompletedProcess(
            args=['xcrun'], returncode=1,
            stdout=b'libpng error: Not a CgBI PNG', stderr=b'')
        with override_settings(DWD_DIR=dwd), mock.patch(
                'mobinspect.StaticAnalyzer.views.ios.icon_analysis.'
                'subprocess.run', return_value=fake_completed):
            app_dict = self._app_dict(tmp)
            get_icon_from_ipa(app_dict)
        out_file = Path(dwd) / f"{app_dict['md5_hash']}-icon.png"
        # ValueError raised -> caught by the except -> real copy2 fallback.
        self.assertTrue(out_file.exists())
        self.assertEqual(out_file.read_bytes(), _PNG_BYTES)

    def test_windows_amd64_cgbipngfix_exe_real_exec_format_error(self):
        # system='Windows', arch='AMD64' -> cgbipng_bin = CgbiPngFix.exe
        # (lines 60-62, 67-69). The committed .exe is a real PE binary;
        # executing it on this macOS host genuinely raises
        # 'Exec format error' -> real except -> real copy2 (lines 71-73,75).
        dwd = tempfile.mkdtemp()
        app_dict = self._non_darwin_case('Windows', 'AMD64', dwd)
        out_file = Path(dwd) / f"{app_dict['md5_hash']}-icon.png"
        self.assertTrue(out_file.exists())

    def test_linux_x86_64_cgbipngfix_amd64_real_exec_format_error(self):
        # system='Linux', arch='x86_64' -> cgbipng_bin = CgbiPngFix_amd64
        # (lines 63-64). Real ELF binary, wrong arch for this host -> real
        # exec format error -> except -> copy2.
        dwd = tempfile.mkdtemp()
        app_dict = self._non_darwin_case('Linux', 'x86_64', dwd)
        out_file = Path(dwd) / f"{app_dict['md5_hash']}-icon.png"
        self.assertTrue(out_file.exists())

    def test_linux_aarch64_cgbipngfix_arm64_real_exec_format_error(self):
        # system='Linux', arch='aarch64' -> cgbipng_bin = CgbiPngFix_arm64
        # (lines 65-66).
        dwd = tempfile.mkdtemp()
        app_dict = self._non_darwin_case('Linux', 'aarch64', dwd)
        out_file = Path(dwd) / f"{app_dict['md5_hash']}-icon.png"
        self.assertTrue(out_file.exists())

    def test_unsupported_arch_falls_back_to_copy_with_warning(self):
        # system='Linux', arch='i386' (unsupported) -> cgbipng_bin stays
        # None -> warning + direct copy2 (lines 77-78).
        dwd = tempfile.mkdtemp()
        app_dict = self._non_darwin_case('Linux', 'i386', dwd)
        out_file = Path(dwd) / f"{app_dict['md5_hash']}-icon.png"
        self.assertTrue(out_file.exists())

    def test_outer_exception_branch_missing_bin_dir_key(self):
        # A real KeyError (app_dict missing 'bin_dir', but 'md5_hash' is
        # set first) is raised organically and caught by the function's
        # own outer except (lines 79-82).
        app_dict = {
            'infoplist': {'bin': 'MyApp'},
            'md5_hash': 'b' * 32,
            # 'bin_dir' intentionally omitted.
        }
        result = get_icon_from_ipa(app_dict)
        self.assertIsNone(result)


class GetIconSourceTests(SimpleTestCase):

    def test_no_appiconset_found_returns_early(self):
        # No .appiconset PNG anywhere in src_dir -> line 102.
        tmp = tempfile.mkdtemp()
        app_dict = {'md5_hash': 'c' * 32, 'app_dir': tmp}
        self.assertIsNone(get_icon_source(app_dict))
        self.assertEqual(app_dict.get('icon_path', ''), '')

    def test_appiconset_found_and_copied(self):
        # Real .appiconset PNG present -> real shutil.copy2 succeeds.
        tmp = tempfile.mkdtemp()
        iconset_dir = os.path.join(tmp, 'Assets.xcassets', 'AppIcon.appiconset')
        os.makedirs(iconset_dir)
        _write_png(os.path.join(iconset_dir, 'icon_60x60.png'))
        dwd = tempfile.mkdtemp()
        app_dict = {'md5_hash': 'd' * 32, 'app_dir': tmp}
        with override_settings(DWD_DIR=dwd):
            get_icon_source(app_dict)
        self.assertEqual(app_dict['icon_path'], f"{app_dict['md5_hash']}-icon.png")

    def test_exception_branch_missing_destination_dir(self):
        # A real .appiconset PNG is found, but DWD_DIR points at a
        # directory that does not exist -> shutil.copy2 genuinely raises
        # FileNotFoundError -> except (lines 107-110).
        tmp = tempfile.mkdtemp()
        iconset_dir = os.path.join(tmp, 'Assets.xcassets', 'AppIcon.appiconset')
        os.makedirs(iconset_dir)
        _write_png(os.path.join(iconset_dir, 'icon_60x60.png'))
        app_dict = {'md5_hash': 'e' * 32, 'app_dir': tmp}
        with override_settings(DWD_DIR='/nonexistent/dir/does/not/exist'):
            result = get_icon_source(app_dict)
        self.assertIsNone(result)
        self.assertEqual(app_dict.get('icon_path', ''), '')
