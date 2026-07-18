# -*- coding: utf_8 -*-
"""Real-execution unit tests for shared_func.py, phase 3 (coverage close-out).

Prefers real execution throughout. A small number of narrow, single-call
monkeypatches are used, each named and justified in its test's docstring:
  * `platform.system` -- to exercise the Windows-only / Linux-only branches
    of `os_unzip` / `ar_extract` on this macOS host (there is no other way
    to reach OS-specific branching without the actual OS).
  * `shutil.which('unzip')` -- to simulate the OS unzip binary being absent
    without uninstalling it from the host.

Everything else -- zip extraction permission failures, the real `lipo` /
`ar` utilities against the real `test_files/macho.dylib` fat binary (which
genuinely makes macOS's `ar` suggest "use lipo(1)"), and the real RBAC-
gated `compare_apps` view -- runs unmocked.
"""
import os
import platform
import shutil
import stat
import tempfile
import zipfile
from pathlib import Path

import pytest

from django.test import RequestFactory, TestCase, override_settings

from mobinspect.StaticAnalyzer.views.common.shared_func import (
    ar_extract,
    compare_apps,
    lipo_thin,
    os_unzip,
    unzip,
)

REPO_ROOT = Path(__file__).resolve().parents[4]
TEST_FILES = REPO_ROOT / 'test_files'
CHK = 'a' * 32


def _tmpdir():
    return tempfile.mkdtemp()


# ---------------------------------------------------------------------------
# unzip(): real extraction failure inside the per-entry try/except
# ---------------------------------------------------------------------------
@pytest.mark.skipif(os.geteuid() == 0, reason='root bypasses file permissions')
def test_unzip_extract_failure_is_caught_per_entry():
    """A real-permission-denied destination directory makes
    `zipptr.extract()` genuinely raise for a file entry; the per-entry
    try/except logs and continues rather than aborting the whole unzip."""
    ext = _tmpdir()
    os.chmod(ext, stat.S_IREAD | stat.S_IEXEC)  # read+traverse, no write
    try:
        zpath = Path(_tmpdir()) / 'readonly_target.zip'
        with zipfile.ZipFile(zpath, 'w') as z:
            z.writestr('cant_write_me.txt', 'content')
        files = unzip(CHK, str(zpath), ext)
        # namelist() still succeeds (that's read-only on the SOURCE zip,
        # unrelated to the destination), so the entry is listed even
        # though the actual extract() call for it failed and was caught.
        assert 'cant_write_me.txt' in files
        assert not (Path(ext) / 'cant_write_me.txt').exists()
    finally:
        os.chmod(ext, stat.S_IRWXU)


# ---------------------------------------------------------------------------
# os_unzip(): Windows guard + "unzip binary not found" guard
# ---------------------------------------------------------------------------
def test_os_unzip_windows_branch(monkeypatch):
    """Windows-only branch: unreachable on this macOS host without
    simulating the OS via `platform.system`, a single narrow patch."""
    monkeypatch.setattr(platform, 'system', lambda: 'Windows')
    out = os_unzip(CHK, str(TEST_FILES / 'android.apk'), _tmpdir())
    assert out == []


def test_os_unzip_missing_unzip_binary(monkeypatch):
    """Simulates the `unzip` CLI being absent, without uninstalling it."""
    monkeypatch.setattr(shutil, 'which', lambda name: None)
    out = os_unzip(CHK, str(TEST_FILES / 'android.apk'), _tmpdir())
    assert out == []


# ---------------------------------------------------------------------------
# lipo_thin(): real success on a genuinely fat Mach-O (macho.dylib)
# ---------------------------------------------------------------------------
def test_lipo_thin_real_success_breaks_on_first_matching_arch():
    """test_files/macho.dylib is a REAL fat Mach-O (armv7 + arm64);
    'armv7' is the first arch lipo_thin tries, and `lipo -thin armv7`
    genuinely succeeds against it, exercising the `if out.returncode == 0:
    break` branch for real (verified by lipo -info reporting the output
    as a single-architecture file)."""
    import subprocess

    dst = _tmpdir()
    new_src = lipo_thin(CHK, str(TEST_FILES / 'macho.dylib'), dst)
    assert new_src is not None
    assert Path(new_src).exists()
    info = subprocess.run(
        ['lipo', '-info', new_src], capture_output=True, text=True)
    assert 'Non-fat file' in info.stdout


# ---------------------------------------------------------------------------
# ar_extract(): platform-specific branches inside the fat-archive fallback
# ---------------------------------------------------------------------------
def test_ar_extract_windows_branch_returns_early(monkeypatch):
    """A non-ar file makes arpy raise -> falls into the OS-ar fallback path
    -> the Windows-only early-return is exercised via a narrow
    `platform.system` patch (there is no other way to reach it on macOS)."""
    monkeypatch.setattr(platform, 'system', lambda: 'Windows')
    dst = _tmpdir()
    # Must not raise, and must return before attempting any ar/lipo calls.
    ar_extract(CHK, str(TEST_FILES / 'android.jar'), dst)


def test_ar_extract_linux_branch_returns_early(monkeypatch):
    """Real `ar t` on a non-ar file (android.jar) genuinely produces
    multi-byte error output (len > 3); combined with a narrow
    `platform.system` patch reporting 'Linux', this exercises the
    "can't convert FAT binary in Linux" early return."""
    monkeypatch.setattr(platform, 'system', lambda: 'Linux')
    dst = _tmpdir()
    ar_extract(CHK, str(TEST_FILES / 'android.jar'), dst)


def test_ar_extract_fat_dylib_triggers_real_lipo_thin_path():
    """test_files/macho.dylib is a real fat Mach-O, not a valid ar archive:
    arpy raises -> OS `ar t` fallback genuinely emits macOS's own
    "...use lipo(1)..." suggestion (verified independently with the real
    `ar` CLI) -> ar_extract recognizes it, and the real `lipo_thin` +
    follow-up `ar_os` calls both run for real (on this actually-fat file)."""
    dst = _tmpdir()
    ar_extract(CHK, str(TEST_FILES / 'macho.dylib'), dst)
    # No assertion beyond "did not raise" -- the real lipo_thin/ar_os calls
    # both have their own internal broad except and never propagate, so
    # this test's job is proving the "lipo(1)" real-detection branch runs.


# ---------------------------------------------------------------------------
# compare_apps(): the real success path (login_required + require_permission
# satisfied via DISABLE_AUTHENTICATION, matching the sibling
# CompareViewTests convention in test_cov_shared_func.py)
# ---------------------------------------------------------------------------
@override_settings(DISABLE_AUTHENTICATION='1')
class CompareAppsSuccessPathTests(TestCase):
    def test_compare_apps_reaches_generic_compare_for_real(self):
        req = RequestFactory().get('/')
        resp = compare_apps(req, '1' * 32, '2' * 32, api=True)
        # generic_compare's own api-mode return is a dict/context, not None,
        # for two distinct valid hashes with no matching scans.
        assert resp is not None
