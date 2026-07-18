# -*- coding: utf_8 -*-
"""Real-execution (no-mock) coverage tests for android code_analysis.py.

Every test drives the real, module-level functions (get_perm_rules,
permission_transform, code_analysis) directly with real files on disk
(real .java source trees, a real yaml rules directory, a genuinely
unreadable file for fault injection) -- matching the direct-call
convention used by the sibling test_cov_app.py / test_cov_manifest_
analysis.py in this same package. No mocking of internal logic; real
libsast SastEngine/ChoiceEngine scans, real DB writes via
append_scan_status.

NOTE: settings_enabled() (mobinspect/MobInspect/utils.py) reads
PERM_MAPPING_ENABLED / NIAP_ENABLED via ``from . import settings`` --
the raw mobinspect.MobInspect.settings *module* -- not
``django.conf.settings``, so ``@override_settings`` has no effect on it
(same documented gotcha as test_cov_lib_analysis.py / test_cov_pdf.py).
Tests below patch the raw module attribute directly instead.
"""
import tempfile
from pathlib import Path
from unittest import mock

import pytest

from mobinspect.MobInspect import settings as raw_settings
from mobinspect.StaticAnalyzer.views.android.code_analysis import (
    code_analysis,
    get_perm_rules,
    permission_transform,
)

REPO_ROOT = Path(__file__).resolve().parents[4]
PERM_RULES = (REPO_ROOT / 'mobinspect' / 'StaticAnalyzer' / 'views'
              / 'android' / 'rules' / 'android_permissions.yaml')

CHECKSUM = 'c0de0000000000000000000000000a1'


# ---------------------------------------------------------------------------
# get_perm_rules
# ---------------------------------------------------------------------------

@pytest.mark.django_db
def test_get_perm_rules_returns_none_when_setting_disabled():
    """settings_enabled('PERM_MAPPING_ENABLED') False -> early None."""
    with mock.patch.object(raw_settings, 'PERM_MAPPING_ENABLED', ''):
        result = get_perm_rules(
            CHECKSUM, PERM_RULES, {'android.permission.INTERNET': ['x']})
    assert result is None


@pytest.mark.django_db
def test_get_perm_rules_exception_branch_missing_rules_file():
    """A real (non-existent) rules path makes perm_rules.open() raise a
    genuine FileNotFoundError -- real fault injection, no mocking -- which
    exercises the except branch and the final `return None` fallthrough."""
    missing = Path(tempfile.mkdtemp()) / 'does_not_exist.yaml'
    result = get_perm_rules(
        CHECKSUM, missing, {'android.permission.INTERNET': ['x']})
    assert result is None


@pytest.mark.django_db
def test_get_perm_rules_success_writes_matching_rules_tempfile():
    """Real success path: the real android_permissions.yaml rules file is
    loaded and filtered against a real, matching permission id, and a real
    NamedTemporaryFile is written and returned."""
    result = get_perm_rules(
        CHECKSUM, PERM_RULES,
        {'android.permission.SET_WALLPAPER': ['normal', 'x', 'y']})
    try:
        assert result is not None
        content = Path(result.name).read_text()
        assert 'android.permission.SET_WALLPAPER' in content
    finally:
        if result is not None:
            Path(result.name).unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# permission_transform
# ---------------------------------------------------------------------------

def test_permission_transform_simplifies_mapping():
    perm_mappings = {
        'android.permission.INTERNET': {
            'files': ['com/example/Net.java'],
            'metadata': {'id': 'android.permission.INTERNET'},
        },
    }
    assert permission_transform(perm_mappings) == {
        'android.permission.INTERNET': ['com/example/Net.java'],
    }


# ---------------------------------------------------------------------------
# code_analysis (full function, real SastEngine/ChoiceEngine/sbom scans)
# ---------------------------------------------------------------------------

@pytest.mark.django_db
def test_code_analysis_invalid_type_hits_outer_exception_handler():
    """An unsupported `typ` makes get_android_src_dir() return None; the
    subsequent `.as_posix()` call raises a real AttributeError, exercising
    the function's outer `except Exception` branch without any mocking."""
    app_dir = tempfile.mkdtemp()
    result = code_analysis(
        CHECKSUM, app_dir, 'not-a-real-type', None, {})
    # On failure the pre-seeded default result dict is returned unchanged.
    assert result['findings'] == {}
    assert result['api'] == {}


@pytest.mark.django_db
def test_code_analysis_niap_enabled_runs_choice_engine():
    """NIAP_ENABLED turned on (raw settings-module patch -- see module
    docstring) with only real, readable source -> exercises the whole
    NIAP ChoiceEngine block (read_files / run_rules / completion log)
    end to end, with a real libsast ChoiceMatcher scan."""
    app_dir = Path(tempfile.mkdtemp())
    src = app_dir / 'java_source' / 'com' / 'example'
    src.mkdir(parents=True)
    (src / 'Main.java').write_text(
        'package com.example;\n'
        'public class Main {\n'
        '    java.security.SecureRandom r = new java.security.SecureRandom();\n'
        '    String url = "http://example.com/api";\n'
        '}\n')

    with mock.patch.object(raw_settings, 'NIAP_ENABLED', '1'):
        result = code_analysis(
            CHECKSUM, app_dir.as_posix(), 'apk', None, {})

    # Real execution completed without raising, and the NIAP ChoiceEngine
    # genuinely ran and populated results for the seeded requirement ids.
    assert isinstance(result['niap'], dict)
    assert result['niap']
    assert 'http://example.com/api' in result['urls_list']


@pytest.mark.django_db
def test_code_analysis_permission_mapping_full_flow():
    """Real android_permissions dict with an id that genuinely matches an
    entry in the real android_permissions.yaml rules file -> get_perm_rules
    returns a truthy tempfile, so code_analysis() runs the full permission
    -mapping SastEngine scan (real subprocess-free libsast regex scan) and
    reaches the 'Permission Mapping Completed' / os.unlink cleanup lines."""
    app_dir = Path(tempfile.mkdtemp())
    src = app_dir / 'java_source' / 'com' / 'example'
    src.mkdir(parents=True)
    (src / 'Wall.java').write_text(
        'package com.example;\n'
        'import android.app.WallpaperManager;\n'
        'class Wall {\n'
        '    void set() { setWallpaper(null); }\n'
        '}\n')

    android_permissions = {
        'android.permission.SET_WALLPAPER': ['normal', 'Set wallpaper', ''],
    }
    result = code_analysis(
        CHECKSUM, app_dir.as_posix(), 'apk', None, android_permissions)

    assert isinstance(result['perm_mappings'], dict)


@pytest.mark.django_db
def test_code_analysis_unreadable_source_file_is_skipped():
    """A real java source file made genuinely unreadable via chmod(0)
    (fault injection, no mocking) makes pfile.read_text() raise a real
    PermissionError inside the URL/email extraction loop (NIAP left at
    its default disabled setting, so only this function's own try/except
    around read_text is exercised -- ChoiceEngine's own file reading,
    covered by the test above, would otherwise raise first). A second,
    readable file in the same tree is still processed normally, proving
    the loop continues past the unreadable one instead of aborting."""
    app_dir = Path(tempfile.mkdtemp())
    src = app_dir / 'java_source' / 'com' / 'example'
    src.mkdir(parents=True)

    readable = src / 'Main.java'
    readable.write_text(
        'package com.example;\n'
        'public class Main {\n'
        '    String url = "http://example.com/api";\n'
        '}\n')

    unreadable = src / 'Blocked.java'
    unreadable.write_text('package com.example;\nclass Blocked {}\n')
    unreadable.chmod(0o000)

    try:
        result = code_analysis(
            CHECKSUM, app_dir.as_posix(), 'apk', None, {})
    finally:
        # Restore permissions so the tmp dir can be cleaned up by the OS.
        unreadable.chmod(0o644)

    # Real execution completed without raising out of code_analysis();
    # the readable file's URL was still extracted despite the unreadable
    # sibling file being skipped via the except/continue branch.
    assert 'http://example.com/api' in result['urls_list']
