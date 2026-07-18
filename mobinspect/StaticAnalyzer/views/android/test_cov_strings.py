# -*- coding: utf_8 -*-
"""Real-execution (no-mock) coverage tests for android strings.py.

Every test drives the real module-level functions (strings_from_so,
strings_from_apk, strings_from_code) directly with real data structures
and real fault injection (bad element types that make real stdlib calls
raise, a real IndexError from an empty list, a real TypeError from
Path(None)) -- matching the direct-call convention used by the sibling
test_cov_app.py / test_cov_code_analysis.py in this same package.

The only test doubles used are plain, minimal, real Python objects
standing in for an androguard ``Resources`` object (rather than
constructing a full real androguard4 APK just to reach two dict
attributes) -- not monkeypatches of any internal call.
"""
import tempfile
from pathlib import Path

import pytest

from mobinspect.StaticAnalyzer.views.android.strings import (
    strings_from_apk,
    strings_from_code,
    strings_from_so,
)

CHECKSUM = '57r1ng50000000000000000000000a1'

# A real, matching Google API key: 'AIza' + 35 chars of [0-9A-Za-z-_].
GOOGLE_API_KEY = 'AIza' + 'A' * 35
# A real, matching Google App ID: \d{1,2}:\d{1,50}:android:[a-f0-9]{1,50}
GOOGLE_APP_ID = '1:1234567890:android:abcdef0123456789'


class FakeResources:
    """Minimal stand-in for androguard's Resources object: only the two
    members strings_from_apk actually touches (get_packages_names() and
    the `.values` dict-of-dicts)."""

    def __init__(self, pkg, values):
        self._pkg = pkg
        self.values = values

    def get_packages_names(self):
        return [self._pkg]

    def get_strings_resources(self):
        return None


class EmptyPackagesResources:
    """Real object whose get_packages_names() genuinely returns an empty
    list, so `rsrc.get_packages_names()[0]` raises a real IndexError."""

    def get_packages_names(self):
        return []


# ---------------------------------------------------------------------------
# strings_from_so
# ---------------------------------------------------------------------------

@pytest.mark.django_db
def test_strings_from_so_skips_empty_and_handles_bad_entry():
    """First .so has an empty string list -> `continue` (line 34). Second
    .so has non-string entries, so the real `' '.join(str_list)` call
    genuinely raises TypeError -> except branch (lines 46-49). Real
    fault injection, no mocking."""
    elf_strings = [
        {'empty.so': []},
        {'bad.so': [123, 456]},
    ]
    result = strings_from_so(CHECKSUM, elf_strings)
    # The exception aborts the whole loop (single try around it), so no
    # entries are appended -- what matters for coverage is that both the
    # `continue` and the except branch genuinely executed without
    # propagating out of strings_from_so.
    assert result == []


@pytest.mark.django_db
def test_strings_from_so_success_path():
    elf_strings = [{'good.so': ['hello world', 'http://example.com/x']}]
    result = strings_from_so(CHECKSUM, elf_strings)
    assert len(result) == 1
    entry = result[0]['good.so']
    assert 'http://example.com/x' in entry['urls_list']


# ---------------------------------------------------------------------------
# strings_from_apk
# ---------------------------------------------------------------------------

@pytest.mark.django_db
def test_strings_from_apk_resource_branches():
    """Real androguard-shaped resource-string walk exercising:
    - a falsy `string` entry -> `continue` (line 77)
    - a falsy `value` entry -> `continue` (line 81)
    - a real matching google_api_key -> firebase_creds branch (line 85)
    - a real matching google_app_id -> firebase_creds branch (line 87)
    """
    values = {
        'com.example': {
            'no_string_key': {'other': 'ignored'},
            'blank_string_list': {'string': None},
            'mixed': {'string': [
                ('some_label', ''),
                ('google_api_key', GOOGLE_API_KEY),
                ('google_app_id', GOOGLE_APP_ID),
                ('normal_label', 'hello'),
            ]},
        },
    }
    rsrc = FakeResources('com.example', values)
    app_dic = {'androguard_apk_resources': rsrc}

    result = strings_from_apk(CHECKSUM, app_dic)

    assert result['firebase_creds']['google_api_key'] == GOOGLE_API_KEY
    assert result['firebase_creds']['google_app_id'] == GOOGLE_APP_ID
    assert '"normal_label" : "hello"' in result['strings']


@pytest.mark.django_db
def test_strings_from_apk_falls_back_to_apk_strings():
    """No androguard resources -> falls back to the raw apk_strings list
    (lines 96/98), still runs URL/email extraction afterwards."""
    app_dic = {'apk_strings': ['"a" : "http://example.org/path"']}
    result = strings_from_apk(CHECKSUM, app_dic)
    assert result['strings'] == ['"a" : "http://example.org/path"']
    assert 'http://example.org/path' in result['urls_list']


@pytest.mark.django_db
def test_strings_from_apk_neither_source_returns_default(caplog):
    """Neither androguard resources nor apk_strings present -> the else
    branch logs a warning and returns the untouched default dict early
    (lines 100-103)."""
    result = strings_from_apk(CHECKSUM, {})
    assert result['strings'] == []
    assert result['firebase_creds'] == {}


@pytest.mark.django_db
def test_strings_from_apk_exception_branch():
    """A real object whose get_packages_names() returns [] makes
    `rsrc.get_packages_names()[0]` raise a genuine IndexError, exercising
    the except branch (lines 111-114) -- no mocking."""
    app_dic = {'androguard_apk_resources': EmptyPackagesResources()}
    result = strings_from_apk(CHECKSUM, app_dic)
    # Exception happened before anything was populated; defaults stand.
    assert result['strings'] == []


# ---------------------------------------------------------------------------
# strings_from_code
# ---------------------------------------------------------------------------

@pytest.mark.django_db
def test_strings_from_code_exception_branch_bad_src_dir():
    """Passing a non-path-like `src_dir` (None) makes the real
    `Path(src_dir)` call inside strings_from_code raise a genuine
    TypeError, exercising the except branch (lines 131-134)."""
    data = strings_from_code(CHECKSUM, None, 'apk', {'.java'})
    # Exception path returns the pre-seeded default dict unchanged.
    assert data == {'strings': set(), 'secrets': set()}


@pytest.mark.django_db
def test_strings_from_code_success_path():
    app_dir = Path(tempfile.mkdtemp())
    src = app_dir / 'java_source' / 'com' / 'example'
    src.mkdir(parents=True)
    (src / 'Main.java').write_text(
        'package com.example;\nclass Main { String x = "a_real_string_1"; }\n')
    data = strings_from_code(CHECKSUM, app_dir.as_posix(), 'apk', {'.java'})
    assert any('a_real_string_1' in s for s in data['strings'])
