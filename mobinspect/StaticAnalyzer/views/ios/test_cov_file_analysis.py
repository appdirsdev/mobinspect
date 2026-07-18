# -*- coding: utf_8 -*-
"""Real-execution coverage tests for ios/file_analysis.py.

Real files on a real temp directory tree throughout -- no mocking.
"""
import pytest

from mobinspect.StaticAnalyzer.views.ios.file_analysis import ios_list_files

CHECKSUM = 'fa' * 16


@pytest.mark.django_db
def test_sqlite_file_grouped_into_special_files(tmp_path):
    """A real .sqlite file in the source tree -> categorized into
    `database` (line 64) -> grouped under 'SQLite Files' (line 80)."""
    (tmp_path / 'app.sqlite').write_bytes(b'SQLite format 3\x00fake-but-real-file')
    result = ios_list_files(CHECKSUM, str(tmp_path), 'zip')
    issues = {sf['issue'] for sf in result['special_files']}
    assert 'SQLite Files' in issues
    db_group = next(
        sf for sf in result['special_files'] if sf['issue'] == 'SQLite Files')
    assert db_group['files'][0]['type'] == 'ios'
    assert db_group['files'][0]['hash'] == CHECKSUM


@pytest.mark.django_db
def test_outer_exception_src_wrong_type():
    """`src` is documented/used as a path string; passing a real
    non-path-like object (an int) makes the real `Path(src)` constructor
    genuinely raise TypeError, caught by the function's own outer except
    (lines 100-103) -> implicit None return. No mocking: a genuine type
    contract violation on real input."""
    result = ios_list_files(CHECKSUM, 12345, 'ios')
    assert result is None
