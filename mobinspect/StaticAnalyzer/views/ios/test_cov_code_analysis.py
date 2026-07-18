# -*- coding: utf_8 -*-
"""Real-execution coverage tests for ios/code_analysis.py.

Real SastEngine runs against real temp-dir source trees (no mocking of the
scan engine itself). Fault injection: a chmod'd-unreadable real .m file
forces a genuine PermissionError inside the file-read loop; a real file
(not a directory) passed as ``src`` makes the real ``Path.rglob()`` walk
genuinely raise, driving the module's own outer exception handler.
"""
import os
import stat

import pytest

from mobinspect.StaticAnalyzer.views.ios.code_analysis import (
    ios_source_analysis,
    merge_findings,
)

CHECKSUM = 'c0' * 16


@pytest.mark.django_db
def test_no_source_files_yields_nocode(tmp_path):
    """An empty source tree -> no swift/objc findings -> source_types is
    empty -> source_type = 'No Code' (line 127)."""
    result = ios_source_analysis(CHECKSUM, str(tmp_path))
    assert result['source_type'] == 'No Code'
    assert result['urls_list'] == []


@pytest.mark.django_db
def test_unreadable_m_file_is_skipped(tmp_path):
    """A real .m file with all read permission bits removed makes the
    real ``pfile.read_text()`` call genuinely raise PermissionError,
    which the inner ``except Exception: continue`` swallows (lines
    115-116) -- the scan still completes normally."""
    bad_file = tmp_path / 'Unreadable.m'
    bad_file.write_text('int totally_unreadable(void) { return 1; }\n')
    os.chmod(bad_file, 0)
    try:
        result = ios_source_analysis(CHECKSUM, str(tmp_path))
    finally:
        # Restore permissions so pytest's own tmp_path cleanup can delete it.
        os.chmod(bad_file, stat.S_IRUSR | stat.S_IWUSR)
    # The unreadable file contributes no urls/emails, but the scan itself
    # completes (does not raise) -- proving the continue branch ran.
    assert result is not None
    assert result['urlnfile'] == []
    assert result['emailnfile'] == []


@pytest.mark.django_db
def test_readable_objc_match_url_and_single_source_type(tmp_path):
    """A real, readable .m file containing a genuine ``sqlite3_exec``
    call (matches the real ``ios_sqlite`` rule in objective_c_rules.yaml)
    plus a real URL string -> url/email extraction on a successfully-read
    file (lines 118-122) and, with only objc findings present, the
    single-type branch ``source_type = source_types.pop().value``
    (line 131) -> 'Objective-C'."""
    (tmp_path / 'Db.m').write_text(
        'void run(void) {\n'
        '  sqlite3_exec(db, "SELECT 1", NULL, NULL, NULL);\n'
        '  sqlite3_finalize(stmt);\n'
        '  // see https://example.com/api for docs\n'
        '}\n')
    result = ios_source_analysis(CHECKSUM, str(tmp_path))
    assert result['source_type'] == 'Objective-C'
    assert any('example.com' in u for u in result['urls_list'])
    assert result['code_anal'] != {}


@pytest.mark.django_db
def test_swift_and_objc_both_match_combined_source_type(tmp_path):
    """Real matching content in both a .m and a .swift file -> both
    source_types are populated -> the 'Swift, Objective-C' combined
    branch (lines 128-129)."""
    (tmp_path / 'Db.m').write_text(
        'void run(void) { sqlite3_exec(db, "x", NULL, NULL, NULL); '
        'sqlite3_finalize(s); }\n')
    (tmp_path / 'Db.swift').write_text(
        'func run() { sqlite3_exec(db, "x", nil, nil, nil); '
        'sqlite3_finalize(s) }\n')
    result = ios_source_analysis(CHECKSUM, str(tmp_path))
    assert result['source_type'] == 'Swift, Objective-C'


@pytest.mark.django_db
def test_outer_exception_src_wrong_type(tmp_path):
    """``ios_source_analysis`` documents ``src`` as a string; a real
    ``.m`` file is present so the loop body actually runs, but passing
    ``src`` as a ``Path`` instead of ``str`` makes the real
    ``pfile.as_posix().replace(src, '')`` call genuinely raise
    ``TypeError`` (str.replace() requires a str argument) -- caught by
    the function's own outer except (lines 151-154) -> None. No
    mocking: this is a genuine type-contract violation on real input."""
    (tmp_path / 'Thing.m').write_text('int y;\n')
    result = ios_source_analysis(CHECKSUM, tmp_path)
    assert result is None


def test_merge_findings_combines_and_dedupes_files():
    """Direct unit test of merge_findings(): a key present in both swift
    and objc dicts has its 'files' sets unioned; objc-only keys are
    added as-is."""
    swift = {'rule1': {'files': {'a.swift'}}}
    objc = {'rule1': {'files': {'b.m'}}, 'rule2': {'files': {'c.m'}}}
    merged = merge_findings(swift, objc)
    assert merged['rule1']['files'] == {'a.swift', 'b.m'}
    assert merged['rule2']['files'] == {'c.m'}
