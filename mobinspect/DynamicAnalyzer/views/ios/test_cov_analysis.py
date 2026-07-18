# -*- coding: utf_8 -*-
"""Real-execution regression tests for ``DynamicAnalyzer.views.ios.analysis``.

No mocks: ``ios_api_analysis`` is driven against a real on-disk
``mobinspect_dump_file.txt`` (the exact file Frida hooks append to in
production via ``Frida.write_log`` / ``frida_response``), and the real
``json`` module parses it. Nothing about Corellium, Frida, or a device is
required to exercise this pure file-parsing code path.

Regression covered: a single malformed/blank line anywhere in the dump file
used to abort parsing of the *entire* file (the bare ``json.loads(line)``
raised, which was only caught by the function's outermost ``except
Exception``), silently discarding every entry that would otherwise have
been parsed after it. A truncated write from a crashed/interrupted Frida
hook, or a stray blank line, is a realistic way for such a line to appear.
"""
from pathlib import Path

import pytest

from mobinspect.DynamicAnalyzer.views.ios.analysis import ios_api_analysis


@pytest.fixture
def app_dir(tmp_path):
    return tmp_path


def _write_dump(app_dir, lines):
    dump_file = Path(app_dir) / 'mobinspect_dump_file.txt'
    dump_file.write_text('\n'.join(lines) + '\n', encoding='utf-8')
    return dump_file


def test_no_dump_file_returns_empty_defaults(app_dir):
    """No dump file at all -> the default empty structure, no crash."""
    result = ios_api_analysis(app_dir)
    assert result['logs'] == []
    assert result['keychain'] == []


def test_all_valid_lines_are_parsed(app_dir):
    """Sanity: every valid line contributes to the result (no regression
    in the happy path from adding the try/except)."""
    _write_dump(app_dir, [
        '{"nslog": "first log line"}',
        '{"nslog": "second log line"}',
        '{"keychain": ["item1"]}',
    ])
    result = ios_api_analysis(app_dir)
    assert set(result['logs']) == {'first log line', 'second log line'}
    assert result['keychain'] == ['item1']


def test_malformed_line_does_not_abort_remaining_lines(app_dir):
    """The regression test: a bad line sandwiched between two good ones.

    Before the fix, ``json.loads`` raised on the malformed second line,
    the exception propagated out of the ``for`` loop entirely (only the
    function-level ``except Exception`` caught it), and the *third* line's
    entry ('second log line' below) was silently NEVER PARSED even though
    it is perfectly valid JSON that appears later in the same file.
    """
    _write_dump(app_dir, [
        '{"nslog": "first log line"}',
        'this is not json at all {{{',
        '{"nslog": "second log line"}',
    ])
    result = ios_api_analysis(app_dir)
    # Before the fix: only {'first log line'} (loop aborted on line 2).
    # After the fix: both lines are present.
    assert set(result['logs']) == {'first log line', 'second log line'}


def test_blank_line_does_not_abort_remaining_lines(app_dir):
    """A stray blank line (e.g. a hook that sent an empty payload) must be
    skipped rather than raising ``json.JSONDecodeError`` on ``''``."""
    _write_dump(app_dir, [
        '{"nslog": "before blank"}',
        '',
        '{"nslog": "after blank"}',
    ])
    result = ios_api_analysis(app_dir)
    assert set(result['logs']) == {'before blank', 'after blank'}
