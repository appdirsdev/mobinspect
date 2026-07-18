# -*- coding: utf_8 -*-
"""Real-execution coverage tests for ios/strings.py.

extract_urls_n_email()'s success paths (dict entries / skipped
Frameworks-Resources / skipped binary-asset extensions / real file reads)
and get_strings_metadata() are already exercised elsewhere via real IPA/
dylib scans. This covers the remaining except branch with a genuine
missing-file real fault (no mocking).
"""
import pytest

from mobinspect.StaticAnalyzer.views.ios.strings import extract_urls_n_email

CHECKSUM = 'st' * 16


@pytest.mark.django_db
def test_missing_file_hits_except_branch():
    """A plain string path in `all_files` that does not exist on disk,
    and doesn't match any of the skip-extension/skip-path branches, makes
    the real `io.open()` call genuinely raise FileNotFoundError -> caught
    by the function's own except (lines 55-58) -> the empty-but-valid
    default shape is still returned."""
    result = extract_urls_n_email(
        CHECKSUM, '/nonexistent/src/',
        ['/nonexistent/src/definitely_missing_file.txt'], [])
    assert result == {'urls_list': [], 'urlnfile': [], 'emailnfile': []}
