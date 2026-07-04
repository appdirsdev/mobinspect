# -*- coding: utf_8 -*-
"""Real-execution coverage tests for Firebase analysis.

STRICT: no mocks, no monkeypatch of internal logic. Drives the real
functions in ``mobsf.StaticAnalyzer.views.common.firebase`` with real
strings, real ``urlparse``/``valid_host`` (SSRF) logic and a real SQLite
test DB (via pytest-django) so ``append_scan_status`` writes to the ORM.

The live HTTP checks (``requests.get`` to ``*.firebaseio.com`` and
``requests.post`` to ``firebaseremoteconfig.googleapis.com``) require
network access and a specific live server response; those are ceiling-gap
and are exercised only up to the request boundary (the code either
completes the real request or its exception handler runs).
"""
import pytest

from mobsf.StaticAnalyzer.views.common.firebase import (
    FIREBASE_FINDINGS,
    firebase_analysis,
    firebase_db_check,
    firebase_remote_config,
    open_firebase,
)

CHECKSUM = 'a' * 32


# ---------------------------------------------------------------------------
# open_firebase
# ---------------------------------------------------------------------------

def test_open_firebase_invalid_host():
    """A non-URL string fails valid_host -> returns (url, False)."""
    url = 'not a valid url at all'
    returl, is_open = open_firebase(CHECKSUM, url)
    assert returl == url
    assert is_open is False


def test_open_firebase_valid_host_but_not_firebase():
    """A numeric public IP passes valid_host (no DNS needed) but the
    netloc does not end with .firebaseio.com -> returns (url, False)."""
    url = 'https://8.8.8.8'
    returl, is_open = open_firebase(CHECKSUM, url)
    assert returl == url
    assert is_open is False


@pytest.mark.django_db
def test_open_firebase_firebaseio_host():
    """A .firebaseio.com URL reaches the valid_host/netloc checks. Offline
    DNS resolution fails (valid_host False) or the real HTTP request runs
    and does not return 200 -> not detected as open."""
    url = 'https://mobsf-does-not-exist-xyz.firebaseio.com'
    returl, is_open = open_firebase(CHECKSUM, url)
    # Never a real open DB in tests.
    assert is_open is False
    assert returl == url


# ---------------------------------------------------------------------------
# firebase_db_check
# ---------------------------------------------------------------------------

def test_firebase_db_check_no_firebase_urls():
    """URLs without .firebaseio.com are skipped -> no findings."""
    code_an_dic = {'urls_list': [
        'https://example.com/a',
        'https://api.github.com',
    ]}
    findings = firebase_db_check(CHECKSUM, code_an_dic)
    assert findings == []


@pytest.mark.django_db
def test_firebase_db_check_with_firebase_url():
    """A firebaseio URL produces the 'db exists' finding (not open)."""
    code_an_dic = {'urls_list': [
        'https://example.com/x',
        'https://mobsf-nope-xyz.firebaseio.com',
        'https://mobsf-nope-xyz.firebaseio.com',  # dup -> deduped by set
    ]}
    findings = firebase_db_check(CHECKSUM, code_an_dic)
    assert len(findings) == 1
    exists = FIREBASE_FINDINGS['firebase_db_exists']
    assert findings[0]['title'] == exists['title']
    assert findings[0]['severity'] == exists['severity']
    assert 'firebaseio.com' in findings[0]['description']


@pytest.mark.django_db
def test_firebase_db_check_missing_urls_list_key():
    """Missing 'urls_list' key raises KeyError -> check-failed finding."""
    findings = firebase_db_check(CHECKSUM, {})
    assert len(findings) == 1
    failed = FIREBASE_FINDINGS['firebase_db_check_failed']
    assert findings[0]['title'] == failed['title']
    assert findings[0]['severity'] == failed['severity']


# ---------------------------------------------------------------------------
# firebase_remote_config
# ---------------------------------------------------------------------------

def test_remote_config_no_creds():
    """No firebase_creds -> returns None."""
    assert firebase_remote_config(CHECKSUM, {}) is None
    assert firebase_remote_config(CHECKSUM, {'firebase_creds': None}) is None
    assert firebase_remote_config(CHECKSUM, {'firebase_creds': {}}) is None


def test_remote_config_missing_keys():
    """Creds present but missing api key / app id -> returns None."""
    assert firebase_remote_config(
        CHECKSUM, {'firebase_creds': {'google_api_key': 'k'}}) is None
    assert firebase_remote_config(
        CHECKSUM, {'firebase_creds': {'google_app_id': '1:123:android:x'}}
    ) is None


def test_remote_config_non_numeric_project_id():
    """A well-formed app id whose project segment is not numeric -> None."""
    creds = {'firebase_creds': {
        'google_api_key': 'AIzaFakeKey',
        'google_app_id': '1:notnumeric:android:abcdef',
    }}
    assert firebase_remote_config(CHECKSUM, creds) is None


@pytest.mark.django_db
def test_remote_config_malformed_app_id_exception():
    """An app id with no ':' triggers IndexError on split[1] -> the
    exception handler produces the remote-config-failed finding."""
    creds = {'firebase_creds': {
        'google_api_key': 'AIzaFakeKey',
        'google_app_id': 'nocolonshere',
    }}
    findings = firebase_remote_config(CHECKSUM, creds)
    assert len(findings) == 1
    failed = FIREBASE_FINDINGS['firebase_remote_config_failed']
    assert findings[0]['title'] == failed['title']
    assert findings[0]['severity'] == failed['severity']


@pytest.mark.django_db
def test_remote_config_numeric_reaches_request():
    """A numeric project id reaches the real HTTP request. Offline that
    raises -> remote-config-failed; online it returns a finding. Either
    way exactly one finding is produced."""
    creds = {'firebase_creds': {
        'google_api_key': 'AIzaFakeInvalidKey',
        'google_app_id': '1:1234567890:android:abcdef',
    }}
    findings = firebase_remote_config(CHECKSUM, creds)
    assert isinstance(findings, list)
    assert len(findings) == 1
    assert 'title' in findings[0]
    assert 'severity' in findings[0]
    assert 'description' in findings[0]


# ---------------------------------------------------------------------------
# firebase_analysis orchestrator
# ---------------------------------------------------------------------------

@pytest.mark.django_db
def test_firebase_analysis_combines_findings():
    """The orchestrator runs both checks and concatenates their findings."""
    code_an_dic = {
        'urls_list': ['https://mobsf-nope-xyz.firebaseio.com'],
        'firebase_creds': {
            'google_api_key': 'AIzaFakeInvalidKey',
            'google_app_id': '1:1234567890:android:abcdef',
        },
    }
    findings = firebase_analysis(CHECKSUM, code_an_dic)
    assert isinstance(findings, list)
    # one from db_check (exists) + one from remote config.
    assert len(findings) == 2


def test_firebase_analysis_empty_inputs():
    """Empty analysis dict yields no findings (db check empty, config None)."""
    findings = firebase_analysis(CHECKSUM, {'urls_list': []})
    assert findings == []
