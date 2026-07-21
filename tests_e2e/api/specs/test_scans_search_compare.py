"""``GET /api/v1/scans``, ``POST /api/v1/search``, ``POST /api/v1/compare``.

See ``api_static_analysis.py::api_recent_scans/api_search/api_compare``.
"""
import pytest

from tests_e2e.fixtures.data import PRIMARY_HASH, SCANNED, SECONDARY_HASH


# ── scans ────────────────────────────────────────────────────────────────

@pytest.mark.positive
def test_scans_list_contains_primary(api_client):
    r = api_client.scans()
    assert r.status_code == 200
    body = r.json()
    assert {'content', 'count', 'num_pages'} <= set(body.keys())
    hashes = {row['MD5'] for row in body['content']}
    # The list is paginated (num_pages can be > 1 on a long-lived shared DB),
    # so page through until found or exhausted, rather than assume page 1
    # always contains our fixture.
    if PRIMARY_HASH not in hashes:
        for page in range(2, body['num_pages'] + 1):
            r_page = api_client.get('/api/v1/scans', params={'page': page})
            hashes |= {row['MD5'] for row in r_page.json()['content']}
    assert PRIMARY_HASH in hashes


# ── search ───────────────────────────────────────────────────────────────

@pytest.mark.positive
def test_search_by_app_name_finds_diva(api_client):
    r = api_client.search('Diva')
    assert r.status_code == 200
    body = r.json()
    assert body.get('md5') == PRIMARY_HASH
    assert body.get('app_name') == SCANNED['apk']['app_name']


@pytest.mark.positive
def test_search_by_hash(api_client):
    r = api_client.search(PRIMARY_HASH)
    assert r.status_code == 200
    assert r.json().get('md5') == PRIMARY_HASH


@pytest.mark.negative
def test_search_no_match_returns_clean_404(api_client):
    """search() with no matching MD5/app/package/file name is a clean 404
    with a helpful message, not a 500/crash (see
    mobinspect/MobInspect/views/home.py::search)."""
    r = api_client.search('this-string-matches-absolutely-nothing-zzz-e2e')
    assert r.status_code == 404
    assert 'error' in r.json()


@pytest.mark.negative
def test_search_missing_query(api_client):
    r = api_client.post('/api/v1/search', data={})
    assert r.status_code == 422
    assert r.json().get('error') == 'Missing Parameters'


# ── compare ──────────────────────────────────────────────────────────────

@pytest.mark.positive
def test_compare_primary_vs_secondary(api_client):
    """compare() only supports two Android APK/ZIP-backed static analyses
    (see StaticAnalyzer/views/comparer.py::generic_compare -- filters
    StaticAnalyzerAndroid only). PRIMARY (apk/Diva) and SECONDARY (jar) are
    both stored as Android static-analysis rows, so they're a valid pair."""
    r = api_client.compare(PRIMARY_HASH, SECONDARY_HASH)
    assert r.status_code == 200
    body = r.json()
    assert 'first_app' in body
    assert 'second_app' in body
    assert 'permissions' in body


@pytest.mark.negative
def test_compare_ios_vs_android_unsupported(api_client):
    """compare() is Android-only; pairing an Android APK with an iOS IPA is
    rejected with a clear message, not a 500 traceback (the app *does*
    return HTTP 500 here by the endpoint's own contract -- see
    api_compare's `if 'error' in resp -> 500` branch -- but the body is a
    clean, documented error, never a stack trace)."""
    r = api_client.compare(PRIMARY_HASH, SCANNED['ipa']['hash'])
    assert r.status_code == 500
    assert 'diff/compare android apps' in r.json().get('error', '')


@pytest.mark.negative
def test_compare_same_hash_rejected(api_client):
    r = api_client.compare(PRIMARY_HASH, PRIMARY_HASH)
    assert r.status_code == 500
    assert r.json().get('error') == 'Results with same hash cannot be compared'


@pytest.mark.negative
def test_compare_missing_params(api_client):
    r = api_client.post('/api/v1/compare', data={'hash1': PRIMARY_HASH})
    assert r.status_code == 422
    assert r.json().get('error') == 'Missing Parameters'
