"""UI spec: remaining general/misc pages not covered by test_general_dynamic.py.

Covers:
    /help/              - in-app help / user guide (FAQ accordion)
    /tasks               - scan queue page
    /find/                - AJAX source-search endpoint (POST only)
    /search               - checksum/text search redirect (GET)
    /compare/<h1>/<h2>/   - side-by-side app diff view

Compare pair: PRIMARY_HASH (Diva APK) vs SECONDARY_HASH (the ``jar`` fixture).
Both are valid per ``StaticAnalyzer.views.comparer.generic_compare`` -- it only
requires a ``StaticAnalyzerAndroid`` row to exist for each hash (verified live
against this environment's DB: both hashes have one), not that the artifact
was literally an .apk. So the README-suggested default pair works as-is; no
substitution needed.

``/find/`` was previously broken on every error path: the view
(``mobinspect/StaticAnalyzer/views/android/views/find.py``) called
``print_n_send_error_response(request, msg, True)`` on every error branch,
which with ``api=True`` returns a bare ``dict`` (not an ``HttpResponse``) ->
Django's response middleware raised ``AttributeError: 'dict' object has no
attribute 'headers'`` -> a 500 on every error path. FIXED: the view now
returns a real ``JsonResponse`` (in the double-encoded shape the source-tree
search client expects, ``JSON.parse(JSON.parse(text)).matches``) with an
appropriate 4xx status and an ``error`` field. The test below asserts that
fix (clean sub-500 JSON error for a bad hash). NOTE the double-encoded wire
format: Playwright's ``resp.json()`` parses the OUTER layer and returns the
inner JSON as a *string*, so the test does a second ``json.loads`` to reach
the dict.
"""
import json
import re

import pytest
from playwright.sync_api import expect

from tests_e2e.fixtures.data import PRIMARY_HASH, SECONDARY_HASH

NO_TRACEBACK = 'Traceback (most recent call last)'


# ─────────────────────────── /help/ ───────────────────────────

@pytest.mark.positive
def test_help_page_renders_faq_and_sections(admin_page):
    page = admin_page
    page.goto('/help/', wait_until='domcontentloaded')

    assert NO_TRACEBACK not in page.content()

    expect(page.get_by_role('heading', name='Help & user guide')).to_be_visible()
    expect(page.get_by_role('heading', name='Getting started')).to_be_visible()
    expect(page.get_by_role('heading', name='Running a scan')).to_be_visible()
    expect(page.get_by_role('heading', name='Reading a report')).to_be_visible()
    expect(page.get_by_role('heading', name='Security score')).to_be_visible()
    expect(page.get_by_role('heading', name='AI Dashboard')).to_be_visible()
    expect(page.get_by_role('heading', name='Frequently asked questions')).to_be_visible()

    # A real FAQ question from home.help_center()'s faqs list.
    expect(page.get_by_text(
        'Does any of my data leave my network?', exact=False)).to_be_visible()


# ─────────────────────────── /tasks ───────────────────────────

@pytest.mark.positive
def test_tasks_page_renders_scan_queue(admin_page):
    page = admin_page
    page.goto('/tasks', wait_until='domcontentloaded')

    assert NO_TRACEBACK not in page.content()

    expect(page.get_by_role('heading', name='Scan queue')).to_be_visible()
    expect(page.locator('#tasks-table')).to_be_attached()


# ─────────────────────────── /find/ (regression: was a 500 on every error path) ───────────────────────────

@pytest.mark.negative
@pytest.mark.regression
def test_find_files_invalid_md5_is_rejected_cleanly(admin_page):
    """An invalid-hash POST to /find/ must return a clean JSON error, not a
    5xx. Regression guard for the bare-dict-return bug (find.run previously
    returned print_n_send_error_response(..., api=True) — a plain dict —
    which Django can't render, 500ing every error path)."""
    page = admin_page
    # Need a CSRF token from a real page first (find.run has no GET form).
    page.goto('/tasks', wait_until='domcontentloaded')
    csrf = page.evaluate(
        "document.cookie.match(/csrftoken=([^;]+)/)?.[1]")
    # `multipart=` (NOT `data=`) so Django parses these into request.POST —
    # this mirrors the real client (source_tree.html posts a FormData object,
    # i.e. multipart/form-data). Playwright's `data={...}` would send a JSON
    # body, which Django's form parser ignores (request.POST stays empty).
    resp = page.request.post(
        '/find/',
        multipart={
            'md5': 'not-a-valid-md5',
            'q': 'x',
            'code': 'java',
            'search_type': 'filename',
        },
        headers={'X-CSRFToken': csrf} if csrf else {},
    )
    # A clean client error, never a 5xx.
    assert 400 <= resp.status < 500, (
        f'expected a clean 4xx JSON error, got HTTP {resp.status}')
    # Double-encoded body (see module docstring): resp.json() yields the inner
    # JSON as a string, so decode once more to reach the dict.
    inner = json.loads(resp.json())
    assert inner.get('error') == 'Invalid Hash'
    assert inner.get('matches') == []


# ─────────────────────────── /search ───────────────────────────

@pytest.mark.positive
def test_search_by_query_redirects_to_the_matching_report(admin_page):
    page = admin_page
    page.goto('/search?query=Diva', wait_until='domcontentloaded')

    assert NO_TRACEBACK not in page.content()
    # home.search() redirects a text-query match straight to the report page.
    page.wait_for_url(re.compile(rf'/static_analyzer/{PRIMARY_HASH}/'))
    expect(page.get_by_text('Diva', exact=False).first).to_be_visible()


@pytest.mark.negative
def test_search_with_no_query_shows_clean_error_not_traceback(admin_page):
    page = admin_page
    page.goto('/search', wait_until='domcontentloaded')

    # home.search()'s error path renders the branded general/error.html via
    # print_n_send_error_response(..., api=False) -- which (consistently,
    # app-wide) responds with HTTP 500 by design for this template, but the
    # BODY is a clean, on-brand error card -- never a raw Python traceback.
    assert NO_TRACEBACK not in page.content()
    expect(page.get_by_role('heading', name='Something went wrong')).to_be_visible()
    expect(page.get_by_text('No search query provided.', exact=False)).to_be_visible()


@pytest.mark.negative
def test_search_with_no_match_shows_clean_error_not_traceback(admin_page):
    page = admin_page
    page.goto('/search?query=zzz-no-such-app-xyz123', wait_until='domcontentloaded')

    assert NO_TRACEBACK not in page.content()
    expect(page.get_by_role('heading', name='Something went wrong')).to_be_visible()
    expect(page.get_by_text(
        'You can search by MD5, app name, package name, or file name.',
        exact=False)).to_be_visible()


# ─────────────────────────── /compare/<h1>/<h2>/ ───────────────────────────

@pytest.mark.positive
def test_compare_apps_renders_real_diff_view(admin_page):
    page = admin_page
    page.goto(
        f'/compare/{PRIMARY_HASH}/{SECONDARY_HASH}/',
        wait_until='domcontentloaded')

    assert NO_TRACEBACK not in page.content()
    expect(page.get_by_text('Side-by-side comparison of', exact=False)).to_be_visible()
    # Both app names (or file names for the unnamed jar fixture) appear.
    expect(page.locator('.mi-appcard').first).to_be_visible()
    expect(page.locator('.mi-appcard')).to_have_count(2)
    # Real MD5s rendered verbatim in the VS cards.
    expect(page.get_by_text(PRIMARY_HASH).first).to_be_visible()
    expect(page.get_by_text(SECONDARY_HASH).first).to_be_visible()


@pytest.mark.negative
def test_compare_same_hash_shows_clean_error_not_traceback(admin_page):
    page = admin_page
    page.goto(
        f'/compare/{PRIMARY_HASH}/{PRIMARY_HASH}/',
        wait_until='domcontentloaded')

    assert NO_TRACEBACK not in page.content()
    expect(page.get_by_role('heading', name='Something went wrong')).to_be_visible()
    expect(page.get_by_text(
        'Results with same hash cannot be compared', exact=False)).to_be_visible()


@pytest.mark.negative
def test_compare_nonexistent_hashes_shows_clean_error_not_traceback(admin_page):
    page = admin_page
    bogus1 = 'b' * 32
    bogus2 = 'c' * 32
    page.goto(f'/compare/{bogus1}/{bogus2}/', wait_until='domcontentloaded')

    assert NO_TRACEBACK not in page.content()
    expect(page.get_by_role('heading', name='Something went wrong')).to_be_visible()
    expect(page.get_by_text('diff/compare android apps', exact=False)).to_be_visible()


@pytest.mark.negative
def test_compare_malformed_hash_in_url_is_a_plain_404_not_a_crash(admin_page):
    page = admin_page
    resp = page.goto('/compare/short/alsoshort/', wait_until='domcontentloaded')

    # Doesn't match the checksum_regex URL pattern at all -> Django 404,
    # never reaches the view -- never a 500/crash.
    assert resp.status == 404
    assert NO_TRACEBACK not in page.content()
