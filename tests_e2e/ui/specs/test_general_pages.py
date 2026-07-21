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

``/find/`` real-app finding (see report): the view
(``mobinspect/StaticAnalyzer/views/android/views/find.py``) always calls
``print_n_send_error_response(request, msg, True)`` on every error branch
(invalid hash, missing source directory, or any other exception). With
``api=True`` that helper returns a bare ``dict`` (not an ``HttpResponse`` /
``JsonResponse``) -- Django's response-processing middleware chain then
raises ``AttributeError: 'dict' object has no attribute 'headers'``, which
surfaces as a real (branded, non-traceback) 500 for every single error path.
Confirmed live: a request with an invalid MD5 500s, and this environment
also doesn't have an on-disk ``java_source`` directory for any seeded fixture
(JADX decompile artifacts aren't retained after scanning here), so even the
"success" query with a real fixture hash still 500s via the "Invalid
Directory Structure" branch -- there is currently NO way to get a 200 out of
this endpoint in this environment. This is captured below as a strict xfail
so a future fix is very visible (test starts failing-the-xfail, i.e. flips
green) rather than being silently skipped.
"""
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


# ─────────────────────────── /find/ (known-broken; see module docstring) ───────────────────────────

@pytest.mark.negative
@pytest.mark.xfail(
    strict=True,
    reason=(
        "Known app bug: find.run() (mobinspect/StaticAnalyzer/views/android/"
        "views/find.py:37,49,76) always calls print_n_send_error_response(..., "
        "True), which returns a plain dict on every error branch instead of a "
        "JsonResponse -- Django's middleware then raises AttributeError and "
        "5xx's. Confirmed live 2026-07-21: an invalid MD5 POST to /find/ "
        "currently 500s instead of returning a clean JSON error. Remove this "
        "xfail once find.py is fixed to always return a real HttpResponse."
    ),
)
def test_find_files_invalid_md5_is_rejected_cleanly(admin_page):
    page = admin_page
    # Need a CSRF token from a real page first (find.run has no GET form).
    page.goto('/tasks', wait_until='domcontentloaded')
    csrf = page.evaluate(
        "document.cookie.match(/csrftoken=([^;]+)/)?.[1]")
    resp = page.request.post(
        '/find/',
        data={
            'md5': 'not-a-valid-md5',
            'q': 'x',
            'code': 'java',
            'search_type': 'filename',
        },
        headers={'X-CSRFToken': csrf} if csrf else {},
    )
    # Desired behavior once fixed: a clean 200 JSON error envelope, not a 5xx.
    assert resp.status < 500, (
        f'expected a clean JSON error, got HTTP {resp.status}')
    body = resp.json()
    assert 'error' in body


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
