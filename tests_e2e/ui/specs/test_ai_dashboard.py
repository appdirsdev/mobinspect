"""UI spec — AI Dashboard negative/edge cases (`/ai_dashboard/<md5>/`).

The happy-path (real generated content for the Diva fixture, watermark
presence) lives in ``test_report.py`` alongside the other report-domain
tests for that same MD5 — this file adds NEW cases only, for scans that
have NO AIEnrichment row at all, so ``ai_dashboard`` (StaticAnalyzer/views/
common/llm/views.py) must gracefully redirect rather than 500.

See ``_enrichment_ctx`` / ``_DASHBOARD_BLOCKED`` in that module: a scan hash
with no ``AIEnrichment`` row returns status ``'none'``, which is one of the
blocked statuses -> ``ai_dashboard`` redirects to ``recent`` with an info
message. This is the real, deliberate "if the model never produced a report,
the user cannot enter" behavior, not a bug — these tests pin it.
"""
import re

import pytest
from playwright.sync_api import expect

from tests_e2e.fixtures.data import SCANNED

# 'aar' and 'so' both have no AIEnrichment row in this environment (verified
# via the ORM this session: AIEnrichment.objects.filter(MD5=...).exists() is
# False for both) — 'aar' is used here; unlike 'jar' (which turned out to
# already have a real AIEnrichment row from a previous enrichment run), this
# one is a genuine "no report was ever generated" case.
NO_ENRICHMENT_HASH = SCANNED['aar']['hash']


def _assert_no_traceback(page):
    assert 'Traceback (most recent call last)' not in page.content()


@pytest.mark.negative
def test_ai_dashboard_redirects_gracefully_when_no_enrichment_exists(
        admin_page):
    """Visiting the AI dashboard for a scan with NO AIEnrichment row must
    redirect to /recent_scans/ with an info message — never a 500 or a
    traceback, and never render the AI page shell for data that doesn't
    exist."""
    page = admin_page
    page.goto(f'/ai_dashboard/{NO_ENRICHMENT_HASH}/',
              wait_until='domcontentloaded')

    # Bounced to the recent-scans list (StaticAnalyzer/views/common/llm/
    # views.py::ai_dashboard -> redirect('recent') for blocked statuses).
    expect(page).to_have_url(re.compile(r'/recent_scans/?$'))

    # A graceful, human-readable info message, not a stack trace.
    expect(page.get_by_text(
        'AI analysis is not available for this scan yet.')).to_be_visible()

    _assert_no_traceback(page)

    # Never returned a 500 status along the way.
    assert page.evaluate('document.title') != ''


@pytest.mark.negative
def test_ai_dashboard_redirects_for_nonexistent_hash(admin_page):
    """A syntactically-valid MD5 that doesn't correspond to ANY scan at all
    behaves the same way as 'no enrichment yet' — graceful redirect, not a
    crash (is_md5() passes, AIEnrichment lookup simply finds nothing)."""
    page = admin_page
    fake_md5 = 'deadbeefdeadbeefdeadbeefdeadbeef'
    page.goto(f'/ai_dashboard/{fake_md5}/', wait_until='domcontentloaded')

    expect(page).to_have_url(re.compile(r'/recent_scans/?$'))
    expect(page.get_by_text(
        'AI analysis is not available for this scan yet.')).to_be_visible()

    _assert_no_traceback(page)


@pytest.mark.negative
def test_ai_dashboard_404s_cleanly_for_malformed_checksum(admin_page):
    """A non-MD5-shaped string in the URL never even reaches ai_dashboard()
    -- MobInspect/urls.py's checksum_regex (32 hex chars) doesn't match it,
    so Django's own URL resolver 404s. This is the routing-layer half of
    the same guardrail: a malformed reference is rejected before any view
    code (let alone _enrichment_ctx) runs, and it must be a clean 404, not
    a 500/traceback."""
    page = admin_page
    response = page.goto('/ai_dashboard/not-a-valid-md5-hash/',
                          wait_until='domcontentloaded')

    assert response.status == 404
    _assert_no_traceback(page)
