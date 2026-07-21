"""Playwright UI spec — static-analysis report pages for a scanned APK (md5).

Covers three pages for the same pre-scanned Android app (MD5 below):

  * GET /static_analyzer/<md5>/   — the Android binary report renders app
    identity + security score + every major section header, the in-page
    "Contents" quick-jump nav (Alpine modal + anchor pills) actually
    navigates to the target section, and the permission/manifest findings
    tables render real, populated rows (not just column headers).
  * GET /appsec_dashboard/<md5>/  — the security-score ring settles at a
    real numeric value, the severity-breakdown donut + quick-nav counts
    render, and an individual finding row expands on click.
  * GET /ai_dashboard/<md5>/      — the admin-only AI dashboard renders and
    the AI-generated content carries the mandatory "AI-generated ·
    unverified" watermark (untrusted-content guardrail).

NON-DESTRUCTIVE: every test is read-only navigation/clicks. No rescan, no
delete, no file upload — the harness's pre-existing scan MD5 is reused as-is.

Fixture is Diva (test_files/android.apk) — deliberately NOT one of the large
real-world samples (e.g. TikTok/CapCut XAPKs), whose full decompile output
runs into multiple GB on disk; Diva is small, has a real (non-trivial)
manifest/permissions surface, a low security score (plenty of findings to
assert against), and already has AI enrichment run for the AI Dashboard
tests below.
"""
import re

import pytest
from playwright.sync_api import expect

MD5 = '82ab8b2193b3cfb1c737e3a786be363a'


def _assert_no_traceback(page):
    assert 'Traceback (most recent call last)' not in page.content()


# ══════════════════════ /static_analyzer/<md5>/ ══════════════════════


def test_android_report_renders_core_sections(admin_page):
    """The Android static-analysis report renders app identity, a real
    security-score badge, and every major section header — not just a
    template shell."""
    admin_page.goto(f'/static_analyzer/{MD5}/', wait_until='domcontentloaded')

    # App identity in the ambient hero header
    heading = admin_page.locator('h1').first
    expect(heading).to_be_visible()
    expect(heading).to_contain_text('Diva')
    expect(admin_page.get_by_text(MD5).first).to_be_visible()

    # "App scores" card carries the semicircle gauge (components/gauge_semi.html
    # — same component used on Home/Analytics/Scorecard for a consistent look)
    # with a real 0-100 security score, and the readout sits inside the gauge's
    # own SVG bounds (regression guard: an earlier arc-gauge version made the
    # number look cramped/overlapping against the ring at this card width).
    scores_card = admin_page.locator('.card', has_text='App scores').first
    expect(scores_card).to_be_visible()
    expect(scores_card).to_contain_text('Security score')
    gauge = scores_card.locator('.mi-semi')
    expect(gauge).to_be_visible()
    gauge_value = gauge.locator('.mi-semi-num')
    expect(gauge_value).to_be_visible()
    expect(gauge_value).to_have_text(re.compile(r'^\d{1,3}$'))
    expect(gauge.get_by_text('/ 100')).to_be_visible()
    svg_box = gauge.locator('svg').bounding_box()
    num_box = gauge_value.bounding_box()
    assert svg_box and num_box
    assert num_box['x'] >= svg_box['x'] - 2
    assert num_box['x'] + num_box['width'] <= svg_box['x'] + svg_box['width'] + 2

    # Every major section header is present with its real anchor id
    for section_id, heading_text in [
        ('permissions', 'Application permissions'),
        ('manifest', 'Manifest analysis'),
        ('code_analysis', 'Code analysis'),
        ('binary_analysis', 'Shared library binary analysis'),
        ('certificate', 'Signer certificate'),
    ]:
        section = admin_page.locator(f'#{section_id}')
        expect(section).to_be_attached()
        expect(section.locator('h2')).to_contain_text(heading_text)

    _assert_no_traceback(admin_page)


def test_android_report_toc_nav_jumps_to_target_section(admin_page):
    """The in-page 'Contents' modal is real navigation: opening it shows the
    quick-jump pills, and clicking one closes the modal, updates the URL
    fragment and scrolls the matching section into view."""
    admin_page.goto(f'/static_analyzer/{MD5}/', wait_until='domcontentloaded')

    contents_btn = admin_page.get_by_role('button', name=re.compile('Contents'))
    expect(contents_btn).to_be_visible()
    contents_btn.click()

    permissions_pill = admin_page.locator('a.mi-toc-pill[href="#permissions"]')
    expect(permissions_pill).to_be_visible()
    expect(permissions_pill).to_contain_text('App permissions')

    permissions_pill.click()

    # Modal (and its pill) closes after navigating away
    expect(permissions_pill).to_be_hidden()
    # URL now carries the section anchor and that section is scrolled into view
    expect(admin_page).to_have_url(re.compile(r'#permissions$'))
    expect(admin_page.locator('#permissions')).to_be_in_viewport()
    expect(admin_page.locator('#permissions h2')).to_contain_text(
        'Application permissions')

    _assert_no_traceback(admin_page)


def test_android_report_findings_tables_render(admin_page):
    """Permission + manifest findings tables render real, populated rows
    with the expected columns (not empty tables)."""
    admin_page.goto(f'/static_analyzer/{MD5}/', wait_until='domcontentloaded')

    perm_table = admin_page.locator('#table_permissions')
    expect(perm_table).to_be_visible()
    expect(perm_table.locator('thead')).to_contain_text('Permission')
    expect(perm_table.locator('thead')).to_contain_text('Status')
    perm_rows = perm_table.locator('tbody tr')
    expect(perm_rows.first).to_be_visible()
    # Diva's manifest declares exactly 3 permissions (WRITE/READ_EXTERNAL_
    # STORAGE + INTERNET) — confirmed via /api/v1/report_json against two
    # independent MobInspect instances, so this is the real, stable count
    # for this fixture, not an environment fluke.
    assert perm_rows.count() >= 3, (
        f'expected >= 3 permission rows, got {perm_rows.count()}')
    # A real dangerous-permission badge is rendered somewhere in the table
    expect(perm_table.get_by_text(re.compile(
        r'dangerous|normal|signature', re.I)).first).to_be_visible()

    manifest_table = admin_page.locator('#table_manifest')
    expect(manifest_table).to_be_visible()
    expect(manifest_table.locator('thead')).to_contain_text('Issue')
    expect(manifest_table.locator('thead')).to_contain_text('Severity')
    manifest_rows = manifest_table.locator('tbody tr')
    expect(manifest_rows.first).to_be_visible()
    assert manifest_rows.count() > 5, (
        f'expected many manifest finding rows, got {manifest_rows.count()}')

    _assert_no_traceback(admin_page)


# ══════════════════════ /appsec_dashboard/<md5>/ ══════════════════════


def test_appsec_dashboard_score_and_severity_render(admin_page):
    """AppSec scorecard (redesigned): the thick semicircle score gauge shows a
    real 0-100 value with its risk-grade strip, the severity donut renders,
    the security-posture radar + risk-by-area bars render, and the findings
    quick-nav carries real counts."""
    admin_page.emulate_media(reduced_motion='reduce')
    admin_page.goto(f'/appsec_dashboard/{MD5}/', wait_until='domcontentloaded')

    expect(admin_page.locator('h1').first).to_contain_text('Diva')

    # Score card: the security-score gauge readout is a real 0-100 number.
    score_card = admin_page.locator('div.card', has_text='Security score').first
    expect(score_card).to_be_visible()
    score_num = score_card.locator('.mi-semi-num')
    expect(score_num).to_be_visible()
    score_val = int(re.sub(r'\D', '', score_num.inner_text()))
    assert 0 <= score_val <= 100

    # Risk-grade strip (A/B/C/F) — the active grade sits in the same card.
    grade = score_card.locator('.mi-grade-active')
    expect(grade).to_be_visible()
    expect(grade).to_have_text(re.compile(r'^[ABCF]$'))

    # Severity donut + the two advanced charts (posture radar, risk-by-area).
    expect(admin_page.locator('#severity_chart')).to_be_visible()
    expect(admin_page.locator('#posture_radar')).to_be_visible()
    expect(admin_page.locator('#dimension_bars')).to_be_visible()

    # Quick-nav severity badges carry real counts (findings breakdown).
    quicknav = admin_page.locator('nav.mi-quicknav')
    expect(quicknav).to_be_visible()
    for label in ('High', 'Medium', 'Info', 'Secure'):
        expect(quicknav).to_contain_text(label)

    _assert_no_traceback(admin_page)


def test_appsec_dashboard_finding_expands_on_click(admin_page):
    """A findings-breakdown row is a real disclosure widget: clicking its
    toggle flips aria-expanded and reveals the detail pane."""
    admin_page.emulate_media(reduced_motion='reduce')
    admin_page.goto(f'/appsec_dashboard/{MD5}/', wait_until='domcontentloaded')

    # NOTE: the HIGH severity bucket's internal level token is "critical"
    # (see appsec_dashboard.html's include of _finding_group.html), so its
    # toggle/panel ids are "finding-toggle-critical-N" / "finding-panel-critical-N".
    first_toggle = admin_page.locator('[id^="finding-toggle-critical-"]').first
    expect(first_toggle).to_be_visible()
    expect(first_toggle).to_have_attribute('aria-expanded', 'false')

    panel_id = first_toggle.get_attribute('aria-controls')
    panel = admin_page.locator(f'#{panel_id}')
    expect(panel).to_be_hidden()

    first_toggle.click()

    expect(first_toggle).to_have_attribute('aria-expanded', 'true')
    expect(panel).to_be_visible()
    expect(panel.locator('pre')).to_be_visible()

    _assert_no_traceback(admin_page)


# ══════════════════════ /ai_dashboard/<md5>/ ══════════════════════


def test_ai_dashboard_renders_for_admin_with_watermark(admin_page):
    """Admin can view the AI Dashboard for this scan, and every AI-generated
    block is visibly watermarked 'AI-generated · unverified' — the
    untrusted-content guardrail must never be silently dropped."""
    admin_page.goto(f'/ai_dashboard/{MD5}/', wait_until='domcontentloaded')

    expect(admin_page.locator('h1')).to_have_text('AI Dashboard')
    expect(admin_page.get_by_text(MD5).first).to_be_visible()

    # Standalone AI Security Analysis section actually rendered (not the
    # 'disabled' / 'invalid' empty state)
    ai_section = admin_page.locator('#ai-analysis')
    expect(ai_section).to_be_visible()
    expect(ai_section).to_contain_text('AI Security Analysis')
    expect(admin_page.get_by_text('AI analysis is not enabled')).to_have_count(0)
    expect(admin_page.get_by_text('Invalid scan reference')).to_have_count(0)

    # Mandatory AI-generated watermark is present and visible
    watermark = admin_page.get_by_text('AI-generated · unverified')
    expect(watermark.first).to_be_visible()
    assert watermark.count() >= 1

    # Back-to-report link points at the same scan
    back_link = admin_page.get_by_role('link', name=re.compile('Back to report'))
    expect(back_link).to_be_visible()
    expect(back_link).to_have_attribute('href', f'/static_analyzer/{MD5}/')

    _assert_no_traceback(admin_page)


# ═══════ additional AI-dashboard coverage (new tests only — see module note
# in the task brief: other report sections here are owned by another spec
# author working concurrently; the existing
# test_ai_dashboard_renders_for_admin_with_watermark above is untouched) ════

@pytest.mark.positive
def test_ai_dashboard_shows_real_generated_findings_content(admin_page):
    """The AI dashboard for Diva doesn't just render a shell — the real,
    already-generated model output is on the page: the executive-summary
    prose and the findings list both surface real, specific content (debug
    certificate signing, unprotected exported components, a hardcoded
    secret) pulled straight from AIEnrichment.FINDING_EXPLANATIONS /
    EXEC_SUMMARY for this scan, not placeholder text. Every AI-generated
    section (executive summary card + findings section) carries its own
    'AI-generated · unverified' watermark badge — the guardrail is not a
    single one-off label but repeated per AI-content section."""
    admin_page.goto(f'/ai_dashboard/{MD5}/', wait_until='domcontentloaded')

    ai_section = admin_page.locator('#ai-analysis')
    expect(ai_section).to_be_visible()

    # Real, specific content from the actual generated report for this scan
    # (verified directly against AIEnrichment.FINDING_EXPLANATIONS this
    # session) — not generic filler text.
    page_text = admin_page.locator('body').inner_text()
    for expected in (
        'Debug Certificate',
        'Unprotected Exported Components',
        'Hardcoded Secret',
    ):
        assert expected in page_text, (
            f'expected real AI finding text {expected!r} on the AI dashboard')

    # The model name used to generate this content is surfaced too.
    expect(admin_page.get_by_text('granite4.1:8b').first).to_be_visible()

    # At least two independent AI-generated sections (executive summary +
    # findings) each carry their own watermark badge, not just one global
    # disclaimer for the whole page.
    watermark = admin_page.get_by_text('AI-generated · unverified')
    assert watermark.count() >= 2, (
        f'expected >= 2 per-section AI watermarks, got {watermark.count()}')
    for i in range(watermark.count()):
        expect(watermark.nth(i)).to_be_visible()

    _assert_no_traceback(admin_page)
