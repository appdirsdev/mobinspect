"""UI spec for the Home dashboard ('/').

Covers the CyberGuard-mirror redesign (per mobsf/templates/general/home.html):
  * the upload dropzone (#upload_form / #uploadFile / "Choose file") is
    present and wired, WITHOUT ever submitting a real file
  * the 5-tile KPI strip (Total scans / Findings / Avg score / This week /
    Apps tracked) — the Alpine `counter()` count-up settles to the real
    server-rendered numbers
  * the command row: the two chart canvases (scan activity / volume) and the
    semicircle fleet-coverage gauge
  * the "Recent scans" table: real rows, clickable, navigating to a real
    report URL (then back — non-destructive)

All tests run against the REAL running server / REAL data (no mocks).
Non-destructive: never fills #uploadFile, never submits #upload_form,
never deletes/creates scans.
"""
import os
import re

from playwright.sync_api import expect

NUMBER_RE = re.compile(r'^\d+$')

BASE = os.environ.get('MOBINSPECT_UI_BASE', 'http://127.0.0.1:8000').rstrip('/')
USER = os.environ.get('MOBINSPECT_ADMIN_USERNAME', 'admin')
PWD = os.environ.get('MOBINSPECT_ADMIN_PASSWORD', 'admin')


def _tile_number(page, label_text):
    """Return the locator for a KPI tile's number, scoped to the `.mi-stat`
    card whose label matches `label_text` exactly (avoids collisions)."""
    label = page.get_by_text(label_text, exact=True)
    tile = page.locator('div.mi-stat').filter(has=label)
    expect(tile).to_have_count(1)
    return tile.locator('.mi-num')


def test_dashboard_loads_without_error(admin_page):
    page = admin_page
    page.goto('/', wait_until='domcontentloaded')
    expect(page).to_have_title(re.compile('Dashboard'))
    # The hero greeting shows "Welcome back" right after login, or a local
    # security tip on any later visit in the same session (see
    # test_greeting_shows_once_then_security_tip below for that behavior) —
    # this is a smoke check, so it only asserts SOME greeting rendered.
    expect(page.locator('#mi-hero-greeting')).to_be_visible()
    assert 'Traceback (most recent call last)' not in page.content()


def test_kpi_strip_shows_five_tiles_with_real_numbers(admin_page):
    """The KPI strip is 5 real-metric tiles. The four count-up tiles (Total
    scans / Findings / This week / Apps tracked) settle to plain integers;
    Avg score shows either a number or an em-dash (no scored apps yet). All
    values are real and satisfy basic invariants — never fabricated."""
    page = admin_page
    page.goto('/', wait_until='domcontentloaded')

    expect(page.locator('div.mi-stat')).to_have_count(5)

    total_num = _tile_number(page, 'Total scans')
    issues_num = _tile_number(page, 'Issues')
    week_num = _tile_number(page, 'This week')
    apps_num = _tile_number(page, 'Apps tracked')

    for loc in (total_num, issues_num, week_num, apps_num):
        expect(loc).to_have_text(NUMBER_RE, timeout=6000)

    # The tiles animate 0 -> N via Alpine counter() (~900ms). to_have_text
    # above matches the initial "0" too, so wait for the count-up to settle
    # before reading, otherwise cross-tile invariants can race mid-animation.
    page.wait_for_timeout(1100)

    total_val = int(total_num.inner_text().strip())
    issues_val = int(issues_num.inner_text().strip())
    week_val = int(week_num.inner_text().strip())
    apps_val = int(apps_num.inner_text().strip())

    # Real-data invariants (all derived from the same RecentScansDB).
    assert total_val >= 0 and issues_val >= 0 and week_val >= 0 and apps_val >= 0
    assert week_val <= total_val
    assert apps_val <= total_val

    # Avg score tile: a number in 0..100, or an em-dash when nothing scored.
    avg_num = _tile_number(page, 'Avg score')
    avg_txt = avg_num.inner_text().strip()
    if avg_txt != '—':
        assert NUMBER_RE.match(avg_txt), f'avg score not an int: {avg_txt!r}'
        assert 0 <= int(avg_txt) <= 100

    assert 'Traceback (most recent call last)' not in page.content()


def test_upload_dropzone_present_not_submitted(admin_page):
    """The upload form/dropzone renders and is wired correctly, but this
    test NEVER selects a file or submits — purely presence/attribute
    assertions (non-destructive)."""
    page = admin_page
    page.goto('/', wait_until='domcontentloaded')

    form = page.locator('#upload_form')
    expect(form).to_be_attached()
    expect(form).to_have_attribute('method', 'post')
    expect(form).to_have_attribute('enctype', 'multipart/form-data')

    file_input = page.locator('#uploadFile')
    expect(file_input).to_be_attached()
    expect(file_input).to_have_attribute('type', 'file')
    expect(file_input).to_have_attribute('name', 'file')
    accept = file_input.get_attribute('accept')
    assert accept is not None
    for ext in ('.apk', '.ipa', '.zip'):
        assert ext in accept

    csrf = form.locator('input[name="csrfmiddlewaretoken"]')
    expect(csrf).to_be_attached()

    choose_btn = page.locator('label[for="uploadFile"] >> text=Choose file')
    expect(choose_btn).to_be_visible()

    assert file_input.evaluate('el => el.files.length') == 0
    assert 'Traceback (most recent call last)' not in page.content()


def test_command_row_charts_and_gauge_render(admin_page):
    """The command row's two chart canvases and the semicircle fleet-coverage
    gauge all render (real data drives them; with zero scans the cards show
    honest empty states instead, which this test tolerates)."""
    page = admin_page
    # networkidle so the deferred Chart.umd + chart-theme + init have run.
    page.goto('/', wait_until='networkidle')

    total_num = _tile_number(page, 'Total scans')
    expect(total_num).to_have_text(NUMBER_RE, timeout=6000)
    has_scans = int(total_num.inner_text().strip()) > 0

    if has_scans:
        # Chart.js canvases are attached and have been given a real pixel
        # size by Chart.js (poll bounding_box rather than assert instant
        # visibility, since sizing happens just after init).
        for cid in ('#breakdown_chart', '#volume_chart'):
            canvas = page.locator(cid)
            expect(canvas).to_be_attached()
            page.wait_for_function(
                'id => { const c = document.querySelector(id);'
                ' return c && c.getBoundingClientRect().width > 10'
                ' && c.getBoundingClientRect().height > 10; }',
                arg=cid, timeout=6000)
        # The semicircle gauge SVG renders with its readout number.
        gauge = page.locator('.mi-semi')
        expect(gauge).to_be_visible()
        expect(gauge.locator('.mi-semi-num')).to_be_visible()
    else:
        # Honest empty states, no charts.
        expect(page.get_by_text('Scan activity will chart here.')).to_be_visible()

    assert 'Traceback (most recent call last)' not in page.content()


def test_recent_scans_button_navigates(admin_page):
    """The hero's 'Recent scans' button navigates to the recent-scans list
    (real route, not just an href assertion)."""
    page = admin_page
    page.goto('/', wait_until='domcontentloaded')

    btn = page.locator('a', has_text='Recent scans').first
    expect(btn).to_be_visible()
    btn.click()
    page.wait_for_url(re.compile(r'/recent_scans/'), timeout=10000)
    assert 'Traceback (most recent call last)' not in page.content()

    page.go_back(wait_until='domcontentloaded')
    expect(page).to_have_url(re.compile(r'/$'))


def test_recent_scans_table_rows_present(admin_page):
    """The 'Recent scans' table (real scans, no fabricated rows) lists
    application / type / score / scanned columns and links to real reports.
    When there are no scans the section shows an honest empty state."""
    page = admin_page
    page.goto('/', wait_until='domcontentloaded')

    section = page.locator(
        'section', has=page.get_by_role('heading', name='Recent scans'))
    expect(section).to_be_visible()

    rows = section.locator('tbody tr')
    if rows.count() == 0:
        expect(section.get_by_text('Your scans will appear here.', exact=False)).to_be_visible()
        return

    header = section.locator('thead tr')
    expect(header.locator('th', has_text='Application')).to_be_visible()
    expect(header.locator('th', has_text='Type')).to_be_visible()
    expect(header.locator('th', has_text='Score')).to_be_visible()
    expect(header.locator('th', has_text='Scanned')).to_be_visible()

    first_row = rows.first
    expect(first_row).to_be_visible()
    onclick = first_row.get_attribute('onclick')
    assert onclick is not None and "window.location.href='/" in onclick

    app_link = first_row.locator('a').first
    href = app_link.get_attribute('href')
    assert href is not None
    assert re.match(r'^/[a-zA-Z_]+/[0-9a-fA-F]{32}/$', href), (
        f'unexpected report link shape: {href}')

    view_all = section.get_by_text('View all')
    expect(view_all).to_have_attribute('href', '/recent_scans/')


def test_recent_scan_row_click_navigates_to_report_and_back(admin_page):
    """Clicking a real recent-scan row navigates to that scan's report URL
    (an actual existing report — non-destructive), then returns home. Skips
    cleanly when the DB has no scans."""
    page = admin_page
    page.goto('/', wait_until='domcontentloaded')

    section = page.locator(
        'section', has=page.get_by_role('heading', name='Recent scans'))
    rows = section.locator('tbody tr')
    if rows.count() == 0:
        return  # no scans to exercise — honest empty state, nothing to click

    first_row = rows.first
    expected_href = first_row.locator('a').first.get_attribute('href')
    assert expected_href is not None

    first_row.click()
    page.wait_for_url(re.compile(re.escape(expected_href)), timeout=10000)
    assert expected_href in page.url
    assert 'Traceback (most recent call last)' not in page.content()

    page.go_back(wait_until='domcontentloaded')
    expect(page).to_have_url(re.compile(r'/$'))
    expect(page.locator('#mi-hero-greeting')).to_be_visible()


def test_dashboard_has_no_server_error_after_render(admin_page):
    """Full-page regression guard: the redesigned dashboard renders the
    upload form + 5 KPI tiles together with no leaked Django error."""
    page = admin_page
    page.goto('/', wait_until='domcontentloaded')

    expect(page.locator('#upload_form')).to_be_attached()
    expect(page.locator('div.mi-stat')).to_have_count(5)
    content = page.content()
    assert 'Traceback (most recent call last)' not in content
    assert 'Internal Server Error' not in content


def test_greeting_shows_once_then_security_tip(browser):
    """A FRESH login (own browser context, not the shared session-scoped
    admin_page) must show "Welcome back" on the very first dashboard view,
    then a local security tip on every later visit in that same session."""
    ctx = browser.new_context(base_url=BASE)
    page = ctx.new_page()
    page.goto(f'{BASE}/login/', wait_until='domcontentloaded')
    page.fill('#id_username', USER)
    page.fill('#id_password', PWD)
    page.click('button[type=submit]')
    page.wait_for_url(lambda u: '/login' not in u, timeout=20000)

    # First view after login: the welcome message.
    expect(page.locator('#mi-hero-greeting')).to_contain_text('Welcome back')

    # Any later visit in the same session: a security tip, not the welcome
    # message — and it must not be empty (proves it's real local content,
    # not a blank/broken fallback).
    page.reload(wait_until='domcontentloaded')
    greeting = page.locator('#mi-hero-greeting')
    expect(greeting).to_be_visible()
    expect(greeting).not_to_contain_text('Welcome back')
    tip_text = greeting.inner_text().strip()
    assert len(tip_text) > 20

    ctx.close()
