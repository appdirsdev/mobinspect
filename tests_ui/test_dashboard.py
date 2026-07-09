"""UI spec for the Home dashboard ('/').

Covers (per mobsf/templates/general/home.html):
  * the 4 animated metric tiles (Alpine `counter()`) — waits for the
    count-up animation to settle and cross-checks against the
    non-animated live chips rendered server-side in the hero
  * the upload dropzone (#upload_form / #uploadFile / "Choose file") is
    present and wired, WITHOUT ever submitting a real file
  * the 3 quick-action tiles (Recent scans / Dynamic analyzer / REST API)
    and their real hrefs
  * the "Recent activity" table: rows exist, are clickable, and navigate
    to a real report URL (then we navigate back — non-destructive)
  * the live inline chips ("total scan", "this week", "Android")

All tests run against the REAL running server / REAL data (no mocks).
Non-destructive: never fills #uploadFile, never submits #upload_form,
never deletes/creates scans.
"""
import re

from playwright.sync_api import expect

NUMBER_RE = re.compile(r'^\d+$')


def _tile_number(page, label_text, timeout_ms=6000):
    """Return the Playwright locator for a metric tile's animated number,
    scoped to the `.mi-stat` card whose label paragraph matches
    `label_text` exactly (avoids substring collisions between tiles like
    "Total scans" / "Scanned this week")."""
    label = page.get_by_text(label_text, exact=True)
    tile = page.locator('div.mi-stat').filter(has=label)
    expect(tile).to_have_count(1)
    # Tag-agnostic: the number sits in a <p> on most tiles but a <span>
    # inside a flex row on tiles that also show a delta pill (e.g. "Scanned
    # this week") — .mi-num identifies the element regardless of tag.
    return tile.locator('.mi-num')


def _wait_settled_int(locator, timeout_ms=6000):
    """Wait (via Playwright's native auto-retrying expect) for a `.mi-num`
    element's text to stop being empty/non-numeric — i.e. for Alpine's
    count-up animation to finish rendering a plain integer — then return
    that integer. Uses expect()'s polling rather than a fixed sleep."""
    expect(locator).to_have_text(NUMBER_RE, timeout=timeout_ms)
    return int(locator.inner_text().strip())


def test_dashboard_loads_without_error(admin_page):
    page = admin_page
    page.goto('/', wait_until='domcontentloaded')
    expect(page).to_have_title(re.compile('Dashboard'))
    expect(page.locator('text=Welcome back').first).to_be_visible()
    assert 'Traceback (most recent call last)' not in page.content()


def test_metric_tiles_animate_and_settle_to_real_numbers(admin_page):
    """The 4 stat tiles (Total scans / Android apps / iOS apps / Scanned
    this week) are driven by Alpine's `counter()` count-up. Wait for each
    to settle to a plain integer, then cross-validate against the
    non-animated live chips in the hero (real server-rendered counts —
    no fabricated expectations)."""
    page = admin_page
    page.goto('/', wait_until='domcontentloaded')

    # Ground truth: the hero chips render {{ stats.* }} directly (no JS
    # animation), so they are stable the instant the page paints.
    total_chip = page.locator('span.badge', has_text='total scan')
    week_chip = page.locator('span.badge', has_text='this week')
    android_chip = page.locator('span.badge', has_text='Android')
    expect(total_chip).to_be_visible()
    expect(week_chip).to_be_visible()
    expect(android_chip).to_be_visible()

    total_expected = int(re.search(r'\d+', total_chip.inner_text()).group())
    week_expected = int(re.search(r'\d+', week_chip.inner_text()).group())
    android_expected = int(re.search(r'\d+', android_chip.inner_text()).group())

    # The iOS chip is conditionally omitted from the DOM when stats.ios is
    # falsy ({% if stats.ios %}) — its absence itself tells us the real
    # expected count is 0.
    ios_chip = page.locator('span.badge', has_text='iOS')
    ios_expected = int(re.search(r'\d+', ios_chip.inner_text()).group()) \
        if ios_chip.count() else 0

    # Each animated tile must settle to EXACTLY the real, live count —
    # expect() polls (auto-wait) until the Alpine count-up finishes rather
    # than sleeping a fixed duration.
    total_num = _tile_number(page, 'Total scans')
    android_num = _tile_number(page, 'Android apps')
    ios_num = _tile_number(page, 'iOS apps')
    week_num = _tile_number(page, 'Scanned this week')

    expect(total_num).to_have_text(str(total_expected), timeout=6000)
    expect(android_num).to_have_text(str(android_expected), timeout=6000)
    expect(ios_num).to_have_text(str(ios_expected), timeout=6000)
    expect(week_num).to_have_text(str(week_expected), timeout=6000)

    # Belt-and-suspenders: re-read and assert numeric parseability +
    # real-world invariants (never fabricated, always derived from the
    # live counts we just captured).
    total_val = _wait_settled_int(total_num)
    android_val = _wait_settled_int(android_num)
    ios_val = _wait_settled_int(ios_num)
    week_val = _wait_settled_int(week_num)

    assert total_val == total_expected
    assert android_val == android_expected
    assert ios_val == ios_expected
    assert week_val == week_expected
    # Sanity invariants on real data.
    assert total_val >= 0 and android_val >= 0 and ios_val >= 0 and week_val >= 0
    assert android_val + ios_val <= total_val
    assert week_val <= total_val


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
    # Accepts the documented mobile-binary extensions.
    accept = file_input.get_attribute('accept')
    assert accept is not None
    for ext in ('.apk', '.ipa', '.zip'):
        assert ext in accept

    # CSRF token must be present for the XHR upload() JS to work later.
    csrf = form.locator('input[name="csrfmiddlewaretoken"]')
    expect(csrf).to_be_attached()

    # The "Choose file" trigger button is visible (label wraps the hidden
    # input; clicking it would open the native OS file picker, so we only
    # assert visibility/text, never click it).
    choose_btn = page.locator('label[for="uploadFile"] >> text=Choose file')
    expect(choose_btn).to_be_visible()

    # No file has been picked / no upload in-flight.
    assert file_input.evaluate('el => el.files.length') == 0
    assert 'Traceback (most recent call last)' not in page.content()


def test_quick_action_tiles_link_to_correct_pages(admin_page):
    """The 3 gradient quick-action tiles point at the real routes."""
    page = admin_page
    page.goto('/', wait_until='domcontentloaded')

    actions = page.locator('a.mi-action')
    expect(actions).to_have_count(3)

    recent_tile = actions.filter(has_text='Recent scans')
    dynamic_tile = actions.filter(has_text='Dynamic analyzer')
    api_tile = actions.filter(has_text='REST API')

    expect(recent_tile).to_have_count(1)
    expect(dynamic_tile).to_have_count(1)
    expect(api_tile).to_have_count(1)

    expect(recent_tile).to_have_attribute('href', '/recent_scans/')
    expect(dynamic_tile).to_have_attribute('href', '/dynamic_analysis/')
    expect(api_tile).to_have_attribute('href', '/api_docs')

    # Descriptive copy renders too (not just bare links).
    expect(recent_tile.locator('text=Browse and re-open your scan history.')).to_be_visible()
    expect(dynamic_tile.locator('text=Run a runtime scan on a connected device.')).to_be_visible()
    expect(api_tile.locator('text=Reference for CI/CD integrations.')).to_be_visible()


def test_recent_scans_shortcut_navigates(admin_page):
    """Clicking the 'Recent scans' quick-action tile actually navigates to
    the recent-scans list (real route, not just an href assertion)."""
    page = admin_page
    page.goto('/', wait_until='domcontentloaded')

    recent_tile = page.locator('a.mi-action').filter(has_text='Recent scans')
    expect(recent_tile).to_be_visible()
    recent_tile.click()
    page.wait_for_url(re.compile(r'/recent_scans/'), timeout=10000)
    assert 'Traceback (most recent call last)' not in page.content()

    page.go_back(wait_until='domcontentloaded')
    expect(page).to_have_url(re.compile(r'/$'))


def test_recent_activity_table_rows_present(admin_page):
    """The 'Recent activity' table (real scans, no fabricated rows) lists
    application / identifier / type / scanned-ago columns."""
    page = admin_page
    page.goto('/', wait_until='domcontentloaded')

    section = page.locator('section', has=page.get_by_role('heading', name='Recent activity'))
    expect(section).to_be_visible()

    # Header columns are the real ones from the template.
    header = section.locator('thead tr')
    expect(header.locator('th', has_text='Application')).to_be_visible()
    expect(header.locator('th', has_text='Identifier')).to_be_visible()
    expect(header.locator('th', has_text='Type')).to_be_visible()
    expect(header.locator('th', has_text='Scanned')).to_be_visible()

    rows = section.locator('tbody tr')
    row_count = rows.count()
    assert row_count > 0, (
        'Recent activity section rendered but has no rows — the {% if '
        'recent %} block should have hidden the whole section in that case'
    )

    first_row = rows.first
    expect(first_row).to_be_visible()
    # Row is clickable (onclick navigation) — verify the affordance and the
    # real per-row report link both point at a valid /<analyzer>/<md5>/ URL.
    onclick = first_row.get_attribute('onclick')
    assert onclick is not None and "window.location.href='/" in onclick

    app_link = first_row.locator('a').first
    href = app_link.get_attribute('href')
    assert href is not None
    assert re.match(r'^/[a-zA-Z_]+/[0-9a-fA-F]{32}/$', href), (
        f'unexpected report link shape: {href}'
    )

    # 'View all' link goes to the full recent-scans page.
    view_all = section.get_by_text('View all')
    expect(view_all).to_have_attribute('href', '/recent_scans/')


def test_recent_activity_row_click_navigates_to_report_and_back(admin_page):
    """Clicking a real recent-activity row navigates to that scan's report
    URL (an actual existing report — non-destructive, no rescan/delete),
    then we return to the dashboard."""
    page = admin_page
    page.goto('/', wait_until='domcontentloaded')

    section = page.locator('section', has=page.get_by_role('heading', name='Recent activity'))
    rows = section.locator('tbody tr')
    assert rows.count() > 0, 'no recent scans available to exercise row-click navigation'

    first_row = rows.first
    expected_href = first_row.locator('a').first.get_attribute('href')
    assert expected_href is not None

    first_row.click()
    page.wait_for_url(re.compile(re.escape(expected_href)), timeout=10000)
    assert expected_href in page.url
    # Report page rendered for real (no server error), even though we don't
    # assert on report-specific content here (out of scope for this spec).
    assert 'Traceback (most recent call last)' not in page.content()

    page.go_back(wait_until='domcontentloaded')
    expect(page).to_have_url(re.compile(r'/$'))
    expect(page.locator('text=Welcome back').first).to_be_visible()


def test_live_chips_present_with_real_counts(admin_page):
    """The hero's live inline chips ('total scan', 'this week', 'Android')
    render real, non-negative integer counts."""
    page = admin_page
    page.goto('/', wait_until='domcontentloaded')

    total_chip = page.locator('span.badge', has_text='total scan')
    week_chip = page.locator('span.badge', has_text='this week')
    android_chip = page.locator('span.badge', has_text='Android')

    for chip in (total_chip, week_chip, android_chip):
        expect(chip).to_be_visible()
        text = chip.inner_text()
        match = re.search(r'\d+', text)
        assert match is not None, f'chip has no numeric count: {text!r}'
        assert int(match.group()) >= 0

    # "Total scans" wording is singular/plural correctly via {{ pluralize }}.
    # (Badges are CSS text-transform: uppercase, so compare case-insensitively
    # — inner_text() reflects the rendered/visual casing, not the DOM text.)
    total_text = total_chip.inner_text().lower()
    assert 'total scan' in total_text
    if total_text.strip().startswith('1 '):
        assert 'total scans' not in total_text
    else:
        assert 'total scans' in total_text

    assert 'Traceback (most recent call last)' not in page.content()


def test_quick_actions_and_upload_form_have_no_server_error_after_render(admin_page):
    """Full-page regression guard: nothing on the dashboard leaks a
    Traceback, and the upload/dropzone + quick actions + tiles all render
    together without console-visible Django errors."""
    page = admin_page
    page.goto('/', wait_until='domcontentloaded')

    expect(page.locator('#upload_form')).to_be_attached()
    expect(page.locator('a.mi-action')).to_have_count(3)
    expect(page.locator('div.mi-stat')).to_have_count(4)
    content = page.content()
    assert 'Traceback (most recent call last)' not in content
    assert 'Internal Server Error' not in content
