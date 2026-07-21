"""UI spec for the Analytics dashboard ('/analytics/').

Covers: KPI/metric tiles (Alpine `counter()` widgets settle to a real
number), Chart.js canvases render with non-zero size (trend line,
platform doughnut, severity doughnut), the platform legend and severity
findings buckets render real data, and hovering charts/buckets never
throws or leaks a Django traceback into the page.

Non-destructive: read-only navigation + hover only. No forms submitted,
no scans created/deleted, no RBAC objects touched.
"""
import json
import re
import time

import pytest
from playwright.sync_api import expect

TRACEBACK = 'Traceback (most recent call last)'

# Every KPI tile's rendered value ultimately lives in a
# `<span x-text="shown">` (Alpine `counter()` widget), whether x-data sits
# on the span itself (iOS / Windows) or on an ancestor wrapper (everything
# else). Scoping to this attribute lets one helper cover every tile.
COUNTER_VALUE_SELECTOR = '[x-text="shown"]'

NUMERIC_RE = re.compile(r'^-?\d+(\.\d+)?$')


def _settled_text(locator, timeout_ms=3000, interval_ms=100):
    """Poll a locator's text until two consecutive reads agree (or timeout).

    The KPI tiles use an Alpine `counter()` that animates from 0 to the
    target value over a fixed 900ms via requestAnimationFrame. Polling for
    two identical reads in a row is a deterministic way to know the
    count-up animation has finished, rather than guessing a sleep length.
    """
    deadline = time.monotonic() + timeout_ms / 1000
    last = locator.inner_text().strip()
    while time.monotonic() < deadline:
        time.sleep(interval_ms / 1000)
        current = locator.inner_text().strip()
        if current == last:
            return current
        last = current
    return last


def _assert_numeric(text, label):
    assert NUMERIC_RE.match(text.strip()), f'{label!r} tile value not numeric: {text!r}'


def _kpi_tile(page, label):
    """The .mi-stat card whose visible label text matches `label`."""
    return page.locator('div.mi-stat', has_text=label).first


def _goto_analytics(page):
    page.goto('/analytics/', wait_until='domcontentloaded')
    expect(page.locator('h1', has_text='Analytics')).to_be_visible()
    return page


def _assert_no_traceback(page):
    assert TRACEBACK not in page.content()


@pytest.mark.positive
def test_analytics_page_loads_without_traceback(admin_page):
    page = admin_page
    _goto_analytics(page)
    # Ambient header hallmarks from dashboard.html
    expect(page.locator('text=Fleet intelligence').first).to_be_visible()
    expect(page.locator('a', has_text='View all scans')).to_be_visible()
    _assert_no_traceback(page)


@pytest.mark.positive
def test_kpi_strip_shows_five_tiles_with_settled_numbers(admin_page):
    """The redesigned KPI strip is one row of 5 real-metric tiles (matching
    the home dashboard): Total scans / This week / Avg score / Issues /
    Fleet health. Each count-up settles to a real number; Fleet health
    carries a trailing % and one decimal; Avg score shows a number (white,
    with a tier pill) or the '—' placeholder when nothing is scored yet."""
    page = admin_page
    _goto_analytics(page)

    expect(page.locator('div.mi-stat')).to_have_count(5)

    for label in ('Total scans', 'This week', 'Issues'):
        tile = _kpi_tile(page, label)
        expect(tile).to_be_visible()
        val = _settled_text(tile.locator('.mi-num').first)
        _assert_numeric(val, label)

    # Fleet health renders "<n.n>%" — strip the unit before the numeric check.
    fleet_tile = _kpi_tile(page, 'Fleet health')
    expect(fleet_tile).to_be_visible()
    fleet_val = _settled_text(fleet_tile.locator('.mi-num').first).rstrip('%').strip()
    _assert_numeric(fleet_val, 'Fleet health')

    # Avg score: a plain number (not a counter widget) or the em-dash.
    score_tile = _kpi_tile(page, 'Avg score')
    expect(score_tile).to_be_visible()
    score_text = score_tile.locator('.mi-num').first.inner_text().strip()
    if score_text != '—':
        _assert_numeric(score_text, 'Avg score')

    _assert_no_traceback(page)


@pytest.mark.positive
def test_charts_render_as_visible_sized_canvases(admin_page):
    """Trend / platform / severity Chart.js canvases are attached, visible
    and laid out with non-zero pixel size (i.e. actually rendered, not
    just present in the DOM)."""
    page = admin_page
    _goto_analytics(page)

    expect(page.locator('canvas').first).to_be_visible()
    assert page.locator('canvas').count() >= 1

    for canvas_id in ('trend_chart', 'platform_chart', 'severity_chart'):
        canvas = page.locator(f'#{canvas_id}')
        expect(canvas).to_be_attached()
        expect(canvas).to_be_visible()
        box = canvas.bounding_box()
        assert box is not None, f'#{canvas_id} has no layout box'
        assert box['width'] > 0, f'#{canvas_id} width is 0: {box}'
        assert box['height'] > 0, f'#{canvas_id} height is 0: {box}'

    _assert_no_traceback(page)


@pytest.mark.positive
def test_platform_legend_renders_with_colored_dots(admin_page):
    """The 'By platform' card renders a legend (colored dot + platform name
    + count) next to its doughnut chart."""
    page = admin_page
    _goto_analytics(page)

    platform_card = page.locator('div.card', has_text='By platform').first
    expect(platform_card).to_be_visible()
    expect(platform_card.locator('#platform_chart')).to_be_visible()

    legend_rows = platform_card.locator('.mi-row')
    expect(legend_rows.first).to_be_visible()
    row_count = legend_rows.count()
    assert row_count >= 1, 'expected at least one platform legend row'

    for i in range(row_count):
        row = legend_rows.nth(i)
        expect(row.locator('.mi-dot')).to_be_attached()
        text = row.inner_text().strip()
        assert text, f'platform legend row {i} has no text'
        # last token on the row is the tabular scan count
        last_token = text.split()[-1]
        assert last_token.isdigit(), f'platform legend row {i} count not numeric: {text!r}'

    _assert_no_traceback(page)


@pytest.mark.positive
def test_severity_buckets_render_with_labels_and_counts(admin_page):
    """The 'Findings by severity' card renders High/Medium/Info/Secure/
    Hotspot buckets, each with a settled numeric count."""
    page = admin_page
    _goto_analytics(page)

    severity_card = page.locator('div.card', has_text='Findings by severity').first
    expect(severity_card).to_be_visible()

    buckets = severity_card.locator('.mi-bucket')
    expect(buckets.first).to_be_visible()
    expect(buckets).to_have_count(5)

    expected_labels = ['High', 'Medium', 'Info', 'Secure', 'Hotspot']
    for i, label in enumerate(expected_labels):
        bucket = buckets.nth(i)
        text = bucket.inner_text()
        assert label.upper() in text.upper(), f'bucket {i} missing label {label!r}: {text!r}'
        count_val = _settled_text(bucket.locator(COUNTER_VALUE_SELECTOR).first)
        _assert_numeric(count_val, f'{label} bucket')

    _assert_no_traceback(page)


@pytest.mark.positive
def test_severity_mix_chart_and_score_gauge_render(admin_page):
    """The 'Severity mix' donut renders, and the adjacent 'Avg security
    score' card shows the semicircle gauge (or its empty state)."""
    page = admin_page
    _goto_analytics(page)

    severity_dist_card = page.locator('div.card', has_text='Severity mix').first
    expect(severity_dist_card).to_be_visible()
    canvas = severity_dist_card.locator('#severity_chart')
    expect(canvas).to_be_visible()
    box = canvas.bounding_box()
    assert box and box['width'] > 0 and box['height'] > 0

    # The average-security-score card carries the semicircle gauge with its
    # numeric readout (when at least one app has been scored).
    score_card = page.locator('div.card', has_text='Avg security score').first
    expect(score_card).to_be_visible()
    gauge = score_card.locator('.mi-semi')
    if gauge.count():
        readout = gauge.locator('.mi-semi-num')
        expect(readout).to_be_visible()
        # Regression guard: the readout must render inside the gauge's own
        # SVG box, not spill outside it (it previously had no positioning
        # CSS and fell into normal document flow below/outside the arc).
        svg_box = gauge.locator('svg').bounding_box()
        num_box = readout.bounding_box()
        assert svg_box and num_box
        assert num_box['x'] >= svg_box['x'] - 2
        assert num_box['x'] + num_box['width'] <= svg_box['x'] + svg_box['width'] + 2
        assert num_box['y'] <= svg_box['y'] + svg_box['height'] + 2

    _assert_no_traceback(page)


@pytest.mark.positive
def test_hovering_charts_does_not_error(admin_page):
    """Hovering each Chart.js canvas (which triggers Chart.js's own tooltip
    / hover interaction handlers) must not throw a JS exception or leak a
    server traceback."""
    page = admin_page
    page_errors = []
    page.on('pageerror', lambda exc: page_errors.append(str(exc)))

    _goto_analytics(page)

    for canvas_id in ('trend_chart', 'platform_chart', 'severity_chart'):
        canvas = page.locator(f'#{canvas_id}')
        expect(canvas).to_be_visible()
        canvas.hover()
        # move again to a slightly different point to trigger a hover-move
        # (Chart.js recomputes the nearest data point on mousemove)
        box = canvas.bounding_box()
        if box:
            page.mouse.move(box['x'] + box['width'] * 0.25, box['y'] + box['height'] * 0.5)
            page.mouse.move(box['x'] + box['width'] * 0.75, box['y'] + box['height'] * 0.5)

    assert page_errors == [], f'JS errors while hovering charts: {page_errors}'
    _assert_no_traceback(page)


@pytest.mark.positive
def test_hovering_severity_buckets_does_not_error(admin_page):
    """Hovering each severity finding bucket (CSS-only hover lift) must not
    error or leak a traceback."""
    page = admin_page
    page_errors = []
    page.on('pageerror', lambda exc: page_errors.append(str(exc)))

    _goto_analytics(page)

    severity_card = page.locator('div.card', has_text='Findings by severity').first
    buckets = severity_card.locator('.mi-bucket')
    expect(buckets.first).to_be_visible()
    for i in range(buckets.count()):
        buckets.nth(i).hover()

    assert page_errors == [], f'JS errors while hovering severity buckets: {page_errors}'
    _assert_no_traceback(page)


@pytest.mark.positive
def test_top_scanned_apps_table_renders(admin_page):
    """'Top scanned apps' table renders with real package/name/scan-count
    columns (or its documented empty state)."""
    page = admin_page
    _goto_analytics(page)

    top_apps_card = page.locator('div.card', has_text='Top scanned apps').first
    expect(top_apps_card).to_be_visible()
    rows = top_apps_card.locator('table tbody tr')
    expect(rows.first).to_be_visible()
    assert rows.count() >= 1

    first_row_text = rows.first.inner_text()
    assert first_row_text.strip(), 'first top-apps row has no text'
    assert first_row_text.strip() != 'No named apps yet.'

    _assert_no_traceback(page)


@pytest.mark.positive
def test_recent_activity_list_renders(admin_page):
    """'Recent activity' list renders real scan entries linking to report
    pages (we assert the link shape, we do not navigate/click it)."""
    page = admin_page
    _goto_analytics(page)

    recent_card = page.locator('div.card', has_text='Recent activity').first
    expect(recent_card).to_be_visible()
    items = recent_card.locator('ul.divide-y > li')
    expect(items.first).to_be_visible()
    assert items.count() >= 1

    first_link = items.first.locator('a').first
    href = first_link.get_attribute('href')
    assert href and href.startswith('/'), f'unexpected recent-activity href: {href!r}'

    view_all = recent_card.locator('a', has_text='View all')
    expect(view_all).to_have_attribute('href', '/recent_scans/')

    _assert_no_traceback(page)


@pytest.mark.positive
def test_charts_are_backed_by_real_nonzero_data_points(admin_page):
    """The three Chart.js canvases aren't just visibly sized placeholders --
    the underlying JSON data blobs they're initialized from (embedded via
    Django's ``json_script`` filter -- see analytics/dashboard.html:372-375)
    carry real, non-empty, non-all-zero data points from the DB's scanned
    fixtures. A canvas can render with a non-zero bounding box even with an
    empty dataset (Chart.js still lays out its own axes/background), so
    this checks the actual numbers feeding the chart, not just its layout.
    """
    page = admin_page
    _goto_analytics(page)

    def _json_script(script_id):
        raw = page.locator(f'#{script_id}').inner_text()
        return json.loads(raw)

    trend_labels = _json_script('trend_labels')
    trend_values = _json_script('trend_values')
    assert len(trend_labels) > 0, 'trend chart has no labels at all'
    assert len(trend_values) == len(trend_labels)
    assert sum(trend_values) > 0, (
        f'trend chart values are all zero: {trend_values!r}')

    platform_data = _json_script('platform_data')
    assert len(platform_data) >= 1, 'platform donut has no slices at all'
    assert sum(platform_data.values()) > 0, (
        f'platform donut values are all zero: {platform_data!r}')

    severity_data = _json_script('severity_data')
    assert len(severity_data) >= 1, 'severity donut has no slices at all'
    assert sum(severity_data.values()) > 0, (
        f'severity donut values are all zero: {severity_data!r}')

    _assert_no_traceback(page)
