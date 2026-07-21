"""UI spec: General + dynamic-landing pages.

Covers:
    /about              - about page
    /api_docs           - REST API docs (endpoint TOC, search/filter, API key card)
    /recent_scans/      - recent scans table (search, empty-state, type filters)
    /dynamic_analysis/  - dynamic-analysis platform picker (Android / iOS choice cards)
    /android/dynamic_analysis/ - Android dynamic-analyzer landing (device table /
                                 "no device" state / controls) -- the page the task's
                                 reference template (dynamic_analysis/android/dynamic_analysis.html)
                                 actually renders. `/dynamic_analysis/` itself renders the
                                 platform-picker template (general/dynamic.html); both are
                                 exercised here so the "device table / no device state /
                                 controls render" requirement is genuinely covered.

Live on-device dynamic flows (Frida instrumentation, logcat streaming, screen mirroring,
"Prepare runtime" provisioning) CANNOT run headless without a real emulator/device attached
-- they are intentionally NOT exercised. Only the landing page and its static controls are
asserted to render. See uncovered_flows in the QA report for the full list.
"""
import re

from playwright.sync_api import expect


NO_TRACEBACK = 'Traceback (most recent call last)'


# ─────────────────────────── /about ───────────────────────────

def test_about_page_renders_key_sections(admin_page):
    page = admin_page
    page.goto('/about', wait_until='domcontentloaded')

    assert NO_TRACEBACK not in page.content()

    # Hero
    expect(page.get_by_role('heading', name='About MobInspect')).to_be_visible()
    expect(page.get_by_text(
        'Mobile Application Security Inspector', exact=False)).to_be_visible()
    hero_recent_link = page.get_by_role('link', name='Recent scans')
    hero_api_link = page.get_by_role('link', name='API docs')
    expect(hero_recent_link).to_be_visible()
    expect(hero_api_link).to_be_visible()

    # "What it does" card
    expect(page.get_by_role('heading', name='What it does')).to_be_visible()
    expect(page.get_by_text('Supported formats')).to_be_visible()
    expect(page.get_by_text('APK', exact=True).first).to_be_visible()

    # Use cases
    expect(page.get_by_role('heading', name='Use cases')).to_be_visible()
    expect(page.get_by_text('Penetration testing')).to_be_visible()
    expect(page.get_by_text('Malware and tracker analysis')).to_be_visible()
    expect(page.get_by_text('Privacy auditing')).to_be_visible()
    expect(page.get_by_text('CI/CD security gating via REST API')).to_be_visible()

    # License + Platform aside
    expect(page.get_by_role('heading', name='License')).to_be_visible()
    expect(page.get_by_text('LICENSE.md').first).to_be_visible()
    expect(page.get_by_role('heading', name='Platform')).to_be_visible()
    # Scope to the "Platform" checklist card -- the intro paragraph above it
    # contains near-identical lowercase phrasing ("modern Tailwind UI, dynamic
    # role-based access control, ...") which would otherwise collide with these
    # case-insensitive substring matches.
    platform_card = page.locator('.card', has=page.get_by_role('heading', name='Platform'))
    expect(platform_card.get_by_text('Modern Tailwind UI', exact=True)).to_be_visible()
    expect(platform_card.get_by_text('Dynamic role-based access control', exact=True)).to_be_visible()
    expect(platform_card.get_by_text('Per-user revocable API keys', exact=True)).to_be_visible()
    expect(platform_card.get_by_text('Analytics dashboard', exact=True)).to_be_visible()

    # Quick-nav links are wired to the real routes.
    expect(hero_recent_link).to_have_attribute('href', re.compile(r'/recent_scans/'))
    expect(hero_api_link).to_have_attribute('href', re.compile(r'/api_docs'))

    # Exercise the "Recent scans" quick link -- non-destructive navigation only.
    hero_recent_link.click()
    page.wait_for_url(re.compile(r'/recent_scans/'))
    assert NO_TRACEBACK not in page.content()


# ─────────────────────────── /api_docs ───────────────────────────

def test_api_docs_page_renders_and_toc_filters(admin_page):
    page = admin_page
    page.goto('/api_docs', wait_until='domcontentloaded')

    assert NO_TRACEBACK not in page.content()

    expect(page.get_by_role('heading', name='REST API Documentation')).to_be_visible()

    # Header stat badges are real numbers computed from the doc body.
    total_stat = page.locator('#mi-stat-total')
    groups_stat = page.locator('#mi-stat-groups')
    get_stat = page.locator('#mi-stat-get')
    post_stat = page.locator('#mi-stat-post')
    expect(total_stat).to_be_visible()
    expect(groups_stat).to_be_visible()
    assert total_stat.inner_text().strip().isdigit()
    assert groups_stat.inner_text().strip().isdigit()
    assert get_stat.inner_text().strip().isdigit()
    assert post_stat.inner_text().strip().isdigit()
    assert int(total_stat.inner_text().strip()) > 0

    # API key card
    expect(page.get_by_role('heading', name='Authorization key')).to_be_visible()
    key_code = page.locator('.mi-key-card code').first
    expect(key_code).to_be_visible()
    expect(page.get_by_role('button', name='Copy key')).to_be_visible()

    # Doc body renders real endpoint sections referenced from the in-page TOC.
    docs_body = page.locator('#mi-api-docs-body')
    expect(docs_body).to_be_attached()
    expect(page.get_by_role('heading', name='Static Analysis', exact=True)).to_be_visible()
    expect(docs_body.get_by_text('Upload File API', exact=True).first).to_be_visible()
    expect(page.locator('#upload-file-api')).to_be_attached()

    # Sidebar endpoint navigator is generated client-side from the same TOC.
    toc_nav = page.locator('#mi-toc-nav')
    expect(toc_nav).to_be_visible()
    toc_links = page.locator('.mi-toc-link')
    expect(toc_links.first).to_be_visible()
    toc_count_before = toc_links.count()
    assert toc_count_before > 0

    # Filter the TOC down to a single known endpoint.
    search = page.locator('#mi-toc-search')
    expect(search).to_be_visible()
    search.fill('Upload File')
    expect(page.locator('.mi-toc-link:visible').first).to_contain_text('Upload File')
    assert page.locator('.mi-toc-link:visible').count() < toc_count_before

    # A nonsense filter yields zero visible endpoints (client-side filter really runs).
    search.fill('zzz-no-such-endpoint-xyz123')
    expect(page.locator('.mi-toc-link:visible')).to_have_count(0)

    # Clear the filter -- back to the full list.
    search.fill('')
    expect(page.locator('.mi-toc-link:visible')).to_have_count(toc_count_before)


# ─────────────────────────── /recent_scans/ ───────────────────────────

def test_recent_scans_page_table_search_and_pagination(admin_page):
    page = admin_page
    page.goto('/recent_scans/', wait_until='domcontentloaded')

    assert NO_TRACEBACK not in page.content()

    expect(page.get_by_role('heading', name='Scans', exact=True)).to_be_visible()
    expect(page.get_by_role('heading', name='Scan history')).to_be_visible()
    expect(page.locator('#miScanTable')).to_be_attached()
    # Table header columns are real.
    header = page.locator('#miScanTable thead tr')
    for col in ['App', 'File', 'Type', 'Hash', 'Date', 'Actions']:
        expect(header.get_by_text(col, exact=True)).to_be_visible()

    search_input = page.locator('input[name="q"]')
    expect(search_input).to_be_visible()

    # Deterministic empty-result search: a nonsense query can never match a real scan.
    needle = 'zzz-no-such-app-xyz123'
    search_input.fill(needle)
    search_input.press('Enter')
    page.wait_for_url(re.compile(r'q='))
    assert NO_TRACEBACK not in page.content()
    expect(page.get_by_role('heading', name=f'No matches for "{needle}"')).to_be_visible()
    # Two "Clear search" links exist on this state (the small inline "x" next to
    # the search box, and the button inside the empty-state card) -- scope to
    # the one inside the table's empty-state row.
    clear_link = page.locator('#miScanTable').get_by_role('link', name='Clear search')
    expect(clear_link).to_be_visible()

    # Clear the search -- back to the unfiltered scan history.
    clear_link.click()
    page.wait_for_url(lambda u: 'recent_scans' in u and 'q=' not in u)
    assert NO_TRACEBACK not in page.content()
    expect(page.locator('#miScanTable')).to_be_attached()

    # Stat tiles / type filter chips / pagination only render when there is at
    # least one scan (Django Page.__bool__ is False for an empty page) -- assert
    # them when present instead of assuming fixed seed data.
    stat_total = page.locator('[data-count-up]').first
    if stat_total.count():
        expect(stat_total).to_be_visible()
        # Count-up animation settles to a real integer.
        expect(stat_total).to_have_text(re.compile(r'^\d+$'), timeout=5000)
        assert int(stat_total.inner_text().strip()) >= 0

    filters = page.locator('#miTypeFilters')
    if filters.count():
        all_chip = filters.locator('.mi-chip[data-filter="all"]')
        android_chip = filters.locator('.mi-chip[data-filter="android"]')
        expect(all_chip).to_have_class(re.compile(r'is-active'))
        android_chip.click()
        expect(android_chip).to_have_class(re.compile(r'is-active'))
        expect(all_chip).not_to_have_class(re.compile(r'is-active'))
        # Restore default state.
        all_chip.click()
        expect(all_chip).to_have_class(re.compile(r'is-active'))

    pagination = page.locator('.card-footer:has-text("Page")')
    if pagination.count():
        expect(pagination).to_be_visible()
        next_link = pagination.get_by_role('link', name=re.compile('Next'))
        if next_link.count():
            expect(next_link).to_be_visible()


# ─────────────────────────── /dynamic_analysis/ (platform picker) ───────────────────────────

def test_dynamic_analysis_landing_platform_picker(admin_page):
    page = admin_page
    page.goto('/dynamic_analysis/', wait_until='domcontentloaded')

    assert NO_TRACEBACK not in page.content()

    expect(page.get_by_role('heading', name='Dynamic Analyzer', exact=True)).to_be_visible()
    expect(page.get_by_text(
        'Run instrumented analysis against a live device or emulator', exact=False)).to_be_visible()

    # Android platform choice card, wired to the real Android dynamic-analysis route.
    android_card = page.locator('a.mi-choice')
    expect(android_card).to_be_visible()
    expect(android_card).to_have_attribute('href', re.compile(r'/android/dynamic_analysis/'))
    expect(android_card.get_by_role('heading', name='Android', exact=True)).to_be_visible()
    expect(android_card.get_by_text('Start Android analysis')).to_be_visible()

    # iOS platform choice card with its two real sub-routes.
    ios_corellium = page.get_by_role('link', name='Corellium VM')
    ios_device = page.get_by_role('link', name='Jailbroken device')
    expect(ios_corellium).to_be_visible()
    expect(ios_device).to_be_visible()
    expect(ios_corellium).to_have_attribute('href', re.compile(r'/ios/dynamic_analysis/'))
    expect(ios_device).to_have_attribute('href', re.compile(r'/ios/dynamic_analysis_device/'))

    # "What's the difference?" disclosure toggle (Alpine, purely presentational).
    toggle = page.get_by_role('button', name="What's the difference?")
    expect(toggle).to_be_visible()
    detail = page.get_by_text('cloud-hosted virtual iOS device', exact=False)
    expect(detail).to_be_hidden()
    toggle.click()
    expect(detail).to_be_visible()

    # "How it works" steps.
    expect(page.get_by_role('heading', name='How it works')).to_be_visible()
    for step in ['1. Connect', '2. Instrument', '3. Exercise', '4. Review']:
        expect(page.get_by_role('heading', name=step)).to_be_visible()

    # Setup note with external docs link.
    expect(page.get_by_text(
        'Dynamic analysis requires a running emulator or jailbroken device',
        exact=False)).to_be_visible()


# ─────────────────────────── /android/dynamic_analysis/ (device table / controls) ───────────────────────────

def test_android_dynamic_analyzer_landing_renders_controls(admin_page):
    page = admin_page
    page.goto('/android/dynamic_analysis/', wait_until='domcontentloaded')

    assert NO_TRACEBACK not in page.content()

    expect(page.get_by_role('heading', name='Android Dynamic Analyzer')).to_be_visible()

    # Runtime status badge is always one of these two real states -- assert
    # whichever is actually rendered rather than assuming a device is attached
    # (this environment has no live emulator).
    runtime_badge = page.get_by_text(re.compile(r'Runtime (connected|offline)', re.I)).first
    expect(runtime_badge).to_be_visible()
    runtime_state = runtime_badge.inner_text().strip().lower()

    # KPI tiles: Runtime / Android version / Apps on device / Apps available.
    expect(page.get_by_text('Runtime', exact=True).first).to_be_visible()
    expect(page.get_by_text('Android version', exact=True)).to_be_visible()
    expect(page.get_by_text('Apps on device', exact=True).first).to_be_visible()
    expect(page.get_by_text('Apps available', exact=True).first).to_be_visible()

    # "Prepare runtime" control is present (disabled with no runtime connected);
    # we do NOT invoke it -- provisioning a real device/emulator can't run headless.
    prepare_btn = page.get_by_role('button', name='Prepare runtime').first
    expect(prepare_btn).to_be_attached()
    if runtime_state == 'runtime offline':
        expect(prepare_btn).to_be_disabled()
    prepare_modal = page.locator('#mi-mobinspecty')
    expect(prepare_modal).to_be_attached()

    # Supported runtimes reference card.
    expect(page.get_by_role('heading', name='Supported runtimes')).to_be_visible()
    expect(page.get_by_text('Genymotion Android VM')).to_be_visible()
    expect(page.get_by_text('Android Emulator AVD', exact=False)).to_be_visible()
    expect(page.get_by_text('Corellium Android VM', exact=False)).to_be_visible()

    if not identifier_connected(runtime_state):
        expect(page.get_by_role('heading', name='Android runtime not found')).to_be_visible()

    # ── Apps on device table: real device table, or the documented "no device
    #    connected" / "no apps detected" empty state -- either is a valid,
    #    concretely-asserted render depending on whether a device is attached.
    device_section = page.locator('section', has=page.get_by_role(
        'heading', name='Apps on device'))
    expect(device_section).to_be_visible()
    device_rows = device_section.locator('#mi-device-tbody tr[data-search]')
    if device_rows.count() > 0:
        expect(device_rows.first).to_be_visible()
        search_box = page.locator('#mi-search-device')
        expect(search_box).to_be_visible()
        search_box.fill('zzz-no-such-package-xyz123')
        expect(page.locator('#mi-device-empty')).to_be_visible()
        search_box.fill('')
        expect(page.locator('#mi-device-empty')).to_be_hidden()
    else:
        expect(device_section.get_by_text(
            re.compile(r'No (device connected|apps detected on device)'))).to_be_visible()

    # ── Apps available table: uploaded scans ready for dynamic analysis, or the
    #    documented empty state.
    apps_section = page.locator('section', has=page.get_by_role(
        'heading', name='Apps available'))
    expect(apps_section).to_be_visible()
    apps_rows = apps_section.locator('#mi-apps-tbody tr[data-search]')
    if apps_rows.count() > 0:
        expect(apps_rows.first).to_be_visible()
        search_box = page.locator('#mi-search-apps')
        expect(search_box).to_be_visible()
        search_box.fill('zzz-no-such-package-xyz123')
        expect(page.locator('#mi-apps-empty')).to_be_visible()
        search_box.fill('')
        expect(page.locator('#mi-apps-empty')).to_be_hidden()
    else:
        expect(apps_section.get_by_text('No apps uploaded yet')).to_be_visible()

    # Back-to-all-platforms control.
    expect(page.get_by_role('link', name='All platforms')).to_be_visible()


def identifier_connected(runtime_state):
    return runtime_state == 'runtime connected'
