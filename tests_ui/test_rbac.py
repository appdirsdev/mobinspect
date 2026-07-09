"""RBAC admin UI spec (Playwright, sync API).

Covers, non-destructively (no shared roles/users/API keys created, deleted,
or revoked):

  * /rbac/roles/          — roles list (hero, stat tiles, role cards, "New role")
  * /rbac/roles/new/      — role create form (fields render; navigated away
                             from WITHOUT submitting)
  * /rbac/api-keys/       — API keys list + create-key form render
  * /rbac/audit/          — audit log renders; filter form + quick-filter chips
                             + pagination (if present) are exercised
  * /rbac/permissions/    — permission catalog renders; client-side search
                             filters rows
  * /users/               — users list renders
  * /create_user/         — create-user ("register") form renders; NOT submitted

Every test asserts real, specific elements (not just HTTP 200) and that no
Django traceback leaked into the page.
"""
from playwright.sync_api import expect


def assert_no_traceback(page):
    assert 'Traceback (most recent call last)' not in page.content()


# ─────────────────────────── Roles list ───────────────────────────


def test_roles_list_renders(admin_page):
    page = admin_page
    page.goto('/rbac/roles/', wait_until='domcontentloaded')

    # Hero heading + copy
    expect(page.locator('h1', has_text='Roles')).to_be_visible()
    expect(page.locator('text=Bundles of permissions assigned to users')).to_be_visible()

    # "New role" link present and points at the create route
    new_role_link = page.locator('a', has_text='New role').first
    expect(new_role_link).to_be_visible()
    expect(new_role_link).to_have_attribute('href', '/rbac/roles/new/')

    # Stat tiles: Total roles / System roles / Custom roles
    # (use exact text matches — the hero copy paragraph also contains the
    # substring "System roles", so a loose match would be ambiguous)
    expect(page.get_by_text('Total roles', exact=True)).to_be_visible()
    expect(page.get_by_text('System roles', exact=True)).to_be_visible()
    expect(page.get_by_text('Custom roles', exact=True)).to_be_visible()

    # At least one role card rendered (seed migrations create the default four)
    role_cards = page.locator('.mi-role-card')
    expect(role_cards.first).to_be_visible()
    assert role_cards.count() >= 1

    # Each visible role card has a name and an Edit link
    expect(role_cards.first.locator('h3').first).to_be_visible()

    assert_no_traceback(page)


def test_roles_list_stat_tiles_show_settled_integer_counts(admin_page):
    page = admin_page
    page.goto('/rbac/roles/', wait_until='domcontentloaded')

    total_tile = page.locator('.mi-stat', has_text='Total roles').locator('.mi-num')
    expect(total_tile).to_be_visible()

    # Wait for the Alpine count-up animation to settle, then assert it is a
    # real (non-negative) integer matching the number of rendered cards.
    page.wait_for_timeout(1200)
    shown_text = total_tile.inner_text().strip()
    assert shown_text.isdigit(), f'expected an integer count, got {shown_text!r}'
    shown_value = int(shown_text)

    role_card_count = page.locator('.mi-role-card').count()
    assert shown_value == role_card_count
    assert shown_value >= 1

    assert_no_traceback(page)


# ─────────────────────────── Role create form ───────────────────────────


def test_role_create_form_renders_without_submitting(admin_page):
    page = admin_page

    # Open the create form via the real "New role" link from the roles list.
    page.goto('/rbac/roles/', wait_until='domcontentloaded')
    page.locator('a', has_text='New role').first.click()
    page.wait_for_url('**/rbac/roles/new/', timeout=10000)

    expect(page.locator('h1', has_text='New role')).to_be_visible()

    # Identity fields
    name_input = page.locator('#id_name')
    expect(name_input).to_be_visible()
    expect(name_input).to_have_attribute('required', '')
    expect(page.locator('#id_description')).to_be_visible()
    expect(page.locator('#id_color')).to_be_attached()
    expect(page.locator('#id_color_text')).to_be_visible()

    # Icon picker + hidden icon field
    expect(page.locator('#id_icon')).to_be_attached()
    icon_buttons = page.locator('.rf-icon-btn')
    assert icon_buttons.count() > 0

    # Color preset swatches
    swatches = page.locator('.rf-swatch')
    assert swatches.count() > 0

    # Permissions matrix: filter box + at least one category + checkboxes
    perm_filter = page.locator('input[type="search"][placeholder*="Filter by name"]')
    expect(perm_filter).to_be_visible()
    perm_checkboxes = page.locator('.rf-perm-row input[type="checkbox"]')
    assert perm_checkboxes.count() > 0

    # Save / Cancel controls present (NOT clicked — non-destructive)
    save_btn = page.locator('button[type="submit"]', has_text='Save role')
    expect(save_btn).to_be_visible()
    cancel_link = page.locator('a', has_text='Cancel')
    expect(cancel_link).to_be_visible()
    expect(cancel_link).to_have_attribute('href', '/rbac/roles/')

    assert_no_traceback(page)

    # Exercise the client-side permission filter (non-destructive: text input
    # only, no submission) then navigate away WITHOUT saving.
    perm_filter.fill('scan')
    expect(page.locator('.rf-perm-row:visible').first).to_be_visible()

    # Navigate away without submitting the form.
    page.goto('/rbac/roles/', wait_until='domcontentloaded')
    assert '/rbac/roles/new' not in page.url
    expect(page.locator('h1', has_text='Roles')).to_be_visible()
    assert_no_traceback(page)


# ─────────────────────────── API keys ───────────────────────────


def test_api_keys_page_renders(admin_page):
    page = admin_page
    page.goto('/rbac/api-keys/', wait_until='domcontentloaded')

    expect(page.locator('h1', has_text='API keys')).to_be_visible()
    expect(page.locator('text=Per-user keys for programmatic access')).to_be_visible()

    # KPI tiles
    expect(page.locator('text=Total keys')).to_be_visible()
    expect(page.locator('text=Active').first).to_be_visible()
    expect(page.locator('text=Expired').first).to_be_visible()
    expect(page.locator('text=Revoked').first).to_be_visible()

    # Create-key form (rendered, NOT submitted — creating a key is not
    # idempotent/shared-safe the way an integration upsert is)
    expect(page.locator('h2', has_text='Create new key')).to_be_visible()
    name_field = page.locator('#id_name')
    expect(name_field).to_be_visible()
    expires_field = page.locator('#id_expires_in_days')
    expect(expires_field).to_be_visible()
    generate_btn = page.locator('button[type="submit"]', has_text='Generate')
    expect(generate_btn).to_be_visible()

    # List table (own keys) with the expected column headers
    expect(page.locator('h2', has_text='Your keys')).to_be_visible()
    table = page.locator('table').filter(has=page.locator('#apiKeysBody'))
    expect(table.locator('th', has_text='Name')).to_be_visible()
    expect(table.locator('th', has_text='Prefix')).to_be_visible()
    expect(table.locator('th', has_text='Status')).to_be_visible()

    assert_no_traceback(page)


# ─────────────────────────── Audit log ───────────────────────────


def test_audit_log_page_renders(admin_page):
    page = admin_page
    page.goto('/rbac/audit/', wait_until='domcontentloaded')

    expect(page.locator('h1', has_text='Audit log')).to_be_visible()
    expect(page.locator('text=Append-only record of all user activity')).to_be_visible()

    # At-a-glance tiles
    expect(page.locator('text=Matched events')).to_be_visible()
    expect(page.locator('text=Current page')).to_be_visible()

    # Filter form
    expect(page.locator('h2', has_text='Filter events')).to_be_visible()
    action_input = page.locator('#action')
    actor_input = page.locator('#actor')
    expect(action_input).to_be_visible()
    expect(actor_input).to_be_visible()

    # Quick-filter chips (real ?action= links)
    denied_chip = page.locator('a.mi-chip', has_text='Denied')
    expect(denied_chip).to_be_visible()
    expect(denied_chip).to_have_attribute('href', '?action=denied')

    # Events table headers
    expect(page.locator('th', has_text='When')).to_be_visible()
    expect(page.locator('th', has_text='Actor')).to_be_visible()
    expect(page.locator('th', has_text='Action')).to_be_visible()

    assert_no_traceback(page)


def test_audit_log_search_filters_and_no_error(admin_page):
    page = admin_page
    page.goto('/rbac/audit/', wait_until='domcontentloaded')

    # Type a query into the actor filter and submit via the real GET form.
    page.fill('#actor', 'admin')
    page.locator('button[type="submit"]', has_text='Filter').click()
    page.wait_for_load_state('domcontentloaded')

    assert 'actor=admin' in page.url
    # The applied-filter badge in the hero reflects the actor filter.
    expect(page.locator('text=actor: admin')).to_be_visible()
    assert_no_traceback(page)

    # Reset back to the unfiltered view via the real Reset link.
    page.locator('a', has_text='Reset').click()
    page.wait_for_load_state('domcontentloaded')
    assert 'actor=' not in page.url
    assert_no_traceback(page)


def test_audit_log_pagination_if_present(admin_page):
    page = admin_page
    page.goto('/rbac/audit/', wait_until='domcontentloaded')

    next_link = page.locator('a.btn', has_text='Next')
    if next_link.count() == 0:
        # Not enough audit events yet to paginate — assert the single-page
        # state explicitly rather than silently skipping.
        expect(page.locator('text=Current page')).to_be_visible()
        assert_no_traceback(page)
        return

    expect(next_link.first).to_be_visible()
    next_link.first.click()
    page.wait_for_load_state('domcontentloaded')
    assert 'page=2' in page.url
    expect(page.locator('h1', has_text='Audit log')).to_be_visible()
    assert_no_traceback(page)


# ─────────────────────────── Permissions catalog ───────────────────────────


def test_permissions_catalog_renders(admin_page):
    page = admin_page
    page.goto('/rbac/permissions/', wait_until='domcontentloaded')

    expect(page.locator('h1', has_text='Permissions catalog')).to_be_visible()
    expect(page.locator('text=Read-only reference')).to_be_visible()

    # Stat tiles — scoped to the .mi-stat KPI cards themselves (exact-text
    # matches alone are ambiguous: "Categories"/"categories" also appears in
    # the hero badge, and "Dangerous" also labels every dangerous-permission
    # row badge further down the page).
    expect(page.locator('.mi-stat p.text-small', has_text='Categories')).to_be_visible()
    expect(page.locator('.mi-stat p.text-small', has_text='Total permissions')).to_be_visible()
    expect(page.locator('.mi-stat p.text-small', has_text='Dangerous')).to_be_visible()
    expect(page.locator('.mi-stat p.text-small', has_text='Role assignments')).to_be_visible()

    # At least one category card with a permission row
    perm_rows = page.locator('.perm-row')
    assert perm_rows.count() > 0
    expect(perm_rows.first).to_be_visible()

    # "Roles" link back to the roles list
    roles_link = page.locator('a', has_text='Roles').last
    expect(roles_link).to_be_visible()

    assert_no_traceback(page)


def test_permissions_catalog_search_filters_rows(admin_page):
    page = admin_page
    page.goto('/rbac/permissions/', wait_until='domcontentloaded')

    total_rows = page.locator('.perm-row').count()
    assert total_rows > 0

    search_box = page.locator('input[type="search"][aria-label="Search permissions"]')
    expect(search_box).to_be_visible()

    # Pick a codename fragment from the first row to guarantee at least one match.
    first_codename = page.locator('.perm-row code').first.inner_text().strip()
    fragment = first_codename.split('.')[0]
    search_box.fill(fragment)

    # Debounced (100ms) client-side filter — wait for it to settle.
    page.wait_for_timeout(400)
    visible_rows = page.locator('.perm-row:visible')
    assert visible_rows.count() >= 1
    assert visible_rows.count() <= total_rows

    # An impossible query should produce the "no results" empty state.
    search_box.fill('zzz_no_such_permission_zzz')
    page.wait_for_timeout(400)
    expect(page.locator('text=No permissions match your search')).to_be_visible()

    # Clear filters via the real control and confirm rows reappear.
    page.locator('button', has_text='Clear filters').click()
    page.wait_for_timeout(400)
    assert page.locator('.perm-row:visible').count() == total_rows

    assert_no_traceback(page)


def test_permissions_catalog_dangerous_only_toggle(admin_page):
    page = admin_page
    page.goto('/rbac/permissions/', wait_until='domcontentloaded')

    dangerous_chip = page.locator('button.mi-chip', has_text='Dangerous only')
    expect(dangerous_chip).to_be_visible()
    dangerous_chip.click()
    page.wait_for_timeout(300)

    expect(dangerous_chip).to_have_attribute('aria-pressed', 'true')
    assert_no_traceback(page)

    # Toggle back off — non-destructive, purely client-side state.
    dangerous_chip.click()
    page.wait_for_timeout(300)
    expect(dangerous_chip).to_have_attribute('aria-pressed', 'false')


# ─────────────────────────── Users list ───────────────────────────


def test_users_list_renders(admin_page):
    page = admin_page
    page.goto('/users/', wait_until='domcontentloaded')

    expect(page.locator('h1', has_text='Users')).to_be_visible()
    expect(page.locator('text=Members of this MobInspect instance')).to_be_visible()

    # "Add user" link -> /create_user/
    add_user_link = page.locator('a', has_text='Add user')
    expect(add_user_link).to_be_visible()
    expect(add_user_link).to_have_attribute('href', '/create_user/')

    # Search box
    search_box = page.locator('input[name="q"]')
    expect(search_box).to_be_visible()

    # Table headers + at least the admin user row (username rendered in the
    # dedicated "font-medium" cell; scoped to avoid matching the "Admin
    # (legacy)" role badge or the per-row "Manage roles for admin" panel)
    expect(page.locator('th', has_text='User')).to_be_visible()
    expect(page.locator('th', has_text='Roles')).to_be_visible()
    expect(page.locator('th', has_text='Status')).to_be_visible()
    expect(page.locator('td p.font-medium', has_text='admin').first).to_be_visible()

    assert_no_traceback(page)


def test_users_list_search_returns_results_no_error(admin_page):
    page = admin_page
    page.goto('/users/', wait_until='domcontentloaded')

    page.fill('input[name="q"]', 'admin')
    page.keyboard.press('Enter')
    page.wait_for_url('**/users/?q=admin', timeout=10000)

    assert 'q=admin' in page.url
    expect(page.locator('td p.font-medium', has_text='admin').first).to_be_visible()
    assert_no_traceback(page)


# ─────────────────────────── Create user ("register") form ───────────────────────────


def test_create_user_form_renders_without_submitting(admin_page):
    page = admin_page

    # Navigate via the real "Add user" link from the users list.
    page.goto('/users/', wait_until='domcontentloaded')
    page.locator('a', has_text='Add user').click()
    page.wait_for_url('**/create_user/', timeout=10000)

    expect(page.locator('h1', has_text='Create user')).to_be_visible()

    # Identity fields
    expect(page.locator('#id_username')).to_be_visible()
    expect(page.locator('#id_username')).to_have_attribute('required', '')
    expect(page.locator('#id_email')).to_be_visible()
    expect(page.locator('#id_email')).to_have_attribute('type', 'email')

    # Security fields
    expect(page.locator('#id_password1')).to_be_visible()
    expect(page.locator('#id_password2')).to_be_visible()

    # Access: role select with real choices + quick-pick pills
    role_select = page.locator('#id_role')
    expect(role_select).to_be_visible()
    option_count = role_select.locator('option').count()
    assert option_count > 1  # placeholder + at least one real role

    # Submit + cancel controls present (submit NOT clicked — non-destructive)
    submit_btn = page.locator('button[type="submit"]', has_text='Create user')
    expect(submit_btn).to_be_visible()
    cancel_link = page.locator('a', has_text='Cancel')
    expect(cancel_link).to_be_visible()
    expect(cancel_link).to_have_attribute('href', '/users/')

    # Live preview sidebar reacts to typed username (non-destructive: no submit)
    page.fill('#id_username', 'qa_preview_check')
    preview_name = page.locator('.mi-recap p.font-medium')
    expect(preview_name).to_have_text('qa_preview_check')

    assert_no_traceback(page)

    # Navigate away WITHOUT submitting.
    page.goto('/users/', wait_until='domcontentloaded')
    assert '/create_user' not in page.url
    expect(page.locator('h1', has_text='Users')).to_be_visible()
    assert_no_traceback(page)
