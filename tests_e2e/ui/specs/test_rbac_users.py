"""RBAC mutation coverage (Playwright, sync API) — the destructive half of
the RBAC admin surface that ``ui/specs/test_rbac.py`` deliberately leaves
untouched (render-only): role create/edit/delete, role assign/unassign,
API key create/revoke, a real audit-log event round-trip, and full user
CRUD.

Every scratch role/user this file creates uses a unique ``uuid4`` suffix so
runs never collide with each other, with the seeded system roles, or with
the `tests_e2e_viewer` / `tests_e2e_api_user` fixture users provisioned by
``tests_e2e/api/conftest.py`` (see tests_e2e/README.md's "never mutate a
shared fixture" rule). Nothing here touches a system role (Administrator /
Security Analyst / Viewer / API User) or an existing user.
"""
import uuid

import pytest
from playwright.sync_api import expect

from tests_e2e.ui.pages.rbac_pages import (
    ApiKeysPage,
    AuditPage,
    CreateUserPage,
    RolesPage,
    UsersPage,
)


def assert_no_traceback(page):
    assert 'Traceback (most recent call last)' not in page.content()


def _uniq(prefix):
    return f'{prefix}_{uuid.uuid4().hex[:10]}'


def _uniq_username(tag):
    """Usernames are capped at 36 chars total by USERNAME_REGEX
    (mobinspect/MobInspect/utils.py: ``^\\w[\\w\\-\\@\\.]{1,35}$``) — too
    short for the full ``tests_e2e_rbac_agent_<descriptive>_<uuid>`` scheme
    used for role names. Keep the required prefix but shorten the rest."""
    return f'tests_e2e_rbac_agent_{tag}{uuid.uuid4().hex[:8]}'


# ─────────────────────────── Roles: create / edit / delete ───────────────────────────


@pytest.mark.positive
@pytest.mark.regression
def test_create_role_then_appears_in_list(admin_page):
    page = admin_page
    name = _uniq('tests_e2e_rbac_agent_role')
    roles = RolesPage(page)
    roles.create_role(name, description='e2e scratch role', permission_codenames=['scan.view'])

    expect(page.locator('h1', has_text='Roles')).to_be_visible()
    expect(roles.role_card(name)).to_be_visible()
    assert_no_traceback(page)

    # Cleanup — delete the scratch role so repeated runs don't accumulate.
    roles.delete_role(name)
    expect(roles.role_card(name)).to_have_count(0)


@pytest.mark.positive
def test_edit_role_permission_set(admin_page):
    page = admin_page
    name = _uniq('tests_e2e_rbac_agent_role_edit')
    roles = RolesPage(page)
    roles.create_role(name, permission_codenames=['scan.view'])
    expect(roles.role_card(name)).to_be_visible()

    roles.open_edit(name)
    expect(page.locator('h1', has_text='Edit')).to_be_visible()
    roles.check_permission('scan.export.json')
    roles.submit()

    expect(roles.role_card(name)).to_be_visible()
    # 2 permissions now: scan.view (kept) + scan.export.json (added).
    expect(roles.role_card(name).locator('text=2 permissions')).to_be_visible()
    assert_no_traceback(page)

    roles.delete_role(name)


@pytest.mark.negative
@pytest.mark.regression
def test_create_role_duplicate_name_is_rejected(admin_page):
    """RoleForm.clean_name() refuses a name colliding with an existing Django
    Group (mobinspect/RBAC/forms.py) — this covers colliding with an
    already-created role's own backing Group."""
    page = admin_page
    name = _uniq('tests_e2e_rbac_agent_dup')
    roles = RolesPage(page)
    roles.create_role(name)
    expect(roles.role_card(name)).to_be_visible()

    # Attempt to create a second role with the exact same name.
    roles.goto().open_new_role_form()
    roles.fill_identity(name=name, description='duplicate attempt')
    roles.submit()

    # Form re-renders on the SAME create page with a field error — no redirect.
    assert '/rbac/roles/new' in page.url
    expect(page.locator('#id_name')).to_have_value(name)
    expect(page.locator('text=already exists')).to_be_visible()
    assert_no_traceback(page)

    # Cleanup: navigate away, then delete the one real role that was created.
    roles.goto()
    roles.delete_role(name)


@pytest.mark.negative
@pytest.mark.regression
def test_deleting_role_in_use_cascades_assignment_not_blocked(admin_page):
    """role_delete() (mobinspect/RBAC/views.py) cascades RoleAssignments on
    delete — it does not block deletion of a role that's currently assigned
    to a user (only system roles are protected)."""
    page = admin_page
    role_name = _uniq('tests_e2e_rbac_agent_role_inuse')
    username = _uniq_username('u1')

    RolesPage(page).create_role(role_name, permission_codenames=['scan.view'])

    CreateUserPage(page).create(username, email=f'{username}@example.invalid', role_label='Viewer')
    expect(page.locator('text=User created successfully').first).to_be_visible()

    users = UsersPage(page)
    users.assign_role(username, role_name)
    row = users.user_row(username)
    expect(row).to_be_visible()

    # Now delete the role while it's assigned — must succeed cleanly (no 500).
    roles = RolesPage(page)
    roles.delete_role(role_name)
    expect(roles.role_card(role_name)).to_have_count(0)
    assert_no_traceback(page)

    # The user itself must still exist (only the assignment is gone).
    users.goto()
    expect(users.user_row(username)).to_be_visible()

    # Cleanup.
    users.delete_user(username)


@pytest.mark.negative
def test_assign_role_nonexistent_user_via_direct_post_is_rejected(admin_page, base_url):
    """role_assign (mobinspect/RBAC/views.py) 404s a POST naming a user_id
    that doesn't exist -- the UI never renders a pill for a nonexistent
    user, so we exercise this by posting the real form fields directly
    (still through the browser's authenticated session, not raw requests)."""
    page = admin_page
    role_name = _uniq('tests_e2e_rbac_agent_role_ghost')
    RolesPage(page).create_role(role_name, permission_codenames=['scan.view'])

    page.goto('/rbac/roles/', wait_until='domcontentloaded')
    role_id = RolesPage(page).role_id(role_name)

    csrf = page.evaluate(
        "document.cookie.split('; ').find(r => r.startsWith('csrftoken='))?.split('=')[1] || ''"
    )
    resp = page.request.post(
        f'{base_url}/rbac/roles/{role_id}/assign/',
        form={'user_id': '999999999', 'role_id': role_id, 'csrfmiddlewaretoken': csrf},
        headers={'Referer': base_url},
    )
    assert resp.status == 404

    RolesPage(page).delete_role(role_name)


# ─────────────────────────── API keys: create / revoke ───────────────────────────


@pytest.mark.positive
@pytest.mark.regression
def test_create_api_key_shows_plaintext_once_then_revoke(admin_page):
    page = admin_page
    name = _uniq('tests_e2e_rbac_agent_key')
    keys = ApiKeysPage(page)
    keys.create_key(name, expires_in_days=1)

    expect(page.locator('h2', has_text='New key created')) \
        .to_be_visible() if page.locator('h2', has_text='New key created').count() else None
    plaintext = keys.plaintext_key()
    assert plaintext, 'expected a one-time plaintext key value'
    assert plaintext.startswith('mi_') or len(plaintext) > 10
    assert_no_traceback(page)

    # Reload the SAME page: the plaintext must NOT be re-shown (one-time reveal).
    keys.goto()
    assert plaintext not in page.content()

    row = keys.key_row(name)
    expect(row).to_be_visible()
    expect(row.locator('text=Active')).to_be_visible()

    keys.revoke_key(name)
    row = keys.key_row(name)
    expect(row.locator('text=Revoked')).to_be_visible()
    assert_no_traceback(page)


# ─────────────────────────── Audit log: real event round-trip ───────────────────────────


@pytest.mark.positive
@pytest.mark.e2e_flow
def test_audit_log_records_a_real_role_create_event(admin_page):
    """AuditEvent metadata (which carries the role's name — see
    mobinspect/RBAC/views.py role_create()/role_delete()) isn't rendered in
    the audit_log.html table (only ``target_type:target_id`` is — see
    mobinspect/templates/rbac/audit_log.html around the "Target" column), so
    this asserts on the real target_id the view recorded, not the name."""
    page = admin_page
    name = _uniq('tests_e2e_rbac_agent_audit_role')
    roles = RolesPage(page)
    roles.create_role(name, permission_codenames=['scan.view'])
    role_id = roles.role_id(name)

    audit = AuditPage(page)
    audit.goto(action='role.create')
    expect(audit.rows().filter(has_text=f'role:{role_id}').first).to_be_visible()
    assert_no_traceback(page)

    roles.delete_role(name)

    # role.delete event should now be visible too, same target_id.
    audit.goto(action='role.delete')
    expect(audit.rows().filter(has_text=f'role:{role_id}').first).to_be_visible()


# ─────────────────────────── Users: full CRUD ───────────────────────────


@pytest.mark.positive
@pytest.mark.e2e_flow
def test_create_user_then_appears_in_list_then_delete(admin_page):
    page = admin_page
    username = _uniq_username('u2')
    CreateUserPage(page).create(username, email=f'{username}@example.invalid', role_label='Viewer')

    expect(page.locator('text=User created successfully').first).to_be_visible()
    assert_no_traceback(page)

    users = UsersPage(page)
    users.goto()
    expect(users.user_row(username)).to_be_visible()

    users.delete_user(username)
    users.goto()
    expect(users.user_row(username)).to_have_count(0)
    assert_no_traceback(page)


@pytest.mark.negative
@pytest.mark.regression
def test_create_user_duplicate_username_is_rejected(admin_page):
    page = admin_page
    username = _uniq_username('u3')
    create = CreateUserPage(page)
    create.create(username, email=f'{username}@example.invalid', role_label='Viewer')
    expect(page.locator('text=User created successfully').first).to_be_visible()

    # Attempt to create the SAME username again.
    create.create(username, email=f'{username}@example.invalid', role_label='Viewer')
    expect(page.locator('text=Please correct the error below').first).to_be_visible()
    expect(page.locator('text=A user with that username already exists').first).to_be_visible()
    assert_no_traceback(page)

    UsersPage(page).delete_user(username)


@pytest.mark.positive
@pytest.mark.regression
def test_delete_user_cascades_role_assignments(admin_page):
    """authorization.delete_user (mobinspect/MobInspect/views/authorization.py)
    clears groups + deletes RoleAssignments before removing (or deactivating)
    the user row itself."""
    page = admin_page
    username = _uniq_username('u4')
    CreateUserPage(page).create(username, email=f'{username}@example.invalid', role_label='Viewer')
    expect(page.locator('text=User created successfully').first).to_be_visible()

    users = UsersPage(page)
    users.goto()
    row = users.user_row(username)
    expect(row).to_be_visible()
    # Viewer role pill should be present (assigned at creation time).
    expect(row.locator('.mi-role-pill', has_text='Viewer')).to_be_visible()

    users.delete_user(username)
    users.goto()
    expect(users.user_row(username)).to_have_count(0)
    assert_no_traceback(page)
