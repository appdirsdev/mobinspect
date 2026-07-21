"""Page Object Model — RBAC admin UI (roles, permissions, API keys, audit,
users). One class per page/section; specs call these methods instead of
poking raw selectors directly (see tests_e2e/README.md's POM convention).

Every method here drives the REAL rendered page (real forms, real links) —
no hidden shortcuts to the DB. Mutating actions (create/delete/assign/
revoke) are meant to be used against SCRATCH data created by the spec
itself (unique ``uuid4``-suffixed names), never against shared/system
roles or the `SCANNED` fixture hashes.
"""
from playwright.sync_api import expect


class RolesPage:
    """/rbac/roles/ and /rbac/roles/new/ /<id>/."""

    def __init__(self, page):
        self.page = page

    def goto(self):
        self.page.goto('/rbac/roles/', wait_until='domcontentloaded')
        return self

    def open_new_role_form(self):
        self.page.locator('a', has_text='New role').first.click()
        self.page.wait_for_url('**/rbac/roles/new/', timeout=10000)
        return self

    def role_card(self, name):
        return self.page.locator('.mi-role-card', has_text=name)

    def role_id(self, name):
        """Resolve a role's numeric pk from its real "Edit" link href."""
        href = self.role_card(name).locator('a', has_text='Edit').get_attribute('href')
        return href.strip('/').split('/')[-1]

    def open_edit(self, name):
        self.role_card(name).locator('a', has_text='Edit').click()
        self.page.wait_for_load_state('domcontentloaded')
        return self

    def check_permission(self, codename):
        """Toggle a single permission checkbox by its codename, on the
        currently-open role_form.html page (create or edit)."""
        row = self.page.locator('.rf-perm-row', has=self.page.locator(f'code:text-is("{codename}")'))
        row.locator('input[type="checkbox"]').check(force=True)
        return self

    def fill_identity(self, name=None, description=None):
        if name is not None:
            self.page.fill('#id_name', name)
        if description is not None:
            self.page.fill('#id_description', description)
        return self

    def submit(self):
        self.page.locator('button[type="submit"]', has_text='Save role').click()
        self.page.wait_for_load_state('domcontentloaded')
        return self

    def create_role(self, name, description='', permission_codenames=()):
        """Full flow: roles list -> new role form -> fill -> save.

        Returns to /rbac/roles/ on success (real redirect from the view).
        """
        self.goto().open_new_role_form()
        self.fill_identity(name=name, description=description)
        for code in permission_codenames:
            self.check_permission(code)
        self.submit()
        return self

    def delete_role(self, name, confirm=True):
        """Click the real Delete form's submit button on the roles list.

        The template wires a JS ``confirm()`` on submit; Playwright's
        default dialog behavior is to auto-dismiss, so we register an
        explicit accept/dismiss handler first.
        """
        self.goto()
        if confirm:
            self.page.once('dialog', lambda d: d.accept())
        else:
            self.page.once('dialog', lambda d: d.dismiss())
        card = self.role_card(name)
        card.locator('form button[type="submit"]', has_text='Delete').click()
        self.page.wait_for_load_state('domcontentloaded')
        return self

    def success_message(self):
        return self.page.locator('.messages, .alert, [role="alert"]')


class PermissionsPage:
    def __init__(self, page):
        self.page = page

    def goto(self):
        self.page.goto('/rbac/permissions/', wait_until='domcontentloaded')
        return self


class ApiKeysPage:
    def __init__(self, page):
        self.page = page

    def goto(self):
        self.page.goto('/rbac/api-keys/', wait_until='domcontentloaded')
        return self

    def create_key(self, name, expires_in_days=None):
        self.goto()
        self.page.fill('#id_name', name)
        if expires_in_days is not None:
            self.page.fill('#id_expires_in_days', str(expires_in_days))
        self.page.locator('button[type="submit"]', has_text='Generate').click()
        self.page.wait_for_load_state('domcontentloaded')
        return self

    def plaintext_key(self):
        return self.page.locator('#plaintextKeyInput').input_value()

    def key_row(self, name):
        return self.page.locator('#apiKeysBody tr', has_text=name)

    def revoke_key(self, name, confirm=True):
        self.goto()
        row = self.key_row(name)
        if confirm:
            self.page.once('dialog', lambda d: d.accept())
        else:
            self.page.once('dialog', lambda d: d.dismiss())
        row.locator('form button[type="submit"]', has_text='Revoke').click()
        self.page.wait_for_load_state('domcontentloaded')
        return self


class AuditPage:
    def __init__(self, page):
        self.page = page

    def goto(self, action=None, actor=None):
        url = '/rbac/audit/'
        params = []
        if action:
            params.append(f'action={action}')
        if actor:
            params.append(f'actor={actor}')
        if params:
            url += '?' + '&'.join(params)
        self.page.goto(url, wait_until='domcontentloaded')
        return self

    def filter_by_actor(self, actor):
        self.goto()
        self.page.fill('#actor', actor)
        self.page.locator('button[type="submit"]', has_text='Filter').click()
        self.page.wait_for_load_state('domcontentloaded')
        return self

    def rows(self):
        return self.page.locator('table tbody tr')

    def contains_event(self, text):
        return self.page.locator('table tbody', has_text=text)


class UsersPage:
    """/users/ list + inline assign/unassign panel."""

    def __init__(self, page):
        self.page = page

    def goto(self, query=None):
        url = '/users/'
        if query:
            url += f'?q={query}'
        self.page.goto(url, wait_until='domcontentloaded')
        return self

    def user_row(self, username):
        return self.page.locator('tr.mi-row', has=self.page.locator('p.font-medium', has_text=username))

    def open_roles_panel(self, username):
        self.user_row(username).locator('button', has_text='Roles').click()
        return self

    def assign_role(self, username, role_name):
        """Open the inline "Manage roles" panel for `username` and click the
        pill for `role_name` (submits role_assign or role_unassign depending
        on current state — same real form the template renders)."""
        self.goto()
        self.open_roles_panel(username)
        row = self.user_row(username)
        panel_id = row.locator('button', has_text='Roles').get_attribute('aria-controls')
        panel = self.page.locator(f'#{panel_id}')
        panel.locator('button.mi-assign-pill', has_text=role_name).click()
        self.page.wait_for_load_state('domcontentloaded')
        return self

    def unassign_role(self, username, role_name):
        # Same pill toggles both directions — assign_role is idempotent here.
        return self.assign_role(username, role_name)

    def delete_user(self, username):
        self.goto()
        self.page.once('dialog', lambda d: d.accept())
        row = self.user_row(username)
        # The button's click handler does confirm() -> fetch(delete_user) ->
        # location.reload() on success. A plain wait_for_load_state right
        # after click can race the async fetch (an immediately-following
        # goto() would cancel the in-flight request), so wait for the real
        # XHR response first, then for the reload navigation it triggers.
        with self.page.expect_response(lambda r: 'delete_user' in r.url):
            row.locator('button.mi-delete-user').click()
        self.page.wait_for_load_state('domcontentloaded')
        return self


class CreateUserPage:
    """/create_user/ ("register") form."""

    def __init__(self, page):
        self.page = page

    def goto(self):
        self.page.goto('/create_user/', wait_until='domcontentloaded')
        return self

    def fill(self, username, email='', password='TestPass!2345', role_label=None):
        self.page.fill('#id_username', username)
        if email:
            self.page.fill('#id_email', email)
        self.page.fill('#id_password1', password)
        self.page.fill('#id_password2', password)
        if role_label:
            self.page.select_option('#id_role', label=role_label)
        return self

    def submit(self):
        self.page.locator('button[type="submit"]', has_text='Create user').click()
        self.page.wait_for_load_state('domcontentloaded')
        return self

    def create(self, username, email='', password='TestPass!2345', role_label=None):
        self.goto()
        self.fill(username, email=email, password=password, role_label=role_label)
        self.submit()
        return self

    def messages_text(self):
        return self.page.content()
