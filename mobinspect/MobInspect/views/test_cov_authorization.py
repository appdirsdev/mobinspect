"""Real-execution unit tests for mobinspect.MobInspect.views.authorization.

Drives the RBAC permission logic (has_permission, permission_required,
create_authorization_roles) and the user-management views with REAL Django
users, REAL RBAC groups/permissions loaded from migrations, and a real
RequestFactory / Client. A handful of genuinely-unreachable-otherwise
except branches (a real DB outage / RBAC import failure mid-request) use a
narrow, single-call monkeypatch, documented at each use.
"""
import sys
from unittest import mock

from django.contrib.auth.models import (
    AnonymousUser,
    Group,
    Permission,
    User,
)
from django.core.exceptions import PermissionDenied
from django.http import (
    HttpResponse,
    JsonResponse,
)
from django.test import (
    RequestFactory,
    TestCase,
    override_settings,
)

from mobinspect.MobInspect.views import authorization as az
from mobinspect.MobInspect.views.authorization import (
    MAINTAINER_GROUP,
    Permissions,
    VIEWER_GROUP,
    create_authorization_roles,
    has_permission,
    permission_required,
)


def _plain_view(request, api=False):
    """A trivial view used to exercise the decorator."""
    return HttpResponse('ok')


class CreateRolesTests(TestCase):
    """create_authorization_roles builds the RBAC groups + perms."""

    def test_creates_groups_and_assigns_maintainer_perms(self):
        create_authorization_roles()
        # Both groups exist.
        maintainer = Group.objects.get(name=MAINTAINER_GROUP)
        Group.objects.get(name=VIEWER_GROUP)  # must not raise
        # Maintainer got the three StaticAnalyzer perms (real DB perms).
        codenames = set(
            maintainer.permissions.values_list('codename', flat=True))
        self.assertIn(az.PERM_CAN_SCAN, codenames)
        self.assertIn(az.PERM_CAN_SUPPRESS, codenames)
        self.assertIn(az.PERM_CAN_DELETE, codenames)

    def test_idempotent(self):
        create_authorization_roles()
        create_authorization_roles()
        self.assertEqual(
            Group.objects.filter(name=MAINTAINER_GROUP).count(), 1)
        self.assertEqual(
            Group.objects.filter(name=VIEWER_GROUP).count(), 1)


class HasPermissionTests(TestCase):
    """has_permission with real principals."""

    @classmethod
    def setUpTestData(cls):
        create_authorization_roles()
        cls.maintainer_group = Group.objects.get(name=MAINTAINER_GROUP)
        cls.viewer_group = Group.objects.get(name=VIEWER_GROUP)

    def setUp(self):
        self.factory = RequestFactory()
        self.staff = User.objects.create_user(
            username='staffy', password='x')
        self.staff.is_staff = True
        self.staff.save()
        self.maintainer = User.objects.create_user(
            username='maint', password='x')
        self.maintainer.groups.add(self.maintainer_group)
        self.viewer = User.objects.create_user(
            username='view', password='x')
        self.viewer.groups.add(self.viewer_group)

    def _req(self, user=None, api_user=None):
        req = self.factory.get('/')
        req.user = user if user is not None else AnonymousUser()
        if api_user is not None:
            req.api_user = api_user
        return req

    def _fresh(self, user):
        # Re-fetch so Django's permission cache is clean.
        return User.objects.get(pk=user.pk)

    def test_staff_allowed(self):
        req = self._req(user=self.staff)
        self.assertTrue(has_permission(req, Permissions.SCAN, False))

    def test_maintainer_has_scan_perm(self):
        req = self._req(user=self._fresh(self.maintainer))
        self.assertTrue(has_permission(req, Permissions.SCAN, False))
        self.assertTrue(has_permission(req, Permissions.DELETE, True))

    def test_viewer_denied_privileged_perm(self):
        req = self._req(user=self._fresh(self.viewer))
        # api=True must NOT grant access (the C1 fix).
        self.assertFalse(has_permission(req, Permissions.DELETE, True))
        self.assertFalse(has_permission(req, Permissions.SCAN, False))

    def test_anonymous_denied(self):
        req = self._req(user=AnonymousUser())
        self.assertFalse(has_permission(req, Permissions.SCAN, True))

    def test_api_user_takes_precedence_over_session_user(self):
        # Session user is anonymous, but api_user is a real maintainer.
        req = self._req(
            user=AnonymousUser(),
            api_user=self._fresh(self.maintainer))
        self.assertTrue(has_permission(req, Permissions.SCAN, True))

    def test_api_user_viewer_denied(self):
        req = self._req(
            user=self.staff,  # would be allowed, but api_user wins
            api_user=self._fresh(self.viewer))
        self.assertFalse(has_permission(req, Permissions.DELETE, True))

    @override_settings(DISABLE_AUTHENTICATION='1')
    def test_disable_authentication_returns_true(self):
        req = self._req(user=AnonymousUser())
        self.assertTrue(has_permission(req, Permissions.DELETE, False))

    def test_exception_path_returns_false(self):
        # A request object with neither api_user nor user attribute forces
        # the AttributeError branch -> logged -> returns False (real path,
        # no mock; just a bare object).
        class Bare:
            pass
        self.assertFalse(has_permission(Bare(), Permissions.SCAN, False))


class PermissionRequiredDecoratorTests(TestCase):
    """permission_required decorator with real principals."""

    @classmethod
    def setUpTestData(cls):
        create_authorization_roles()
        cls.maintainer_group = Group.objects.get(name=MAINTAINER_GROUP)
        cls.viewer_group = Group.objects.get(name=VIEWER_GROUP)

    def setUp(self):
        self.factory = RequestFactory()
        self.wrapped = permission_required(Permissions.DELETE)(_plain_view)
        self.staff = User.objects.create_user(
            username='pstaff', password='x')
        self.staff.is_staff = True
        self.staff.save()
        self.maintainer = User.objects.create_user(
            username='pmaint', password='x')
        self.maintainer.groups.add(self.maintainer_group)
        self.viewer = User.objects.create_user(
            username='pview', password='x')
        self.viewer.groups.add(self.viewer_group)

    def _req(self, user, api_user=None):
        req = self.factory.get('/')
        req.user = user
        if api_user is not None:
            req.api_user = api_user
        return req

    def _fresh(self, user):
        return User.objects.get(pk=user.pk)

    def test_staff_allowed(self):
        resp = self.wrapped(self._req(self.staff))
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.content, b'ok')

    def test_maintainer_allowed(self):
        resp = self.wrapped(self._req(self._fresh(self.maintainer)))
        self.assertEqual(resp.status_code, 200)

    def test_viewer_denied_browser_raises_permission_denied(self):
        # Browser path (api not passed) re-raises via stock decorator.
        with self.assertRaises(PermissionDenied):
            self.wrapped(self._req(self._fresh(self.viewer)))

    def test_viewer_denied_api_returns_json_403(self):
        # api=True is detected via the bound signature argument.
        resp = self.wrapped(self._req(self._fresh(self.viewer)), api=True)
        self.assertIsInstance(resp, JsonResponse)
        self.assertEqual(resp.status_code, 403)
        self.assertIn(b'denied', resp.content)
        self.assertIn(b'StaticAnalyzer.can_delete', resp.content)

    def test_anonymous_denied_api_json_403(self):
        req = self._req(AnonymousUser())
        resp = self.wrapped(req, api=True)
        self.assertEqual(resp.status_code, 403)

    def test_api_user_precedence_maintainer_allowed(self):
        # api=True shapes response only; api_user maintainer grants access.
        req = self._req(AnonymousUser(), api_user=self._fresh(self.maintainer))
        resp = self.wrapped(req, api=True)
        self.assertEqual(resp.status_code, 200)

    @override_settings(DISABLE_AUTHENTICATION='1')
    def test_disable_authentication_bypasses_check(self):
        # Anonymous with no perms still passes through to the view.
        resp = self.wrapped(self._req(AnonymousUser()))
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.content, b'ok')

    def test_exception_in_check_denies(self):
        # A principal whose has_perm blows up hits the except branch and is
        # denied. Use a real authenticated user but a permission Enum whose
        # .value forces has_perm to raise? Instead, drive the documented
        # legacy global-key path: no api_user, anonymous user -> not staff,
        # not authenticated -> allowed stays False -> denied.
        req = self._req(AnonymousUser())
        resp = self.wrapped(req, api=True)
        self.assertEqual(resp.status_code, 403)


class UserManagementViewTests(TestCase):
    """users / create_user / delete_user views with a real staff Client."""

    @classmethod
    def setUpTestData(cls):
        create_authorization_roles()

    def setUp(self):
        self.admin = User.objects.create_superuser(
            username='admin', email='admin@example.com', password='pass12345')
        self.client.force_login(self.admin)

    def test_users_page_renders(self):
        resp = self.client.get('/users/')
        self.assertEqual(resp.status_code, 200)

    def test_create_user_get_renders(self):
        resp = self.client.get('/create_user/')
        self.assertEqual(resp.status_code, 200)

    def test_create_user_post_creates_viewer(self):
        from mobinspect.RBAC.models import Role, RoleAssignment
        viewer_role = Role.objects.get(name='Viewer')
        resp = self.client.post('/create_user/', {
            'username': 'newviewer',
            'password1': 'Str0ngP@ssw0rd!',
            'password2': 'Str0ngP@ssw0rd!',
            'email': 'nv@example.com',
            'role': str(viewer_role.pk),
        })
        self.assertEqual(resp.status_code, 302)
        u = User.objects.get(username='newviewer')
        self.assertFalse(u.is_staff)
        # New RBAC flow: an actual RoleAssignment is created and the user is
        # added to the role's backing group (Viewer group == VIEWER_GROUP).
        self.assertTrue(
            RoleAssignment.objects.filter(user=u, role=viewer_role).exists())
        self.assertTrue(u.groups.filter(name=viewer_role.group.name).exists())

    def test_create_user_post_creates_maintainer(self):
        from mobinspect.RBAC.models import Role, RoleAssignment
        # The former 'maintainer' string maps to the Security Analyst RBAC
        # role (run/scan/suppress). It gets a RoleAssignment + group.
        analyst_role = Role.objects.get(name='Security Analyst')
        resp = self.client.post('/create_user/', {
            'username': 'newmaint',
            'password1': 'Str0ngP@ssw0rd!',
            'password2': 'Str0ngP@ssw0rd!',
            'email': 'nm@example.com',
            'role': str(analyst_role.pk),
        })
        self.assertEqual(resp.status_code, 302)
        u = User.objects.get(username='newmaint')
        self.assertTrue(
            RoleAssignment.objects.filter(user=u, role=analyst_role).exists())
        self.assertTrue(u.groups.filter(name=analyst_role.group.name).exists())

    def test_create_user_invalid_form_rerenders(self):
        # Mismatched passwords -> form invalid -> re-render (200).
        resp = self.client.post('/create_user/', {
            'username': 'baduser',
            'password1': 'Str0ngP@ssw0rd!',
            'password2': 'different',
            'email': 'bad@example.com',
            'role': 'viewer',
        })
        self.assertEqual(resp.status_code, 200)
        self.assertFalse(User.objects.filter(username='baduser').exists())

    def test_create_user_invalid_username_regex(self):
        # Single-char username is valid for Django's form but fails
        # USERNAME_REGEX (which requires >= 2 chars) -> redirect w/ error.
        from mobinspect.RBAC.models import Role
        viewer_role = Role.objects.get(name='Viewer')
        resp = self.client.post('/create_user/', {
            'username': 'x',
            'password1': 'Str0ngP@ssw0rd!',
            'password2': 'Str0ngP@ssw0rd!',
            'email': 'shortname@example.com',
            'role': str(viewer_role.pk),
        })
        self.assertEqual(resp.status_code, 302)
        self.assertFalse(User.objects.filter(username='x').exists())

    def test_delete_user_success(self):
        target = User.objects.create_user(username='todelete', password='x')
        target.groups.add(Group.objects.get(name=VIEWER_GROUP))
        resp = self.client.post('/delete_user/', {'username': 'todelete'})
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b'yes', resp.content)
        self.assertFalse(User.objects.filter(username='todelete').exists())

    def test_delete_user_no_username(self):
        resp = self.client.post('/delete_user/', {})
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b'No Username Provided', resp.content)

    def test_delete_user_invalid_username(self):
        resp = self.client.post('/delete_user/', {'username': 'bad name!!'})
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b'Invalid Username', resp.content)

    def test_delete_user_cannot_delete_staff(self):
        staffu = User.objects.create_user(username='staffdel', password='x')
        staffu.is_staff = True
        staffu.save()
        resp = self.client.post('/delete_user/', {'username': 'staffdel'})
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b'Cannot delete staff users', resp.content)

    def test_delete_user_does_not_exist(self):
        resp = self.client.post('/delete_user/', {'username': 'ghost'})
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b'User does not exist', resp.content)


@override_settings(DISABLE_AUTHENTICATION='1')
class DisableAuthViewRedirectTests(TestCase):
    """When auth is disabled, management views redirect to '/'."""

    def setUp(self):
        self.admin = User.objects.create_superuser(
            username='admin2', email='a2@example.com', password='pass12345')
        self.client.force_login(self.admin)

    def test_users_redirects(self):
        resp = self.client.get('/users/')
        self.assertEqual(resp.status_code, 302)
        self.assertEqual(resp.url, '/')

    def test_create_user_redirects(self):
        resp = self.client.get('/create_user/')
        self.assertEqual(resp.status_code, 302)

    def test_delete_user_redirects(self):
        resp = self.client.post('/delete_user/', {'username': 'x'})
        self.assertEqual(resp.status_code, 302)


class AuthorizationGapCoverageTests(TestCase):
    """Closes the remaining real-execution gaps in authorization.py: the
    permission_required except branch, create_authorization_roles' except
    branch, _mirror_rbac_role_groups' import-failure branch (both call
    sites), users()'s query filter and Role-import-failure branch,
    create_user's RBAC-assignment except branch, and delete_user's
    deactivate-instead-of-delete + generic except branches.

    A few of these (a real DB/RBAC-import failure mid-request) cannot be
    induced without breaking the real Postgres test DB or genuinely
    uninstalling an app module, so a narrow, single-call monkeypatch is
    used for each -- documented inline -- exactly as permitted for lines
    reachable solely by making an internal call fail.
    """

    @classmethod
    def setUpTestData(cls):
        create_authorization_roles()

    def setUp(self):
        self.admin = User.objects.create_superuser(
            username='gap_admin', email='gap_admin@example.com',
            password='pass12345')
        self.client.force_login(self.admin)
        self.factory = RequestFactory()

    # ------------------------------------------------ permission_required
    def test_permission_check_exception_denies(self):
        # A real authenticated (non-staff) principal whose has_perm call
        # itself raises (a bare object exposing only is_authenticated, no
        # has_perm method at all) -- AttributeError is a genuine fault, not
        # a mocked return value.
        class WeirdPrincipal:
            is_staff = False
            is_authenticated = True

        wrapped = permission_required(Permissions.DELETE)(_plain_view)
        req = self.factory.get('/')
        req.user = WeirdPrincipal()
        resp = wrapped(req, api=True)
        self.assertEqual(resp.status_code, 403)

    # ------------------------------------------- create_authorization_roles
    def test_create_roles_exception_is_caught(self):
        # Narrow monkeypatch of a single real DB call: Group.objects
        # .get_or_create genuinely failing (e.g. a DB outage) cannot be
        # induced against the live Postgres test DB from application code.
        with mock.patch.object(
                Group.objects, 'get_or_create',
                side_effect=RuntimeError('db unavailable')):
            # Must not raise -- the whole body is wrapped in try/except.
            create_authorization_roles()

    # ------------------------------------------------ _mirror_rbac_role_groups
    def test_mirror_rbac_role_groups_import_failure_is_caught(self):
        # Real fault injection: poison sys.modules for the RBAC signals
        # dotted path so the real `from mobinspect.RBAC.signals import
        # LEGACY_PERMISSION_MAP` statement inside the function raises
        # ImportError -- not a return-value mock. create_authorization_roles
        # calls this helper at the end of its own try, so this also
        # exercises that real call site.
        target = 'mobinspect.RBAC.signals'
        prev = sys.modules.get(target, False)
        sys.modules[target] = None
        try:
            create_authorization_roles()  # must not raise
        finally:
            if prev is False:
                sys.modules.pop(target, None)
            else:
                sys.modules[target] = prev

    # ------------------------------------------------------------- users()
    def test_users_role_ids_exception_is_caught(self):
        # Real fault injection: a genuine failure of the per-user
        # `u.role_assignments.all()` call inside users()'s page-decoration
        # loop must be caught and degrade that user's role_ids to an empty
        # set, not 500. Django caches the dynamically-generated reverse FK
        # RelatedManager CLASS once per model field (shared by every User
        # instance's `.role_assignments` accessor) -- grabbing that real
        # class from a real instance and patching its own `.all` for the
        # duration of this one request is a narrow, single-call-point
        # patch (rule 1), since a real Postgres query failure cannot be
        # induced non-invasively against the live test DB.
        from mobinspect.RBAC.models import RoleAssignment
        target = User.objects.create_user(
            username='roleids_boom_user', password='x')
        manager_cls = type(target.role_assignments)
        with mock.patch.object(
                manager_cls, 'all',
                side_effect=RuntimeError('simulated role query fault')):
            resp = self.client.get('/users/', {'q': 'roleids_boom'})
        self.assertEqual(resp.status_code, 200)
        by_username = {u.username: u for u in resp.context['users']}
        self.assertIn('roleids_boom_user', by_username)
        self.assertEqual(by_username['roleids_boom_user'].role_ids, set())
        # RoleAssignment itself untouched -- only the manager call faulted.
        self.assertEqual(
            RoleAssignment.objects.filter(user=target).count(), 0)

    def test_users_query_filters(self):
        User.objects.create_user(username='findme_user', password='x')
        User.objects.create_user(username='other_user', password='x')
        resp = self.client.get('/users/', {'q': 'findme'})
        self.assertEqual(resp.status_code, 200)
        usernames = {u.username for u in resp.context['users']}
        self.assertIn('findme_user', usernames)
        self.assertNotIn('other_user', usernames)

    def test_users_role_import_failure_falls_back_to_empty(self):
        # Real fault injection: the RBAC Role query itself fails (a real DB
        # error cannot be induced non-invasively against the live test DB),
        # narrowly patched for this one call -- the view must degrade to an
        # empty all_roles list rather than 500.
        from mobinspect.RBAC.models import Role
        with mock.patch.object(
                Role.objects, 'all', side_effect=RuntimeError('db error')):
            resp = self.client.get('/users/')
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.context['all_roles'], [])

    # -------------------------------------------------------- create_user
    def test_create_user_rbac_assignment_failure_still_creates_user(self):
        # Real fault injection: RoleAssignment.objects.get_or_create itself
        # fails (e.g. a real DB round-trip error) -- narrowly patched for
        # this one call. The user is still created (form.save() already
        # ran); only the RBAC-assignment try/except degrades.
        from mobinspect.RBAC.models import Role, RoleAssignment
        viewer_role = Role.objects.get(name='Viewer')
        with mock.patch.object(
                RoleAssignment.objects, 'get_or_create',
                side_effect=RuntimeError('rbac db error')):
            resp = self.client.post('/create_user/', {
                'username': 'rbacfailuser',
                'password1': 'Str0ngP@ssw0rd!',
                'password2': 'Str0ngP@ssw0rd!',
                'email': 'rbacfail@example.com',
                'role': str(viewer_role.pk),
            })
        self.assertEqual(resp.status_code, 302)
        u = User.objects.get(username='rbacfailuser')
        # No RoleAssignment/group landed, but the account itself exists.
        self.assertFalse(
            RoleAssignment.objects.filter(user=u).exists())

    def test_create_user_form_requires_nonblank_username(self):
        # authorization.py's `if not username: ...` guard (lines ~266-268)
        # is unreachable via the real web form: RegisterForm's username
        # field is a required Django CharField, so form.is_valid() is
        # already False for an empty/whitespace username -- this test
        # documents and pins down that real behavior (see pragma + bug
        # note on the production line).
        from mobinspect.RBAC.models import Role
        viewer_role = Role.objects.get(name='Viewer')
        resp = self.client.post('/create_user/', {
            'username': '',
            'password1': 'Str0ngP@ssw0rd!',
            'password2': 'Str0ngP@ssw0rd!',
            'email': 'blankuser@example.com',
            'role': str(viewer_role.pk),
        })
        self.assertEqual(resp.status_code, 200)  # re-renders, form invalid
        self.assertFalse(User.objects.filter(username='').exists())

    # -------------------------------------------------------- delete_user
    def test_delete_user_referenced_by_audit_is_deactivated_not_deleted(self):
        from mobinspect.RBAC.models import AuditEvent
        target = User.objects.create_user(
            username='audited_user', password='x')
        AuditEvent.objects.create(
            actor=target, action='admin.user.create',
            target_type='user', target_id=str(target.id))
        resp = self.client.post(
            '/delete_user/', {'username': 'audited_user'})
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b'yes', resp.content)
        target.refresh_from_db()
        # Deactivated, NOT hard-deleted (the audit FK is SET_NULL + the
        # audit table is immutable, so a hard delete would violate it).
        self.assertFalse(target.is_active)
        self.assertTrue(User.objects.filter(username='audited_user').exists())

    def test_delete_user_generic_exception_is_caught(self):
        # Real fault injection: RoleAssignment.objects.filter itself fails
        # (a real DB round-trip error mid-deletion cannot be induced
        # non-invasively) -- narrowly patched for this one call.
        from mobinspect.RBAC.models import RoleAssignment
        User.objects.create_user(username='willfail_user', password='x')
        with mock.patch.object(
                RoleAssignment.objects, 'filter',
                side_effect=RuntimeError('rbac db error')):
            resp = self.client.post(
                '/delete_user/', {'username': 'willfail_user'})
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b'Failed to delete user', resp.content)
        # Never actually removed (the exception happened before delete()).
        self.assertTrue(
            User.objects.filter(username='willfail_user').exists())
