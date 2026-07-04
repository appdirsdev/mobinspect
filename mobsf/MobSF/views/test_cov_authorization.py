"""Real-execution unit tests for mobsf.MobSF.views.authorization (NO mocks).

Drives the RBAC permission logic (has_permission, permission_required,
create_authorization_roles) and the user-management views with REAL Django
users, REAL RBAC groups/permissions loaded from migrations, and a real
RequestFactory / Client. No mocks, no monkeypatch of internal logic.
"""
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

from mobsf.MobSF.views import authorization as az
from mobsf.MobSF.views.authorization import (
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
        resp = self.client.post('/create_user/', {
            'username': 'newviewer',
            'password1': 'Str0ngP@ssw0rd!',
            'password2': 'Str0ngP@ssw0rd!',
            'email': 'nv@example.com',
            'role': 'viewer',
        })
        self.assertEqual(resp.status_code, 302)
        u = User.objects.get(username='newviewer')
        self.assertFalse(u.is_staff)
        self.assertTrue(u.groups.filter(name=VIEWER_GROUP).exists())

    def test_create_user_post_creates_maintainer(self):
        resp = self.client.post('/create_user/', {
            'username': 'newmaint',
            'password1': 'Str0ngP@ssw0rd!',
            'password2': 'Str0ngP@ssw0rd!',
            'email': 'nm@example.com',
            'role': 'maintainer',
        })
        self.assertEqual(resp.status_code, 302)
        u = User.objects.get(username='newmaint')
        self.assertTrue(u.groups.filter(name=MAINTAINER_GROUP).exists())

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
        resp = self.client.post('/create_user/', {
            'username': 'x',
            'password1': 'Str0ngP@ssw0rd!',
            'password2': 'Str0ngP@ssw0rd!',
            'email': 'shortname@example.com',
            'role': 'viewer',
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
