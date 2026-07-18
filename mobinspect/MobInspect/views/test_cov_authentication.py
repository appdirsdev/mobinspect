# -*- coding: utf_8 -*-
"""Real-execution (STRICT no-mock) coverage tests for
mobinspect.MobInspect.views.authentication.

Every branch is exercised by driving the REAL Django views (login_view,
logout_view, change_password) and the REAL login_required decorator with a
real Django test Client/RequestFactory, real Users, and real settings
overrides (SSO config toggles, DISABLE_AUTHENTICATION). No mocks, no
monkeypatching of internal logic.
"""
from django.contrib.auth import get_user_model
from django.test import Client, RequestFactory, TestCase, override_settings

from mobinspect.MobInspect.views import authentication as auth


# A real-looking IdP config -- values only, no network round-trip is ever
# made by login_view/change_password (SAML network calls live in saml2.py).
SSO_SETTINGS = dict(
    IDP_METADATA_URL=None,
    IDP_SSO_URL='https://idp.example.com/sso',
    IDP_ENTITY_ID='https://idp.example.com/metadata',
    IDP_X509CERT='MIICfake',
)
NO_SSO_SETTINGS = dict(
    IDP_METADATA_URL=None,
    IDP_SSO_URL='',
    IDP_ENTITY_ID='',
    IDP_X509CERT='',
)


@override_settings(RATELIMIT_ENABLE=False, DISABLE_AUTHENTICATION=None)
class LoginRequiredDecoratorTests(TestCase):
    """login_required directly, real Users, real function signatures."""

    @classmethod
    def setUpTestData(cls):
        User = get_user_model()
        cls.user = User.objects.create_user(username='deco_user', password='x')

    def setUp(self):
        self.factory = RequestFactory()

    def test_api_kwarg_bypasses_web_auth(self):
        @auth.login_required
        def a_view(request, api=False):
            return 'called'
        req = self.factory.get('/x')
        req.user = None  # never consulted -- the api=True branch skips auth
        self.assertEqual(a_view(req, api=True), 'called')

    @override_settings(DISABLE_AUTHENTICATION='1')
    def test_disable_authentication_bypasses_web_auth(self):
        @auth.login_required
        def a_view(request):
            return 'called'
        req = self.factory.get('/x')
        req.user = None
        self.assertEqual(a_view(req), 'called')

    def test_web_call_without_auth_redirects_to_login(self):
        # Real (non-API) call through the Django Client -- anonymous user
        # must be redirected by the real `lg` (django login_required).
        @auth.login_required
        def a_view(request):
            from django.http import HttpResponse
            return HttpResponse('secret')
        req = self.factory.get('/x')
        from django.contrib.auth.models import AnonymousUser
        req.user = AnonymousUser()
        resp = a_view(req)
        self.assertEqual(resp.status_code, 302)

    def test_web_call_with_real_authenticated_user_passes_through(self):
        @auth.login_required
        def a_view(request):
            from django.http import HttpResponse
            return HttpResponse('secret')
        req = self.factory.get('/x')
        req.user = self.user
        resp = a_view(req)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.content, b'secret')


@override_settings(RATELIMIT_ENABLE=False)
class LoginViewTests(TestCase):
    """login_view: every real branch of the SSO/password/session logic."""

    @classmethod
    def setUpTestData(cls):
        User = get_user_model()
        cls.user = User.objects.create_user(
            username='login_user', password='real-pw-12345')

    def setUp(self):
        self.client = Client()

    @override_settings(DISABLE_AUTHENTICATION='1')
    def test_disable_authentication_redirects_root(self):
        resp = self.client.get('/login/')
        self.assertEqual(resp.status_code, 302)
        self.assertEqual(resp.url, '/')

    @override_settings(**NO_SSO_SETTINGS, DISABLE_AUTHENTICATION=None)
    def test_no_sso_allows_password_get_renders_form(self):
        resp = self.client.get('/login/')
        self.assertEqual(resp.status_code, 200)
        self.assertFalse(resp.context['sso'])
        self.assertTrue(resp.context['allow_pwd'])

    @override_settings(
        **SSO_SETTINGS, SP_ALLOW_PASSWORD='1', DISABLE_AUTHENTICATION=None)
    def test_sso_configured_with_password_allowed(self):
        resp = self.client.get('/login/')
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(resp.context['sso'])
        self.assertTrue(resp.context['allow_pwd'])

    @override_settings(
        **SSO_SETTINGS, SP_ALLOW_PASSWORD='0', DISABLE_AUTHENTICATION=None)
    def test_sso_configured_password_disallowed(self):
        resp = self.client.get('/login/')
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(resp.context['sso'])
        self.assertFalse(resp.context['allow_pwd'])

    @override_settings(**NO_SSO_SETTINGS, DISABLE_AUTHENTICATION=None)
    def test_authenticated_user_visiting_login_redirects(self):
        self.client.force_login(self.user)
        resp = self.client.get('/login/?next=/recent_scans/')
        self.assertEqual(resp.status_code, 302)
        self.assertEqual(resp.url, '/recent_scans/')

    @override_settings(
        **SSO_SETTINGS, SP_ALLOW_PASSWORD='0', DISABLE_AUTHENTICATION=None)
    def test_post_with_sso_and_password_disallowed_redirects_root(self):
        resp = self.client.post(
            '/login/', {'username': 'login_user', 'password': 'real-pw-12345'})
        self.assertEqual(resp.status_code, 302)
        self.assertEqual(resp.url, '/')
        # Never actually logged in.
        self.assertFalse(
            '_auth_user_id' in self.client.session)

    @override_settings(**NO_SSO_SETTINGS, DISABLE_AUTHENTICATION=None)
    def test_post_valid_credentials_logs_in_and_sets_session_flag(self):
        resp = self.client.post(
            '/login/', {'username': 'login_user', 'password': 'real-pw-12345'})
        self.assertEqual(resp.status_code, 302)
        self.assertEqual(resp.url, '/')
        self.assertTrue('_auth_user_id' in self.client.session)
        self.assertTrue(self.client.session.get('just_logged_in'))

    @override_settings(**NO_SSO_SETTINGS, DISABLE_AUTHENTICATION=None)
    def test_post_invalid_credentials_rerenders_form(self):
        resp = self.client.post(
            '/login/', {'username': 'login_user', 'password': 'totally-wrong'})
        self.assertEqual(resp.status_code, 200)
        self.assertFalse('_auth_user_id' in self.client.session)
        self.assertIn('form', resp.context)

    @override_settings(**NO_SSO_SETTINGS, DISABLE_AUTHENTICATION=None)
    def test_post_valid_credentials_honors_next_redirect(self):
        resp = self.client.post(
            '/login/?next=/help/',
            {'username': 'login_user', 'password': 'real-pw-12345'})
        self.assertEqual(resp.status_code, 302)
        self.assertEqual(resp.url, '/help/')


@override_settings(RATELIMIT_ENABLE=False, DISABLE_AUTHENTICATION=None)
class LogoutViewTests(TestCase):
    """logout_view: real session termination + redirect."""

    def test_logout_redirects_to_login_url(self):
        User = get_user_model()
        user = User.objects.create_user(username='logout_user', password='x')
        client = Client()
        client.force_login(user)
        self.assertTrue('_auth_user_id' in client.session)
        resp = client.get('/logout')
        self.assertEqual(resp.status_code, 302)
        # A real session logout -- the auth key is gone afterward.
        self.assertFalse('_auth_user_id' in client.session)


@override_settings(RATELIMIT_ENABLE=False, DISABLE_AUTHENTICATION=None)
class ChangePasswordViewTests(TestCase):
    """change_password: every real branch, including the audit-record call."""

    def setUp(self):
        User = get_user_model()
        self.user = User.objects.create_user(
            username='pw_user', password='old-real-pw-1')
        self.client = Client()
        self.client.force_login(self.user)

    @override_settings(DISABLE_AUTHENTICATION='1')
    def test_disable_authentication_redirects_root(self):
        resp = self.client.get('/change_password/')
        self.assertEqual(resp.status_code, 302)
        self.assertEqual(resp.url, '/')

    def test_get_renders_form(self):
        resp = self.client.get('/change_password/')
        self.assertEqual(resp.status_code, 200)
        self.assertIn('form', resp.context)

    def test_post_valid_change_updates_password_and_records_audit(self):
        from mobinspect.RBAC.models import AuditEvent
        before = AuditEvent.objects.count()
        resp = self.client.post('/change_password/', {
            'old_password': 'old-real-pw-1',
            'new_password1': 'Brand-New-Real-Pw-2',
            'new_password2': 'Brand-New-Real-Pw-2',
        })
        self.assertEqual(resp.status_code, 302)
        self.assertEqual(resp.url, '/change_password/')
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password('Brand-New-Real-Pw-2'))
        # A real audit record was created for the self-service reset.
        self.assertEqual(AuditEvent.objects.count(), before + 1)
        event = AuditEvent.objects.latest('id')
        self.assertEqual(event.action, 'admin.user.reset_password')
        self.assertTrue(event.metadata.get('self_service'))
        # The session survives the password change (update_session_auth_hash).
        resp2 = self.client.get('/change_password/')
        self.assertEqual(resp2.status_code, 200)

    def test_post_invalid_change_rerenders_with_error(self):
        resp = self.client.post('/change_password/', {
            'old_password': 'WRONG-old-password',
            'new_password1': 'Brand-New-Real-Pw-2',
            'new_password2': 'Brand-New-Real-Pw-2',
        })
        self.assertEqual(resp.status_code, 200)
        self.user.refresh_from_db()
        # Password never actually changed.
        self.assertTrue(self.user.check_password('old-real-pw-1'))
        messages = list(resp.context['messages'])
        self.assertTrue(
            any('correct the error' in str(m) for m in messages))
