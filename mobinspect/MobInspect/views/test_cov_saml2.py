"""Real-execution unit tests for mobinspect.MobInspect.views.saml2 (NO mocks)."""
from django.test import (
    RequestFactory,
    TestCase,
    override_settings,
)

from mobinspect.MobInspect.views import saml2
from mobinspect.MobInspect.views.authorization import (
    MAINTAINER_GROUP,
    VIEWER_GROUP,
)


# Minimal valid IdP settings so OneLogin_Saml2_Auth can be constructed
# without any network round-trip (IDP_METADATA_URL disabled).
IDP_SETTINGS = dict(
    IDP_METADATA_URL=None,
    IDP_ENTITY_ID='https://idp.example.com/metadata',
    IDP_SSO_URL='https://idp.example.com/sso',
    IDP_X509CERT=(
        'MIICCzCCAXQCCQDBcvxKvA3PDANBgkqhkiG9w0BAQsFADBFMQswCQYDVQQG'
        'EwJVUzETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50ZXJuZXQ'),
    IDP_IS_ADFS='0',
    SP_HOST=None,
    DISABLE_AUTHENTICATION=None,
)

# Same, but with a real-looking SP host so OneLogin accepts the ACS URL
# (the default Django test host 'testserver' is rejected as invalid).
IDP_SETTINGS_SP = {**IDP_SETTINGS, 'SP_HOST': 'https://sp.example.com'}


class PureHelpersTests(TestCase):
    """Pure functions with no external deps."""

    def test_get_url_components_with_port(self):
        scheme, netloc, port = saml2.get_url_components(
            'https://example.com:8443/acs')
        self.assertEqual(scheme, 'https')
        self.assertEqual(netloc, 'example.com:8443')
        self.assertEqual(port, 8443)

    def test_get_url_components_no_port(self):
        scheme, netloc, port = saml2.get_url_components(
            'http://example.com/acs')
        self.assertEqual(scheme, 'http')
        self.assertEqual(netloc, 'example.com')
        self.assertIsNone(port)

    def test_get_user_role_maintainer(self):
        # Case-insensitive substring match on MAINTAINER_GROUP.
        role = saml2.get_user_role([MAINTAINER_GROUP.upper(), 'other'])
        self.assertEqual(role, MAINTAINER_GROUP)

    def test_get_user_role_viewer_default(self):
        role = saml2.get_user_role(['some-random-group', 'another'])
        self.assertEqual(role, VIEWER_GROUP)

    def test_get_user_role_empty(self):
        self.assertEqual(saml2.get_user_role([]), VIEWER_GROUP)


class GetRedirectUrlTests(TestCase):
    """get_redirect_url reads req['post_data'] (a QueryDict)."""

    def _req(self, post=None):
        rf = RequestFactory()
        request = rf.post('/sso/acs/', data=post or {})
        with override_settings(**IDP_SETTINGS):
            return saml2.prepare_django_request(request)

    def test_no_relaystate_returns_root(self):
        req = self._req({})
        self.assertEqual(saml2.get_redirect_url(req), '/')

    def test_empty_relaystate_returns_root(self):
        req = self._req({'RelayState': ''})
        self.assertEqual(saml2.get_redirect_url(req), '/')

    def test_valid_relative_relaystate(self):
        req = self._req({'RelayState': '/recent_scans/'})
        self.assertEqual(saml2.get_redirect_url(req), '/recent_scans/')

    def test_open_redirect_relaystate_sanitized(self):
        # Absolute/protocol-relative URLs are rejected -> '/'.
        req = self._req({'RelayState': 'https://evil.example.com'})
        self.assertEqual(saml2.get_redirect_url(req), '/')
        req2 = self._req({'RelayState': '//evil.example.com'})
        self.assertEqual(saml2.get_redirect_url(req2), '/')


class PrepareDjangoRequestTests(TestCase):
    """prepare_django_request branch coverage with real requests."""

    def test_default_no_sp_host_http(self):
        rf = RequestFactory()
        request = rf.get('/sso/login/?next=/x/')
        with override_settings(**{**IDP_SETTINGS, 'SP_HOST': None}):
            res = saml2.prepare_django_request(request)
        self.assertEqual(res['https'], 'off')
        self.assertEqual(res['http_host'], 'testserver')
        self.assertEqual(res['sp_url'], 'http://testserver')
        self.assertFalse(res['lowercase_urlencoding'])
        self.assertIn('query_string', res)

    def test_sp_host_https_default_port(self):
        rf = RequestFactory()
        request = rf.get('/sso/login/')
        with override_settings(
                **{**IDP_SETTINGS, 'SP_HOST': 'https://sp.example.com/'}):
            res = saml2.prepare_django_request(request)
        self.assertEqual(res['https'], 'on')
        self.assertEqual(res['http_host'], 'sp.example.com')
        self.assertEqual(res['server_port'], 443)
        self.assertEqual(res['sp_url'], 'https://sp.example.com')

    def test_sp_host_http_default_port(self):
        rf = RequestFactory()
        request = rf.get('/sso/login/')
        with override_settings(
                **{**IDP_SETTINGS, 'SP_HOST': 'http://sp.example.com/'}):
            res = saml2.prepare_django_request(request)
        self.assertEqual(res['https'], 'off')
        self.assertEqual(res['server_port'], 80)

    def test_sp_host_explicit_port(self):
        rf = RequestFactory()
        request = rf.get('/sso/login/')
        with override_settings(
                **{**IDP_SETTINGS, 'SP_HOST': 'http://sp.example.com:8000/'}):
            res = saml2.prepare_django_request(request)
        self.assertEqual(res['server_port'], 8000)
        self.assertEqual(res['sp_url'], 'http://sp.example.com:8000')

    def test_adfs_lowercase_urlencoding(self):
        rf = RequestFactory()
        request = rf.get('/sso/login/')
        with override_settings(**{**IDP_SETTINGS, 'IDP_IS_ADFS': '1'}):
            res = saml2.prepare_django_request(request)
        self.assertTrue(res['lowercase_urlencoding'])


class InitSamlAuthAndReplayTests(TestCase):
    """init_saml_auth builds a real OneLogin auth; check_replay no-op path."""

    def test_init_saml_auth_returns_auth_and_login_url(self):
        rf = RequestFactory()
        request = rf.get('/sso/login/')
        with override_settings(**IDP_SETTINGS_SP):
            req = saml2.prepare_django_request(request)
            auth = saml2.init_saml_auth(req)
            # Real OneLogin auth object; login() builds a redirect URL
            # to the IdP SSO endpoint (no network).
            url = auth.login(return_to='/')
            self.assertTrue(url.startswith('https://idp.example.com/sso'))

    def test_check_replay_noop_without_assertion(self):
        rf = RequestFactory()
        request = rf.get('/sso/login/')
        with override_settings(**IDP_SETTINGS_SP):
            req = saml2.prepare_django_request(request)
            auth = saml2.init_saml_auth(req)
            # Fresh auth has no last assertion id -> no exception, no add.
            before = len(saml2.ASSERTION_IDS)
            saml2.check_replay(auth)
            self.assertEqual(len(saml2.ASSERTION_IDS), before)


class SamlLoginViewTests(TestCase):
    """saml_login view branches."""

    def test_login_disabled_authentication_redirects_root(self):
        rf = RequestFactory()
        request = rf.get('/sso/login/')
        with override_settings(
                **{**IDP_SETTINGS, 'DISABLE_AUTHENTICATION': '1'}):
            resp = saml2.saml_login(request)
        self.assertEqual(resp.status_code, 302)
        self.assertEqual(resp.url, '/')

    def test_login_redirects_to_idp(self):
        rf = RequestFactory()
        request = rf.get('/sso/login/?next=/recent_scans/')
        with override_settings(**IDP_SETTINGS_SP):
            resp = saml2.saml_login(request)
        # Redirect to the IdP SSO URL.
        self.assertEqual(resp.status_code, 302)
        self.assertTrue(resp.url.startswith('https://idp.example.com/sso'))

    def test_login_bad_settings_hits_error_branch(self):
        rf = RequestFactory()
        request = rf.get('/sso/login/')
        # Missing SSO URL/entity id -> OneLogin settings validation error
        # -> except branch -> error response (not a redirect).
        bad = {**IDP_SETTINGS, 'IDP_SSO_URL': '', 'IDP_ENTITY_ID': ''}
        with override_settings(**bad):
            resp = saml2.saml_login(request)
        self.assertNotEqual(resp.status_code, 302)


class SamlAcsViewTests(TestCase):
    """saml_acs view branches reachable without a real IdP response."""

    def test_acs_disabled_authentication_redirects_root(self):
        rf = RequestFactory()
        request = rf.post('/sso/acs/', data={})
        with override_settings(
                **{**IDP_SETTINGS, 'DISABLE_AUTHENTICATION': '1'}):
            resp = saml2.saml_acs(request)
        self.assertEqual(resp.status_code, 302)
        self.assertEqual(resp.url, '/')

    def test_acs_missing_saml_response_hits_error_branch(self):
        rf = RequestFactory()
        # No SAMLResponse in POST -> auth.process_response() raises
        # -> except branch -> error response (not a redirect).
        request = rf.post('/sso/acs/', data={'RelayState': '/'})
        with override_settings(**IDP_SETTINGS_SP):
            resp = saml2.saml_acs(request)
        self.assertNotEqual(resp.status_code, 302)
