"""Real-execution unit tests for mobinspect.MobInspect.views.saml2 (NO mocks)."""
import base64
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from datetime import datetime, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from onelogin.saml2.utils import OneLogin_Saml2_Utils
from onelogin.saml2.xml_utils import OneLogin_Saml2_XML

from django.contrib.auth.models import Group, User
from django.contrib.sessions.backends.db import SessionStore
from django.test import (
    RequestFactory,
    TestCase,
    override_settings,
)

from mobinspect.MobInspect.views import saml2
from mobinspect.MobInspect.views.authorization import (
    MAINTAINER_GROUP,
    VIEWER_GROUP,
    create_authorization_roles,
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

    def test_init_saml_auth_metadata_fetch_failure_is_caught(self):
        # IDP_METADATA_URL set -> init_saml_auth attempts a REAL fetch.
        # Point it at a loopback port nothing listens on (port 1) so the
        # real request fails FAST with connection-refused -- mirrors the
        # established convention in test_cov_apk_downloader.py's DEAD_URL
        # (a real socket that fails fast, never the actual internet). The
        # except branch logs and falls back to the static idp settings, so
        # init_saml_auth still returns a usable, real OneLogin auth object.
        rf = RequestFactory()
        request = rf.get('/sso/login/')
        settings_with_dead_metadata = {
            **IDP_SETTINGS_SP,
            'IDP_METADATA_URL': 'http://127.0.0.1:1/idp-metadata.xml',
        }
        with override_settings(**settings_with_dead_metadata):
            req = saml2.prepare_django_request(request)
            auth = saml2.init_saml_auth(req)
            # Falls back to the static idp settings (SSO URL still usable).
            url = auth.login(return_to='/')
            self.assertTrue(url.startswith('https://idp.example.com/sso'))

    def test_init_saml_auth_real_metadata_fetch_overrides_idp_settings(self):
        # Real success branch (line 78): IDP_METADATA_URL points at a real
        # background loopback HTTP server (127.0.0.1, OS-assigned port --
        # never the actual internet, exactly like DEAD_URL's real-socket
        # convention above, just serving a genuine 200 this time) that
        # returns genuine, well-formed SAML IdP metadata XML. OneLogin's
        # own OneLogin_Saml2_IdPMetadataParser.parse_remote() really
        # fetches and really parses it, producing a truthy idp_data whose
        # ['idp'] genuinely overwrites saml_settings['idp'] -- so the
        # resulting real OneLogin_Saml2_Auth reports the SSO URL from the
        # fetched metadata, not the static IDP_SETTINGS_SP fallback.
        metadata_xml = (
            '<?xml version="1.0"?>'
            '<md:EntityDescriptor '
            'xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" '
            'entityID="https://real-idp.example.com/metadata">'
            '<md:IDPSSODescriptor protocolSupportEnumeration='
            '"urn:oasis:names:tc:SAML:2.0:protocol">'
            '<md:SingleSignOnService '
            'Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" '
            'Location="https://real-idp.example.com/sso"/>'
            '</md:IDPSSODescriptor>'
            '</md:EntityDescriptor>'
        ).encode()

        class _Handler(BaseHTTPRequestHandler):
            def log_message(self, fmt, *args):
                pass

            def do_GET(self):
                self.send_response(200)
                self.send_header('Content-Type', 'application/xml')
                self.end_headers()
                self.wfile.write(metadata_xml)

        httpd = ThreadingHTTPServer(('127.0.0.1', 0), _Handler)
        port = httpd.server_address[1]
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(httpd.shutdown)
        self.addCleanup(httpd.server_close)

        rf = RequestFactory()
        request = rf.get('/sso/login/')
        settings_with_real_metadata = {
            **IDP_SETTINGS_SP,
            'IDP_METADATA_URL': f'http://127.0.0.1:{port}/idp-metadata.xml',
        }
        with override_settings(**settings_with_real_metadata):
            req = saml2.prepare_django_request(request)
            auth = saml2.init_saml_auth(req)
        # The real fetched metadata's SSO URL wins over the static settings.
        self.assertEqual(auth.get_sso_url(), 'https://real-idp.example.com/sso')

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

    def test_acs_well_formed_but_unsigned_response_is_not_authenticated(self):
        # A syntactically valid (parseable) SAMLResponse that carries no
        # signature at all -- onelogin's real OneLogin_Saml2_Response.is_valid()
        # unconditionally rejects any unsigned response (see
        # response.py: "No Signature found. SAML Response rejected"), so
        # process_response() completes without raising, but
        # auth.is_authenticated() is genuinely False -> saml_acs's own
        # 'SAML authentication failed.' branch -> caught by the outer
        # except -> non-redirect error response. No signing/crypto needed
        # for this one -- it is deliberately minimal.
        unsigned_xml = (
            '<samlp:Response '
            'xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
            'ID="_unsigned1" Version="2.0" '
            'IssueInstant="2024-01-01T00:00:00Z">'
            '<samlp:Status>'
            '<samlp:StatusCode '
            'Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>'
            '</samlp:Status>'
            '</samlp:Response>'
        )
        b64 = base64.b64encode(unsigned_xml.encode()).decode()
        rf = RequestFactory()
        request = rf.post('/sso/acs/', data={'SAMLResponse': b64})
        with override_settings(**IDP_SETTINGS_SP):
            resp = saml2.saml_acs(request)
        # check_replay(auth) ran (real line), auth.is_authenticated() is
        # really False, the real exception was raised and caught.
        self.assertNotEqual(resp.status_code, 302)


def _self_signed_cert_and_key():
    """A REAL self-signed RSA cert+key pair, generated once for this test
    module. Used to build a genuinely, cryptographically-signed SAML
    Response fixture below -- no mocking of onelogin's own signature
    verification, which unconditionally rejects unsigned assertions."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'test-idp')])
    now = datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption()).decode()
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    cert_bare = ''.join(cert_pem.splitlines()[1:-1])
    return key_pem, cert_pem, cert_bare


IDP_ENTITY_FOR_SIGNED = 'https://idp.example.com/metadata'
ACS_URL_FOR_SIGNED = 'https://sp.example.com/sso/acs/'


def _signed_saml_response_b64(cert_pem, key_pem, assertion_id, email=None,
                              role=None, recipient=ACS_URL_FOR_SIGNED):
    """Build a REAL, cryptographically-signed SAML Response XML (base64),
    matching exactly what init_saml_auth()'s strict settings require:
    correct Destination/Audience/Issuer, valid Conditions/SubjectConfirmation
    timestamps, and a genuine XML-DSig signature over the Assertion using
    OneLogin's own `add_sign` helper (the same routine a real IdP-side
    integration would use) -- so `validate_sign()` on the receiving end
    passes for real, not because of any mock.

    NOTE: the XML is deliberately built with NO whitespace between
    elements. onelogin's strict-mode XSD validation treats even
    whitespace-only text nodes between certain elements as invalid
    "character content" for element-only content models.
    """
    now = datetime.utcnow()
    fmt = '%Y-%m-%dT%H:%M:%SZ'
    issue_instant = now.strftime(fmt)
    not_before = (now - timedelta(minutes=5)).strftime(fmt)
    not_on_or_after = (now + timedelta(minutes=5)).strftime(fmt)

    attrs = ''
    if email is not None:
        attrs += (
            '<saml:Attribute Name="email">'
            f'<saml:AttributeValue>{email}</saml:AttributeValue>'
            '</saml:Attribute>')
    if role is not None:
        attrs += (
            '<saml:Attribute Name="role">'
            f'<saml:AttributeValue>{role}</saml:AttributeValue>'
            '</saml:Attribute>')

    assertion_xml = (
        '<saml:Assertion '
        'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" '
        f'ID="{assertion_id}" IssueInstant="{issue_instant}" '
        'Version="2.0">'
        f'<saml:Issuer>{IDP_ENTITY_FOR_SIGNED}</saml:Issuer>'
        '<saml:Subject>'
        '<saml:NameID>saml_user@example.com</saml:NameID>'
        '<saml:SubjectConfirmation '
        'Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">'
        f'<saml:SubjectConfirmationData NotOnOrAfter="{not_on_or_after}" '
        f'Recipient="{recipient}"/>'
        '</saml:SubjectConfirmation>'
        '</saml:Subject>'
        f'<saml:Conditions NotBefore="{not_before}" '
        f'NotOnOrAfter="{not_on_or_after}">'
        '<saml:AudienceRestriction>'
        f'<saml:Audience>{ACS_URL_FOR_SIGNED}</saml:Audience>'
        '</saml:AudienceRestriction>'
        '</saml:Conditions>'
        f'<saml:AuthnStatement AuthnInstant="{issue_instant}" '
        'SessionIndex="_session1">'
        '<saml:AuthnContext><saml:AuthnContextClassRef>'
        'urn:oasis:names:tc:SAML:2.0:ac:classes:Password'
        '</saml:AuthnContextClassRef></saml:AuthnContext>'
        '</saml:AuthnStatement>'
        f'<saml:AttributeStatement>{attrs}</saml:AttributeStatement>'
        '</saml:Assertion>'
    )
    signed_assertion = OneLogin_Saml2_Utils.add_sign(
        assertion_xml, key_pem, cert_pem)
    # Re-serialize through lxml to collapse xmlsec's own formatting back
    # to a single line (same whitespace-sensitivity as noted above).
    signed_compact = OneLogin_Saml2_XML.to_string(
        OneLogin_Saml2_XML.to_etree(signed_assertion)).decode()

    response_xml = (
        '<samlp:Response '
        'xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
        'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" '
        f'ID="_response_{assertion_id}" Version="2.0" '
        f'IssueInstant="{issue_instant}" Destination="{recipient}">'
        f'<saml:Issuer>{IDP_ENTITY_FOR_SIGNED}</saml:Issuer>'
        '<samlp:Status><samlp:StatusCode '
        'Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>'
        '</samlp:Status>'
        f'{signed_compact}'
        '</samlp:Response>'
    )
    return base64.b64encode(response_xml.encode()).decode()


@override_settings(RATELIMIT_ENABLE=False)
class SamlAcsSignedAssertionTests(TestCase):
    """saml_acs's REAL authenticated success path -- driven by a genuinely
    signed SAML assertion (self-signed test cert/key generated once for
    this class), not a mock. This is the only way to reach
    auth.is_authenticated() == True: onelogin's real validate_sign()
    unconditionally requires a valid XML-DSig signature matching the
    configured IDP_X509CERT, verified for real here.
    """

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.key_pem, cls.cert_pem, cls.cert_bare = _self_signed_cert_and_key()
        cls.settings_override = {
            **IDP_SETTINGS_SP,
            'IDP_ENTITY_ID': IDP_ENTITY_FOR_SIGNED,
            'IDP_X509CERT': cls.cert_bare,
        }

    def setUp(self):
        # saml_acs looks up real Group rows by name (MAINTAINER_GROUP /
        # VIEWER_GROUP) -- these must exist for real, same as
        # authorization.py's own create_authorization_roles() sets up.
        create_authorization_roles()
        self.rf = RequestFactory()

    def _post(self, b64):
        request = self.rf.post('/sso/acs/', data={'SAMLResponse': b64})
        # A plain RequestFactory request has no `.session` (that's normally
        # wired by SessionMiddleware) -- django.contrib.auth.login() and the
        # 'just_logged_in' flag both need a real session store, same as
        # test_cov_home_stats.py's `authed_request` fixture does.
        request.session = SessionStore()
        with override_settings(**self.settings_override):
            return saml2.saml_acs(request)

    def test_valid_signed_response_creates_new_user_and_logs_in(self):
        b64 = _signed_saml_response_b64(
            self.cert_pem, self.key_pem, assertion_id='_assertion_new',
            email='newsaml@example.com', role=VIEWER_GROUP)
        self.assertFalse(User.objects.filter(username='newsaml@example.com').exists())
        resp = self._post(b64)
        self.assertEqual(resp.status_code, 302)
        self.assertEqual(resp.url, '/')
        user = User.objects.get(username='newsaml@example.com')
        self.assertFalse(user.is_staff)
        self.assertTrue(user.groups.filter(name=VIEWER_GROUP).exists())

    def test_valid_signed_response_existing_user_resets_groups(self):
        existing = User.objects.create_user(
            username='existingsaml@example.com',
            email='existingsaml@example.com')
        # Pre-attach the MAINTAINER group -- a Viewer-role assertion must
        # CLEAR it and set only Viewer (real user.groups.clear() branch).
        existing.groups.add(Group.objects.get(name=MAINTAINER_GROUP))
        b64 = _signed_saml_response_b64(
            self.cert_pem, self.key_pem, assertion_id='_assertion_existing',
            email='existingsaml@example.com', role=VIEWER_GROUP)
        resp = self._post(b64)
        self.assertEqual(resp.status_code, 302)
        existing.refresh_from_db()
        self.assertEqual(
            list(existing.groups.values_list('name', flat=True)),
            [VIEWER_GROUP])

    def test_missing_email_attribute_hits_error_branch(self):
        b64 = _signed_saml_response_b64(
            self.cert_pem, self.key_pem, assertion_id='_assertion_noemail',
            email=None, role=VIEWER_GROUP)
        resp = self._post(b64)
        # 'email attribute not found' -> caught by the outer except ->
        # error response, not a redirect to '/'.
        self.assertNotEqual(resp.status_code, 302)

    def test_missing_role_attribute_hits_error_branch(self):
        b64 = _signed_saml_response_b64(
            self.cert_pem, self.key_pem, assertion_id='_assertion_norole',
            email='norole@example.com', role=None)
        resp = self._post(b64)
        self.assertNotEqual(resp.status_code, 302)

    def test_replay_of_same_assertion_id_is_rejected(self):
        # The FIRST post is a real, valid, first-time login.
        b64 = _signed_saml_response_b64(
            self.cert_pem, self.key_pem, assertion_id='_assertion_replay',
            email='replay@example.com', role=VIEWER_GROUP)
        first = self._post(b64)
        self.assertEqual(first.status_code, 302)
        # The SECOND post replays the exact same (still well-formed, still
        # validly signed) assertion id -- check_replay's real
        # ASSERTION_IDS membership check now raises 'Replay attack
        # detected.', caught by the outer except -> not a redirect.
        second = self._post(b64)
        self.assertNotEqual(second.status_code, 302)
