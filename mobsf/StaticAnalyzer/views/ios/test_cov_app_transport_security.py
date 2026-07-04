# -*- coding: utf_8 -*-
"""Real-execution unit tests for iOS ATS plist parsing.

No mocks. Pure dict parsing of NSAppTransportSecurity configurations
fed with crafted plist dictionaries; assertions on real return values.
"""
from django.test import SimpleTestCase

from mobsf.StaticAnalyzer.views.ios.app_transport_security import (
    check_transport_security,
)


def _issues(findings):
    return [f['issue'] for f in findings]


class ATSNoConfigTests(SimpleTestCase):

    def test_empty_plist_returns_empty(self):
        self.assertEqual(check_transport_security({}), [])

    def test_missing_ats_key_returns_empty(self):
        self.assertEqual(
            check_transport_security({'CFBundleName': 'App'}), [])

    def test_ats_key_present_but_none(self):
        # Key present but value falsy -> no findings.
        self.assertEqual(
            check_transport_security({'NSAppTransportSecurity': None}), [])

    def test_ats_empty_dict(self):
        self.assertEqual(
            check_transport_security({'NSAppTransportSecurity': {}}), [])


class ATSArbitraryLoadsTests(SimpleTestCase):

    def test_allows_arbitrary_loads(self):
        p = {'NSAppTransportSecurity': {'NSAllowsArbitraryLoads': True}}
        res = check_transport_security(p)
        self.assertEqual(len(res), 1)
        self.assertIn('AllowsArbitraryLoads is allowed', res[0]['issue'])
        self.assertEqual(res[0]['severity'], 'high')

    def test_allows_arbitrary_loads_for_media(self):
        p = {'NSAppTransportSecurity':
             {'NSAllowsArbitraryLoadsForMedia': True}}
        res = check_transport_security(p)
        self.assertEqual(_issues(res), ['Insecure media load is allowed'])
        self.assertEqual(res[0]['severity'], 'high')

    def test_allows_arbitrary_loads_in_webcontent(self):
        p = {'NSAppTransportSecurity':
             {'NSAllowsArbitraryLoadsInWebContent': True}}
        res = check_transport_security(p)
        self.assertEqual(_issues(res), ['Insecure WebView load is allowed'])

    def test_allows_local_networking(self):
        p = {'NSAppTransportSecurity': {'NSAllowsLocalNetworking': True}}
        res = check_transport_security(p)
        self.assertEqual(
            _issues(res), ['Insecure local networking is allowed'])

    def test_all_arbitrary_flags_together(self):
        p = {'NSAppTransportSecurity': {
            'NSAllowsArbitraryLoads': True,
            'NSAllowsArbitraryLoadsForMedia': True,
            'NSAllowsArbitraryLoadsInWebContent': True,
            'NSAllowsLocalNetworking': True,
        }}
        res = check_transport_security(p)
        self.assertEqual(len(res), 4)

    def test_flags_false_produce_nothing(self):
        p = {'NSAppTransportSecurity': {
            'NSAllowsArbitraryLoads': False,
            'NSAllowsArbitraryLoadsForMedia': False,
            'NSAllowsArbitraryLoadsInWebContent': False,
            'NSAllowsLocalNetworking': False,
        }}
        self.assertEqual(check_transport_security(p), [])


class ATSExceptionDomainListTests(SimpleTestCase):

    def test_exception_domains_summary_finding(self):
        p = {'NSAppTransportSecurity': {'NSExceptionDomains': {
            'example.com': {},
            'test.org': {},
        }}}
        res = check_transport_security(p)
        # First finding is the info summary of domain keys.
        self.assertEqual(res[0]['issue'], 'NSExceptionDomains')
        self.assertEqual(res[0]['severity'], 'info')
        self.assertIn('example.com', res[0]['description'])
        self.assertIn('test.org', res[0]['description'])

    def test_non_dict_config_skipped(self):
        p = {'NSAppTransportSecurity': {'NSExceptionDomains': {
            'example.com': 'not-a-dict',
        }}}
        res = check_transport_security(p)
        # Only the summary finding; string config is skipped.
        self.assertEqual(_issues(res), ['NSExceptionDomains'])


class ATSInsecureHTTPLoadsTests(SimpleTestCase):

    def test_insecure_http_loads_current_key(self):
        p = {'NSAppTransportSecurity': {'NSExceptionDomains': {
            'insecure.com': {'NSExceptionAllowsInsecureHTTPLoads': True},
        }}}
        res = check_transport_security(p)
        self.assertIn(
            'Insecure communication to insecure.com is allowed', _issues(res))

    def test_insecure_http_loads_temporary_legacy_key(self):
        p = {'NSAppTransportSecurity': {'NSExceptionDomains': {
            'legacy.com': {
                'NSTemporaryExceptionAllowsInsecureHTTPLoads': True},
        }}}
        res = check_transport_security(p)
        self.assertIn(
            'Insecure communication to legacy.com is allowed', _issues(res))

    def test_insecure_http_loads_thirdparty_legacy_key(self):
        p = {'NSAppTransportSecurity': {'NSExceptionDomains': {
            'third.com': {
                'NSThirdPartyExceptionAllowsInsecureHTTPLoads': True},
        }}}
        res = check_transport_security(p)
        self.assertIn(
            'Insecure communication to third.com is allowed', _issues(res))

    def test_localhost_insecure_loads_skipped(self):
        p = {'NSAppTransportSecurity': {'NSExceptionDomains': {
            'localhost': {'NSExceptionAllowsInsecureHTTPLoads': True},
        }}}
        res = check_transport_security(p)
        # localhost skipped -> no insecure communication finding for it.
        # Also CT default (NO) still fires warning, so assert insecure absent.
        self.assertNotIn(
            'Insecure communication to localhost is allowed', _issues(res))

    def test_loopback_ip_insecure_loads_skipped(self):
        p = {'NSAppTransportSecurity': {'NSExceptionDomains': {
            '127.0.0.1': {'NSExceptionAllowsInsecureHTTPLoads': True},
        }}}
        res = check_transport_security(p)
        self.assertNotIn(
            'Insecure communication to 127.0.0.1 is allowed', _issues(res))


class ATSSubdomainsTests(SimpleTestCase):

    def test_includes_subdomains_true(self):
        p = {'NSAppTransportSecurity': {'NSExceptionDomains': {
            'example.com': {'NSIncludesSubdomains': True},
        }}}
        res = check_transport_security(p)
        self.assertIn(
            'NSIncludesSubdomains set to TRUE for example.com', _issues(res))

    def test_includes_subdomains_false_no_finding(self):
        p = {'NSAppTransportSecurity': {'NSExceptionDomains': {
            'example.com': {'NSIncludesSubdomains': False},
        }}}
        res = check_transport_security(p)
        self.assertNotIn(
            'NSIncludesSubdomains set to TRUE for example.com', _issues(res))


class ATSMinimumTLSVersionTests(SimpleTestCase):

    def _run(self, tls, key='NSExceptionMinimumTLSVersion'):
        p = {'NSAppTransportSecurity': {'NSExceptionDomains': {
            'example.com': {key: tls},
        }}}
        return check_transport_security(p)

    def _tls_finding(self, res):
        for f in res:
            if f['issue'].startswith('NSExceptionMinimumTLSVersion'):
                return f
        return None

    def test_tls_1_0_high(self):
        f = self._tls_finding(self._run('TLSv1.0'))
        self.assertIsNotNone(f)
        self.assertEqual(f['severity'], 'high')

    def test_tls_1_1_high(self):
        f = self._tls_finding(self._run('TLSv1.1'))
        self.assertEqual(f['severity'], 'high')

    def test_tls_1_2_warning(self):
        f = self._tls_finding(self._run('TLSv1.2'))
        self.assertEqual(f['severity'], 'warning')

    def test_tls_1_3_secure(self):
        f = self._tls_finding(self._run('TLSv1.3'))
        self.assertEqual(f['severity'], 'secure')

    def test_tls_unknown_value_info(self):
        f = self._tls_finding(self._run('TLSv9.9'))
        self.assertEqual(f['severity'], 'info')

    def test_tls_legacy_temporary_key(self):
        f = self._tls_finding(
            self._run('TLSv1.0', key='NSTemporaryExceptionMinimumTLSVersion'))
        self.assertIsNotNone(f)
        self.assertEqual(f['severity'], 'high')

    def test_tls_none_no_finding(self):
        # No TLS key at all -> inc_min_tls None -> no TLS finding.
        p = {'NSAppTransportSecurity': {'NSExceptionDomains': {
            'example.com': {},
        }}}
        res = check_transport_security(p)
        self.assertIsNone(self._tls_finding(res))


class ATSForwardSecrecyTests(SimpleTestCase):

    def _fs_finding(self, res):
        for f in res:
            if f['issue'].startswith('NSExceptionRequiresForwardSecrecy'):
                return f
        return None

    def test_forward_secrecy_no_current_key(self):
        p = {'NSAppTransportSecurity': {'NSExceptionDomains': {
            'example.com': {'NSExceptionRequiresForwardSecrecy': 'NO'},
        }}}
        f = self._fs_finding(check_transport_security(p))
        self.assertIsNotNone(f)
        self.assertEqual(f['severity'], 'high')

    def test_forward_secrecy_no_temporary_key(self):
        p = {'NSAppTransportSecurity': {'NSExceptionDomains': {
            'example.com': {
                'NSTemporaryExceptionRequiresForwardSecrecy': 'NO'},
        }}}
        f = self._fs_finding(check_transport_security(p))
        self.assertEqual(f['severity'], 'high')

    def test_forward_secrecy_no_thirdparty_key(self):
        p = {'NSAppTransportSecurity': {'NSExceptionDomains': {
            'example.com': {
                'NSThirdPartyExceptionRequiresForwardSecrecy': 'NO'},
        }}}
        f = self._fs_finding(check_transport_security(p))
        self.assertEqual(f['severity'], 'high')

    def test_forward_secrecy_yes_no_finding(self):
        # cur == 'YES' is truthy but 'NO' not in list -> no finding.
        p = {'NSAppTransportSecurity': {'NSExceptionDomains': {
            'example.com': {'NSExceptionRequiresForwardSecrecy': 'YES'},
        }}}
        f = self._fs_finding(check_transport_security(p))
        self.assertIsNone(f)


class ATSCertificateTransparencyTests(SimpleTestCase):

    def _ct_finding(self, res):
        for f in res:
            if f['issue'].startswith('NSRequiresCertificateTransparency'):
                return f
        return None

    def test_ct_default_missing_warning(self):
        # No CT key -> default False -> warning finding.
        p = {'NSAppTransportSecurity': {'NSExceptionDomains': {
            'example.com': {},
        }}}
        f = self._ct_finding(check_transport_security(p))
        self.assertIsNotNone(f)
        self.assertIn('set to NO', f['issue'])
        self.assertEqual(f['severity'], 'warning')

    def test_ct_explicit_no_warning(self):
        p = {'NSAppTransportSecurity': {'NSExceptionDomains': {
            'example.com': {'NSRequiresCertificateTransparency': 'NO'},
        }}}
        f = self._ct_finding(check_transport_security(p))
        self.assertEqual(f['severity'], 'warning')

    def test_ct_yes_secure(self):
        p = {'NSAppTransportSecurity': {'NSExceptionDomains': {
            'example.com': {'NSRequiresCertificateTransparency': 'YES'},
        }}}
        f = self._ct_finding(check_transport_security(p))
        self.assertIsNotNone(f)
        self.assertIn('set to YES', f['issue'])
        self.assertEqual(f['severity'], 'secure')


class ATSCombinedRealisticTests(SimpleTestCase):

    def test_full_insecure_domain_configuration(self):
        p = {'NSAppTransportSecurity': {
            'NSAllowsArbitraryLoads': True,
            'NSExceptionDomains': {
                'insecure.example.com': {
                    'NSExceptionAllowsInsecureHTTPLoads': True,
                    'NSIncludesSubdomains': True,
                    'NSExceptionMinimumTLSVersion': 'TLSv1.0',
                    'NSExceptionRequiresForwardSecrecy': 'NO',
                    'NSRequiresCertificateTransparency': 'NO',
                },
            },
        }}
        res = check_transport_security(p)
        issues = _issues(res)
        self.assertIn(
            'App Transport Security AllowsArbitraryLoads is allowed', issues)
        self.assertIn('NSExceptionDomains', issues)
        self.assertIn(
            'Insecure communication to insecure.example.com is allowed',
            issues)
        self.assertIn(
            'NSIncludesSubdomains set to TRUE for insecure.example.com',
            issues)
        # High-severity count sanity: arbitrary + insecure http + tls + fs.
        highs = [f for f in res if f['severity'] == 'high']
        self.assertGreaterEqual(len(highs), 4)

    def test_secure_domain_configuration(self):
        p = {'NSAppTransportSecurity': {'NSExceptionDomains': {
            'secure.example.com': {
                'NSExceptionMinimumTLSVersion': 'TLSv1.3',
                'NSRequiresCertificateTransparency': 'YES',
            },
        }}}
        res = check_transport_security(p)
        severities = {f['severity'] for f in res}
        self.assertIn('secure', severities)
        self.assertNotIn('high', severities)

    def test_multiple_exception_domains(self):
        p = {'NSAppTransportSecurity': {'NSExceptionDomains': {
            'a.com': {'NSExceptionAllowsInsecureHTTPLoads': True},
            'b.com': {'NSExceptionMinimumTLSVersion': 'TLSv1.2'},
        }}}
        res = check_transport_security(p)
        issues = _issues(res)
        self.assertIn('Insecure communication to a.com is allowed', issues)
        self.assertTrue(
            any('TLSv1.2' in i and 'b.com' in i for i in issues))
