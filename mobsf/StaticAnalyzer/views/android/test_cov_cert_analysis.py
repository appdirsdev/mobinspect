# -*- coding: utf_8 -*-
"""Real-execution (no-mock) tests for cert_analysis.

Drives the real signed test_files/android.apk certificate through the real
androguard parser, the real apksigner.jar, real apksigtool and real
cryptography key parsing. No mocks, no monkeypatching.
"""
import os
import shutil
import tempfile
import zipfile
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec
from cryptography import x509

from django.test import TestCase

from mobsf.StaticAnalyzer.tools.androguard4 import apk
from mobsf.StaticAnalyzer.views.android.cert_analysis import (
    apksigtool_cert,
    cert_info,
    get_cert_data,
    get_cert_details,
    get_hardcoded_cert_keystore,
    get_pub_key_details,
    get_signature_versions,
)

REPO_ROOT = Path(__file__).resolve().parents[4]
APK_PATH = (REPO_ROOT / 'test_files' / 'android.apk').as_posix()
TOOLS_DIR = (REPO_ROOT / 'mobsf' / 'StaticAnalyzer' / 'tools').as_posix()
CHECKSUM = 'testcert0000000000000000000000ab'


def _load_apk():
    return apk.APK(APK_PATH)


def _first_cert_der():
    a = _load_apk()
    return a.get_certificate_der(a.get_signature_names()[0])


class HardcodedCertKeystoreTests(TestCase):

    def test_finds_certs_and_keystores(self):
        app_dic = {
            'md5': CHECKSUM,
            'files': [
                'assets/server.pem',
                'res/keys/client.der',
                'secret.p12',
                'store/release.jks',
                'store/debug.bks',
                'noextension',
                'code.smali',
            ],
        }
        get_hardcoded_cert_keystore(app_dic)
        findings = app_dic['file_analysis']
        # One certificate finding + one keystore finding.
        self.assertEqual(len(findings), 2)
        cert_finding = findings[0]
        self.assertIn('Certificate/Key files', cert_finding['finding'])
        self.assertIn('assets/server.pem', cert_finding['files'])
        self.assertIn('secret.p12', cert_finding['files'])
        self.assertNotIn('code.smali', cert_finding['files'])
        ks_finding = findings[1]
        self.assertIn('Keystore', ks_finding['finding'])
        self.assertIn('store/release.jks', ks_finding['files'])
        self.assertIn('store/debug.bks', ks_finding['files'])

    def test_apk_files_fallback_and_no_hits(self):
        # No 'files' key -> falls back to 'apk_files'; none match -> empty.
        app_dic = {
            'md5': CHECKSUM,
            'apk_files': ['classes.dex', 'AndroidManifest.xml'],
        }
        get_hardcoded_cert_keystore(app_dic)
        self.assertEqual(app_dic['file_analysis'], [])

    def test_no_files_returns_early(self):
        app_dic = {'md5': CHECKSUM, 'files': []}
        get_hardcoded_cert_keystore(app_dic)
        self.assertEqual(app_dic['file_analysis'], [])

    def test_exception_branch_is_swallowed(self):
        # A non-string file name makes Path(...).suffix raise inside the try;
        # the except branch runs and file_analysis stays the reset [].
        app_dic = {'md5': CHECKSUM, 'files': [123, 456]}
        get_hardcoded_cert_keystore(app_dic)
        self.assertEqual(app_dic['file_analysis'], [])


class CertDetailsTests(TestCase):

    def test_real_cert_details(self):
        certlist = get_cert_details(_first_cert_der())
        blob = '\n'.join(certlist)
        self.assertIn('X.509 Subject:', blob)
        self.assertIn('CN=Android Debug', blob)
        self.assertIn('Signature Algorithm:', blob)
        self.assertIn('Valid From:', blob)
        self.assertIn('Valid To:', blob)
        self.assertIn('Issuer:', blob)
        self.assertIn('Serial Number: 0x', blob)
        self.assertIn('Hash Algorithm:', blob)
        # Every hash function must be emitted.
        for algo in ('md5', 'sha1', 'sha256', 'sha512'):
            self.assertIn(f'{algo}:', blob)


class PubKeyDetailsTests(TestCase):
    """Exercise every public-key algorithm branch with real keys."""

    def test_rsa_branch_from_real_cert(self):
        # Derive the real RSA SubjectPublicKeyInfo from the APK's cert.
        cert = x509.load_der_x509_certificate(_first_cert_der())
        der = cert.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo)
        out = get_pub_key_details(der)
        blob = '\n'.join(out)
        self.assertIn('PublicKey Algorithm: rsa', blob)
        self.assertIn('Bit Size:', blob)
        self.assertIn('Fingerprint:', blob)

    def test_dsa_branch(self):
        priv = dsa.generate_private_key(key_size=1024)
        der = priv.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo)
        out = get_pub_key_details(der)
        self.assertIn('PublicKey Algorithm: dsa', '\n'.join(out))

    def test_ec_branch(self):
        priv = ec.generate_private_key(ec.SECP256R1())
        der = priv.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo)
        out = get_pub_key_details(der)
        self.assertIn('PublicKey Algorithm: ec', '\n'.join(out))


class SignatureVersionsTests(TestCase):

    def test_signed_real_apksigner(self):
        # Real apksigner.jar verifies the real v1-signed APK.
        v1, v2, v3, v4 = get_signature_versions(
            CHECKSUM, APK_PATH, TOOLS_DIR, True)
        self.assertTrue(v1)
        self.assertFalse(v2)
        self.assertFalse(v3)
        self.assertFalse(v4)

    def test_unsigned_short_circuit(self):
        # signed=False returns immediately without invoking apksigner.
        self.assertEqual(
            get_signature_versions(CHECKSUM, APK_PATH, TOOLS_DIR, False),
            (False, False, False, False))

    def test_exception_branch_bad_path(self):
        # Non-existent apk path makes apksigner fail -> except branch,
        # all versions default to False.
        self.assertEqual(
            get_signature_versions(
                CHECKSUM, '/nonexistent/does_not_exist.apk', TOOLS_DIR, True),
            (False, False, False, False))


class GetCertDataTests(TestCase):

    def test_signed_apk_via_androguard(self):
        a = _load_apk()
        out = get_cert_data(CHECKSUM, a, APK_PATH, TOOLS_DIR)
        self.assertTrue(out['signed'])
        self.assertTrue(out['v1'])
        self.assertIsNone(out['min_sdk'])
        self.assertIn('Binary is signed', out['cert_data'])
        self.assertIn('v1 signature: True', out['cert_data'])
        self.assertIn('CN=Android Debug', out['cert_data'])
        self.assertIn('unique certificates', out['cert_data'])


class ApksigtoolCertTests(TestCase):

    def test_apksigtool_runs_on_real_apk(self):
        # android.apk is v1-only; apksigtool's v2/v3 block parse raises and is
        # handled, exercising the fallback signature-version logic and the
        # 'not signed' path of this parser.
        out = apksigtool_cert(CHECKSUM, APK_PATH, TOOLS_DIR)
        self.assertIn('signed', out)
        self.assertIn('cert_data', out)
        # No v2/v3 signing block -> apksigtool cannot mark it signed, so the
        # apksigner short-circuits on signed=False and all versions are False.
        self.assertFalse(out['signed'])
        self.assertFalse(out['v1'])
        self.assertIn('Binary is not signed', out['cert_data'])
        self.assertIn('v1 signature:', out['cert_data'])

    def test_apksigtool_missing_certificate_on_bad_input(self):
        # A path that is not a valid zip/apk drives the outer except branch,
        # appending 'Missing certificate'.
        with tempfile.NamedTemporaryFile(
                suffix='.apk', delete=False) as tf:
            tf.write(b'not a real apk')
            bad = tf.name
        try:
            out = apksigtool_cert(CHECKSUM, bad, TOOLS_DIR)
            self.assertIn('Missing certificate', out['cert_data'])
            self.assertFalse(out['signed'])
        finally:
            os.remove(bad)


class CertInfoTests(TestCase):

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.app_dir = tempfile.mkdtemp(prefix='certinfo_')
        # Extract the real APK so META-INF/MANIFEST.MF exists on disk.
        with zipfile.ZipFile(APK_PATH) as z:
            for name in z.namelist():
                if name.startswith('META-INF/'):
                    z.extract(name, cls.app_dir)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.app_dir, ignore_errors=True)
        super().tearDownClass()

    def _base_app_dic(self):
        return {
            'md5': CHECKSUM,
            'androguard_apk': _load_apk(),
            'app_path': APK_PATH,
            'app_dir': self.app_dir,
            'tools_dir': TOOLS_DIR,
        }

    def test_full_signed_flow_with_min_sdk(self):
        # man_dict min_sdk drives api_level -> v1 Janus finding + debug cert.
        app_dic = self._base_app_dic()
        man_dict = {'min_sdk': '21'}
        result = cert_info(app_dic, man_dict)
        self.assertIn('certificate_info', result)
        info = result['certificate_info']
        self.assertIn('Binary is signed', info)
        summary = result['certificate_summary']
        # Signed -> at least one info-level entry (keys are lowercase).
        self.assertGreaterEqual(summary['info'], 1)
        titles = [t for _, _, t in result['certificate_findings']]
        self.assertIn('Signed Application', titles)
        self.assertIn(
            'Application vulnerable to Janus Vulnerability', titles)
        self.assertIn(
            'Application signed with debug certificate', titles)

    def test_api_level_from_cert_data_when_manifest_missing(self):
        # man_dict min_sdk falsy -> falls through to cert_data['min_sdk'].
        # For the androguard path cert min_sdk is None -> api_level None,
        # so the v1 Janus branch (requires api_level) is skipped.
        app_dic = self._base_app_dic()
        man_dict = {'min_sdk': None}
        result = cert_info(app_dic, man_dict)
        titles = [t for _, _, t in result['certificate_findings']]
        self.assertIn('Signed Application', titles)
        self.assertNotIn(
            'Application vulnerable to Janus Vulnerability', titles)

    def test_apksigtool_fallback_when_no_androguard(self):
        # No androguard_apk -> cert_info switches to apksigtool_cert path.
        app_dic = self._base_app_dic()
        app_dic['androguard_apk'] = None
        result = cert_info(app_dic, {'min_sdk': '21'})
        self.assertIn('certificate_info', result)
        self.assertIn('certificate_summary', result)

    def test_exception_returns_empty_dict(self):
        # Missing required keys makes cert_info raise internally -> {}.
        result = cert_info({'md5': CHECKSUM}, {'min_sdk': None})
        self.assertEqual(result, {})
