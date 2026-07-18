# -*- coding: utf_8 -*-
"""Real-execution (no-mock) tests for cert_analysis.

Drives the real signed test_files/android.apk certificate through the real
androguard parser, the real apksigner.jar, real apksigtool and real
cryptography key parsing. No mocks, no monkeypatching (one narrow exception,
noted at its call site below).
"""
import os
import shutil
import subprocess
import tempfile
import zipfile
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec
from cryptography import x509

from django.test import TestCase

from mobinspect.StaticAnalyzer.tools.androguard4 import apk
from mobinspect.StaticAnalyzer.views.android.cert_analysis import (
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
TOOLS_DIR = (REPO_ROOT / 'mobinspect' / 'StaticAnalyzer' / 'tools').as_posix()
APKTOOL_JAR = (REPO_ROOT / 'mobinspect' / 'StaticAnalyzer' / 'tools'
               / 'apktool_2.10.0.jar').as_posix()
APKSIGNER_JAR = (REPO_ROOT / 'mobinspect' / 'StaticAnalyzer' / 'tools'
                 / 'apksigner.jar').as_posix()
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


class RealSigningScenarioTests(TestCase):
    """Build real, deliberately-signed APK fixtures with keytool / jarsigner /
    apktool / apksigner (all real tools, no mocks) to reach cert_analysis
    branches the stock debug-signed test_files/android.apk cannot: a v2/v3
    -only signed APK, a truly unsigned APK, and JAR-signed APKs whose
    self-signed certificate deliberately uses MD5withRSA / SHA1withRSA so the
    'Hash Algorithm: md5|sha1' branches in cert_info() fire for real.
    """

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.work = Path(tempfile.mkdtemp(prefix='real_sign_'))

        def keystore(name, alias, sigalg):
            path = cls.work / f'{name}.jks'
            subprocess.run([
                'keytool', '-genkeypair', '-keystore', path.as_posix(),
                '-storepass', 'password', '-keypass', 'password',
                '-alias', alias, '-dname', f'CN=Test {name}, OU=T, O=T, C=US',
                '-validity', '3650', '-keyalg', 'RSA', '-keysize', '2048',
                '-sigalg', sigalg,
            ], check=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            return path

        cls.sha1_ks = keystore('sha1', 'sha1key', 'SHA1withRSA')
        cls.md5_ks = keystore('md5', 'md5key', 'MD5withRSA')
        cls.v3_ks = keystore('v3', 'v3key', 'SHA256withRSA')

        def strip_meta_inf(src, dst):
            with zipfile.ZipFile(src) as zin, zipfile.ZipFile(dst, 'w') as zout:
                for item in zin.infolist():
                    if item.filename.startswith('META-INF/'):
                        continue
                    zout.writestr(item, zin.read(item.filename))

        # Truly unsigned APK (no META-INF at all).
        cls.unsigned_apk = (cls.work / 'unsigned.apk').as_posix()
        strip_meta_inf(APK_PATH, cls.unsigned_apk)

        # JAR (v1)-signed with a SHA1withRSA cert, manifest digests forced to
        # SHA-256 -> cert_info() sees 'Hash Algorithm: sha1' *and*
        # 'SHA-256-Digest' in the same scan (the sha256_digest downgrade
        # branch).
        cls.sha1_sha256_apk = (cls.work / 'sha1_sha256.apk').as_posix()
        strip_meta_inf(APK_PATH, cls.sha1_sha256_apk)
        subprocess.run([
            'jarsigner', '-keystore', cls.sha1_ks.as_posix(),
            '-storepass', 'password', '-sigalg', 'SHA1withRSA',
            '-digestalg', 'SHA-256', cls.sha1_sha256_apk, 'sha1key',
        ], check=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

        # JAR (v1)-signed with an MD5withRSA cert (MD5 manifest digest too).
        cls.md5_apk = (cls.work / 'md5.apk').as_posix()
        strip_meta_inf(APK_PATH, cls.md5_apk)
        subprocess.run([
            'jarsigner', '-keystore', cls.md5_ks.as_posix(),
            '-storepass', 'password', '-sigalg', 'MD5withRSA',
            '-digestalg', 'MD5', cls.md5_apk, 'md5key',
        ], check=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

        # v2/v3-only signed APK (no v1) with minSdkVersion raised to 24 via
        # apktool decode/rebuild, so apksigner verify does not require v1.
        decoded = cls.work / 'decoded'
        subprocess.run([
            'java', '-jar', APKTOOL_JAR, 'd', '-f', '-o', decoded.as_posix(),
            APK_PATH,
        ], check=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        yml = decoded / 'apktool.yml'
        text = yml.read_text().replace('minSdkVersion: 15', 'minSdkVersion: 24')
        yml.write_text(text)
        cls.v3_apk = (cls.work / 'v3.apk').as_posix()
        subprocess.run([
            'java', '-jar', APKTOOL_JAR, 'b', decoded.as_posix(),
            '-o', cls.v3_apk,
        ], check=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        subprocess.run([
            'java', '-jar', APKSIGNER_JAR, 'sign',
            '--ks', cls.v3_ks.as_posix(), '--ks-pass', 'pass:password',
            '--key-pass', 'pass:password', '--ks-key-alias', 'v3key',
            '--v1-signing-enabled', 'false', '--v2-signing-enabled', 'true',
            '--v3-signing-enabled', 'true', cls.v3_apk,
        ], check=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

        # v1+v2+v3 all signed with the same (low, original) minSdkVersion ->
        # androguard reads real v2/v3 public keys (get_pub_key_details loop
        # in get_cert_data) and cert_info's Janus WARNING-downgrade branch
        # (v1 present *and* v2/v3 present *and* api_level < 27) fires.
        cls.allsigned_apk = (cls.work / 'allsigned.apk').as_posix()
        shutil.copy(APK_PATH, cls.allsigned_apk)
        subprocess.run([
            'java', '-jar', APKSIGNER_JAR, 'sign',
            '--ks', cls.v3_ks.as_posix(), '--ks-pass', 'pass:password',
            '--key-pass', 'pass:password', '--ks-key-alias', 'v3key',
            '--v1-signing-enabled', 'true', '--v2-signing-enabled', 'true',
            '--v3-signing-enabled', 'true', cls.allsigned_apk,
        ], check=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.work, ignore_errors=True)
        super().tearDownClass()

    def test_v3_only_apk_signature_versions_and_apksigtool_block(self):
        # Real apksigner detects v2+v3 (not v1) -> covers the v3=True branch
        # in get_signature_versions (previously only v1 was ever exercised).
        v1, v2, v3, v4 = get_signature_versions(
            'rs1', self.v3_apk, TOOLS_DIR, True)
        self.assertFalse(v1)
        self.assertTrue(v2)
        self.assertTrue(v3)

        # apksigtool_cert's own APK Signing Block v2/v3 parser (used when
        # androguard fails) walks a real signer entry: exercises the
        # is_v2()/is_v3()/min_sdk/get_cert_details/get_pub_key_details loop.
        out = apksigtool_cert('rs2', self.v3_apk, TOOLS_DIR)
        self.assertTrue(out['signed'])
        self.assertEqual(out['min_sdk'], 24)
        self.assertIn('Binary is signed', out['cert_data'])

    def test_cert_info_min_sdk_falls_back_to_apksigtool_min_sdk(self):
        # man_dict min_sdk is falsy -> cert_info() falls through to
        # cert_data['min_sdk'] (only ever populated by the apksigtool v3
        # parser), reaching the `elif cert_data['min_sdk']:` branch.
        app_dic = {
            'md5': 'rs3',
            'androguard_apk': None,
            'app_path': self.v3_apk,
            'app_dir': tempfile.mkdtemp(),
            'tools_dir': TOOLS_DIR,
        }
        result = cert_info(app_dic, {'min_sdk': None})
        self.assertIn('certificate_summary', result)
        shutil.rmtree(app_dic['app_dir'], ignore_errors=True)

    def test_apksigtool_signed_block_but_apksigner_fails(self):
        # Narrow, single-call monkeypatch (per project rule 1): a real v2/v3
        # signing block (parsed for real by apksigtool) combined with a
        # forced apksigner.jar failure is otherwise impossible to produce
        # deterministically -- a real APK that apksigner itself rejects
        # while its signing-block bytes still parse structurally could not
        # be built with the tools available in this environment. This
        # reaches the 'apksigner.jar failed to get signature versions'
        # fallback branch inside apksigtool_cert (av1/av2/av3/av4 used).
        orig = subprocess.check_output

        def fake_check_output(args, **kwargs):
            if 'apksigner.jar' in ' '.join(args):
                raise subprocess.CalledProcessError(1, args)
            return orig(args, **kwargs)

        subprocess.check_output = fake_check_output
        try:
            out = apksigtool_cert('rs4', self.v3_apk, TOOLS_DIR)
        finally:
            subprocess.check_output = orig
        self.assertTrue(out['signed'])
        # Versions were substituted from apksigtool's own av1..av4 reading
        # (the last-processed signing-block pair is the v3 block).
        self.assertFalse(out['v1'])
        self.assertTrue(out['v3'])

    def test_unsigned_apk_get_cert_data_not_signed_branch(self):
        # A real APK with META-INF stripped -> androguard reports
        # is_signed()=False, covering the 'not signed' branch of
        # get_cert_data (as opposed to apksigtool_cert's own).
        a = apk.APK(self.unsigned_apk)
        self.assertFalse(a.is_signed())
        out = get_cert_data('rs5', a, self.unsigned_apk, TOOLS_DIR)
        self.assertFalse(out['signed'])
        self.assertIn('Binary is not signed', out['cert_data'])
        self.assertIn('Missing certificate', out['cert_data'])

    def test_sha1_cert_plus_sha256_manifest_digest_hash_collision_warning(self):
        # Real SHA1withRSA-signed cert (Hash Algorithm: sha1) + a manifest
        # forced to SHA-256 digests -> the sha256_digest downgrade branch
        # (HIGH -> WARNING, retitled) inside cert_info() fires for real.
        # apksigner.jar itself refuses to verify SHA1withRSA (disabled
        # algorithm), so cert_info naturally falls back to androguard's own
        # is_signed_v1() reading -- no patch needed for that fallback.
        app_dir = tempfile.mkdtemp()
        with zipfile.ZipFile(self.sha1_sha256_apk) as z:
            for name in z.namelist():
                if name.startswith('META-INF/'):
                    z.extract(name, app_dir)
        app_dic = {
            'md5': 'rs6',
            'androguard_apk': apk.APK(self.sha1_sha256_apk),
            'app_path': self.sha1_sha256_apk,
            'app_dir': app_dir,
            'tools_dir': TOOLS_DIR,
        }
        result = cert_info(app_dic, {'min_sdk': '21'})
        titles = [t for _, _, t in result['certificate_findings']]
        self.assertIn(
            'Certificate algorithm might be '
            'vulnerable to hash collision', titles)
        shutil.rmtree(app_dir, ignore_errors=True)

    def test_md5_cert_hash_collision_warning(self):
        # Real MD5withRSA-signed cert -> 'Hash Algorithm: md5' branch.
        app_dir = tempfile.mkdtemp()
        with zipfile.ZipFile(self.md5_apk) as z:
            for name in z.namelist():
                if name.startswith('META-INF/'):
                    z.extract(name, app_dir)
        app_dic = {
            'md5': 'rs7',
            'androguard_apk': apk.APK(self.md5_apk),
            'app_path': self.md5_apk,
            'app_dir': app_dir,
            'tools_dir': TOOLS_DIR,
        }
        result = cert_info(app_dic, {'min_sdk': '21'})
        titles = [t for _, _, t in result['certificate_findings']]
        self.assertIn(
            'Certificate algorithm vulnerable to hash collision', titles)
        shutil.rmtree(app_dir, ignore_errors=True)

    def test_v1_plus_v2v3_signed_janus_warning_downgrade_and_v3_pubkeys(self):
        # Real v1+v2+v3-signed APK with api_level (21) < ANDROID_8_1_LEVEL
        # (27): the Janus finding's status is downgraded HIGH -> WARNING
        # (get_cert_data reads the real v2/v3 public keys from androguard,
        # covering the get_pub_key_details loop for that path too).
        a = apk.APK(self.allsigned_apk)
        out = get_cert_data('rs8', a, self.allsigned_apk, TOOLS_DIR)
        self.assertTrue(out['v1'] and (out['v2'] or out['v3']))
        self.assertIn('PublicKey Algorithm', out['cert_data'])

        app_dir = tempfile.mkdtemp()
        with zipfile.ZipFile(self.allsigned_apk) as z:
            for name in z.namelist():
                if name.startswith('META-INF/'):
                    z.extract(name, app_dir)
        app_dic = {
            'md5': 'rs9',
            'androguard_apk': a,
            'app_path': self.allsigned_apk,
            'app_dir': app_dir,
            'tools_dir': TOOLS_DIR,
        }
        result = cert_info(app_dic, {'min_sdk': '21'})
        janus = next(
            f for f in result['certificate_findings']
            if f[2] == 'Application vulnerable to Janus Vulnerability')
        self.assertEqual(janus[0], 'warning')
        self.assertGreaterEqual(result['certificate_summary']['warning'], 1)
        shutil.rmtree(app_dir, ignore_errors=True)
