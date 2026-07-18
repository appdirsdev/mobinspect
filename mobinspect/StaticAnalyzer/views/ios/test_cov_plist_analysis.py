# -*- coding: utf_8 -*-
"""Real-execution coverage tests for ios/plist_analysis.py.

Real plistlib / OpenStepDecoder parsing throughout, real files on disk
(.entitlements, .pbxproj, Info.plist -- both XML and binary format), and
real fault injection (malformed OpenStep text, malformed binary plist
bytes, nonexistent source directories, a real plistlib.UID value that
genuinely cannot be re-serialized to XML). No mocking of the module under
test.
"""
import os
import plistlib
import tempfile
from pathlib import Path

from django.test import SimpleTestCase

from mobinspect.StaticAnalyzer.views.ios.plist_analysis import (
    convert_bin_xml,
    get_bundle_id,
    get_plist_secrets,
    get_summary,
    plist_analysis,
)


def _write_plist(path, data, fmt=plistlib.FMT_XML):
    with open(path, 'wb') as fh:
        plistlib.dump(data, fh, fmt=fmt)


class GetBundleIdTests(SimpleTestCase):

    def test_no_possible_ids_returns_empty_string(self):
        # Nothing anywhere -> line 93.
        tmp = tempfile.mkdtemp()
        self.assertEqual(get_bundle_id({}, tmp), '')

    def test_entitlements_no_groups_continues(self):
        # com.apple.security.application-groups absent/falsy -> line 63.
        tmp = tempfile.mkdtemp()
        ent_path = os.path.join(tmp, 'App.entitlements')
        _write_plist(ent_path, {'com.apple.security.get-task-allow': True})
        self.assertEqual(get_bundle_id({}, tmp), '')

    def test_entitlements_malformed_logs_warning(self):
        # Real invalid plist bytes -> plistlib.loads() raises for real ->
        # except (lines 67-68).
        tmp = tempfile.mkdtemp()
        ent_path = os.path.join(tmp, 'Bad.entitlements')
        with open(ent_path, 'wb') as fh:
            fh.write(b'this is not a valid plist at all')
        # Should not raise -- caught internally, falls through to ''.
        self.assertEqual(get_bundle_id({}, tmp), '')

    def test_pbxproj_parses_to_empty_dict_continues(self):
        # '{}' is valid OpenStep syntax that parses to a real, empty
        # (falsy) dict -> `if not parsed: continue` (line 78).
        tmp = tempfile.mkdtemp()
        pbx_path = os.path.join(tmp, 'project.pbxproj')
        with open(pbx_path, 'w') as fh:
            fh.write('{}')
        self.assertEqual(get_bundle_id({}, tmp), '')

    def test_pbxproj_empty_file_raises_internally(self):
        # A genuinely empty file makes OpenStepDecoder raise a real
        # IndexError internally -> caught by the except (lines 87-88),
        # never propagating out of get_bundle_id.
        tmp = tempfile.mkdtemp()
        pbx_path = os.path.join(tmp, 'project.pbxproj')
        with open(pbx_path, 'w') as fh:
            fh.write('')
        self.assertEqual(get_bundle_id({}, tmp), '')

    def test_pbxproj_malformed_logs_warning(self):
        # Real invalid OpenStep syntax -> OpenStepDecoder.ParseFromString
        # raises for real -> except (lines 87-88).
        tmp = tempfile.mkdtemp()
        pbx_path = os.path.join(tmp, 'project.pbxproj')
        with open(pbx_path, 'w') as fh:
            fh.write('{{{ not valid at all ][[')
        self.assertEqual(get_bundle_id({}, tmp), '')

    def test_pbxproj_bundle_id_skip_chars_start_continue(self):
        # A PRODUCT_BUNDLE_IDENTIFIER value that itself starts with a
        # build-variable template ('$(...)') is skipped (line 81).
        tmp = tempfile.mkdtemp()
        pbx_path = os.path.join(tmp, 'project.pbxproj')
        with open(pbx_path, 'w') as fh:
            fh.write(
                '// !$*UTF8*$!\n'
                '{\n'
                '    PRODUCT_BUNDLE_IDENTIFIER = "$(PRODUCT_BUNDLE_IDENTIFIER)";\n'
                '}\n'
            )
        # No usable id survives -> ''.
        self.assertEqual(get_bundle_id({}, tmp), '')

    def test_pbxproj_bundle_id_dot_dollar_split(self):
        # A value containing '.$(' gets truncated at the template marker
        # (line 85) and the resulting prefix is used as a candidate id.
        tmp = tempfile.mkdtemp()
        pbx_path = os.path.join(tmp, 'project.pbxproj')
        with open(pbx_path, 'w') as fh:
            fh.write(
                '// !$*UTF8*$!\n'
                '{\n'
                '    PRODUCT_BUNDLE_IDENTIFIER = '
                '"com.example.$(PRODUCT_NAME:rfc1034identifier)";\n'
                '}\n'
            )
        self.assertEqual(get_bundle_id({}, tmp), 'com.example')


class ConvertBinXmlTests(SimpleTestCase):

    def test_malformed_binary_xml_logs_warning(self):
        # Real invalid bytes -> plistlib.load() raises for real -> except
        # (lines 105-106). Function has no return value either way.
        tmp = tempfile.mkdtemp()
        bad_file = os.path.join(tmp, 'bad.plist')
        with open(bad_file, 'wb') as fh:
            fh.write(b'not a plist')
        self.assertIsNone(convert_bin_xml(bad_file))


class GetSummaryTests(SimpleTestCase):

    def test_all_severities_counted(self):
        # Exercises the warning/info/secure branches (lines 228-233); high
        # is already covered elsewhere.
        ats = [
            {'severity': 'high'},
            {'severity': 'warning'},
            {'severity': 'info'},
            {'severity': 'secure'},
        ]
        summary = get_summary(ats)
        self.assertEqual(
            summary, {'high': 1, 'warning': 1, 'info': 1, 'secure': 1})


class GetPlistSecretsTests(SimpleTestCase):

    def test_secret_key_value_pair_found(self):
        # A <key> line matching is_secret_key() immediately followed by a
        # single-token value line -> lines 253-254, 257-258.
        tmp = tempfile.mkdtemp()
        secret_plist = os.path.join(tmp, 'Secrets.plist')
        with open(secret_plist, 'w') as fh:
            fh.write(
                '<plist>\n<dict>\n'
                '<key>ApiKey</key>\n<string>abc123xyz</string>\n'
                '</dict>\n</plist>\n')
        result = get_plist_secrets('a' * 32, tmp)
        self.assertTrue(
            any('ApiKey' in r and 'abc123xyz' in r for r in result))


class PlistAnalysisTests(SimpleTestCase):

    def test_zip_scan_google_service_info_skipped_no_real_info_plist(self):
        # A GoogleService-Info.plist is found but explicitly skipped from
        # becoming `plist_file` (line 145); with no real Info.plist
        # present, analysis correctly reports "cannot find" (lines 163,
        # 165).
        tmp = tempfile.mkdtemp()
        _write_plist(
            os.path.join(tmp, 'GoogleService-Info.plist'), {'X': 'Y'})
        result = plist_analysis('a' * 32, tmp, 'zip')
        self.assertEqual(result['bin_name'], '')
        self.assertEqual(result['id'], '')

    def test_zip_scan_no_plist_at_all(self):
        # No .plist files anywhere -> lines 163, 165.
        tmp = tempfile.mkdtemp()
        result = plist_analysis('b' * 32, tmp, 'zip')
        self.assertEqual(result['bin_name'], '')

    def test_ipa_scan_missing_bin_name_falls_back_to_app_dir(self):
        # scan_type == 'ipa', Info.plist lacks CFBundleDisplayName/Name ->
        # bin_name falls back to the .app directory name (line 181), and
        # CFBundleURLTypes as a dict (not list) gets wrapped (line 194).
        tmp = tempfile.mkdtemp()
        app_dir = os.path.join(tmp, 'MyRealApp.app')
        os.makedirs(app_dir)
        _write_plist(os.path.join(app_dir, 'Info.plist'), {
            'CFBundleExecutable': 'MyRealApp',
            'CFBundleURLTypes': {'CFBundleURLSchemes': ['myapp']},
        })
        result = plist_analysis('c' * 32, tmp, 'ipa')
        self.assertEqual(result['bin_name'], 'MyRealApp')
        self.assertEqual(
            result['bundle_url_types'],
            [{'CFBundleURLSchemes': ['myapp']}])

    def test_outer_exception_branch_ipa_nonexistent_src(self):
        # scan_type == 'ipa' with a nonexistent src -> os.listdir(src)
        # genuinely raises FileNotFoundError -> the function's own outer
        # except (lines 214-217).
        result = plist_analysis(
            'd' * 32, '/nonexistent/src/path/does/not/exist', 'ipa')
        self.assertIsNone(result)

    def test_pxml_dump_failure_real_uid_value(self):
        # A real plistlib.UID value survives a real binary-plist load()
        # but genuinely cannot be re-serialized by dumps() (default XML
        # format) -> TypeError -> except -> pxml stays '' (lines 173-175).
        tmp = tempfile.mkdtemp()
        app_dir = os.path.join(tmp, 'UidApp.app')
        os.makedirs(app_dir)
        info_plist = os.path.join(app_dir, 'Info.plist')
        _write_plist(info_plist, {
            'CFBundleExecutable': 'UidApp',
            'CFBundleName': 'UidApp',
            'CF$UIDMarker': plistlib.UID(1),
        }, fmt=plistlib.FMT_BINARY)
        result = plist_analysis('e' * 32, tmp, 'ipa')
        self.assertEqual(result['plist_xml'], '')
        self.assertEqual(result['bin_name'], 'UidApp')

    def test_ats_full_severity_mix_via_real_plist(self):
        # A real Info.plist whose NSAppTransportSecurity/NSExceptionDomains
        # section produces high, warning, info and secure ATS findings in
        # one real plist_analysis() call, feeding get_summary() end to end.
        tmp = tempfile.mkdtemp()
        app_dir = os.path.join(tmp, 'AtsApp.app')
        os.makedirs(app_dir)
        _write_plist(os.path.join(app_dir, 'Info.plist'), {
            'CFBundleExecutable': 'AtsApp',
            'CFBundleName': 'AtsApp',
            'NSAppTransportSecurity': {
                'NSExceptionDomains': {
                    'insecure.example.com': {
                        'NSExceptionAllowsInsecureHTTPLoads': True,
                        'NSExceptionMinimumTLSVersion': 'TLSv1.2',
                        'NSRequiresCertificateTransparency': 'YES',
                    },
                },
            },
        })
        result = plist_analysis('f' * 32, tmp, 'ipa')
        summary = result['inseccon']['ats_summary']
        self.assertGreaterEqual(summary.get('high', 0), 1)
        self.assertGreaterEqual(summary.get('warning', 0), 1)
        self.assertGreaterEqual(summary.get('info', 0), 1)
        self.assertGreaterEqual(summary.get('secure', 0), 1)
