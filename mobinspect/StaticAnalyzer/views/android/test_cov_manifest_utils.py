# -*- coding: utf_8 -*-
"""Real-execution unit tests for manifest_utils (NO mocks)."""
import tempfile
from pathlib import Path

from django.test import TestCase

from defusedxml.minidom import parseString

from mobinspect.StaticAnalyzer.views.android.manifest_utils import (
    bs4_xml_parser,
    extract_manifest_data,
    get_fallback,
    get_manifest_file,
    get_parsed_manifest,
    get_xml_namespace,
)


FULL_MANIFEST = (
    '<?xml version="1.0" encoding="utf-8"?>\n'
    '<manifest xmlns:android="http://schemas.android.com/apk/res/android"\n'
    '    package="com.example.app"\n'
    '    android:versionCode="10"\n'
    '    android:versionName="1.5">\n'
    '    <uses-sdk android:minSdkVersion="19"'
    ' android:targetSdkVersion="30" android:maxSdkVersion="33"/>\n'
    '    <uses-permission android:name="android.permission.SEND_SMS"/>\n'
    '    <uses-permission'
    ' android:name="com.google.android.c2dm.permission.RECEIVE"/>\n'
    '    <uses-permission android:name="com.custom.MY_PERMISSION"/>\n'
    '    <uses-permission-sdk-23'
    ' android:name="android.permission.CALL_PHONE"/>\n'
    '    <uses-library android:name="org.apache.http.legacy"/>\n'
    '    <application android:icon="@drawable/ic_launcher">\n'
    '        <activity android:name=".MainActivity">\n'
    '            <intent-filter>\n'
    '                <action android:name="android.intent.action.MAIN"/>\n'
    '                <category'
    ' android:name="android.intent.category.LAUNCHER"/>\n'
    '            </intent-filter>\n'
    '        </activity>\n'
    '        <service android:name=".MyService"/>\n'
    '        <provider android:name=".MyProvider"/>\n'
    '        <receiver android:name=".MyReceiver"/>\n'
    '    </application>\n'
    '</manifest>\n'
)


def _app_dic(**extra):
    d = {'md5': 'a' * 32, 'manifest_namespace': 'android'}
    d.update(extra)
    return d


class GetFallbackTests(TestCase):

    def test_get_fallback_returns_failed_package(self):
        dom = get_fallback()
        manifest = dom.getElementsByTagName('manifest')[0]
        self.assertEqual(manifest.getAttribute('package'), 'Failed')
        self.assertEqual(
            manifest.getAttribute('android:versionCode'), 'Failed')


class GetXmlNamespaceTests(TestCase):

    def test_xmlns_maps_to_android(self):
        xml = '<manifest xmlns:android="http://x">'
        self.assertEqual(get_xml_namespace(xml), 'android')

    def test_android_namespace(self):
        xml = '<manifest android:foo="bar">'
        self.assertEqual(get_xml_namespace(xml), 'android')

    def test_non_standard_namespace(self):
        xml = '<manifest customns:foo="bar">'
        self.assertEqual(get_xml_namespace(xml), 'customns')

    def test_no_namespace_returns_none(self):
        self.assertIsNone(get_xml_namespace('<root><child/></root>'))


class Bs4ParserTests(TestCase):

    def test_bs4_parses_valid_xml(self):
        out = bs4_xml_parser('<manifest package="x"><a/></manifest>')
        self.assertIsInstance(out, bytes)
        self.assertIn(b'manifest', out)

    def test_bs4_fixes_malformed_xml(self):
        # bs4 in xml mode repairs the unclosed tag rather than raising.
        out = bs4_xml_parser('<manifest package="x"><application></manifest>')
        self.assertIsInstance(out, bytes)


class GetManifestFileTests(TestCase):

    def test_aar_manifest_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            app_dir = Path(tmp)
            (app_dir / 'AndroidManifest.xml').write_text(FULL_MANIFEST)
            app_dic = _app_dic(
                app_path=(app_dir / 'x.aar').as_posix(),
                app_dir=app_dir.as_posix(),
                tools_dir='/tmp/tools',
                zipped='aar')
            mf = get_manifest_file(app_dic)
            self.assertTrue(mf.exists())
            self.assertEqual(mf.name, 'AndroidManifest.xml')

    def test_apk_manifest_already_extracted(self):
        # apktool_out/AndroidManifest.xml exists -> returns without apktool.
        with tempfile.TemporaryDirectory() as tmp:
            app_dir = Path(tmp)
            out = app_dir / 'apktool_out'
            out.mkdir()
            (out / 'AndroidManifest.xml').write_text(FULL_MANIFEST)
            app_dic = _app_dic(
                app_path=(app_dir / 'x.apk').as_posix(),
                app_dir=app_dir.as_posix(),
                tools_dir='/tmp/tools',
                zipped='apk')
            mf = get_manifest_file(app_dic)
            self.assertTrue(mf.exists())
            self.assertEqual(mf.parent.name, 'apktool_out')

    def test_eclipse_manifest_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            app_dir = Path(tmp)
            app_dic = _app_dic(
                app_path=(app_dir / 'x').as_posix(),
                app_dir=app_dir.as_posix(),
                tools_dir='/tmp/tools',
                zipped='eclipse')
            mf = get_manifest_file(app_dic)
            self.assertEqual(mf.name, 'AndroidManifest.xml')
            self.assertEqual(mf.parent, app_dir)

    def test_studio_manifest_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            app_dir = Path(tmp)
            app_dic = _app_dic(
                app_path=(app_dir / 'x').as_posix(),
                app_dir=app_dir.as_posix(),
                tools_dir='/tmp/tools',
                zipped='studio')
            mf = get_manifest_file(app_dic)
            self.assertEqual(
                mf, app_dir / 'app' / 'src' / 'main' / 'AndroidManifest.xml')

    def test_unknown_type_returns_none(self):
        with tempfile.TemporaryDirectory() as tmp:
            app_dir = Path(tmp)
            app_dic = _app_dic(
                app_path=(app_dir / 'x').as_posix(),
                app_dir=app_dir.as_posix(),
                tools_dir='/tmp/tools',
                zipped='whatever')
            self.assertIsNone(get_manifest_file(app_dic))

    def test_missing_keys_triggers_exception_branch(self):
        # Missing 'app_path' raises inside try -> caught -> None.
        self.assertIsNone(get_manifest_file({'md5': 'b' * 32}))


TOOLS_DIR = (
    Path(__file__).resolve().parents[2] / 'tools').as_posix()


class GetManifestFileApktoolTests(TestCase):
    """Drive the real apktool path with a bogus APK so it fails fast."""

    def test_apk_apktool_fails_androguard_fallback(self):
        with tempfile.TemporaryDirectory() as tmp:
            app_dir = Path(tmp)
            bogus = app_dir / 'x.apk'
            bogus.write_bytes(b'not a real apk')
            good = (
                '<?xml version="1.0" encoding="utf-8"?>'
                '<manifest xmlns:android="http://schemas.android.com/'
                'apk/res/android" package="ag.fallback"></manifest>'
            ).encode('utf-8')
            app_dic = _app_dic(
                app_path=bogus.as_posix(),
                app_dir=app_dir.as_posix(),
                tools_dir=TOOLS_DIR,
                zipped='apk',
                androguard_manifest_xml=good)
            mf = get_manifest_file(app_dic)
            # apktool could not decode the bogus apk, so androguard bytes
            # were written to the manifest location.
            self.assertTrue(mf.exists())
            self.assertIn('ag.fallback', mf.read_text())

    def test_apk_apktool_fails_no_androguard_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            app_dir = Path(tmp)
            bogus = app_dir / 'x.apk'
            bogus.write_bytes(b'not a real apk')
            app_dic = _app_dic(
                app_path=bogus.as_posix(),
                app_dir=app_dir.as_posix(),
                tools_dir=TOOLS_DIR,
                zipped='apk',
                androguard_manifest_xml=None)
            mf = get_manifest_file(app_dic)
            # Manifest was never produced; error path taken.
            self.assertFalse(mf.exists())


class GetParsedManifestTests(TestCase):

    def test_manifest_not_found(self):
        with tempfile.TemporaryDirectory() as tmp:
            app_dir = Path(tmp)
            app_dic = _app_dic(
                app_path=(app_dir / 'x').as_posix(),
                app_dir=app_dir.as_posix(),
                tools_dir='/tmp/tools',
                zipped='studio')  # points to a non-existent file
            get_parsed_manifest(app_dic)
            self.assertIsNone(
                app_dic['manifest_file']
                and app_dic['manifest_file'].exists() or None)
            # Fallback parsed xml retained.
            self.assertIsNotNone(app_dic['manifest_parsed_xml'])

    def test_parse_success_real_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            app_dir = Path(tmp)
            (app_dir / 'AndroidManifest.xml').write_text(FULL_MANIFEST)
            app_dic = _app_dic(
                app_path=(app_dir / 'x.aar').as_posix(),
                app_dir=app_dir.as_posix(),
                tools_dir='/tmp/tools',
                zipped='aar')
            get_parsed_manifest(app_dic)
            self.assertEqual(app_dic['manifest_namespace'], 'android')
            parsed = app_dic['manifest_parsed_xml']
            self.assertEqual(
                parsed.getElementsByTagName('manifest')[0]
                .getAttribute('package'),
                'com.example.app')

    def test_fallback_to_androguard(self):
        # Malformed on-disk XML -> primary parse fails ->
        # androguard bytes are valid -> used and rewritten to disk.
        with tempfile.TemporaryDirectory() as tmp:
            app_dir = Path(tmp)
            mfp = app_dir / 'AndroidManifest.xml'
            mfp.write_text('<manifest package="x"><bad></manifest')
            good = (
                '<?xml version="1.0" encoding="utf-8"?>'
                '<manifest xmlns:android="http://schemas.android.com/'
                'apk/res/android" package="from.androguard"></manifest>'
            ).encode('utf-8')
            app_dic = _app_dic(
                app_path=(app_dir / 'x.aar').as_posix(),
                app_dir=app_dir.as_posix(),
                tools_dir='/tmp/tools',
                zipped='aar',
                androguard_manifest_xml=good)
            get_parsed_manifest(app_dic)
            parsed = app_dic['manifest_parsed_xml']
            self.assertEqual(
                parsed.getElementsByTagName('manifest')[0]
                .getAttribute('package'),
                'from.androguard')
            # File overwritten with androguard bytes.
            self.assertIn('from.androguard', mfp.read_text())

    def test_fallback_to_bs4(self):
        # Malformed XML + invalid androguard bytes -> bs4 repairs.
        with tempfile.TemporaryDirectory() as tmp:
            app_dir = Path(tmp)
            mfp = app_dir / 'AndroidManifest.xml'
            mfp.write_text(
                '<manifest package="bs4pkg"><application></manifest>')
            app_dic = _app_dic(
                app_path=(app_dir / 'x.aar').as_posix(),
                app_dir=app_dir.as_posix(),
                tools_dir='/tmp/tools',
                zipped='aar',
                androguard_manifest_xml=b'not valid <<< xml')
            get_parsed_manifest(app_dic)
            parsed = app_dic['manifest_parsed_xml']
            self.assertTrue(parsed.getElementsByTagName('manifest'))

    def test_all_methods_fail(self):
        # Malformed XML, invalid androguard, and bs4 output unparsable-ish.
        with tempfile.TemporaryDirectory() as tmp:
            app_dir = Path(tmp)
            mfp = app_dir / 'AndroidManifest.xml'
            # Empty content -> primary parse fails, bs4 gives empty output.
            mfp.write_text('')
            app_dic = _app_dic(
                app_path=(app_dir / 'x.aar').as_posix(),
                app_dir=app_dir.as_posix(),
                tools_dir='/tmp/tools',
                zipped='aar',
                androguard_manifest_xml=b'')
            # Should not raise; fallback dom remains.
            get_parsed_manifest(app_dic)
            self.assertIsNotNone(app_dic['manifest_parsed_xml'])


class ExtractManifestDataTests(TestCase):

    def test_full_extraction(self):
        dom = parseString(FULL_MANIFEST)
        app_dic = _app_dic(manifest_parsed_xml=dom)
        data = extract_manifest_data(app_dic)
        self.assertEqual(data['packagename'], 'com.example.app')
        self.assertEqual(data['mainactivity'], '.MainActivity')
        self.assertEqual(data['min_sdk'], '19')
        self.assertEqual(data['max_sdk'], '33')
        self.assertEqual(data['target_sdk'], '30')
        self.assertEqual(data['androver'], '10')
        self.assertEqual(data['androvername'], '1.5')
        self.assertIn('.MyService', data['services'])
        self.assertIn('.MyProvider', data['providers'])
        self.assertIn('.MyReceiver', data['receivers'])
        self.assertIn('org.apache.http.legacy', data['libraries'])
        self.assertIn('android.intent.category.LAUNCHER', data['categories'])
        self.assertIn('@drawable/ic_launcher', data['icons'])
        perm = data['perm']
        # Known permission (dangerous SEND_SMS)
        self.assertEqual(
            perm['android.permission.SEND_SMS'][0], 'dangerous')
        # uses-permission-sdk-23 merged
        self.assertIn('android.permission.CALL_PHONE', perm)
        # Special permission branch
        self.assertIn(
            'com.google.android.c2dm.permission.RECEIVE', perm)
        # Unknown permission branch
        self.assertEqual(
            perm['com.custom.MY_PERMISSION'][0], 'unknown')

    def test_launcher_only_alt_main(self):
        xml = (
            '<manifest'
            ' xmlns:android="http://schemas.android.com/apk/res/android"'
            ' package="p">'
            '<application>'
            '<activity android:name=".LauncherOnly">'
            '<intent-filter>'
            '<category android:name="android.intent.category.LAUNCHER"/>'
            '</intent-filter>'
            '</activity>'
            '</application>'
            '</manifest>'
        )
        dom = parseString(xml)
        app_dic = _app_dic(manifest_parsed_xml=dom)
        data = extract_manifest_data(app_dic)
        self.assertEqual(data['mainactivity'], '.LauncherOnly')

    def test_targetsdk_defaults_to_minsdk(self):
        xml = (
            '<manifest'
            ' xmlns:android="http://schemas.android.com/apk/res/android"'
            ' package="p">'
            '<uses-sdk android:minSdkVersion="15"/>'
            '</manifest>'
        )
        dom = parseString(xml)
        app_dic = _app_dic(manifest_parsed_xml=dom)
        data = extract_manifest_data(app_dic)
        self.assertEqual(data['min_sdk'], '15')
        self.assertEqual(data['target_sdk'], '15')

    def test_targetsdk_from_apk_features(self):
        xml = (
            '<manifest'
            ' xmlns:android="http://schemas.android.com/apk/res/android"'
            ' package="p">'
            '<uses-sdk android:minSdkVersion="15"'
            ' android:targetSdkVersion="21"/>'
            '</manifest>'
        )
        dom = parseString(xml)
        app_dic = _app_dic(
            manifest_parsed_xml=dom,
            apk_features={'target_sdk_version': '34'})
        data = extract_manifest_data(app_dic)
        self.assertEqual(data['target_sdk'], '34')

    def test_empty_package_and_backups(self):
        # No package, no perms, no activity, no uses-sdk in manifest ->
        # values pulled from apk_features backups.
        xml = (
            '<manifest'
            ' xmlns:android="http://schemas.android.com/apk/res/android">'
            '<application/>'
            '</manifest>'
        )
        dom = parseString(xml)
        app_dic = _app_dic(
            manifest_parsed_xml=dom,
            apk_features={
                'package': 'backup.pkg',
                'launchable_activity': 'backup.Main',
                'min_sdk_version': '16',
                'permissions': ['android.permission.INTERNET'],
            })
        data = extract_manifest_data(app_dic)
        self.assertEqual(data['packagename'], 'backup.pkg')
        self.assertEqual(data['mainactivity'], 'backup.Main')
        self.assertEqual(data['min_sdk'], '16')
        self.assertIn('android.permission.INTERNET', data['perm'])

    def test_extract_exception_branch_returns_none(self):
        # Missing 'manifest_parsed_xml' -> KeyError caught -> None.
        app_dic = _app_dic()
        self.assertIsNone(extract_manifest_data(app_dic))
