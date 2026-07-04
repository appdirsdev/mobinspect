# -*- coding: utf_8 -*-
"""Real-execution unit tests for ios view_source.py (NO mocks).

Every test drives the real ``run`` view / ``set_ext_api`` helper with real
files placed on disk under a real (temp) UPLD_DIR, real Django requests
(RequestFactory / Client) and a real created superuser. No mocking, no
monkeypatching of internal logic, no fake returns.
"""
import datetime
import json
import os
import plistlib
import sqlite3
import tempfile
from pathlib import Path

from django.conf import settings
from django.contrib.auth import get_user_model
from django.test import (
    Client,
    RequestFactory,
    TestCase,
    override_settings,
)

from mobsf.StaticAnalyzer.views.ios.views.view_source import (
    run,
    set_ext_api,
)

# A real, valid-looking md5 (32 hex chars) used as the scan hash / dir name.
MD5 = 'a' * 32
# A second hash for the "ipa without payload" case.
MD5_NO_PAYLOAD = 'b' * 32

# Module-level real temp dir used as UPLD_DIR for every test.
TMP_UPLD = tempfile.mkdtemp(prefix='mobsf_ios_vs_')


def _build_fixtures():
    """Create real files under TMP_UPLD/<md5> exercising every branch."""
    base = Path(TMP_UPLD) / MD5
    base.mkdir(parents=True, exist_ok=True)

    # .m  -> cpp
    (base / 'code.m').write_text('#import <Foundation/Foundation.h>\nint x;\n')
    # .xml -> xml
    (base / 'data.xml').write_text('<root><a>1</a></root>')
    # .txt -> text
    (base / 'notes.txt').write_text('hello world\nsecond line\n')
    # classdump.txt (special-cased txt) -> present
    (base / 'classdump.txt').write_text('@interface Foo\n@end\n')

    # binary plist -> json
    with open(base / 'good.plist', 'wb') as f:
        plistlib.dump({'k': 'v', 'n': 1}, f, fmt=plistlib.FMT_BINARY)
    # xml plist -> json
    with open(base / 'goodxml.plist', 'wb') as f:
        plistlib.dump({'name': 'test'}, f, fmt=plistlib.FMT_XML)
    # invalid plist (not binary/xml) -> InvalidFileException -> read_text/xml
    (base / 'bad.plist').write_text('this is not a plist at all')
    # plist whose loaded content is not JSON serializable (bytes+datetime)
    # -> plistlib.load ok, json.dumps raises -> generic except -> dat=None
    with open(base / 'unserializable.plist', 'wb') as f:
        plistlib.dump(
            {'blob': b'\x00\x01\x02', 'when': datetime.datetime(2020, 1, 1)},
            f, fmt=plistlib.FMT_BINARY)

    # sqlite db -> asciidoc + sql_dump  (fixtures may build more than once)
    dbp = base / 'store.db'
    if dbp.exists():
        dbp.unlink()
    con = sqlite3.connect(str(dbp))
    con.execute('CREATE TABLE t (id INTEGER, name TEXT)')
    con.execute("INSERT INTO t VALUES (1, 'alpha')")
    con.commit()
    con.close()

    # ipa payload dir (capital Payload) with a real file inside
    payload = base / 'Payload'
    payload.mkdir(exist_ok=True)
    (payload / 'inside.txt').write_text('payload content')

    # A second scan dir that exists but has NO payload/Payload
    Path(TMP_UPLD, MD5_NO_PAYLOAD).mkdir(parents=True, exist_ok=True)


@override_settings(UPLD_DIR=TMP_UPLD)
class SetExtApiTests(TestCase):
    """Pure helper: extension -> internal type mapping."""

    def test_all_extension_branches(self):
        self.assertEqual(set_ext_api('a.plist'), 'plist')
        self.assertEqual(set_ext_api('a.xml'), 'xml')
        self.assertEqual(set_ext_api('a.sqlitedb'), 'db')
        self.assertEqual(set_ext_api('a.db'), 'db')
        self.assertEqual(set_ext_api('a.sqlite'), 'db')
        self.assertEqual(set_ext_api('a.m'), 'm')
        # anything else falls through to txt
        self.assertEqual(set_ext_api('a.swift'), 'txt')
        self.assertEqual(set_ext_api('a.txt'), 'txt')
        self.assertEqual(set_ext_api('noext'), 'txt')


@override_settings(UPLD_DIR=TMP_UPLD)
class ApiRunTests(TestCase):
    """Drive run(request, api=True) against real files on disk."""

    @classmethod
    def setUpTestData(cls):
        _build_fixtures()

    def setUp(self):
        self.factory = RequestFactory()

    def _api(self, fil, mode='ios', md5=MD5):
        req = self.factory.post(
            '/view_file_ios/',
            {'file': fil, 'hash': md5, 'type': mode})
        return run(req, api=True)

    def test_m_file_cpp(self):
        ctx = self._api('code.m')
        self.assertEqual(ctx['type'], 'cpp')
        self.assertIn('Foundation', ctx['data'])
        self.assertEqual(ctx['file'], 'code.m')

    def test_xml_file(self):
        ctx = self._api('data.xml')
        self.assertEqual(ctx['type'], 'xml')
        self.assertIn('<root>', ctx['data'])

    def test_txt_file(self):
        ctx = self._api('notes.txt')
        self.assertEqual(ctx['type'], 'text')
        self.assertIn('hello world', ctx['data'])

    def test_plist_binary_json(self):
        ctx = self._api('good.plist')
        self.assertEqual(ctx['type'], 'json')
        parsed = json.loads(ctx['data'])
        self.assertEqual(parsed['k'], 'v')

    def test_plist_xml_json(self):
        ctx = self._api('goodxml.plist')
        self.assertEqual(ctx['type'], 'json')
        self.assertEqual(json.loads(ctx['data'])['name'], 'test')

    def test_plist_invalid_falls_back_to_xml(self):
        ctx = self._api('bad.plist')
        # InvalidFileException -> file_format becomes 'xml', raw text read
        self.assertEqual(ctx['type'], 'xml')
        self.assertIn('not a plist', ctx['data'])

    def test_plist_unserializable_sets_none(self):
        # plistlib loads, json.dumps raises -> generic except -> dat=None
        ctx = self._api('unserializable.plist')
        self.assertEqual(ctx['type'], 'json')
        self.assertIsNone(ctx['data'])

    def test_db_sqlite_dump(self):
        ctx = self._api('store.db')
        self.assertEqual(ctx['type'], 'asciidoc')
        self.assertIn('t', ctx['sqlite'])
        self.assertIn('alpha', ctx['sqlite']['t']['data'][0])

    def test_classdump_present(self):
        ctx = self._api('classdump.txt')
        self.assertEqual(ctx['type'], 'cpp')
        self.assertIn('@interface', ctx['data'])

    def test_classdump_absent(self):
        # Valid md5 dir with no classdump.txt -> "not Found" message
        ctx = self._api('classdump.txt', md5=MD5_NO_PAYLOAD)
        self.assertEqual(ctx['type'], 'cpp')
        self.assertEqual(ctx['data'], 'Class Dump result not Found')

    def test_ipa_payload_dir(self):
        ctx = self._api('inside.txt', mode='ipa')
        self.assertEqual(ctx['type'], 'text')
        self.assertIn('payload content', ctx['data'])

    def test_ipa_missing_payload_raises(self):
        # dir exists but no Payload -> Exception -> api error dict
        out = self._api('inside.txt', mode='ipa', md5=MD5_NO_PAYLOAD)
        self.assertIn('error', out)
        self.assertIn('Payload', out['error'])

    def test_form_invalid_traversal_blocked(self):
        # path traversal in file name -> form clean_file raises -> err dict
        out = self._api('../../etc/passwd.txt')
        self.assertIn('file', out)
        self.assertIn('Attack', out['file'])

    def test_form_invalid_bad_hash(self):
        out = self._api('notes.txt', md5='zzz')
        # invalid md5 -> hash field error (min_length / Invalid Hash)
        self.assertIn('hash', out)

    def test_missing_file_error_response(self):
        # valid form, safe path, but file does not exist -> open() raises
        out = self._api('doesnotexist.txt')
        self.assertIn('error', out)

    def test_dylib_mode_unhandled_raises(self):
        # 'dylib' is a valid form choice but run() never sets src -> NameError
        out = self._api('notes.txt', mode='dylib')
        self.assertIn('error', out)


@override_settings(UPLD_DIR=TMP_UPLD)
class WebRunTests(TestCase):
    """Drive the web path via real Client + real superuser (login_required)."""

    @classmethod
    def setUpTestData(cls):
        _build_fixtures()
        User = get_user_model()
        cls.user = User.objects.create_superuser(
            'ios_vs_admin', 'ios_vs_admin@example.com', 'Str0ngPass!123')

    def setUp(self):
        self.client = Client()
        self.client.force_login(self.user)

    def _get(self, fil, mode='ios', md5=MD5):
        return self.client.get(
            '/view_file_ios/',
            {'file': fil, 'md5': md5, 'type': mode})

    def test_web_txt_renders(self):
        resp = self._get('notes.txt')
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, 'notes.txt')

    def test_web_m_renders(self):
        resp = self._get('code.m')
        self.assertEqual(resp.status_code, 200)

    def test_web_db_renders(self):
        resp = self._get('store.db')
        self.assertEqual(resp.status_code, 200)

    def test_web_form_invalid_traversal(self):
        # traversal blocked at form level -> error response (not 200 render)
        resp = self._get('../../secret.txt')
        self.assertNotEqual(resp.status_code, 200)

    def test_web_missing_file(self):
        resp = self._get('nope.txt')
        # exception path -> error response
        self.assertNotEqual(resp.status_code, 200)
