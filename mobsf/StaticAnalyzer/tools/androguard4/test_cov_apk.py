# -*- coding: utf_8 -*-
"""Real-execution (NO MOCK) unit tests for the vendored androguard4 APK parser.

Every test drives real code with real inputs: the repo's test_files samples
(android.apk, android.aar, android.jar) plus crafted zips built with the stdlib
zipfile module. No unittest.mock, no monkeypatch, no fake returns.
"""
import io
import os
import zipfile

import pytest

from mobsf.StaticAnalyzer.tools.androguard4.apk import (
    APK,
    BrokenAPKError,
    FileNotPresent,
    ensure_final_value,
    get_apkid,
    show_Certificate,
)

_HERE = os.path.dirname(os.path.abspath(__file__))
# .../mobsf/StaticAnalyzer/tools/androguard4/ -> repo root is 4 dirs up
_REPO_ROOT = os.path.abspath(os.path.join(_HERE, '..', '..', '..', '..'))
TEST_FILES = os.path.join(_REPO_ROOT, 'test_files')


def _p(name):
    path = os.path.join(TEST_FILES, name)
    assert os.path.exists(path), path
    return path


# ----- Shared real APK objects (parsed once, reused) -----

@pytest.fixture(scope='module')
def apk():
    return APK(_p('android.apk'))


@pytest.fixture(scope='module')
def apk_raw():
    with open(_p('android.apk'), 'rb') as f:
        return APK(f.read(), raw=True)


@pytest.fixture(scope='module')
def jar():
    # A jar has no AndroidManifest.xml -> exercises the "not an APK" branch
    return APK(_p('android.jar'))


@pytest.fixture(scope='module')
def aar():
    return APK(_p('android.aar'))


@pytest.fixture(scope='module')
def plain_zip():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w') as z:
        z.writestr('hello.txt', 'world')
        z.writestr('dir/data.bin', b'\x00\x01\x02\x03')
    return APK(buf.getvalue(), raw=True)


# ----------------------------------------------------------------------------
# Core manifest parsing on a real, valid APK
# ----------------------------------------------------------------------------

def test_valid_apk_and_package(apk):
    assert apk.is_valid_APK() is True
    assert apk.get_package() == 'jakhar.aseem.diva'


def test_version_code_and_name(apk):
    assert apk.get_androidversion_code() == '1'
    assert apk.get_androidversion_name() == '1.0'


def test_permissions_real(apk):
    perms = apk.get_permissions()
    assert isinstance(perms, list)
    assert 'android.permission.INTERNET' in perms
    # uses_permissions rows are [name, maxSdkVersion]
    assert all(len(row) == 2 for row in apk.uses_permissions)


def test_activities_and_main_activity(apk):
    acts = apk.get_activities()
    assert 'jakhar.aseem.diva.MainActivity' in acts
    assert apk.get_main_activity() == 'jakhar.aseem.diva.MainActivity'
    assert apk.get_main_activities() == {'jakhar.aseem.diva.MainActivity'}


def test_services_receivers_providers(apk):
    assert apk.get_services() == []
    assert apk.get_receivers() == []
    assert apk.get_providers() == ['jakhar.aseem.diva.NotesProvider']


def test_sdk_versions(apk):
    assert apk.get_min_sdk_version() == '15'
    assert apk.get_target_sdk_version() == '23'
    assert apk.get_max_sdk_version() is None
    assert apk.get_effective_target_sdk_version() == 23


def test_app_name_and_icon(apk):
    assert apk.get_app_name() == 'Diva'
    icon = apk.get_app_icon()
    assert icon and icon.endswith('.png')


def test_app_name_locale_variant(apk):
    # Passing a locale exercises the ARSCResTableConfig(locale=...) branch
    assert isinstance(apk.get_app_name(locale='en'), str)


def test_features_libraries_and_form_factor_flags(apk):
    assert apk.get_features() == []
    assert apk.get_libraries() == []
    assert apk.is_wearable() is False
    assert apk.is_leanback() is False
    assert apk.is_androidtv() is False


def test_activity_aliases_empty(apk):
    assert apk.get_activity_aliases() == []


def test_intent_filters_real(apk):
    filt = apk.get_intent_filters('activity', apk.get_main_activity())
    assert 'android.intent.action.MAIN' in filt['action']
    assert 'android.intent.category.LAUNCHER' in filt['category']


def test_declared_and_implied_permissions(apk):
    assert apk.get_declared_permissions() == []
    assert isinstance(apk.get_declared_permissions_details(), dict)
    # target sdk 23 -> none of the <16 / <4 implied branches fire
    assert apk.get_uses_implied_permission_list() == []


def test_res_value_unresolvable_passthrough(apk):
    # A well-formed but unresolvable resource id hits the except branch and
    # is returned unchanged.
    val = '@7f999999'
    assert apk.get_res_value(val) == val


# ----------------------------------------------------------------------------
# Files / raw bytes
# ----------------------------------------------------------------------------

def test_get_files_and_raw(apk):
    files = apk.get_files()
    assert 'AndroidManifest.xml' in files
    assert 'classes.dex' in files
    raw = apk.get_raw()
    assert isinstance(raw, (bytes, bytearray))
    assert raw[:2] == b'PK'


def test_get_file_present_and_missing(apk):
    data = apk.get_file('AndroidManifest.xml')
    assert isinstance(data, bytes) and len(data) > 0
    with pytest.raises(FileNotPresent):
        apk.get_file('does/not/exist.xyz')


def test_dex_helpers(apk):
    assert apk.get_dex()[:4] == b'dex\n' or len(apk.get_dex()) > 0
    assert list(apk.get_dex_names()) == ['classes.dex']
    assert len(list(apk.get_all_dex())) == 1
    assert apk.is_multidex() is False


def test_files_crc32(apk):
    crc = apk.get_files_crc32()
    assert isinstance(crc, dict)
    assert 'AndroidManifest.xml' in crc
    assert all(isinstance(v, int) for v in crc.values())


def test_manifest_axml_and_xml(apk):
    from mobsf.StaticAnalyzer.tools.androguard4.axml import AXMLPrinter
    assert isinstance(apk.get_android_manifest_axml(), AXMLPrinter)
    xml = apk.get_android_manifest_xml()
    assert xml is not None
    assert xml.tag == 'manifest'


def test_android_resources(apk):
    from mobsf.StaticAnalyzer.tools.androguard4.axml import ARSCParser
    assert isinstance(apk.get_android_resources(), ARSCParser)


# ----------------------------------------------------------------------------
# Signatures / certificates (v1 present, v2/v3 absent in this sample)
# ----------------------------------------------------------------------------

def test_signature_state(apk):
    assert apk.is_signed() is True
    assert apk.is_signed_v1() is True
    assert apk.is_signed_v2() is False
    assert apk.is_signed_v3() is False


def test_signature_names_and_data(apk):
    names = apk.get_signature_names()
    assert names == ['META-INF/CERT.RSA']
    assert apk.get_signature_name() == 'META-INF/CERT.RSA'
    sigs = apk.get_signatures()
    assert len(sigs) == 1 and isinstance(sigs[0], bytes)
    assert apk.get_signature() == sigs[0]


def test_get_certificate_der_and_object(apk):
    from asn1crypto import x509
    name = apk.get_signature_names()[0]
    der = apk.get_certificate_der(name)
    assert isinstance(der, bytes) and len(der) > 0
    cert = apk.get_certificate(name)
    assert isinstance(cert, x509.Certificate)


def test_get_certificates_unique(apk):
    from asn1crypto import x509
    certs = apk.get_certificates()
    assert len(certs) == 1
    assert isinstance(certs[0], x509.Certificate)
    # v1 verified list matches
    assert len(apk.get_certificates_v1()) == 1


def test_v2_v3_empty_collections(apk):
    assert apk.get_certificates_v2() == []
    assert apk.get_certificates_v3() == []
    assert apk.get_public_keys_v2() == []
    assert apk.get_public_keys_v3() == []
    assert apk.get_certificates_der_v2() == []
    assert apk.get_certificates_der_v3() == []
    assert apk.get_public_keys_der_v2() == []
    assert apk.get_public_keys_der_v3() == []


def test_show_certificate_real_output(apk, capsys):
    cert = apk.get_certificate(apk.get_signature_names()[0])
    show_Certificate(cert)
    out = capsys.readouterr().out
    assert 'SHA1 Fingerprint' in out
    assert 'SHA256 Fingerprint' in out
    assert 'Issuer' in out and 'Subject' in out


def test_canonical_name_real(apk):
    cert = apk.get_certificate(apk.get_signature_names()[0])
    canonical = apk.canonical_name(cert.subject)
    assert isinstance(canonical, str)
    # Android Debug cert -> country + org + common name present
    assert 'android' in canonical.lower()


# ----------------------------------------------------------------------------
# raw=True construction path
# ----------------------------------------------------------------------------

def test_raw_construction(apk_raw):
    assert apk_raw.is_valid_APK() is True
    assert apk_raw.get_filename().startswith('raw_apk_sha256:')
    assert apk_raw.get_package() == 'jakhar.aseem.diva'


# ----------------------------------------------------------------------------
# testzip integrity check on a real, intact APK
# ----------------------------------------------------------------------------

def test_testzip_intact():
    a = APK(_p('android.apk'), testzip=True)
    assert a.is_valid_APK() is True


# ----------------------------------------------------------------------------
# jar / aar: valid zips but not APKs -> "missing manifest" branch
# ----------------------------------------------------------------------------

def test_jar_is_not_valid_apk(jar):
    assert jar.is_valid_APK() is False
    assert jar.get_permissions() == []
    assert jar.get_activities() == []
    assert jar.get_android_manifest_axml() is None
    assert jar.get_android_manifest_xml() is None


def test_aar_is_not_valid_apk(aar):
    assert aar.is_valid_APK() is False
    # aar has no resources.arsc at root
    assert aar.get_android_resources() is None
    assert aar.get_signature_names() == []
    assert aar.get_certificates() == []


# ----------------------------------------------------------------------------
# Crafted plain zip (not an APK) -> error/empty branches without any mock
# ----------------------------------------------------------------------------

def test_plain_zip_no_manifest(plain_zip):
    assert plain_zip.is_valid_APK() is False
    assert set(plain_zip.get_files()) == {'hello.txt', 'dir/data.bin'}
    assert plain_zip.get_permissions() == []
    assert plain_zip.get_services() == []
    assert plain_zip.get_providers() == []
    assert plain_zip.get_signature_names() == []
    assert plain_zip.get_signatures() == []
    assert plain_zip.get_certificates() == []
    assert plain_zip.get_dex() == b''
    assert plain_zip.get_android_manifest_axml() is None
    assert plain_zip.get_android_resources() is None
    assert plain_zip.is_signed() is False


def test_plain_zip_app_name_and_icon(plain_zip):
    # No manifest -> app name empty, icon None (no resources)
    assert plain_zip.get_app_name() == ''
    assert plain_zip.get_app_icon() is None


def test_non_zip_bytes_raises():
    # A buffer that is not a zip at all must raise during parse
    with pytest.raises(Exception):
        APK(b'this is definitely not a zip archive', raw=True)


# ----------------------------------------------------------------------------
# Manifest with a broken/binary (non-AXML) manifest -> invalid branch
# ----------------------------------------------------------------------------

def test_garbage_manifest_marks_invalid():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w') as z:
        z.writestr('AndroidManifest.xml', b'not a real binary xml manifest')
        z.writestr('classes.dex', b'\x00' * 16)
    a = APK(buf.getvalue(), raw=True)
    # AXML parsing fails -> apk stays invalid, no crash
    assert a.is_valid_APK() is False
    assert a.get_permissions() == []


# ----------------------------------------------------------------------------
# Multidex detection with a crafted zip
# ----------------------------------------------------------------------------

def test_multidex_detection():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w') as z:
        z.writestr('classes.dex', b'\x00')
        z.writestr('classes2.dex', b'\x00')
    a = APK(buf.getvalue(), raw=True)
    assert a.is_multidex() is True
    assert sorted(a.get_dex_names()) == ['classes.dex', 'classes2.dex']
    assert len(list(a.get_all_dex())) == 2


# ----------------------------------------------------------------------------
# get_signature_names skips partial signatures (missing .SF)
# ----------------------------------------------------------------------------

def test_partial_signature_skipped():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w') as z:
        # .RSA present but no matching .SF -> partial, skipped
        z.writestr('META-INF/FOO.RSA', b'\x30\x82')
    a = APK(buf.getvalue(), raw=True)
    assert a.get_signature_names() == []
    # is_signed_v1 relies on signature_name being None
    assert a.is_signed_v1() is False


# ----------------------------------------------------------------------------
# Module-level helpers
# ----------------------------------------------------------------------------

def test_get_apkid_real():
    appid, version_code, version_name = get_apkid(_p('android.apk'))
    assert appid == 'jakhar.aseem.diva'
    assert version_code == '1'
    assert version_name == '1.0'


def test_ensure_final_value_passthrough_and_empty(apk):
    arsc = apk.get_android_resources()
    pkg = apk.get_package()
    # Plain literal is returned unchanged
    assert ensure_final_value(pkg, arsc, 'plain') == 'plain'
    # Empty value -> empty string
    assert ensure_final_value(pkg, arsc, '') == ''
    # A bogus @-value that is not a valid res id falls back to itself
    assert ensure_final_value(pkg, arsc, '@zzz') == '@zzz'


def test_get_value_from_tag_and_attribute(apk):
    # Real xml tag round-trip through the namespace-aware getters
    xml = apk.get_android_manifest_xml()
    assert apk.get_value_from_tag(xml, 'versionName') == '1.0'
    assert apk.get_attribute_value('manifest', 'versionName') == '1.0'


def test_find_tags_with_attribute_filter(apk):
    tags = apk.find_tags('activity', name='jakhar.aseem.diva.MainActivity')
    assert len(tags) == 1
    # format_value=True + attribute filter both exercised
    val = apk.get_attribute_value(
        'activity', 'name', format_value=True,
        name='jakhar.aseem.diva.MainActivity')
    assert val == 'jakhar.aseem.diva.MainActivity'


def test_pickle_round_trip():
    import pickle
    # NB: __getstate__ mutates the object in place, so use a dedicated instance.
    src = APK(_p('android.apk'))
    restored = pickle.loads(pickle.dumps(src))
    assert restored.get_package() == 'jakhar.aseem.diva'
    assert restored.is_valid_APK() is True
    assert restored.get_androidversion_name() == '1.0'


def test_format_value_prefixes_package(apk):
    # value beginning with a dot gets package prefixed
    assert apk._format_value('.Foo') == 'jakhar.aseem.diva.Foo'
    # dotless value also gets prefixed
    assert apk._format_value('Foo') == 'jakhar.aseem.diva.Foo'
    # already-qualified value unchanged
    assert apk._format_value('a.b.C') == 'a.b.C'
