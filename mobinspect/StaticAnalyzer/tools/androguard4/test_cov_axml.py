# -*- coding: utf_8 -*-
"""
Real-execution (NO MOCK) tests for the vendored androguard4 axml parser.

Drives the real binary AXML/ARSC parsers with real bytes extracted from
test_files/android.apk plus crafted byte buffers for the malformed-chunk
error branches. No unittest.mock, no monkeypatch, no fake returns.
"""
import io
import os
import zipfile
from struct import pack

import pytest

from mobinspect.StaticAnalyzer.tools.androguard4.axml import (
    ARSCHeader,
    ARSCParser,
    ARSCResTableConfig,
    AXMLParser,
    AXMLPrinter,
    ResParserError,
    START_TAG,
    END_TAG,
    END_DOCUMENT,
    RES_STRING_POOL_TYPE,
    RES_TABLE_TYPE,
    StringBlock,
    complexToFloat,
    format_value,
    get_arsc_info,
)
from mobinspect.StaticAnalyzer.tools.androguard4.types import (
    TYPE_ATTRIBUTE,
    TYPE_DIMENSION,
    TYPE_FLOAT,
    TYPE_FRACTION,
    TYPE_INT_BOOLEAN,
    TYPE_INT_COLOR_ARGB8,
    TYPE_INT_DEC,
    TYPE_INT_HEX,
    TYPE_REFERENCE,
    TYPE_STRING,
)


REPO_ROOT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), '..', '..', '..', '..')
)
APK = os.path.join(REPO_ROOT, 'test_files', 'android.apk')


# --------------------------------------------------------------------------
# Fixtures: real binary AndroidManifest.xml + resources.arsc from the APK
# --------------------------------------------------------------------------
@pytest.fixture(scope='module')
def manifest_bytes():
    with zipfile.ZipFile(APK) as z:
        return z.read('AndroidManifest.xml')


@pytest.fixture(scope='module')
def arsc_bytes():
    with zipfile.ZipFile(APK) as z:
        return z.read('resources.arsc')


@pytest.fixture(scope='module')
def arsc(arsc_bytes):
    return ARSCParser(arsc_bytes)


def _make_header_buff(data: bytes) -> io.BufferedReader:
    return io.BufferedReader(io.BytesIO(data))


# --------------------------------------------------------------------------
# Module-level helpers
# --------------------------------------------------------------------------
def test_complex_to_float_known_value():
    # 0x00000100 -> mantissa 0x100, radix index 0 -> 256 * 0.00390625 == 1.0
    assert complexToFloat(0x00000100) == pytest.approx(1.0)
    assert complexToFloat(0) == 0.0


def test_format_value_string_lookup():
    assert format_value(TYPE_STRING, 5, lambda ix: 'HELLO-%d' % ix) == 'HELLO-5'


def test_format_value_attribute_and_reference_android_prefix():
    # data >> 24 == 1 -> "android:" prefix
    assert format_value(TYPE_ATTRIBUTE, 0x01010203) == '?android:01010203'
    assert format_value(TYPE_REFERENCE, 0x01010203) == '@android:01010203'
    # non-android package -> no prefix
    assert format_value(TYPE_REFERENCE, 0x7F060000) == '@7F060000'


def test_format_value_float():
    # pack a known float bit pattern
    from struct import unpack, pack as _pack
    bits = unpack('=L', _pack('=f', 2.5))[0]
    assert format_value(TYPE_FLOAT, bits) == '%f' % 2.5


def test_format_value_int_hex_and_dec_and_bool():
    assert format_value(TYPE_INT_HEX, 0xABCD) == '0x0000ABCD'
    assert format_value(TYPE_INT_DEC, 42) == '42'
    # negative interpretation for high values
    assert format_value(TYPE_INT_DEC, 0xFFFFFFFF) == '-1'
    assert format_value(TYPE_INT_BOOLEAN, 0) == 'false'
    assert format_value(TYPE_INT_BOOLEAN, 1) == 'true'


def test_format_value_dimension_fraction_color_and_unknown():
    # dimension: unit index 1 -> "dip"
    dim = format_value(TYPE_DIMENSION, 0x00000101)
    assert dim.endswith('dip')
    frac = format_value(TYPE_FRACTION, 0x00000100)  # unit 0 -> "%"
    assert frac.endswith('%')
    assert format_value(TYPE_INT_COLOR_ARGB8, 0x11223344) == '#11223344'
    # unknown type -> fallback representation
    assert format_value(0xFE, 0x1234) == '<0x1234, type 0xFE>'


# --------------------------------------------------------------------------
# AXMLPrinter over the real AndroidManifest.xml
# --------------------------------------------------------------------------
def test_axmlprinter_parses_real_manifest(manifest_bytes):
    p = AXMLPrinter(manifest_bytes)
    assert p.is_valid() is True
    xml = p.get_xml()
    assert isinstance(xml, bytes)
    assert b'manifest' in xml
    assert b'jakhar.aseem.diva' in xml
    # android namespace should be resolved into the XML
    assert b'schemas.android.com/apk/res/android' in xml


def test_axmlprinter_get_buff_and_obj(manifest_bytes):
    p = AXMLPrinter(manifest_bytes)
    buff = p.get_buff()  # non-pretty
    pretty = p.get_xml(pretty=True)
    assert isinstance(buff, bytes) and len(buff) > 0
    # pretty output includes newlines/indentation, non-pretty is more compact
    assert len(pretty) >= len(buff)
    obj = p.get_xml_obj()
    assert obj is not None
    assert obj.tag == 'manifest'
    # 'package' attribute should be present on the root
    assert obj.get('package') == 'jakhar.aseem.diva'


def test_axmlprinter_not_packed(manifest_bytes):
    p = AXMLPrinter(manifest_bytes)
    # a normal compiled manifest is not a packer
    assert p.is_packed() is False


# --------------------------------------------------------------------------
# AXMLParser direct iteration + accessors on the real manifest
# --------------------------------------------------------------------------
def test_axmlparser_iteration_and_accessors(manifest_bytes):
    ap = AXMLParser(manifest_bytes)
    assert ap.is_valid() is True

    names = []
    saw_attributes = False
    android_ns_seen = False
    while True:
        ev = next(ap)
        if ev == END_DOCUMENT:
            break
        if ev == START_TAG:
            names.append(ap.name)
            # nsmap should contain the android prefix mapping at some point
            if 'android' in ap.nsmap:
                android_ns_seen = True
            cnt = ap.getAttributeCount()
            assert cnt >= 0
            for i in range(cnt):
                nm = ap.getAttributeName(i)
                assert isinstance(nm, str) and nm != ''
                # numeric type/data accessors
                assert isinstance(ap.getAttributeValueType(i), int)
                assert isinstance(ap.getAttributeValueData(i), int)
                # value lookup returns a string (possibly '')
                assert isinstance(ap.getAttributeValue(i), str)
                # namespace/uri accessors
                assert isinstance(ap.getAttributeUri(i), int)
                assert isinstance(ap.getAttributeNamespace(i), str)
                saw_attributes = True
        elif ev == END_TAG:
            # legacy getters must work at END_TAG
            assert isinstance(ap.getName(), str)

    assert 'manifest' in names
    assert 'application' in names
    assert saw_attributes is True
    assert android_ns_seen is True


def test_axmlparser_legacy_getters_outside_tag(manifest_bytes):
    ap = AXMLParser(manifest_bytes)
    # before iterating, name/text/namespace should be empty strings
    assert ap.name == ''
    assert ap.text == ''
    assert ap.namespace == ''
    # getAttributeCount returns -1 when not in a START_TAG
    assert ap.getAttributeCount() == -1


def test_axmlparser_comment_property(manifest_bytes):
    ap = AXMLParser(manifest_bytes)
    next(ap)  # advance to first tag
    # comment is either None (no comment) or a string
    c = ap.comment
    assert c is None or isinstance(c, str)


# --------------------------------------------------------------------------
# AXMLParser invalid / malformed inputs (real error branches, no mocks)
# --------------------------------------------------------------------------
def test_axmlparser_too_small_buffer():
    ap = AXMLParser(b'\x00\x00\x00')  # < 8 bytes
    assert ap.is_valid() is False


def test_axmlparser_plain_xml_is_invalid():
    # A plain XML file is not AXML; the header will not validate.
    plain = b'<?xml version="1.0"?><manifest></manifest>' + b'\x00' * 40
    ap = AXMLParser(plain)
    assert ap.is_valid() is False


def test_axmlprinter_on_plain_xml_yields_no_root():
    plain = b'<?xml version="1.0"?><a></a>' + b'\x00' * 40
    p = AXMLPrinter(plain)
    assert p.is_valid() is False
    assert p.get_xml_obj() is None


def test_axmlparser_bad_string_pool_header():
    # Valid first RES_XML header (type=0x0003, header_size=8) but the following
    # string pool header type is wrong -> parser must go invalid.
    buff = pack('<HHL', RES_TABLE_TYPE, 8, 40)  # first header (type != XML ok)
    buff += pack('<HHL', 0x9999, 0x1C, 20)      # wrong string-pool type
    buff += b'\x00' * 40
    ap = AXMLParser(buff)
    assert ap.is_valid() is False


# --------------------------------------------------------------------------
# ARSCHeader crafted error branches
# --------------------------------------------------------------------------
def test_arscheader_truncated_raises():
    with pytest.raises(ResParserError):
        ARSCHeader(_make_header_buff(b'\x01\x00\x08'))  # < SIZE bytes


def test_arscheader_expected_type_mismatch():
    data = pack('<HHL', 0x0002, 8, 8) + b'\x00' * 8
    with pytest.raises(ResParserError):
        ARSCHeader(_make_header_buff(data), expected_type=0x0001)


def test_arscheader_header_size_too_small():
    data = pack('<HHL', 0x0001, 4, 100) + b'\x00' * 8
    with pytest.raises(ResParserError):
        ARSCHeader(_make_header_buff(data))


def test_arscheader_chunk_size_too_small():
    data = pack('<HHL', 0x0001, 8, 4) + b'\x00' * 8
    with pytest.raises(ResParserError):
        ARSCHeader(_make_header_buff(data))


def test_arscheader_size_smaller_than_header_size():
    data = pack('<HHL', 0x0001, 16, 12) + b'\x00' * 16
    with pytest.raises(ResParserError):
        ARSCHeader(_make_header_buff(data))


def test_arscheader_valid_properties():
    data = pack('<HHL', RES_TABLE_TYPE, 12, 100) + b'\x00' * 100
    h = ARSCHeader(_make_header_buff(data))
    assert h.type == RES_TABLE_TYPE
    assert h.header_size == 12
    assert h.size == 100
    assert h.start == 0
    assert h.end == 100
    assert 'ARSCHeader' in repr(h)


# --------------------------------------------------------------------------
# ARSCParser over the real resources.arsc
# --------------------------------------------------------------------------
def test_arscparser_too_small_buffer_raises():
    with pytest.raises(ResParserError):
        ARSCParser(b'\x00\x00\x00\x00')


def test_arscparser_packages_locales_types(arsc):
    pkgs = arsc.get_packages_names()
    assert pkgs == ['jakhar.aseem.diva']
    pkg = pkgs[0]
    locales = arsc.get_locales(pkg)
    assert '\x00\x00' in locales
    assert 'ca' in locales
    types = arsc.get_types(pkg)
    assert 'string' in types
    assert 'public' in types


def test_arscparser_resource_xml_getters(arsc):
    pkg = arsc.get_packages_names()[0]
    for getter in (
        arsc.get_public_resources,
        arsc.get_string_resources,
        arsc.get_id_resources,
        arsc.get_integer_resources,
        arsc.get_color_resources,
        arsc.get_dimen_resources,
    ):
        out = getter(pkg)
        assert isinstance(out, bytes)
        assert out.startswith(b'<?xml')
        assert b'<resources>' in out
    combined = arsc.get_strings_resources()
    assert b'<packages>' in combined
    assert b'jakhar.aseem.diva' in combined


def test_arscparser_bool_resources_index_error(arsc):
    # Real bug in vendored code for this APK: get_resource_bool can produce a
    # 1-element list, so formatting i[1] raises IndexError. Assert the real
    # behaviour rather than faking it.
    pkg = arsc.get_packages_names()[0]
    with pytest.raises(IndexError):
        arsc.get_bool_resources(pkg)


def test_arscparser_get_arsc_info_hits_bool_bug(arsc):
    # get_arsc_info walks every type and eventually hits the bool bug above.
    with pytest.raises(IndexError):
        get_arsc_info(arsc)


def test_arscparser_string_resolution(arsc):
    pkg = arsc.get_packages_names()[0]
    arsc._analyse()
    publics = arsc.values[pkg]['\x00\x00']['public']
    string_pub = next(x for x in publics if x[0] == 'string')
    _type, name, rid = string_pub

    # get_id round-trips
    assert arsc.get_id(pkg, rid) == (_type, name, rid)
    # xml name
    xml_name = arsc.get_resource_xml_name(rid)
    assert xml_name.endswith('string/%s' % name)
    xml_name_pkg = arsc.get_resource_xml_name(rid, pkg)
    assert xml_name_pkg == '@string/%s' % name
    # id-by-key round trip
    assert arsc.get_res_id_by_key(pkg, 'string', name) == rid
    # get_string returns [name, value]
    s = arsc.get_string(pkg, name)
    assert s[0] == name and isinstance(s[1], str)


def test_arscparser_res_configs_and_resolution(arsc):
    pkg = arsc.get_packages_names()[0]
    arsc._analyse()
    publics = arsc.values[pkg]['\x00\x00']['public']
    rid = next(x for x in publics if x[0] == 'string')[2]

    configs = arsc.get_res_configs(rid)
    assert len(configs) >= 1
    # resolution returns (config, resolved-string) tuples
    resolved = arsc.get_resolved_res_configs(rid)
    assert len(resolved) >= 1
    cfg, value = resolved[0]
    assert isinstance(value, str) and value != ''

    resolved_strings = arsc.get_resolved_strings()
    assert pkg in resolved_strings
    assert 'DEFAULT' in resolved_strings[pkg]


def test_arscparser_get_res_configs_errors(arsc):
    with pytest.raises(ValueError):
        arsc.get_res_configs(0)  # rid falsy
    with pytest.raises(ValueError):
        arsc.get_res_configs('notanint')  # wrong type
    # unknown rid returns empty list (real warning branch)
    assert arsc.get_res_configs(0x7F999999) == []


def test_arscparser_complex_resource_resolution(arsc):
    # Resolve a complex (style/attr) entry to exercise the complex/reference
    # branches of ResourceResolver.
    pkg = arsc.get_packages_names()[0]
    arsc._analyse()
    publics = arsc.values[pkg]['\x00\x00']['public']
    complex_types = {'style', 'attr'}
    candidate = next(
        (x for x in publics if x[0] in complex_types), None
    )
    if candidate is None:
        pytest.skip('No complex style/attr resource in this APK')
    resolved = arsc.get_resolved_res_configs(candidate[2])
    # complex entries resolve into a list of formatted values
    assert isinstance(resolved, list)


def test_arscparser_get_items_and_type_configs(arsc):
    pkg = arsc.get_packages_names()[0]
    items = arsc.get_items(pkg)
    assert isinstance(items, list) and len(items) > 0
    tc = arsc.get_type_configs(pkg)
    assert 'string' in tc
    # None package_name defaults to the first package
    tc_default = arsc.get_type_configs(None)
    assert len(tc_default) > 0


def test_arscparser_get_id_unknown_returns_none_tuple(arsc):
    pkg = arsc.get_packages_names()[0]
    assert arsc.get_id(pkg, 0xDEADBEEF) == (None, None, None)


# --------------------------------------------------------------------------
# ARSCParser.parse_id (static)
# --------------------------------------------------------------------------
def test_parse_id_valid_with_and_without_package():
    assert ARSCParser.parse_id('@7f060000') == (0x7F060000, None)
    assert ARSCParser.parse_id('@android:7f060000') == (0x7F060000, 'android')


def test_parse_id_malformed():
    with pytest.raises(ValueError):
        ARSCParser.parse_id('7f060000')  # missing @
    with pytest.raises(ValueError):
        ARSCParser.parse_id('@7f06')      # not 8 chars
    with pytest.raises(ValueError):
        ARSCParser.parse_id('@zzzzzzzz')  # not hex


# --------------------------------------------------------------------------
# StringBlock via the real main string pool
# --------------------------------------------------------------------------
def test_stringblock_access(arsc):
    sb = arsc.stringpool_main
    assert isinstance(sb, StringBlock)
    assert len(sb) > 0
    first = sb.getString(0)
    assert isinstance(first, str)
    # indexing and iteration
    assert sb[0] == first
    it = iter(sb)
    assert isinstance(next(it), str)
    # out-of-range index returns empty string (no exception)
    assert sb.getString(-1) == ''
    assert sb.getString(len(sb) + 1000) == ''
    assert 'StringPool' in repr(sb)


# --------------------------------------------------------------------------
# ARSCResTableConfig
# --------------------------------------------------------------------------
def test_restableconfig_default():
    d = ARSCResTableConfig.default_config()
    assert d.is_default() is True
    assert d.get_qualifier() == ''
    assert d.get_language_and_region() == '\x00\x00'
    # default_config is cached / equal to itself
    assert ARSCResTableConfig.default_config() == d
    assert hash(d) == hash(ARSCResTableConfig.default_config())


def test_restableconfig_from_kwargs_locale_and_density():
    cfg = ARSCResTableConfig(locale='en-rUS', density=240)
    assert cfg.get_language_and_region() == 'en-rUS'
    q = cfg.get_qualifier()
    assert 'en-rUS' in q
    assert 'hdpi' in q  # density 240 -> hdpi
    assert cfg.get_language() == 'en'
    assert cfg.get_country() == 'US'
    assert cfg.get_density() == 240
    assert cfg.is_default() is False


def test_restableconfig_equality_and_hash():
    a = ARSCResTableConfig(locale='fr')
    b = ARSCResTableConfig(locale='fr')
    c = ARSCResTableConfig(locale='de')
    assert a == b
    assert hash(a) == hash(b)
    assert a != c


def test_arscparser_getters_missing_locale_keyerror(arsc):
    # A bogus locale exercises the `except KeyError: pass` branch of every
    # resource getter (they return an empty <resources/> document).
    pkg = arsc.get_packages_names()[0]
    bogus = 'zz-rZZ'
    for getter in (
        arsc.get_public_resources,
        arsc.get_string_resources,
        arsc.get_id_resources,
        arsc.get_integer_resources,
        arsc.get_color_resources,
        arsc.get_dimen_resources,
    ):
        out = getter(pkg, bogus)
        assert out.startswith(b'<?xml')
        assert b'<resources>' in out
    # bool getter with bogus locale: KeyError branch -> no IndexError here
    assert arsc.get_bool_resources(pkg, bogus).startswith(b'<?xml')


def test_arscparser_get_string_and_key_unknown_return_none(arsc):
    pkg = arsc.get_packages_names()[0]
    assert arsc.get_string(pkg, 'this_name_does_not_exist_xyz') is None
    assert arsc.get_res_id_by_key(pkg, 'string', 'nope_xyz') is None
    # unknown package -> KeyError branch returning None
    assert arsc.get_string('no.such.pkg', 'whatever') is None


def test_arscparser_get_resource_xml_name_unknown(arsc):
    pkg = arsc.get_packages_names()[0]
    assert arsc.get_resource_xml_name(0xDEADBEEF) is None
    assert arsc.get_resource_xml_name(0xDEADBEEF, pkg) is None


def test_restableconfig_legacy_alias():
    cfg = ARSCResTableConfig(locale='fr-rCA')
    assert cfg.get_config_name_friendly() == cfg.get_qualifier()


def test_arscparser_resolve_complex_entry_with_references(arsc):
    # Find a genuinely complex ARSCResTableEntry and resolve it so the
    # complex + reference branches of ResourceResolver run on real data.
    arsc._analyse()
    complex_rid = None
    for rid, options in arsc.resource_values.items():
        for cfg, ate in options.items():
            if ate.is_complex():
                complex_rid = rid
                break
        if complex_rid is not None:
            break
    if complex_rid is None:
        pytest.skip('No complex resource entry present in this APK')
    resolved = arsc.get_resolved_res_configs(complex_rid)
    assert isinstance(resolved, list)


def test_restableconfig_get_qualifier_many_branches():
    # Build a config with a wide variety of fields set so get_qualifier walks
    # most of its qualifier-emitting branches on real data.
    cfg = ARSCResTableConfig(
        mcc=310,
        mnc=260,
        locale='en-rUS',
        orientation=1,          # port
        touchscreen=3,          # finger
        density=240,            # hdpi
        keyboard=2,             # qwerty
        navigation=2,           # dpad
        inputFlags=0x05,        # keysexposed + navexposed
        screenWidth=1080,
        screenHeight=1920,
        sdkVersion=29,
        screenLayout=0x62,      # ldltr + normal + long
        uiMode=0x23,            # car + night
        smallestScreenWidthDp=320,
        screenWidthDp=411,
        screenHeightDp=731,
    )
    q = cfg.get_qualifier()
    for token in (
        'mcc310', 'mnc260', 'en-rUS', 'ldltr', 'sw320dp', 'w411dp',
        'h731dp', 'normal', 'long', 'port', 'car', 'night', 'hdpi',
        'finger', 'qwerty', 'dpad', 'keysexposed', 'navexposed',
        '1080x1920', 'v29',
    ):
        assert token in q, '%s missing from %s' % (token, q)


def test_restableconfig_real_config_from_arsc(arsc):
    # Pull a real non-default config out of the parsed resources and exercise
    # get_qualifier / get_language_and_region on real bytes.
    pkg = arsc.get_packages_names()[0]
    arsc._analyse()
    real_cfg = None
    for rid, options in arsc.resource_values.items():
        for cfg in options:
            if not cfg.is_default():
                real_cfg = cfg
                break
        if real_cfg:
            break
    assert real_cfg is not None
    assert isinstance(real_cfg.get_qualifier(), str)
    assert isinstance(real_cfg.get_language_and_region(), str)
