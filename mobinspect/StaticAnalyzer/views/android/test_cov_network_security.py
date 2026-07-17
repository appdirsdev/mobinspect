# -*- coding: utf_8 -*-
"""Real-execution tests for network_security parsing (NO mocks)."""
import pytest

from mobinspect.StaticAnalyzer.views.android.network_security import (
    analysis,
    read_netsec_config,
)

CHK = 'deadbeefdeadbeefdeadbeefdeadbeef'


def _write_studio(app_dir, name, xml):
    xml_dir = app_dir / 'app' / 'src' / 'main' / 'res' / 'xml'
    xml_dir.mkdir(parents=True, exist_ok=True)
    (xml_dir / f'{name}.xml').write_text(xml, encoding='utf8')
    return xml_dir


def _write_apk(app_dir, name, xml):
    xml_dir = app_dir / 'apktool_out' / 'res' / 'xml'
    xml_dir.mkdir(parents=True, exist_ok=True)
    (xml_dir / f'{name}.xml').write_text(xml, encoding='utf8')
    return xml_dir


# ------------------- read_netsec_config -------------------

@pytest.mark.django_db
def test_read_config_studio(tmp_path):
    _write_studio(tmp_path, 'network_security_config', '<x/>')
    out = read_netsec_config(
        CHK, str(tmp_path), '@xml/network_security_config', 'studio')
    assert out == '<x/>'


@pytest.mark.django_db
def test_read_config_apk(tmp_path):
    _write_apk(tmp_path, 'network_security_config', '<y/>')
    out = read_netsec_config(
        CHK, str(tmp_path), '@xml/network_security_config', 'apk')
    assert out == '<y/>'


@pytest.mark.django_db
def test_read_config_fallback_glob(tmp_path):
    # Config name in manifest doesn't resolve to a file, but a file with
    # 'network_security' in its stem exists -> fallback glob path.
    _write_apk(tmp_path, 'my_network_security_cfg', '<z/>')
    out = read_netsec_config(
        CHK, str(tmp_path), '@xml/does_not_exist', 'apk')
    assert out == '<z/>'


@pytest.mark.django_db
def test_read_config_not_found(tmp_path):
    _write_apk(tmp_path, 'unrelated', '<a/>')
    out = read_netsec_config(
        CHK, str(tmp_path), '@xml/missing', 'apk')
    assert out is None


@pytest.mark.django_db
def test_read_config_path_traversal(tmp_path):
    # A traversal config value skips the direct read but still globs xml_dir.
    _write_apk(tmp_path, 'network_security_config', '<b/>')
    out = read_netsec_config(
        CHK, str(tmp_path), '../../etc/passwd', 'apk')
    assert out == '<b/>'


@pytest.mark.django_db
def test_read_config_missing_dir_returns_none(tmp_path):
    out = read_netsec_config(
        CHK, str(tmp_path), '@xml/network_security_config', 'apk')
    assert out is None


# ------------------- analysis: guard clauses -------------------

@pytest.mark.django_db
def test_analysis_no_config(tmp_path):
    res = analysis(CHK, str(tmp_path), '', False, 'apk')
    assert res == {'network_findings': [], 'network_summary': {}}


@pytest.mark.django_db
def test_analysis_config_but_no_file(tmp_path):
    res = analysis(CHK, str(tmp_path), '@xml/nope', False, 'apk')
    assert res == {'network_findings': [], 'network_summary': {}}


def _run(tmp_path, xml, is_debuggable=False, src_type='apk'):
    _write_apk(tmp_path, 'network_security_config', xml)
    return analysis(
        CHK, str(tmp_path), '@xml/network_security_config',
        is_debuggable, src_type)


# ------------------- base-config -------------------

@pytest.mark.django_db
def test_base_cleartext_true(tmp_path):
    xml = ('<network-security-config>'
           '<base-config cleartextTrafficPermitted="true"/>'
           '</network-security-config>')
    res = _run(tmp_path, xml)
    assert res['network_summary']['high'] == 1
    assert 'permit clear text traffic to all domains' \
        in res['network_findings'][0]['description']
    assert res['network_findings'][0]['scope'] == ['*']


@pytest.mark.django_db
def test_base_cleartext_false(tmp_path):
    xml = ('<network-security-config>'
           '<base-config cleartextTrafficPermitted="false"/>'
           '</network-security-config>')
    res = _run(tmp_path, xml)
    assert res['network_summary']['secure'] == 1
    assert res['network_findings'][0]['severity'] == 'secure'


@pytest.mark.django_db
def test_base_trust_raw_system_user_override(tmp_path):
    xml = ('<network-security-config>'
           '<base-config>'
           '<trust-anchors>'
           '<certificates src="@raw/mycert"/>'
           '<certificates src="system"/>'
           '<certificates src="user" overridePins="true"/>'
           '</trust-anchors>'
           '</base-config>'
           '</network-security-config>')
    res = _run(tmp_path, xml)
    s = res['network_summary']
    # @raw -> info, system -> warning, user -> high, overridePins -> high
    assert s['info'] == 1
    assert s['warning'] == 1
    assert s['high'] == 2
    descs = [f['description'] for f in res['network_findings']]
    assert any('bundled certs' in d for d in descs)
    assert any('system certificates' in d for d in descs)
    assert any('user installed certificates' in d for d in descs)
    assert any('bypass certificate pinning' in d for d in descs)


# ------------------- domain-config -------------------

@pytest.mark.django_db
def test_domain_cleartext_true(tmp_path):
    xml = ('<network-security-config>'
           '<domain-config cleartextTrafficPermitted="true">'
           '<domain includeSubdomains="true">example.com</domain>'
           '<domain>test.com</domain>'
           '</domain-config>'
           '</network-security-config>')
    res = _run(tmp_path, xml)
    assert res['network_summary']['high'] == 1
    f = res['network_findings'][0]
    assert f['scope'] == ['example.com', 'test.com']
    assert 'permit clear text traffic' in f['description']


@pytest.mark.django_db
def test_domain_cleartext_false(tmp_path):
    xml = ('<network-security-config>'
           '<domain-config cleartextTrafficPermitted="false">'
           '<domain>secure.com</domain>'
           '</domain-config>'
           '</network-security-config>')
    res = _run(tmp_path, xml)
    assert res['network_summary']['secure'] == 1
    assert res['network_findings'][0]['scope'] == ['secure.com']


@pytest.mark.django_db
def test_domain_trust_anchors_all(tmp_path):
    xml = ('<network-security-config>'
           '<domain-config>'
           '<domain>d.com</domain>'
           '<trust-anchors>'
           '<certificates src="@raw/dcert"/>'
           '<certificates src="system"/>'
           '<certificates src="user" overridePins="true"/>'
           '</trust-anchors>'
           '</domain-config>'
           '</network-security-config>')
    res = _run(tmp_path, xml)
    s = res['network_summary']
    assert s['info'] == 1
    assert s['warning'] == 1
    assert s['high'] == 2
    descs = [f['description'] for f in res['network_findings']]
    assert any('Domain config is configured to trust ' in d
               and 'bundled certs' in d for d in descs)


@pytest.mark.django_db
def test_domain_pinset_with_expiration_and_digest(tmp_path):
    xml = ('<network-security-config>'
           '<domain-config>'
           '<domain>pin.com</domain>'
           '<pin-set expiration="2030-01-01">'
           '<pin digest="SHA-256">AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</pin>'
           '</pin-set>'
           '</domain-config>'
           '</network-security-config>')
    res = _run(tmp_path, xml)
    assert res['network_summary']['info'] == 1
    d = res['network_findings'][0]['description']
    assert 'expires on 2030-01-01' in d
    assert 'Digest: SHA-256' in d


@pytest.mark.django_db
def test_domain_pinset_no_expiration_no_digest(tmp_path):
    xml = ('<network-security-config>'
           '<domain-config>'
           '<domain>pin2.com</domain>'
           '<pin-set>'
           '<pin>BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=</pin>'
           '</pin-set>'
           '</domain-config>'
           '</network-security-config>')
    res = _run(tmp_path, xml)
    assert res['network_summary']['secure'] == 1
    d = res['network_findings'][0]['description']
    assert 'does not have an expiry' in d
    assert 'Digest' not in d


# ------------------- debug-overrides -------------------

@pytest.mark.django_db
def test_debug_overrides_debuggable(tmp_path):
    xml = ('<network-security-config>'
           '<debug-overrides cleartextTrafficPermitted="true">'
           '<trust-anchors>'
           '<certificates src="@raw/debugcert" overridePins="true"/>'
           '</trust-anchors>'
           '</debug-overrides>'
           '</network-security-config>')
    res = _run(tmp_path, xml, is_debuggable=True)
    s = res['network_summary']
    # cleartext true (high) + @raw bundled debug (high) + overridePins (high)
    assert s['high'] == 3
    descs = [f['description'] for f in res['network_findings']]
    assert any('app is debuggable' in d for d in descs)
    assert any('bundled debug certs' in d for d in descs)
    assert any('bypass certificate pinning' in d for d in descs)


@pytest.mark.django_db
def test_debug_overrides_not_debuggable_ignored(tmp_path):
    xml = ('<network-security-config>'
           '<debug-overrides cleartextTrafficPermitted="true">'
           '<trust-anchors>'
           '<certificates src="@raw/debugcert" overridePins="true"/>'
           '</trust-anchors>'
           '</debug-overrides>'
           '</network-security-config>')
    res = _run(tmp_path, xml, is_debuggable=False)
    assert res['network_summary'] == {
        'high': 0, 'warning': 0, 'info': 0, 'secure': 0}
    assert res['network_findings'] == []


# ------------------- malformed xml -> exception branch -------------------

@pytest.mark.django_db
def test_malformed_xml_handled(tmp_path):
    res = _run(tmp_path, '<network-security-config><base-config>')
    # Parse error is caught; defaults returned unchanged.
    assert res == {'network_findings': [], 'network_summary': {}}


@pytest.mark.django_db
def test_combined_config_full_summary(tmp_path):
    xml = ('<network-security-config>'
           '<base-config cleartextTrafficPermitted="true"/>'
           '<domain-config cleartextTrafficPermitted="false">'
           '<domain>a.com</domain>'
           '<pin-set expiration="2031-05-05">'
           '<pin digest="SHA-256">CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=</pin>'
           '</pin-set>'
           '</domain-config>'
           '</network-security-config>')
    res = _run(tmp_path, xml)
    s = res['network_summary']
    assert s['high'] == 1      # base cleartext true
    assert s['secure'] == 1    # domain cleartext false
    assert s['info'] == 1      # pinset expiration
    assert len(res['network_findings']) == 3
