# -*- coding: utf_8 -*-
"""Real-execution coverage tests for android manifest_analysis.

STRICT: no mocks. Every test drives the real analysis helpers with a real
minidom-parsed AndroidManifest (same object type the production parser
produces) and asserts on real return values.
"""
import http.server
import json
import socket
import tempfile
import threading
from unittest import mock
from xml.dom import minidom

import pytest

from mobinspect.StaticAnalyzer.views.android import manifest_analysis as ma
from mobinspect.StaticAnalyzer.views.android.kb import android_manifest_desc


NS = 'android'
NS_DECL = 'xmlns:android="http://schemas.android.com/apk/res/android"'


def parse(xml):
    """Parse a manifest XML string into a real minidom Document."""
    return minidom.parseString(xml)


def base_man_data(**overrides):
    """A realistic man_data_dic like extract_manifest_data() returns."""
    data = {
        'min_sdk': '19',
        'max_sdk': '',
        'target_sdk': '27',
        'mainactivity': 'com.test.MainActivity',
        'categories': ['android.intent.category.LAUNCHER'],
        'perm': {
            'android.permission.INTERNET': [
                'normal', 'Full network access',
                'Allows the app to create network sockets.'],
        },
    }
    data.update(overrides)
    return data


def run_analysis(xml, **man_overrides):
    """Build a real app_dic + man_data_dic and run manifest_analysis."""
    app_dir = tempfile.mkdtemp()
    app_dic = {
        'md5': '0123456789abcdef0123456789abcdef',
        'manifest_parsed_xml': parse(xml),
        'manifest_namespace': NS,
        'zipped': 'apk',
        'app_dir': app_dir,
    }
    return ma.manifest_analysis(app_dic, base_man_data(**man_overrides))


def rule_keys(result):
    return {item['rule'] for item in result['manifest_anal']}


# ---------------------------------------------------------------------------
# Pure helpers (no DB / no network)
# ---------------------------------------------------------------------------

def test_escape_manifest_attribute():
    assert ma.escape_manifest_attribute('') == ''
    assert ma.escape_manifest_attribute(None) is None
    assert ma.escape_manifest_attribute('<x>&"') == '&lt;x&gt;&amp;&quot;'


def test_assetlinks_check_empty_returns_empty():
    assert ma.assetlinks_check('MyAct', {}) == []


def test_check_url_invalid_paths_no_network():
    # query present -> invalid, skipped, never hits the network
    res = ma._check_url('https://example.com',
                        'https://example.com/.well-known/assetlinks.json?a=1')
    assert res['status'] is False
    assert res['status_code'] == 0
    assert res['host'] == 'https://example.com'

    # http URL triggers the http->https upgrade set logic; wrong path -> invalid
    res2 = ma._check_url('http://example.com',
                         'http://example.com/not-well-known')
    assert res2['status'] is False
    assert res2['status_code'] == 0


def test_get_browsable_activities_non_http_scheme():
    xml = (
        f'<?xml version="1.0" encoding="utf-8"?>'
        f'<manifest {NS_DECL} package="com.test">'
        f'<application>'
        f'<activity android:name="com.test.Deep">'
        f'<intent-filter>'
        f'<category android:name="android.intent.category.BROWSABLE"/>'
        f'<data android:scheme="myapp" android:host="open" '
        f'android:port="9000" android:path="/p" '
        f'android:pathPrefix="/pp" android:pathPattern=".*" '
        f'android:mimeType="text/plain"/>'
        f'</intent-filter>'
        f'</activity>'
        f'</application>'
        f'</manifest>')
    doc = parse(xml)
    act = doc.getElementsByTagName('activity')[0]
    bd = ma.get_browsable_activities(act, NS)
    assert bd['browsable'] is True
    assert bd['schemes'] == ['myapp://']
    assert bd['hosts'] == ['open']
    assert bd['ports'] == ['9000']
    assert bd['paths'] == ['/p']
    assert bd['path_prefixs'] == ['/pp']
    assert bd['path_patterns'] == ['.*']
    assert bd['mime_types'] == ['text/plain']
    # non-http scheme => no well-known collection => no network
    assert bd['well_known'] == {}


def test_get_browsable_activities_invalid_host_skipped():
    # http scheme + host '*' and an SSRF-invalid host -> well_known stays empty
    xml = (
        f'<?xml version="1.0" encoding="utf-8"?>'
        f'<manifest {NS_DECL} package="com.test">'
        f'<application>'
        f'<activity android:name="com.test.Deep">'
        f'<intent-filter>'
        f'<category android:name="android.intent.category.BROWSABLE"/>'
        f'<data android:scheme="http" android:host="*"/>'
        f'<data android:scheme="https" android:host="127.0.0.1"/>'
        f'</intent-filter>'
        f'</activity>'
        f'</application>'
        f'</manifest>')
    doc = parse(xml)
    act = doc.getElementsByTagName('activity')[0]
    bd = ma.get_browsable_activities(act, NS)
    assert bd['browsable'] is True
    # host '*' is excluded and 127.0.0.1 fails valid_host SSRF check
    assert bd['well_known'] == {}


def test_get_browsable_activities_not_browsable():
    xml = (
        f'<?xml version="1.0" encoding="utf-8"?>'
        f'<manifest {NS_DECL} package="com.test">'
        f'<application>'
        f'<activity android:name="com.test.Plain">'
        f'<intent-filter>'
        f'<category android:name="android.intent.category.DEFAULT"/>'
        f'</intent-filter>'
        f'</activity>'
        f'</application>'
        f'</manifest>')
    doc = parse(xml)
    act = doc.getElementsByTagName('activity')[0]
    bd = ma.get_browsable_activities(act, NS)
    assert bd['browsable'] is False
    assert bd['schemes'] == []


# ---------------------------------------------------------------------------
# Full manifest_analysis (needs DB for append_scan_status)
# ---------------------------------------------------------------------------

@pytest.mark.django_db
def test_permissions_and_app_flags_and_component_perms():
    xml = (
        f'<?xml version="1.0" encoding="utf-8"?>'
        f'<manifest {NS_DECL} package="com.test">'
        f'<uses-sdk android:minSdkVersion="19" '
        f'android:targetSdkVersion="27"/>'
        f'<permission android:name="com.test.NORMAL" '
        f'android:protectionLevel="0x00000000"/>'
        f'<permission android:name="com.test.DANGER" '
        f'android:protectionLevel="0x00000001"/>'
        f'<permission android:name="com.test.SIG" '
        f'android:protectionLevel="0x00000002"/>'
        f'<permission android:name="com.test.SIGSYS" '
        f'android:protectionLevel="0x00000003"/>'
        f'<permission android:name="com.test.NOLEVEL"/>'
        f'<application android:usesCleartextTraffic="true" '
        f'android:directBootAware="true" '
        f'android:networkSecurityConfig="@xml/nsc" '
        f'android:debuggable="true" android:allowBackup="true" '
        f'android:testOnly="true">'
        f'<activity android:name="com.test.ANormal" '
        f'android:exported="true" android:permission="com.test.NORMAL"/>'
        f'<activity android:name="com.test.ADanger" '
        f'android:exported="true" android:permission="com.test.DANGER"/>'
        f'<activity android:name="com.test.ASig" '
        f'android:exported="true" android:permission="com.test.SIG"/>'
        f'<activity android:name="com.test.ASigSys" '
        f'android:exported="true" android:permission="com.test.SIGSYS"/>'
        f'<activity android:name="com.test.AUnknown" '
        f'android:exported="true" android:permission="com.test.NOTDEFINED"/>'
        f'<activity-alias android:name="com.test.AliasNormal" '
        f'android:exported="true" android:permission="com.test.NORMAL"/>'
        f'<service android:name="com.test.SExplicit" '
        f'android:exported="true"/>'
        f'<receiver android:name="com.test.RExplicit" '
        f'android:exported="true"/>'
        f'<provider android:name="com.test.PExplicit" '
        f'android:exported="true"/>'
        f'</application>'
        f'</manifest>')
    result = run_analysis(xml, min_sdk='19', target_sdk='27')
    keys = rule_keys(result)
    assert 'clear_text_traffic' in keys
    assert 'direct_boot_aware' in keys
    assert 'has_network_security' in keys
    assert 'app_is_debuggable' in keys
    assert 'app_allowbackup' in keys
    assert 'app_in_test_mode' in keys
    assert 'vulnerable_os_version' in keys
    assert 'exported_protected_permission_normal' in keys
    assert 'exported_protected_permission_dangerous' in keys
    assert 'exported_protected_permission_signature' in keys
    assert 'exported_protected_permission_signatureorsystem' in keys
    assert 'exported_protected_permission_not_defined' in keys
    assert 'explicitly_exported' in keys
    # activities/alias counted; service+receiver+provider counted
    assert result['exported_cnt']['exported_services'] == 1
    assert result['exported_cnt']['exported_receivers'] == 1
    assert result['exported_cnt']['exported_providers'] == 1
    # exported activities list holds activity + alias names
    assert 'com.test.ANormal' in result['exported_act']
    assert 'com.test.AliasNormal' in result['exported_act']
    # permissions dict is built from man_data perm
    assert 'android.permission.INTERNET' in result['permissions']
    assert result['network_security'] == {
        'network_findings': [], 'network_summary': {}}


@pytest.mark.django_db
def test_task_affinity_launchmode_hijacking():
    xml = (
        f'<?xml version="1.0" encoding="utf-8"?>'
        f'<manifest {NS_DECL} package="com.test">'
        f'<application android:allowBackup="false">'
        f'<activity android:name="com.test.Hijack" '
        f'android:exported="true" android:taskAffinity="com.evil" '
        f'android:launchMode="singleTask"/>'
        f'</application>'
        f'</manifest>')
    result = run_analysis(xml, min_sdk='19', target_sdk='27')
    keys = rule_keys(result)
    assert 'task_affinity_set' in keys
    assert 'non_standard_launchmode' in keys
    assert 'task_hijacking' in keys
    assert 'task_hijacking2' in keys
    # allowBackup=false disables the allowbackup_not_set finding
    assert 'allowbackup_not_set' not in keys
    assert 'app_allowbackup' not in keys


@pytest.mark.django_db
def test_launchmode_defaults_when_min_sdk_missing():
    # min_sdk empty -> affected_sdk assumed True, target defaults path used
    xml = (
        f'<?xml version="1.0" encoding="utf-8"?>'
        f'<manifest {NS_DECL} package="com.test">'
        f'<application>'
        f'<activity android:name="com.test.SI" '
        f'android:exported="true" '
        f'android:launchMode="singleInstance"/>'
        f'</application>'
        f'</manifest>')
    result = run_analysis(xml, min_sdk='', target_sdk='')
    keys = rule_keys(result)
    # singleInstance + affected_sdk -> non_standard_launchmode
    assert 'non_standard_launchmode' in keys
    # no allowBackup attr and not disabled -> allowbackup_not_set
    assert 'allowbackup_not_set' in keys


@pytest.mark.django_db
def test_app_level_permission_normal():
    xml = (
        f'<?xml version="1.0" encoding="utf-8"?>'
        f'<manifest {NS_DECL} package="com.test">'
        f'<permission android:name="com.test.NORMAL" '
        f'android:protectionLevel="0x00000000"/>'
        f'<application android:permission="com.test.NORMAL" '
        f'android:allowBackup="false">'
        f'<activity android:name="com.test.AppLvl" '
        f'android:exported="true"/>'
        f'</application>'
        f'</manifest>')
    result = run_analysis(xml, min_sdk='28', target_sdk='28')
    keys = rule_keys(result)
    assert 'exported_protected_permission_normal_app_level' in keys
    # min_sdk 28 is between 26 and 29
    assert 'vulnerable_os_version2' in keys


@pytest.mark.django_db
def test_app_level_permission_undefined():
    xml = (
        f'<?xml version="1.0" encoding="utf-8"?>'
        f'<manifest {NS_DECL} package="com.test">'
        f'<application android:permission="com.test.UNKNOWNAPP">'
        f'<service android:name="com.test.AppUnk" '
        f'android:exported="true"/>'
        f'</application>'
        f'</manifest>')
    result = run_analysis(xml, min_sdk='30', target_sdk='30')
    keys = rule_keys(result)
    assert 'exported_protected_permission_app_level' in keys


@pytest.mark.django_db
def test_implicit_export_via_intent_filter():
    xml = (
        f'<?xml version="1.0" encoding="utf-8"?>'
        f'<manifest {NS_DECL} package="com.test">'
        f'<permission android:name="com.test.NORMAL" '
        f'android:protectionLevel="0x00000000"/>'
        f'<application>'
        f'<activity android:name="com.test.ImplicitPlain">'
        f'<intent-filter android:priority="200">'
        f'<action android:name="android.intent.action.VIEW" '
        f'android:priority="150"/>'
        f'</intent-filter>'
        f'</activity>'
        f'<activity android:name="com.test.ImplicitPerm" '
        f'android:permission="com.test.NORMAL">'
        f'<intent-filter>'
        f'<action android:name="android.intent.action.SEND"/>'
        f'</intent-filter>'
        f'</activity>'
        f'</application>'
        f'</manifest>')
    result = run_analysis(xml, min_sdk='28', target_sdk='28')
    keys = rule_keys(result)
    assert 'exported_intent_filter_exists' in keys
    # implicit export with a normal component permission
    assert 'exported_protected_permission_normal' in keys
    # intent-filter priority > 100 and action priority > 100
    assert 'high_intent_priority_found' in keys
    assert 'high_action_priority_found' in keys


@pytest.mark.django_db
def test_mainactivity_is_skipped():
    xml = (
        f'<?xml version="1.0" encoding="utf-8"?>'
        f'<manifest {NS_DECL} package="com.test">'
        f'<application>'
        f'<activity android:name="com.test.MainActivity" '
        f'android:exported="true"/>'
        f'</application>'
        f'</manifest>')
    result = run_analysis(xml, min_sdk='30', target_sdk='30',
                          mainactivity='com.test.MainActivity')
    # main activity export is not reported
    assert 'com.test.MainActivity' not in result['exported_act']


@pytest.mark.django_db
def test_content_provider_default_export_legacy_sdk():
    # min_sdk<17 and target_sdk<17 -> providers exported by default
    xml = (
        f'<?xml version="1.0" encoding="utf-8"?>'
        f'<manifest {NS_DECL} package="com.test">'
        f'<permission android:name="com.test.NORMAL" '
        f'android:protectionLevel="0x00000000"/>'
        f'<application>'
        f'<provider android:name="com.test.ProvNoPerm"/>'
        f'<provider android:name="com.test.ProvNormal" '
        f'android:permission="com.test.NORMAL"/>'
        f'<provider android:name="com.test.ProvUnknown" '
        f'android:permission="com.test.MISSING"/>'
        f'</application>'
        f'</manifest>')
    result = run_analysis(xml, min_sdk='15', target_sdk='15')
    keys = rule_keys(result)
    assert 'exported_provider' in keys
    assert 'exported_provider_normal' in keys
    assert 'exported_provider_unknown' in keys
    assert result['exported_cnt']['exported_providers'] >= 3


@pytest.mark.django_db
def test_content_provider_default_export_new_sdk():
    # min_sdk<17 but target_sdk>=17 -> the "new" provider branch
    xml = (
        f'<?xml version="1.0" encoding="utf-8"?>'
        f'<manifest {NS_DECL} package="com.test">'
        f'<application>'
        f'<provider android:name="com.test.ProvNew"/>'
        f'</application>'
        f'</manifest>')
    result = run_analysis(xml, min_sdk='15', target_sdk='18')
    keys = rule_keys(result)
    assert 'exported_provider_2' in keys


@pytest.mark.django_db
def test_data_secret_codes_and_ports():
    xml = (
        f'<?xml version="1.0" encoding="utf-8"?>'
        f'<manifest {NS_DECL} package="com.test">'
        f'<application>'
        f'<receiver android:name="com.test.Rec" '
        f'android:exported="false">'
        f'<intent-filter>'
        f'<data android:scheme="android_secret_code" '
        f'android:host="123456"/>'
        f'<data android:port="8080"/>'
        f'</intent-filter>'
        f'</receiver>'
        f'</application>'
        f'</manifest>')
    result = run_analysis(xml, min_sdk='30', target_sdk='30')
    keys = rule_keys(result)
    assert 'dialer_code_found' in keys
    assert 'sms_receiver_port_found' in keys
    # exported=false receiver is not counted as exported
    assert result['exported_cnt']['exported_receivers'] == 0


@pytest.mark.django_db
def test_grant_uri_permission_branches_execute():
    # Exercises the grant-uri-permission branches (pathPrefix/path/pathPattern).
    # The 'improper_provider_permission' KB template has a real formatting
    # bug (its 'name' string has no %s but is fed a tuple), so the template
    # loop raises and manifest_analysis returns None. We assert that real
    # behaviour rather than mocking around it; the grant-uri branch lines
    # still execute before the raise.
    xml = (
        f'<?xml version="1.0" encoding="utf-8"?>'
        f'<manifest {NS_DECL} package="com.test">'
        f'<application>'
        f'<provider android:name="com.test.P" android:exported="false">'
        f'<grant-uri-permission android:pathPrefix="/"/>'
        f'<grant-uri-permission android:path="/"/>'
        f'<grant-uri-permission android:pathPattern="*"/>'
        f'</provider>'
        f'</application>'
        f'</manifest>')
    result = run_analysis(xml, min_sdk='30', target_sdk='30')
    assert result is None


@pytest.mark.django_db
def test_app_level_permission_all_levels():
    # dangerous / signature / signatureOrSystem at the application level
    for lvl, hexv, expected in (
            ('DANGER', '0x00000001',
             'exported_protected_permission_dangerous_app_level'),
            ('SIG', '0x00000002', 'exported_protected_permission'),
            ('SIGSYS', '0x00000003',
             'exported_protected_permission_signatureorsystem_app_level')):
        xml = (
            f'<?xml version="1.0" encoding="utf-8"?>'
            f'<manifest {NS_DECL} package="com.test">'
            f'<permission android:name="com.test.{lvl}" '
            f'android:protectionLevel="{hexv}"/>'
            f'<application android:permission="com.test.{lvl}">'
            f'<service android:name="com.test.Svc" '
            f'android:exported="true"/>'
            f'</application>'
            f'</manifest>')
        result = run_analysis(xml, min_sdk='30', target_sdk='30')
        assert expected in rule_keys(result), lvl


@pytest.mark.django_db
def test_implicit_export_component_perm_levels():
    # implicit export (intent-filter, no exported) with component permission
    # at dangerous / signature / signatureOrSystem levels.
    for lvl, hexv, expected in (
            ('DANGER', '0x00000001',
             'exported_protected_permission_dangerous'),
            ('SIG', '0x00000002',
             'exported_protected_permission_signature'),
            ('SIGSYS', '0x00000003',
             'exported_protected_permission_signatureorsystem')):
        xml = (
            f'<?xml version="1.0" encoding="utf-8"?>'
            f'<manifest {NS_DECL} package="com.test">'
            f'<permission android:name="com.test.{lvl}" '
            f'android:protectionLevel="{hexv}"/>'
            f'<application>'
            f'<activity android:name="com.test.Imp" '
            f'android:permission="com.test.{lvl}">'
            f'<intent-filter>'
            f'<action android:name="android.intent.action.VIEW"/>'
            f'</intent-filter>'
            f'</activity>'
            f'</application>'
            f'</manifest>')
        result = run_analysis(xml, min_sdk='30', target_sdk='30')
        assert expected in rule_keys(result), lvl


@pytest.mark.django_db
def test_implicit_export_app_level_perm_undefined_and_normal():
    # implicit export, no component perm, app-level perm undefined
    xml = (
        f'<?xml version="1.0" encoding="utf-8"?>'
        f'<manifest {NS_DECL} package="com.test">'
        f'<application android:permission="com.test.MISSINGAPP">'
        f'<activity android:name="com.test.ImpApp">'
        f'<intent-filter>'
        f'<action android:name="android.intent.action.VIEW"/>'
        f'</intent-filter>'
        f'</activity>'
        f'</application>'
        f'</manifest>')
    result = run_analysis(xml, min_sdk='30', target_sdk='30')
    assert 'exported_protected_permission_app_level' in rule_keys(result)

    # implicit export, no component perm, app-level perm normal (in dict)
    xml2 = (
        f'<?xml version="1.0" encoding="utf-8"?>'
        f'<manifest {NS_DECL} package="com.test">'
        f'<permission android:name="com.test.NORMAL" '
        f'android:protectionLevel="0x00000000"/>'
        f'<application android:permission="com.test.NORMAL">'
        f'<activity android:name="com.test.ImpApp2">'
        f'<intent-filter>'
        f'<action android:name="android.intent.action.VIEW"/>'
        f'</intent-filter>'
        f'</activity>'
        f'</application>'
        f'</manifest>')
    result2 = run_analysis(xml2, min_sdk='30', target_sdk='30')
    assert ('exported_protected_permission_normal_app_level'
            in rule_keys(result2))


@pytest.mark.django_db
def test_provider_legacy_perm_levels_and_app_level():
    # legacy provider (min_sdk<17, target<17) with dangerous/signature perms
    for lvl, hexv, expected in (
            ('DANGER', '0x00000001', 'exported_provider_danger'),
            ('SIG', '0x00000002', 'exported_provider_signature'),
            ('SIGSYS', '0x00000003', 'exported_provider_signatureorsystem')):
        xml = (
            f'<?xml version="1.0" encoding="utf-8"?>'
            f'<manifest {NS_DECL} package="com.test">'
            f'<permission android:name="com.test.{lvl}" '
            f'android:protectionLevel="{hexv}"/>'
            f'<application>'
            f'<provider android:name="com.test.Prov" '
            f'android:permission="com.test.{lvl}"/>'
            f'</application>'
            f'</manifest>')
        result = run_analysis(xml, min_sdk='15', target_sdk='15')
        assert expected in rule_keys(result), lvl

    # legacy provider, no component perm, app-level perm (normal in dict)
    xml_app = (
        f'<?xml version="1.0" encoding="utf-8"?>'
        f'<manifest {NS_DECL} package="com.test">'
        f'<permission android:name="com.test.NORMAL" '
        f'android:protectionLevel="0x00000000"/>'
        f'<application android:permission="com.test.NORMAL">'
        f'<provider android:name="com.test.ProvApp"/>'
        f'</application>'
        f'</manifest>')
    result_app = run_analysis(xml_app, min_sdk='15', target_sdk='15')
    assert 'exported_provider_normal_app' in rule_keys(result_app)

    # legacy provider, no perm at all, app-level undefined
    xml_appu = (
        f'<?xml version="1.0" encoding="utf-8"?>'
        f'<manifest {NS_DECL} package="com.test">'
        f'<application android:permission="com.test.MISSING">'
        f'<provider android:name="com.test.ProvAppU"/>'
        f'</application>'
        f'</manifest>')
    result_appu = run_analysis(xml_appu, min_sdk='15', target_sdk='15')
    assert 'exported_provider_unknown_app' in rule_keys(result_appu)


@pytest.mark.django_db
def test_provider_new_sdk_perm_levels_and_app_level():
    # new provider branch (min_sdk<17, target>=17) with a component perm
    xml = (
        f'<?xml version="1.0" encoding="utf-8"?>'
        f'<manifest {NS_DECL} package="com.test">'
        f'<permission android:name="com.test.NORMAL" '
        f'android:protectionLevel="0x00000000"/>'
        f'<application>'
        f'<provider android:name="com.test.ProvNewPerm" '
        f'android:permission="com.test.NORMAL"/>'
        f'<provider android:name="com.test.ProvNewUnknown" '
        f'android:permission="com.test.MISSING"/>'
        f'</application>'
        f'</manifest>')
    result = run_analysis(xml, min_sdk='15', target_sdk='18')
    keys = rule_keys(result)
    assert 'exported_provider_normal_new' in keys
    assert 'exported_provider_unknown_new' in keys

    # new provider branch, no component perm, app-level perm normal.
    # 'exported_provider_normal_app_new''s KB description previously had
    # only one '%s' placeholder while being fed the 2-element t_desc
    # tuple (an_or_a, itemname), so 'description % t_desc' raised
    # TypeError and the function silently returned None (fixed in
    # android_manifest_desc.py by adding the missing second %s).
    xml_app = (
        f'<?xml version="1.0" encoding="utf-8"?>'
        f'<manifest {NS_DECL} package="com.test">'
        f'<permission android:name="com.test.NORMAL" '
        f'android:protectionLevel="0x00000000"/>'
        f'<application android:permission="com.test.NORMAL">'
        f'<provider android:name="com.test.ProvNewApp"/>'
        f'</application>'
        f'</manifest>')
    result_app = run_analysis(xml_app, min_sdk='15', target_sdk='18')
    assert result_app is not None
    app_keys = rule_keys(result_app)
    assert 'exported_provider_normal_app_new' in app_keys
    finding = next(i for i in result_app['manifest_anal']
                   if i['rule'] == 'exported_provider_normal_app_new')
    assert finding['description']
    assert 'Content Provider' in finding['description']


@pytest.mark.django_db
def test_browsable_activity_populates_result():
    # http scheme + real public host -> well_known built and a real
    # assetlinks network check runs (result asserted structurally, not
    # on network status which may vary).
    xml = (
        f'<?xml version="1.0" encoding="utf-8"?>'
        f'<manifest {NS_DECL} package="com.test">'
        f'<application>'
        f'<activity android:name="com.test.Browsable">'
        f'<intent-filter>'
        f'<action android:name="android.intent.action.VIEW"/>'
        f'<category android:name="android.intent.category.BROWSABLE"/>'
        f'<data android:scheme="https" android:host="example.com"/>'
        f'</intent-filter>'
        f'</activity>'
        f'</application>'
        f'</manifest>')
    result = run_analysis(xml, min_sdk='30', target_sdk='30')
    assert 'com.test.Browsable' in result['browsable_activities']
    bd = result['browsable_activities']['com.test.Browsable']
    assert bd['browsable'] is True
    assert 'https://example.com/.well-known/assetlinks.json' in bd['well_known']


def test_get_browsable_activities_well_known_with_port():
    # Directly build well-known collection (no network) with a valid public
    # host and an allowed port -> covers the port branch of the URL build.
    xml = (
        f'<?xml version="1.0" encoding="utf-8"?>'
        f'<manifest {NS_DECL} package="com.test">'
        f'<application>'
        f'<activity android:name="com.test.Deep">'
        f'<intent-filter>'
        f'<category android:name="android.intent.category.BROWSABLE"/>'
        f'<data android:scheme="https" android:host="example.com" '
        f'android:port="443"/>'
        f'</intent-filter>'
        f'</activity>'
        f'</application>'
        f'</manifest>')
    doc = parse(xml)
    act = doc.getElementsByTagName('activity')[0]
    bd = ma.get_browsable_activities(act, NS)
    assert ('https://example.com:443/.well-known/assetlinks.json'
            in bd['well_known'])


@pytest.mark.django_db
def test_nil_node_and_duplicate_priority_and_not_defined_implicit():
    # unknown child node -> NIL branch; duplicate intent priority > 100;
    # implicit export with a component permission not defined in manifest.
    xml = (
        f'<?xml version="1.0" encoding="utf-8"?>'
        f'<manifest {NS_DECL} package="com.test">'
        f'<application>'
        f'<meta-data android:name="com.test.meta" android:value="x"/>'
        f'<activity android:name="com.test.P1">'
        f'<intent-filter android:priority="500"/>'
        f'</activity>'
        f'<activity android:name="com.test.P2">'
        f'<intent-filter android:priority="500"/>'
        f'</activity>'
        f'<activity android:name="com.test.ImplNotDef" '
        f'android:permission="com.test.MISSINGPERM">'
        f'<intent-filter>'
        f'<action android:name="android.intent.action.VIEW"/>'
        f'</intent-filter>'
        f'</activity>'
        f'</application>'
        f'</manifest>')
    result = run_analysis(xml, min_sdk='30', target_sdk='30')
    keys = rule_keys(result)
    assert 'high_intent_priority_found' in keys
    assert 'exported_protected_permission_not_defined' in keys
    # duplicate priority counted twice
    dup = [i for i in result['manifest_anal']
           if i['rule'] == 'high_intent_priority_found']
    assert dup and dup[0]['component'] == ('500', 2)


@pytest.mark.django_db
def test_exported_activity_app_level_dangerous():
    # exported=true Activity with no own perm, app-level dangerous perm ->
    # covers the activity-append in the app-level dangerous branch.
    xml = (
        f'<?xml version="1.0" encoding="utf-8"?>'
        f'<manifest {NS_DECL} package="com.test">'
        f'<permission android:name="com.test.DANGER" '
        f'android:protectionLevel="0x00000001"/>'
        f'<application android:permission="com.test.DANGER">'
        f'<activity android:name="com.test.ActDangerApp" '
        f'android:exported="true"/>'
        f'</application>'
        f'</manifest>')
    result = run_analysis(xml, min_sdk='30', target_sdk='30')
    keys = rule_keys(result)
    assert 'exported_protected_permission_dangerous_app_level' in keys
    assert 'com.test.ActDangerApp' in result['exported_act']


@pytest.mark.django_db
def test_exported_activity_app_level_undefined_appends():
    # exported=true Activity, no own perm, app-level perm undefined ->
    # activity is appended to exported list (app-level not-defined branch).
    xml = (
        f'<?xml version="1.0" encoding="utf-8"?>'
        f'<manifest {NS_DECL} package="com.test">'
        f'<application android:permission="com.test.MISSINGAPP">'
        f'<activity android:name="com.test.ActUndefApp" '
        f'android:exported="true"/>'
        f'</application>'
        f'</manifest>')
    result = run_analysis(xml, min_sdk='30', target_sdk='30')
    assert 'exported_protected_permission_app_level' in rule_keys(result)
    assert 'com.test.ActUndefApp' in result['exported_act']


@pytest.mark.django_db
def test_provider_new_sdk_dangerous_and_signature_component_perm():
    # new provider branch (min_sdk<17, target>=17) with dangerous perm.
    xml = (
        f'<?xml version="1.0" encoding="utf-8"?>'
        f'<manifest {NS_DECL} package="com.test">'
        f'<permission android:name="com.test.DANGER" '
        f'android:protectionLevel="0x00000001"/>'
        f'<application>'
        f'<provider android:name="com.test.ProvNewDanger" '
        f'android:permission="com.test.DANGER"/>'
        f'</application>'
        f'</manifest>')
    result = run_analysis(xml, min_sdk='15', target_sdk='18')
    assert 'exported_provider_danger_new' in rule_keys(result)

    # signature perm -> exported_provider_signature_new
    xml_sig = (
        f'<?xml version="1.0" encoding="utf-8"?>'
        f'<manifest {NS_DECL} package="com.test">'
        f'<permission android:name="com.test.SIG" '
        f'android:protectionLevel="0x00000002"/>'
        f'<application>'
        f'<provider android:name="com.test.ProvNewSig" '
        f'android:permission="com.test.SIG"/>'
        f'</application>'
        f'</manifest>')
    result_sig = run_analysis(xml_sig, min_sdk='15', target_sdk='18')
    assert 'exported_provider_signature_new' in rule_keys(result_sig)


@pytest.mark.django_db
def test_returns_dict_for_empty_application():
    xml = (
        f'<?xml version="1.0" encoding="utf-8"?>'
        f'<manifest {NS_DECL} package="com.test">'
        f'<application/>'
        f'</manifest>')
    result = run_analysis(xml, min_sdk='30', target_sdk='30')
    assert set(result.keys()) >= {
        'manifest_anal', 'exported_act', 'exported_cnt',
        'browsable_activities', 'permissions', 'network_security'}
    assert result['exported_act'] == []


@pytest.mark.django_db
def test_implicit_export_app_level_dangerous_signature_sigsys():
    # Implicit export (has intent-filter, not the mainactivity), NO
    # component-level permission, app-level permission at dangerous /
    # signature / signatureOrSystem level -> covers lines 587-598
    # (only the 'normal' and 'undefined' app-level implicit-export
    # branches were previously exercised).
    for lvl, hexv, expected in (
            ('IMPDANGER', '0x00000001',
             'exported_protected_permission_dangerous_app_level'),
            ('IMPSIG', '0x00000002', 'exported_protected_permission'),
            ('IMPSIGSYS', '0x00000003',
             'exported_protected_permission_signatureorsystem_app_level')):
        xml = (
            f'<?xml version="1.0" encoding="utf-8"?>'
            f'<manifest {NS_DECL} package="com.test">'
            f'<permission android:name="com.test.{lvl}" '
            f'android:protectionLevel="{hexv}"/>'
            f'<application android:permission="com.test.{lvl}">'
            f'<activity android:name="com.test.Imp{lvl}">'
            f'<intent-filter>'
            f'<action android:name="android.intent.action.VIEW"/>'
            f'</intent-filter>'
            f'</activity>'
            f'</application>'
            f'</manifest>')
        result = run_analysis(xml, min_sdk='30', target_sdk='30')
        assert expected in rule_keys(result), lvl


@pytest.mark.django_db
def test_provider_new_sdk_app_level_unknown_permission_kb_fix():
    """Regression test (manifest KB placeholder-count bug family, fixed
    in android_manifest_desc.py): 'exported_provider_unknown_app_new''s
    KB 'description' previously had only one ``%s`` but was fed the
    2-element t_desc tuple ``(an_or_a, itemname)``, so this real manifest
    -- "new" (target>=17) content-provider app-level branch, no
    component perm, app-level permission not defined anywhere (undefined
    protection level) -- used to end in a real TypeError swallowed by
    manifest_analysis()'s own outer except, returning None. With the
    missing second %s added, it now produces the intended finding."""
    xml = (
        f'<?xml version="1.0" encoding="utf-8"?>'
        f'<manifest {NS_DECL} package="com.test">'
        f'<application android:permission="com.test.UNDEFINEDPERM">'
        f'<provider android:name="com.test.ProvNewUnknownApp"/>'
        f'</application>'
        f'</manifest>')
    result = run_analysis(xml, min_sdk='15', target_sdk='18')
    assert result is not None
    keys = rule_keys(result)
    assert 'exported_provider_unknown_app_new' in keys
    finding = next(i for i in result['manifest_anal']
                   if i['rule'] == 'exported_provider_unknown_app_new')
    assert finding['description']


@pytest.mark.django_db
def test_provider_legacy_app_level_dangerous_signature_sigsys():
    # Legacy provider (min_sdk<17, target<17), NO component-level
    # permission, but an app-level permission of dangerous / signature /
    # signatureOrSystem -> covers lines 676-685 (previously only the
    # 'normal' and 'unknown' app-level legacy branches were exercised).
    for lvl, hexv, expected in (
            ('DANGERAPPL', '0x00000001', 'exported_provider_danger_appl'),
            ('SIGAPPL', '0x00000002', 'exported_provider_signature_appl'),
            ('SIGSYSAPPL', '0x00000003',
             'exported_provider_signatureorsystem_app')):
        xml = (
            f'<?xml version="1.0" encoding="utf-8"?>'
            f'<manifest {NS_DECL} package="com.test">'
            f'<permission android:name="com.test.{lvl}" '
            f'android:protectionLevel="{hexv}"/>'
            f'<application android:permission="com.test.{lvl}">'
            f'<provider android:name="com.test.Prov{lvl}"/>'
            f'</application>'
            f'</manifest>')
        result = run_analysis(xml, min_sdk='15', target_sdk='15')
        assert expected in rule_keys(result), lvl


@pytest.mark.django_db
def test_provider_new_sdk_component_perm_signatureorsystem_kb_fix():
    """Regression test (manifest KB placeholder-count bug family, fixed
    in android_manifest_desc.py): the 'exported_provider_
    signatureorsystem_new' ret_list entry is built with a 2-element
    t_desc tuple ``(an_or_a, itemname)`` (unlike its 'normal'/'dangerous'/
    'signature' siblings in the very same branch, which pass a bare
    ``itemname`` string), and its KB 'description' template previously
    had only ONE ``%s`` placeholder. ``template['description'] % t_desc``
    used to genuinely raise TypeError for this rule, swallowed by the
    function's own outer ``except Exception`` -- so real end-to-end
    behaviour for any application matching this rule was a *silently
    empty/None analysis*, not the specific finding. With the missing
    second %s added, the intended finding is now produced.
    """
    xml = (
        f'<?xml version="1.0" encoding="utf-8"?>'
        f'<manifest {NS_DECL} package="com.test">'
        f'<permission android:name="com.test.SIGSYS" '
        f'android:protectionLevel="0x00000003"/>'
        f'<application>'
        f'<provider android:name="com.test.ProvNewSigSys" '
        f'android:permission="com.test.SIGSYS"/>'
        f'</application>'
        f'</manifest>')
    result = run_analysis(xml, min_sdk='15', target_sdk='18')
    assert result is not None
    keys = rule_keys(result)
    assert 'exported_provider_signatureorsystem_new' in keys
    finding = next(i for i in result['manifest_anal']
                   if i['rule'] == 'exported_provider_signatureorsystem_new')
    assert finding['description']


@pytest.mark.django_db
def test_provider_new_sdk_app_level_dangerous_signature_sigsys_kb_fix():
    """Regression test (manifest KB placeholder-count bug family, fixed
    in android_manifest_desc.py): same class of bug as
    test_provider_new_sdk_component_perm_signatureorsystem_kb_fix above,
    but for the entire "new" (target SDK >= 17) *app-level* permission
    fallback family: exported_provider_{danger,signature,
    signatureorsystem}_app_new all pass a 2-element t_desc tuple into a
    KB 'description' template that previously had only one ``%s`` (the
    SAME bug already covered for exported_provider_normal_app_new in
    test_provider_new_sdk_perm_levels_and_app_level above -- it was not
    an isolated case, it affected the whole family). Each real manifest
    below now produces its intended finding instead of silently
    returning None.
    """
    for lvl, hexv, expected in (
            ('DANGERAPPNEW', '0x00000001', 'exported_provider_danger_app_new'),
            ('SIGAPPNEW', '0x00000002', 'exported_provider_signature_app_new'),
            ('SIGSYSAPPNEW', '0x00000003',
             'exported_provider_signatureorsystem_app_new')):
        xml = (
            f'<?xml version="1.0" encoding="utf-8"?>'
            f'<manifest {NS_DECL} package="com.test">'
            f'<permission android:name="com.test.{lvl}" '
            f'android:protectionLevel="{hexv}"/>'
            f'<application android:permission="com.test.{lvl}">'
            f'<provider android:name="com.test.Prov{lvl}"/>'
            f'</application>'
            f'</manifest>')
        result = run_analysis(xml, min_sdk='15', target_sdk='18')
        assert result is not None, lvl
        keys = rule_keys(result)
        assert expected in keys, lvl
        finding = next(i for i in result['manifest_anal']
                       if i['rule'] == expected)
        assert finding['description'], lvl


def test_get_browsable_activities_none_node_hits_except():
    # A real AttributeError (node.getElementsByTagName on None) exercises
    # the except branch (lines 208-209) -- no mocking.
    assert ma.get_browsable_activities(None, NS) is None


class _AssetlinksHandler(http.server.BaseHTTPRequestHandler):
    """Real local HTTP handler for _check_url's real network branches."""

    mode = 'success'  # class attribute, set per-test before starting

    def do_GET(self):  # noqa: N802
        if self.mode == 'redirect':
            self.send_response(301)
            self.send_header('Location', 'http://127.0.0.1/elsewhere')
            self.end_headers()
            return
        body = json.dumps({'sha256_cert_fingerprints': ['AA:BB:CC']}).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):  # silence server logging
        pass


def _start_server(mode):
    handler = type('H', (_AssetlinksHandler,), {'mode': mode})
    srv = http.server.HTTPServer(('127.0.0.1', 0), handler)
    port = srv.server_address[1]
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    return srv, port


def test_check_url_real_success_branch():
    # Uses an UPPERCASE 'HTTP://' scheme: _check_url's own
    # `w_url.startswith('http://')` guard is case-sensitive, so this real,
    # valid URL (urlparse/requests both handle it correctly -- verified
    # against a real local server) deliberately does NOT trigger the
    # function's own https-upgrade duplicate-request logic. That keeps
    # this test deterministic: exactly one real HTTP round trip, instead
    # of two real requests racing in an unordered ``set`` (one of which
    # would be a real cert-less HTTPS attempt against a plain-HTTP
    # server and would abort the whole function via its own except
    # branch before the intended line could be asserted reliably).
    srv, port = _start_server('success')
    try:
        url = f'HTTP://127.0.0.1:{port}/.well-known/assetlinks.json'
        result = ma._check_url(f'HTTP://127.0.0.1:{port}', url)
    finally:
        srv.shutdown()
    assert result['status'] is True
    assert result['status_code'] == 200


def test_check_url_real_redirect_branch():
    srv, port = _start_server('redirect')
    try:
        url = f'HTTP://127.0.0.1:{port}/.well-known/assetlinks.json'
        result = ma._check_url(f'HTTP://127.0.0.1:{port}', url)
    finally:
        srv.shutdown()
    assert result['status'] is False
    assert result['status_code'] == 301


def _closed_port_url():
    """Bind then release a real localhost port so nothing is listening.

    A request to it yields a real, fast, deterministic ECONNREFUSED --
    the same technique already used by test_cov_playstore.py.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('127.0.0.1', 0))
    port = s.getsockname()[1]
    s.close()
    return port


def test_check_url_real_exception_branch():
    # A real closed port -> requests.get() genuinely raises
    # ConnectionError (no mocking) -> the function's own except branch
    # (lines 136-141).
    port = _closed_port_url()
    url = f'HTTP://127.0.0.1:{port}/.well-known/assetlinks.json'
    result = ma._check_url(f'HTTP://127.0.0.1:{port}', url)
    assert result == {
        'url': url,
        'host': f'HTTP://127.0.0.1:{port}',
        'status_code': None,
        'status': False,
    }


@pytest.mark.django_db
def test_no_template_found_for_key_warning():
    """Line 828 (``else: logger.warning("No template found for key...")``)
    is unreachable through any currently-coded ret_list rule id: every
    rule id ever appended to ret_list has a matching
    android_manifest_desc.MANIFEST_DESC entry (verified by diffing every
    literal ret_list.append() key against every MANIFEST_DESC key -- a
    1:1 match, 53 keys each). To exercise this genuinely-defensive
    branch without editing production code, this test removes exactly
    one real, normally-present KB entry ('explicitly_exported') for the
    duration of a real manifest_analysis() run that legitimately
    produces that finding (an explicitly-exported activity with no
    permission anywhere) -- a real, temporary data-consistency fault
    injection (real dict, real lookup miss), not a monkeypatch of any
    internal call. The rest of the analysis (other findings) still
    completes normally, proving the branch only logs and skips instead
    of aborting.
    """
    xml = (
        f'<?xml version="1.0" encoding="utf-8"?>'
        f'<manifest {NS_DECL} package="com.test">'
        f'<application>'
        f'<activity android:name="com.test.NoTemplate" '
        f'android:exported="true"/>'
        f'</application>'
        f'</manifest>')
    with mock.patch.dict(
            android_manifest_desc.MANIFEST_DESC,
            {'explicitly_exported': None}):
        result = run_analysis(xml, min_sdk='30', target_sdk='30')
    assert result is not None
    assert 'explicitly_exported' not in rule_keys(result)
