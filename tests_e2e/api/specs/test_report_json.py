"""``POST /api/v1/report_json`` — REST contract across every scanned format.

See ``mobinspect/MobInspect/views/api/api_static_analysis.py::api_json_report``
(delegates to ``StaticAnalyzer/views/common/pdf.py::pdf(..., jsonres=True)``).
"""
import json
import os

import jsonschema
import pytest

from tests_e2e.fixtures.data import SCANNED

SCHEMA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'schemas')

with open(os.path.join(SCHEMA_DIR, 'report_json_android.schema.json')) as fh:
    ANDROID_SCHEMA = json.load(fh)

with open(os.path.join(SCHEMA_DIR, 'report_json_ios.schema.json')) as fh:
    IOS_SCHEMA = json.load(fh)

# scan_type family -> (expected schema, extra required keys spot-checked)
ANDROID_FORMATS = ('apk', 'xapk', 'jar', 'aar', 'android_src', 'so')
IOS_FORMATS = ('ipa', 'dylib', 'ios_src', 'ios_swift_src')
# appx (Windows) has an entirely different, much smaller shape -- handled
# separately below rather than shoehorned into either schema.


@pytest.mark.positive
@pytest.mark.parametrize('fmt', ANDROID_FORMATS)
def test_report_json_android_family(api_client, fmt):
    sample = SCANNED[fmt]
    r = api_client.report_json(sample['hash'])
    assert r.status_code == 200
    body = r.json()
    jsonschema.validate(body, ANDROID_SCHEMA)
    assert body['app_name'] == sample['app_name']
    assert body['md5'] == sample['hash']
    # Real, format-specific content -- not just key presence.
    assert 'permissions' in body
    assert 'manifest_analysis' in body
    assert 'certificate_analysis' in body


@pytest.mark.positive
@pytest.mark.parametrize('fmt', IOS_FORMATS)
def test_report_json_ios_family(api_client, fmt):
    sample = SCANNED[fmt]
    r = api_client.report_json(sample['hash'])
    assert r.status_code == 200
    body = r.json()
    jsonschema.validate(body, IOS_SCHEMA)
    assert body['app_name'] == sample['app_name']
    assert body['md5'] == sample['hash']
    # iOS/Mach-O reports use a different top-level shape than Android's --
    # no 'manifest_analysis'/'certificate_analysis', but real Mach-O/plist
    # analysis keys instead.
    assert 'info_plist' in body
    assert 'macho_analysis' in body
    assert 'manifest_analysis' not in body


@pytest.mark.positive
def test_report_json_appx_windows_shape(api_client):
    """Windows APPX reports have neither the Android nor the iOS shape --
    no permissions/manifest_analysis/code_analysis at all (no APK-style
    manifest, no Mach-O), just PE/appx-specific binary metadata."""
    sample = SCANNED['appx']
    r = api_client.report_json(sample['hash'])
    assert r.status_code == 200
    body = r.json()
    assert body['app_name'] == sample['app_name']
    assert body['md5'] == sample['hash']
    assert 'binary_analysis' in body
    assert 'permissions' not in body
    assert 'manifest_analysis' not in body


@pytest.mark.negative
def test_report_json_missing_hash(api_client):
    r = api_client.post('/api/v1/report_json', data={})
    assert r.status_code == 422
    assert r.json().get('error') == 'Missing Parameters'


@pytest.mark.negative
def test_report_json_malformed_hash(api_client):
    r = api_client.report_json('not-a-valid-md5')
    assert r.status_code == 400
    assert r.json().get('error') == 'Invalid Hash'


@pytest.mark.negative
def test_report_json_nonexistent_hash(api_client):
    r = api_client.report_json('0' * 32)
    assert r.status_code == 404
    assert r.json().get('report') == 'Report not Found'
