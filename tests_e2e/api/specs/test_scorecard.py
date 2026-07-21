"""``POST /api/v1/scorecard`` — app security scorecard REST contract.

See ``api_static_analysis.py::api_scorecard`` (delegates to
``StaticAnalyzer/views/common/appsec.py::appsec_dashboard``).
"""
import json
import os

import jsonschema
import pytest

from tests_e2e.fixtures.data import PRIMARY_HASH, SCANNED

SCHEMA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'schemas')
with open(os.path.join(SCHEMA_DIR, 'scorecard.schema.json')) as fh:
    SCORECARD_SCHEMA = json.load(fh)


@pytest.mark.positive
def test_scorecard_primary_apk(api_client):
    r = api_client.scorecard(PRIMARY_HASH)
    assert r.status_code == 200
    body = r.json()
    jsonschema.validate(body, SCORECARD_SCHEMA)
    assert body['hash'] == PRIMARY_HASH
    assert body['app_name'] == SCANNED['apk']['app_name']
    assert isinstance(body['high'], list)


@pytest.mark.positive
@pytest.mark.parametrize('fmt', ['jar', 'aar', 'so', 'android_src', 'ipa', 'dylib'])
def test_scorecard_other_formats(api_client, fmt):
    sample = SCANNED[fmt]
    r = api_client.scorecard(sample['hash'])
    assert r.status_code == 200
    body = r.json()
    jsonschema.validate(body, SCORECARD_SCHEMA)
    assert body['hash'] == sample['hash']


@pytest.mark.negative
def test_scorecard_appx_not_supported(api_client):
    """Windows APPX has no security-scorecard dashboard implementation --
    a real, documented gap, not a crash: 404 not_found."""
    sample = SCANNED['appx']
    r = api_client.scorecard(sample['hash'])
    assert r.status_code == 404
    assert r.json().get('not_found')


@pytest.mark.negative
def test_scorecard_missing_hash(api_client):
    r = api_client.post('/api/v1/scorecard', data={})
    assert r.status_code == 422
    assert r.json().get('error') == 'Missing Parameters'


@pytest.mark.negative
def test_scorecard_malformed_hash(api_client):
    r = api_client.scorecard('not-a-valid-md5')
    assert r.status_code == 400
    assert r.json().get('error') == 'Invalid Hash'


@pytest.mark.negative
def test_scorecard_nonexistent_hash(api_client):
    r = api_client.scorecard('0' * 32)
    assert r.status_code == 404
    assert r.json().get('not_found')
