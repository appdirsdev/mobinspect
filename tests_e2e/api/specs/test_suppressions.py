"""``list_suppressions`` / ``suppress_by_rule`` / ``delete_suppression``.

Suppression mutates a scan's finding set, so this runs against a private
scratch scan (never a shared ``fixtures.data.SCANNED`` hash) -- see
``tests_e2e/README.md``'s "never mutate a shared fixture" rule.

See ``mobinspect/StaticAnalyzer/views/common/suppression.py`` for the real
contract: ``suppress_by_rule_id``/``delete_suppression`` require
``{hash, rule, type}`` (``type`` is ``code`` or ``manifest``) -- the
existing ``client.py`` helpers ``suppress_by_rule``/``delete_suppression``
don't send ``type`` and always 422, so this spec uses the new
``suppress_by_rule_typed``/``delete_suppression_typed`` client methods
added alongside it (see client.py comment).
"""
import pytest

from tests_e2e.api.scratch_utils import (
    cleanup_scratch_file,
    make_scratch_copy,
    poll_report_json,
)


@pytest.fixture
def scratch_scan(api_client):
    """Upload + scan a private scratch copy, yield its hash, clean up after."""
    scratch_path = make_scratch_copy('android_src.zip')
    file_hash = None
    try:
        upload_r = api_client.upload_file(scratch_path)
        assert upload_r.status_code == 200
        file_hash = upload_r.json()['hash']
        scan_r = api_client.scan(file_hash)
        assert scan_r.status_code == 200
        poll_report_json(api_client, file_hash, timeout=180)
        yield file_hash
    finally:
        cleanup_scratch_file(scratch_path)
        if file_hash:
            api_client.delete_scan(file_hash)


@pytest.mark.e2e_flow
@pytest.mark.positive
def test_suppress_list_delete_roundtrip(api_client, scratch_scan):
    file_hash = scratch_scan

    # Initially empty.
    list_r = api_client.list_suppressions(file_hash)
    assert list_r.status_code == 200
    assert list_r.json() == {'status': 'ok', 'message': []}

    # Suppress a real manifest rule id from this scan's own findings. Which
    # rule ids fire is content-derived (android_src.zip's actual manifest),
    # not a fixed set across runs/environments, so pick whichever one this
    # scan actually produced rather than hardcoding a specific rule id.
    report = api_client.report_json(file_hash).json()
    manifest_findings = report['manifest_analysis']['manifest_findings']
    assert manifest_findings, 'expected at least one manifest finding to suppress'
    manifest_rule = manifest_findings[0]['rule']

    suppress_r = api_client.suppress_by_rule_typed(file_hash, manifest_rule, 'manifest')
    assert suppress_r.status_code == 200
    assert suppress_r.json() == {'status': 'ok'}

    list_r2 = api_client.list_suppressions(file_hash)
    assert list_r2.status_code == 200
    entries = list_r2.json()['message']
    assert len(entries) == 1
    assert manifest_rule in entries[0]['SUPPRESS_RULE_ID']
    assert entries[0]['SUPPRESS_TYPE'] == 'manifest'

    # Delete it -- back to no active rule suppressions.
    delete_r = api_client.delete_suppression_typed(file_hash, manifest_rule, 'manifest')
    assert delete_r.status_code == 200
    assert delete_r.json() == {'status': 'ok'}

    list_r3 = api_client.list_suppressions(file_hash)
    assert list_r3.status_code == 200
    remaining_rules = list_r3.json()['message'][0]['SUPPRESS_RULE_ID']
    assert manifest_rule not in remaining_rules


@pytest.mark.negative
def test_suppress_by_rule_missing_params(api_client, scratch_scan):
    r = api_client.post('/api/v1/suppress_by_rule', data={'hash': scratch_scan})
    assert r.status_code == 422
    assert r.json().get('error') == 'Missing Parameters'


@pytest.mark.negative
def test_suppress_by_rule_invalid_type(api_client, scratch_scan):
    """`type` must be 'code' or 'manifest' -- anything else is a clean,
    documented failure (500 by this endpoint's own contract), never a
    crash. See suppression.py::suppress_by_rule_id's `type_check` guard."""
    r = api_client.suppress_by_rule_typed(scratch_scan, 'some_rule', 'bogus_type')
    assert r.status_code == 500
    assert r.json().get('status') == 'failed'


@pytest.mark.negative
def test_suppress_by_rule_malformed_hash(api_client):
    r = api_client.suppress_by_rule_typed('not-a-valid-md5', 'some_rule', 'manifest')
    assert r.status_code == 500
    assert r.json().get('status') == 'failed'


@pytest.mark.negative
def test_suppress_by_rule_nonexistent_hash(api_client):
    """A well-formed but unscanned hash has no package -> get_package()
    returns None -> the same invalid_params() 500, not a 404. Documenting
    the real (slightly surprising) contract rather than assuming REST-ideal
    behavior."""
    r = api_client.suppress_by_rule_typed('0' * 32, 'some_rule', 'manifest')
    assert r.status_code == 500
    assert r.json().get('status') == 'failed'


@pytest.mark.negative
def test_list_suppressions_missing_hash(api_client):
    r = api_client.post('/api/v1/list_suppressions', data={})
    assert r.status_code == 422
    assert r.json().get('error') == 'Missing Parameters'


@pytest.mark.negative
def test_delete_suppression_missing_params(api_client, scratch_scan):
    r = api_client.post('/api/v1/delete_suppression', data={'hash': scratch_scan})
    assert r.status_code == 422
    assert r.json().get('error') == 'Missing Parameters'
