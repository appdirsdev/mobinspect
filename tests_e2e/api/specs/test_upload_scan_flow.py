"""``upload`` -> ``scan`` -> ``report_json`` -> ``download_pdf`` -> ``delete_scan``.

A full, real-execution journey against a private scratch file (never a
shared ``fixtures.data.SCANNED`` hash -- see ``tests_e2e/README.md``'s
"never mutate a shared fixture" rule). Also covers the endpoint-level
negative/error contracts for ``upload`` and ``scan``.
"""
import pytest

from tests_e2e.api.scratch_utils import (
    cleanup_scratch_file,
    make_scratch_copy,
    poll_report_json,
)
from tests_e2e.fixtures.data import PRIMARY_HASH

PDF_MAGIC = b'%PDF'


@pytest.mark.e2e_flow
@pytest.mark.positive
def test_full_upload_scan_report_pdf_delete_flow(api_client):
    scratch_path = make_scratch_copy('android_src.zip')
    file_hash = None
    try:
        # 1. upload
        upload_r = api_client.upload_file(scratch_path)
        assert upload_r.status_code == 200
        upload_body = upload_r.json()
        assert upload_body['status'] == 'success'
        file_hash = upload_body['hash']
        assert upload_body['scan_type'] == 'zip'

        # 2. scan (async -- queued to the qcluster worker)
        scan_r = api_client.scan(file_hash)
        assert scan_r.status_code == 200
        assert 'task_id' in scan_r.json() or 'message' in scan_r.json()

        # 3. poll report_json until the worker finishes
        report_r = poll_report_json(api_client, file_hash, timeout=180)
        report = report_r.json()
        assert report['md5'] == file_hash
        assert report['app_name']
        # Real content, not just presence of the scan row.
        assert isinstance(report['permissions'], dict)
        assert isinstance(report['manifest_analysis'], dict)
        assert isinstance(report['certificate_analysis'], dict)

        # 4. download_pdf
        pdf_r = api_client.download_pdf(file_hash)
        assert pdf_r.status_code == 200
        assert pdf_r.content.startswith(PDF_MAGIC)
        assert b'tamper' not in pdf_r.content.lower()

        # 5. delete_scan
        delete_r = api_client.delete_scan(file_hash)
        assert delete_r.status_code == 200
        assert delete_r.json().get('deleted') == 'yes'
        file_hash = None  # already cleaned up server-side

        # 6. report_json now 404s
        after_delete_r = api_client.report_json(upload_body['hash'])
        assert after_delete_r.status_code == 404
        assert after_delete_r.json().get('report') == 'Report not Found'
    finally:
        cleanup_scratch_file(scratch_path)
        if file_hash:
            # Best-effort cleanup if an earlier assertion failed mid-flow.
            api_client.delete_scan(file_hash)


@pytest.mark.negative
def test_upload_missing_file_field(api_client):
    # The field-name mismatch means the server rejects the request via form
    # validation before ever reading the file's bytes -- nothing is
    # persisted/scanned, so this is safe to point at a real fixture file
    # directly rather than a scratch copy (no mutation occurs).
    from tests_e2e.fixtures.data import SCANNED
    r = api_client.upload_file(SCANNED['so']['file'], field_name='not_the_file_field')
    assert r.status_code == 400
    assert 'file' in r.json().get('error', {})


@pytest.mark.negative
def test_scan_invalid_hash_format(api_client):
    r = api_client.scan('not-a-valid-md5')
    assert r.status_code == 500
    assert r.json().get('error') == 'Invalid Checksum'


@pytest.mark.negative
def test_scan_nonexistent_hash(api_client):
    r = api_client.scan('0' * 32)
    assert r.status_code == 500
    assert r.json().get('error') == 'The file is not uploaded/available'


@pytest.mark.negative
def test_scan_missing_hash(api_client):
    r = api_client.post('/api/v1/scan', data={})
    assert r.status_code == 422
    assert r.json().get('error') == 'Missing Parameters'


@pytest.mark.negative
@pytest.mark.regression
def test_duplicate_upload_of_already_scanned_apk_is_rejected(api_client):
    """Re-uploading an already-scanned app's exact bytes is rejected before
    any new mutation happens (see scanning.py::find_duplicate_scan's
    "Layer 1: identical bytes"), so this is safe to run directly against the
    read-only PRIMARY (Diva) fixture -- unlike every other test in this
    file, it deliberately targets fixtures.data.SCANNED, not a scratch copy,
    because the dedup check itself is the thing under test."""
    from tests_e2e.fixtures.data import SCANNED
    r = api_client.upload_file(SCANNED['apk']['file'])
    assert r.status_code == 409
    body = r.json()
    assert body['status'] == 'error'
    assert body['duplicate'] is True
    assert body['hash'] == PRIMARY_HASH
    assert body['existing_hash'] == PRIMARY_HASH
    assert body['existing_url'] == f'/static_analyzer/{PRIMARY_HASH}/'
    assert 'description' in body
