"""``POST /api/v1/download_pdf`` — PDF report export REST contract.

See ``api_static_analysis.py::api_pdf_report`` (delegates to
``StaticAnalyzer/views/common/pdf.py::pdf(..., api=True)``).
"""
import pytest

from tests_e2e.fixtures.data import PRIMARY_HASH, SCANNED

PDF_MAGIC = b'%PDF'


@pytest.mark.positive
def test_download_pdf_primary_apk(api_client):
    r = api_client.download_pdf(PRIMARY_HASH)
    assert r.status_code == 200
    assert r.content.startswith(PDF_MAGIC)


@pytest.mark.positive
@pytest.mark.parametrize('fmt', ['jar', 'ios_src', 'appx'])
def test_download_pdf_other_formats(api_client, fmt):
    sample = SCANNED[fmt]
    r = api_client.download_pdf(sample['hash'])
    assert r.status_code == 200
    assert r.content.startswith(PDF_MAGIC)


@pytest.mark.regression
def test_download_pdf_no_tamper_false_positive(api_client):
    """Pins the fix in commit 21666f3 ("Fix false 'Executable/Library
    Tampering Detected' breaking PDF export") -- the runtime exec-tamper
    monkeypatch (mobinspect/MobInspect/utils.py) used to false-positive on a
    redeployed/cloned environment and broke wkhtmltopdf calls, surfacing as
    an "application tamper" error in the API response. It is now gated
    behind MOBINSPECT_EXEC_TAMPER_DETECTION (default OFF), so a real PDF
    must come back clean, with no tamper-error text anywhere in the body."""
    r = api_client.download_pdf(PRIMARY_HASH)
    assert r.status_code == 200
    assert r.content.startswith(PDF_MAGIC)
    lowered = r.content.lower()
    assert b'tamper' not in lowered
    assert b'temper' not in lowered


@pytest.mark.negative
def test_download_pdf_missing_hash(api_client):
    r = api_client.post('/api/v1/download_pdf', data={})
    assert r.status_code == 422
    assert r.json().get('error') == 'Missing Parameters'


@pytest.mark.negative
def test_download_pdf_malformed_hash(api_client):
    r = api_client.download_pdf('not-a-valid-md5')
    assert r.status_code == 400
    assert r.json().get('error') == 'Invalid Hash'


@pytest.mark.negative
def test_download_pdf_nonexistent_hash(api_client):
    r = api_client.download_pdf('0' * 32)
    assert r.status_code == 404
    assert r.json().get('report') == 'Report not Found'
