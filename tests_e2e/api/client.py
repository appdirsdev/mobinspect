"""Thin REST client for MobInspect's ``/api/v1/*`` surface.

Wraps ``requests`` so specs assert on a small, typed surface (status code +
parsed JSON) instead of repeating header/URL plumbing. Header name and error
envelopes come from two DISTINCT layers — do not conflate them:

  * ``api_middleware.RestApiAuthMiddleware`` (runs first, for every
    ``/api/*`` path): no/invalid key at all ->
    ``401 {"error": "You are unauthorized to make this request."}``.
    Header is ``X-MobInspect-Api-Key`` (or ``Authorization``); HTTP header
    names are case-insensitive so ``X-Mobinspect-Api-Key`` also works.
  * ``RBAC.decorators.require_permission``/``require_role`` (per-view, runs
    AFTER auth succeeds): a valid key whose resolved user is None ->
    ``401 {"error": "unauthenticated"}``; a valid, identified user lacking
    the permission -> ``403 {"error": "forbidden", "detail": "..."}``.
"""
import os

import requests

API_KEY_HEADER = 'X-Mobinspect-Api-Key'


class ApiResponse:
    """Wraps a `requests.Response`, exposing lazily-parsed JSON."""

    def __init__(self, response):
        self.raw = response
        self.status_code = response.status_code
        self.headers = response.headers
        self.content = response.content
        self.text = response.text

    def json(self):
        return self.raw.json()


class MobInspectApiClient:
    """Calls MobInspect's REST API with (optionally) an API key."""

    def __init__(self, base_url, api_key=None, timeout=60):
        self.base_url = base_url.rstrip('/')
        self.api_key = api_key
        self.timeout = timeout
        self.session = requests.Session()

    def _headers(self, extra=None):
        headers = {}
        if self.api_key:
            headers[API_KEY_HEADER] = self.api_key
        if extra:
            headers.update(extra)
        return headers

    def _url(self, path):
        return f'{self.base_url}/{path.lstrip("/")}'

    def get(self, path, params=None, **kw):
        r = self.session.get(
            self._url(path), params=params, headers=self._headers(),
            timeout=self.timeout, **kw)
        return ApiResponse(r)

    def post(self, path, data=None, files=None, **kw):
        r = self.session.post(
            self._url(path), data=data, files=files,
            headers=self._headers(), timeout=self.timeout, **kw)
        return ApiResponse(r)

    def without_key(self):
        """A sibling client with no API key, for 401 assertions."""
        return MobInspectApiClient(self.base_url, api_key=None, timeout=self.timeout)

    def with_key(self, api_key):
        """A sibling client using a different (e.g. lower-privilege) key."""
        return MobInspectApiClient(self.base_url, api_key=api_key, timeout=self.timeout)

    def upload_apk(self, file_path, field_name='file', content_type='application/octet-stream'):
        """Upload a file for scanning.

        Sends an EXPLICIT multipart Content-Type (real bug found and fixed
        while building this suite: a bare file handle passed to ``requests``'
        ``files=`` omits the per-part Content-Type entirely; Django's
        ``UploadedFile.content_type`` then isn't one of ``settings.APK_MIME``/
        ``ZIP_MIME``/etc — see ``mobinspect/MobInspect/views/helpers.py::
        FileType.is_allow_file`` — so the upload was rejected with
        ``400 {"error": "File format not Supported!"}`` regardless of the
        file's real bytes/extension. `curl -F` and a real browser both set a
        Content-Type on the part automatically, which is why manual curl
        checks and the UI's Playwright upload never surfaced this).
        """
        with open(file_path, 'rb') as fh:
            file_name = os.path.basename(file_path)
            return self.post(
                '/api/v1/upload',
                files={field_name: (file_name, fh, content_type)})

    # Backwards-compatible alias — some specs were written against this name.
    upload_file = upload_apk

    def scan(self, file_hash):
        return self.post('/api/v1/scan', data={'hash': file_hash})

    def report_json(self, file_hash):
        return self.post('/api/v1/report_json', data={'hash': file_hash})

    def scorecard(self, file_hash):
        return self.post('/api/v1/scorecard', data={'hash': file_hash})

    def download_pdf(self, file_hash):
        return self.post('/api/v1/download_pdf', data={'hash': file_hash})

    def search(self, query):
        return self.post('/api/v1/search', data={'query': query})

    def compare(self, hash1, hash2):
        return self.post('/api/v1/compare', data={'hash1': hash1, 'hash2': hash2})

    def scans(self):
        return self.get('/api/v1/scans')

    def list_suppressions(self, file_hash):
        return self.post('/api/v1/list_suppressions', data={'hash': file_hash})

    def delete_scan(self, file_hash):
        return self.post('/api/v1/delete_scan', data={'hash': file_hash})

    def suppress_by_rule_typed(self, file_hash, rule_id, rule_type,
                                reason='e2e-suite'):
        """Suppress a single rule/finding.

        ``type`` (``code`` or ``manifest``) is REQUIRED by
        ``api_suppress_by_rule_id`` (see ``mobinspect/StaticAnalyzer/views/
        common/suppression.py``) — omitting it gets a clean
        ``422 Missing Parameters`` every time.
        """
        return self.post('/api/v1/suppress_by_rule', data={
            'hash': file_hash, 'rule': rule_id, 'type': rule_type,
            'reason': reason})

    def delete_suppression_typed(self, file_hash, rule_id, rule_type, kind=None):
        data = {'hash': file_hash, 'rule': rule_id, 'type': rule_type}
        if kind is not None:
            data['kind'] = kind
        return self.post('/api/v1/delete_suppression', data=data)
