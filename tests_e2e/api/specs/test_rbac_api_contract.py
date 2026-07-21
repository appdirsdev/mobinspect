"""RBAC contract matrix for the REST API surface (H17 / tests_e2e).

Cross-product of representative ``/api/v1/*`` endpoints x principals
(anon / Viewer / API User / Administrator), asserting the CORRECT denial
envelope for whichever of the THREE distinct layers actually guards each
endpoint (see the module docstring in ``tests_e2e/api/client.py`` and
``tests_e2e/README.md``'s "two distinct RBAC denial shapes" convention):

  1. ``RestApiAuthMiddleware`` (api_middleware.py) — runs first, for every
     ``/api/*`` path, before any view executes:
       * no/invalid key              -> 401 {"error": "You are unauthorized ..."}
       * valid key, role lacks       -> 403 {"error": "API access not permitted
         ``api.use``                      for this user."}
  2. ``RBAC.decorators.require_permission`` (per-view, current system) —
     runs AFTER the middleware, only for views that declare it:
       * authenticated, lacks the specific permission -> 403
         {"error": "forbidden", "detail": "Insufficient permissions."}
  3. A few LEGACY views still use Django's classic
     ``@permission_required(Permissions.X)`` (checks real Django Group
     membership, NOT the RBAC permission catalog) -> 403
     {"status": "denied", "message": "..."} — NO "error" key. The
     conftest-provisioned ``tests_e2e_api_user``/``tests_e2e_viewer``
     accounts are never added to a Django Group (only the admin UI's
     ``create_user`` flow does that mirroring — see
     ``mobinspect/MobInspect/views/authorization.py``'s
     ``sync_legacy_group_permissions``), so ANY legacy-decorated endpoint
     denies them regardless of which RBAC permissions their role holds.

Real per-endpoint decorator, read directly from source (not guessed):

  * ``report_json``  (api_json_report)      @require_permission('scan.export.json')  — layer 2
  * ``download_pdf``  (api_pdf_report)      @require_permission('scan.export.pdf')   — layer 2
  * ``scorecard``    (api_scorecard)        delegates to appsec_dashboard(), which
                                              carries @require_permission('scan.view') — layer 2
  * ``compare``      (api_compare)          delegates to compare_apps(), which
                                              carries @require_permission('scan.view') — layer 2
  * ``list_suppressions`` (api_list_suppressions) delegates to
                                              suppression.list_suppressions(), which
                                              carries @require_permission('scan.view') — layer 2
  * ``scans``        (api_recent_scans)     NO per-view permission at all — only
                                              the middleware's api.use gate
  * ``search``       (api_search)           delegates to home.search(), which
                                              carries only @login_required — only
                                              the middleware's api.use gate
  * ``delete_scan``  (api_delete_scan)      delegates to home.delete_scan(), LEGACY
                                              @permission_required(Permissions.DELETE) — layer 3
  * ``suppress_by_rule`` (api_suppress_by_rule_id) delegates to
                                              suppression.suppress_by_rule_id(), LEGACY
                                              @permission_required(Permissions.SUPPRESS) — layer 3

'API User' (api.use + finding.suppress/scan.create/scan.view/scan.export.json,
NOT scan.export.pdf/scan.delete) is deliberately the role used here: it
distinguishes the layer-2 permission-specific 403 (denied on download_pdf,
which needs scan.export.pdf) from layer-2 grants (report_json/scorecard/
compare/list_suppressions, all satisfied by scan.view/scan.export.json) and
from the layer-3 legacy denial (delete_scan/suppress_by_rule — denied
regardless, per the Django-Group note above).

Mutating endpoints (suppress_by_rule / delete_scan) are exercised ONLY
against a private SCRATCH scan this file uploads and deletes itself (a
uniquely-content copy of test_files/android.so) — never against
PRIMARY_HASH/SECONDARY_HASH, per tests_e2e/README.md's "never mutate a
shared fixture" rule.
"""
import os
import uuid

import pytest

from tests_e2e.fixtures.data import PRIMARY_HASH, SECONDARY_HASH, TEST_FILES_DIR

MW_401 = ('anon_api_client', 401, {'error': 'You are unauthorized to make this request.'})
MW_403 = ('viewer_api_client', 403, {'error': 'API access not permitted for this user.'})
RBAC_403 = ('api_user_api_client', 403, {'error': 'forbidden', 'detail': 'Insufficient permissions.'})
LEGACY_403 = ('api_user_api_client', 403, None)  # shape checked separately (no "error" key)
OK_200 = ('api_client', 200, None)


def _client(request, name):
    return request.getfixturevalue(name)


# ─────────────────────────── Layer 2 (RBAC decorator): granted by API User ───────────────────────────


@pytest.mark.negative
@pytest.mark.parametrize('client_name,status,body', [MW_401, MW_403])
def test_report_json_denied(request, client_name, status, body):
    client = _client(request, client_name)
    r = client.report_json(PRIMARY_HASH)
    assert r.status_code == status
    assert r.json() == body


@pytest.mark.positive
def test_report_json_allowed_for_api_user_and_admin(api_user_api_client, api_client):
    """API User has scan.export.json -> allowed, same as admin."""
    for client in (api_user_api_client, api_client):
        r = client.report_json(PRIMARY_HASH)
        assert r.status_code == 200
        assert r.json().get('app_name') == 'Diva'


@pytest.mark.negative
@pytest.mark.parametrize('client_name,status,body', [MW_401, MW_403])
def test_scorecard_denied(request, client_name, status, body):
    client = _client(request, client_name)
    r = client.scorecard(PRIMARY_HASH)
    assert r.status_code == status
    assert r.json() == body


@pytest.mark.positive
def test_scorecard_allowed_for_api_user_and_admin(api_user_api_client, api_client):
    """API User has scan.view -> allowed, same as admin."""
    for client in (api_user_api_client, api_client):
        r = client.scorecard(PRIMARY_HASH)
        assert r.status_code == 200
        assert r.json().get('hash') == PRIMARY_HASH


@pytest.mark.negative
@pytest.mark.parametrize('client_name,status,body', [MW_401, MW_403])
def test_compare_denied(request, client_name, status, body):
    client = _client(request, client_name)
    r = client.compare(PRIMARY_HASH, SECONDARY_HASH)
    assert r.status_code == status
    assert r.json() == body


@pytest.mark.positive
def test_compare_allowed_for_api_user_and_admin(api_user_api_client, api_client):
    """API User has scan.view -> allowed, same as admin."""
    for client in (api_user_api_client, api_client):
        r = client.compare(PRIMARY_HASH, SECONDARY_HASH)
        assert r.status_code == 200


@pytest.mark.negative
@pytest.mark.parametrize('client_name,status,body', [MW_401, MW_403])
def test_list_suppressions_denied(request, client_name, status, body):
    client = _client(request, client_name)
    r = client.list_suppressions(PRIMARY_HASH)
    assert r.status_code == status
    assert r.json() == body


@pytest.mark.positive
def test_list_suppressions_allowed_for_api_user_and_admin(api_user_api_client, api_client):
    """API User has scan.view -> allowed, same as admin."""
    for client in (api_user_api_client, api_client):
        r = client.list_suppressions(PRIMARY_HASH)
        assert r.status_code == 200
        assert r.json().get('status') == 'ok'


@pytest.mark.negative
@pytest.mark.regression
@pytest.mark.parametrize('client_name,status,body', [MW_401, MW_403])
def test_download_pdf_denied_by_middleware(request, client_name, status, body):
    client = _client(request, client_name)
    r = client.download_pdf(PRIMARY_HASH)
    assert r.status_code == status
    assert r.json() == body


@pytest.mark.negative
@pytest.mark.regression
def test_download_pdf_denied_for_api_user_lacking_export_pdf(api_user_api_client):
    """API User has scan.export.json but NOT scan.export.pdf -- the ONE
    endpoint in this matrix where an authenticated, api.use-holding,
    otherwise-broadly-permissioned key still gets a layer-2 RBAC 403 (not
    a middleware-level denial, and not the legacy layer-3 shape)."""
    r = api_user_api_client.download_pdf(PRIMARY_HASH)
    assert r.status_code == 403
    assert r.json() == {'error': 'forbidden', 'detail': 'Insufficient permissions.'}


@pytest.mark.positive
def test_download_pdf_allowed_for_admin(api_client):
    r = api_client.download_pdf(PRIMARY_HASH)
    assert r.status_code == 200
    assert r.headers.get('Content-Type') == 'application/pdf'
    assert r.content[:4] == b'%PDF'


# ─────────────────────────── Layer: middleware only (no per-view permission) ───────────────────────────


@pytest.mark.negative
@pytest.mark.parametrize('client_name,status,body', [MW_401, MW_403])
def test_scans_denied(request, client_name, status, body):
    client = _client(request, client_name)
    r = client.scans()
    assert r.status_code == status
    assert r.json() == body


@pytest.mark.positive
def test_scans_allowed_for_any_api_use_holder(api_user_api_client, api_client):
    """api_recent_scans() has NO per-view permission decorator at all
    (mobinspect/MobInspect/views/api/api_static_analysis.py) -- any role
    with just ``api.use`` reaches it, regardless of scan.* permissions."""
    for client in (api_user_api_client, api_client):
        r = client.scans()
        assert r.status_code == 200
        assert 'content' in r.json()


@pytest.mark.negative
@pytest.mark.parametrize('client_name,status,body', [MW_401, MW_403])
def test_search_denied(request, client_name, status, body):
    client = _client(request, client_name)
    r = client.search(PRIMARY_HASH)
    assert r.status_code == status
    assert r.json() == body


@pytest.mark.positive
def test_search_allowed_for_any_api_use_holder(api_user_api_client, api_client):
    """home.search() (mobinspect/MobInspect/views/home.py) carries only
    @login_required -- same "middleware gate only" shape as scans."""
    for client in (api_user_api_client, api_client):
        r = client.search(PRIMARY_HASH)
        assert r.status_code == 200
        assert r.json().get('app_name') == 'Diva'


# ─────────────────────────── Layer 3 (legacy @permission_required) ───────────────────────────


@pytest.fixture
def scratch_scan(api_client):
    """Upload + scan a private, uniquely-content copy of android.so via the
    REAL API (not the ORM), yielding its hash; deletes it afterwards.

    Never reuses fixtures.data.SCANNED['so'] bytes -- a fresh uuid4 suffix
    guarantees a distinct MD5 so this never collides with (or mutates) the
    shared SCANNED fixture other specs rely on.

    NOTE: requests' multipart encoder only sets a part Content-Type header
    when it can guess one from the filename via the stdlib `mimetypes`
    module; `.so` has no registered MIME type, so a bare
    ``files={'file': fh}`` upload (as ``client.upload_apk()`` does) sends
    the part with NO Content-Type header at all, and Django's parser then
    reports ``file_obj.content_type == ''`` -- which is not in
    ``settings.APK_MIME`` (unlike '' 's sibling 'application/octet-stream',
    which IS) -> the server correctly rejects it as "File format not
    Supported!". A real browser upload always sends an explicit
    Content-Type for unknown extensions, so this is an artifact of the
    thin client, not a server bug -- worked around here by setting the
    part's Content-Type explicitly, matching what a browser would send.
    """
    src = os.path.join(TEST_FILES_DIR, 'android.so')
    with open(src, 'rb') as fh:
        payload = fh.read() + f'e2e-scratch-{uuid.uuid4().hex}'.encode()
    scratch_dir = os.path.join(TEST_FILES_DIR, '.e2e_scratch')
    os.makedirs(scratch_dir, exist_ok=True)
    scratch_name = f'api_contract_scratch_{uuid.uuid4().hex[:8]}.so'
    scratch_path = os.path.join(scratch_dir, scratch_name)
    with open(scratch_path, 'wb') as fh:
        fh.write(payload)

    file_hash = None
    try:
        with open(scratch_path, 'rb') as fh:
            r = api_client.post(
                '/api/v1/upload',
                files={'file': (scratch_name, fh, 'application/octet-stream')},
            )
        assert r.status_code == 200, r.text
        file_hash = r.json()['hash']
        r2 = api_client.scan(file_hash)
        assert r2.status_code == 200, r2.text
        yield file_hash
    finally:
        os.remove(scratch_path)
        if file_hash:
            api_client.delete_scan(file_hash)  # idempotent no-op if already gone


@pytest.mark.negative
@pytest.mark.parametrize('client_name,status,body', [MW_401, MW_403])
def test_delete_scan_denied_by_middleware(request, client_name, status, body):
    client = _client(request, client_name)
    r = client.delete_scan(PRIMARY_HASH)  # never reaches the view; PRIMARY_HASH is safe here
    assert r.status_code == status
    assert r.json() == body


@pytest.mark.negative
@pytest.mark.regression
def test_delete_scan_denied_for_api_user_legacy_shape(api_user_api_client):
    """Pinned regression for the LEGACY envelope documented in
    api/specs/test_scaffold_smoke.py: home.delete_scan's classic
    @permission_required(Permissions.DELETE) denies api_user_api_client
    with a {"status": "denied", ...} body -- no "error" key."""
    r = api_user_api_client.delete_scan(PRIMARY_HASH)
    assert r.status_code == 403
    body = r.json()
    assert body.get('status') == 'denied'
    assert 'error' not in body


@pytest.mark.positive
@pytest.mark.e2e_flow
def test_delete_scan_allowed_for_admin_on_scratch(api_client, scratch_scan):
    r = api_client.delete_scan(scratch_scan)
    assert r.status_code == 200
    assert r.json() == {'deleted': 'yes'}


def _suppress_by_rule(client, file_hash, rule_id, sup_type='manifest'):
    """Direct call bypassing MobInspectApiClient.suppress_by_rule() -- that
    helper doesn't send the required 'type' param (suppress_by_rule_id()
    in mobinspect/StaticAnalyzer/views/common/suppression.py requires
    hash+rule+type; 'type' must be 'code' or 'manifest')."""
    return client.post('/api/v1/suppress_by_rule', data={
        'hash': file_hash, 'rule': rule_id, 'type': sup_type, 'reason': 'e2e-suite'})


@pytest.mark.negative
@pytest.mark.parametrize('client_name,status,body', [MW_401, MW_403])
def test_suppress_by_rule_denied_by_middleware(request, client_name, status, body):
    client = _client(request, client_name)
    r = _suppress_by_rule(client, PRIMARY_HASH, 'irrelevant_rule')
    assert r.status_code == status
    assert r.json() == body


@pytest.mark.negative
@pytest.mark.regression
def test_suppress_by_rule_denied_for_api_user_legacy_shape(api_user_api_client):
    """API User HOLDS the RBAC permission 'finding.suppress', but
    suppress_by_rule_id() is guarded by the LEGACY
    @permission_required(Permissions.SUPPRESS) decorator (classic Django
    Group membership), not the RBAC permission catalog -- and
    conftest-provisioned test accounts are never added to a Django Group
    (only the admin create_user UI flow mirrors that). So API User is
    denied here despite holding the semantically-matching RBAC permission
    -- a real, worth-flagging inconsistency between the RBAC catalog and
    this one legacy-guarded endpoint (see also delete_scan's identical gap,
    already pinned in test_scaffold_smoke.py)."""
    r = api_user_api_client.post('/api/v1/suppress_by_rule', data={
        'hash': PRIMARY_HASH, 'rule': 'irrelevant_rule', 'type': 'manifest'})
    assert r.status_code == 403
    body = r.json()
    assert body.get('status') == 'denied'
    assert 'error' not in body


@pytest.mark.positive
@pytest.mark.e2e_flow
def test_suppress_by_rule_allowed_for_admin_on_scratch(api_client, scratch_scan):
    r = _suppress_by_rule(api_client, scratch_scan, 'e2e_contract_rule')
    assert r.status_code == 200
    assert r.json() == {'status': 'ok'}

    listed = api_client.list_suppressions(scratch_scan)
    assert listed.status_code == 200
    rules = [
        rid
        for row in listed.json().get('message', [])
        for rid in row.get('SUPPRESS_RULE_ID', [])
    ]
    assert 'e2e_contract_rule' in rules

    cleanup = api_client.post('/api/v1/delete_suppression', data={
        'hash': scratch_scan, 'rule': 'e2e_contract_rule', 'type': 'manifest'})
    assert cleanup.status_code == 200
