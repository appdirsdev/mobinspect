"""Sanity check for the api/ scaffolding itself (fixtures, client, RBAC provisioning)."""
from tests_e2e.fixtures.data import PRIMARY_HASH


def test_admin_client_authenticates(api_client):
    r = api_client.report_json(PRIMARY_HASH)
    assert r.status_code == 200
    assert r.json().get('app_name') == 'Diva'


def test_anon_client_is_rejected(anon_api_client):
    r = anon_api_client.report_json(PRIMARY_HASH)
    assert r.status_code == 401
    assert r.json().get('error') == 'You are unauthorized to make this request.'


def test_viewer_role_has_no_api_access_at_all(viewer_api_client):
    """Viewer lacks the `api.use` permission -> denied by the middleware
    gate before any per-view check, on every /api/ endpoint without exception."""
    r = viewer_api_client.report_json(PRIMARY_HASH)
    assert r.status_code == 403
    assert r.json().get('error') == 'API access not permitted for this user.'


def test_api_user_role_can_read_but_not_delete(api_user_api_client):
    """'API User' has api.use + scan.view/export.json but not scan.delete.

    NOTE: delete_scan (mobinspect/MobInspect/views/home.py) is guarded by the
    LEGACY Django ``@permission_required(Permissions.DELETE)`` decorator
    (checks the classic ``StaticAnalyzer.can_delete`` model permission), not
    the newer RBAC ``require_permission('scan.delete')`` codename system most
    other endpoints use -> a different denial envelope
    (``{"message": ..., "status": "denied"}``, no ``"error"`` key).
    """
    r = api_user_api_client.report_json(PRIMARY_HASH)
    assert r.status_code == 200
    r2 = api_user_api_client.delete_scan(PRIMARY_HASH)
    assert r2.status_code == 403
    assert r2.json().get('status') == 'denied'
