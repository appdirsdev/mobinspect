"""Fixtures for the API contract suite.

Runs straight HTTP calls against a REAL running server (see
``tests_e2e/README.md``) — no Django test client, no mocks. When
``MOBINSPECT_ADMIN_API_KEY`` isn't provided, we provision a fresh per-user
RBAC key for the admin account directly via the ORM (same Postgres the
server itself uses) rather than hardcoding a key, so the suite is
reproducible against any freshly seeded environment.

IMPORTANT: the *global* env-configured API key (sha256 of a shared secret)
authenticates but has no associated user, so every RBAC-gated endpoint
(almost all of them) rejects it as unauthenticated. Always use a per-user
key minted via ``ApiKey.generate(user, ...)``.
"""
import os

import pytest

from tests_e2e.api.client import MobInspectApiClient
from tests_e2e.conftest import ADMIN_API_KEY, ADMIN_USERNAME, BASE_URL

# When api/ specs run in the SAME pytest session as ui/ (Playwright) specs,
# the playwright plugin's fixtures keep an asyncio event loop alive; Django's
# sync-ORM guard then refuses our plain ORM provisioning calls below with
# SynchronousOnlyOperation, even though nothing here is actually concurrent.
# This is Django's own documented escape hatch for exactly that situation —
# see django.utils.asyncio.async_unsafe.
os.environ.setdefault('DJANGO_ALLOW_ASYNC_UNSAFE', 'true')


def _provision_admin_key():
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'mobinspect.MobInspect.settings')
    import django
    django.setup()
    from django.contrib.auth import get_user_model
    from mobinspect.RBAC.models import ApiKey

    user_model = get_user_model()
    admin = user_model.objects.get(username=ADMIN_USERNAME)
    _obj, raw_key = ApiKey.generate(admin, name='tests_e2e-suite-key')
    return raw_key


@pytest.fixture(scope='session')
def admin_api_key(django_db_blocker):
    if ADMIN_API_KEY:
        return ADMIN_API_KEY
    # Session-scoped ORM access outside any test's db-transaction: pytest-django
    # blocks raw db access by default, so unblock explicitly for this one-time
    # provisioning call (this suite runs against a live server's REAL db over
    # HTTP for the tests themselves; this is the one exception, purely to mint
    # a key the same way the admin UI's "Create API key" button would).
    with django_db_blocker.unblock():
        return _provision_admin_key()


@pytest.fixture(scope='session')
def api_client(admin_api_key):
    """An authenticated (Administrator) API client."""
    return MobInspectApiClient(BASE_URL, api_key=admin_api_key)


@pytest.fixture(scope='session')
def anon_api_client():
    """A client with NO API key — used to assert 401 on gated endpoints."""
    return MobInspectApiClient(BASE_URL, api_key=None)


def _provision_role_key(role_name, username):
    """Mint (or reuse) a user assigned to ``role_name`` and a fresh API key.

    NOTE the RBAC model has TWO independent gates on every ``/api/*`` call:
    (1) ``RestApiAuthMiddleware`` requires the resolved user to hold the
    ``api.use`` permission at all — Viewer does NOT have it, so a Viewer key
    is rejected categorically (403 "API access not permitted for this user.")
    before any per-view check ever runs. (2) per-view ``require_permission``
    then gates individual actions. So "low-privilege but API-capable" tests
    (403 on a specific action, 200 on another) need a role that HAS api.use
    but lacks the privileged action — "API User" (api.use + scan.create/view/
    export.json, no scan.delete/rbac.*/settings.*) is that role; "Viewer" is
    the categorical-denial case.
    """
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'mobinspect.MobInspect.settings')
    import django
    django.setup()
    from django.contrib.auth import get_user_model
    from mobinspect.RBAC.models import ApiKey, Role, RoleAssignment

    user_model = get_user_model()
    user, created = user_model.objects.get_or_create(
        username=username, defaults={'email': f'{username}@example.invalid'})
    if created:
        user.set_password('e2e-suite-pw-not-used')
        user.is_superuser = False
        user.is_staff = False
        user.save()
    role = Role.objects.filter(name__iexact=role_name).first()
    if role is None:
        raise RuntimeError(f'RBAC role {role_name!r} not seeded — run create_roles first.')
    if not RoleAssignment.objects.filter(user=user, role=role).exists():
        RoleAssignment.objects.create(user=user, role=role)
    _obj, raw_key = ApiKey.generate(user, name=f'{username}-key')
    return raw_key


@pytest.fixture(scope='session')
def viewer_api_key(django_db_blocker):
    """Viewer role: NO ``api.use`` -> every /api/ call is denied categorically."""
    with django_db_blocker.unblock():
        return _provision_role_key('Viewer', 'tests_e2e_viewer')


@pytest.fixture(scope='session')
def viewer_api_client(viewer_api_key):
    return MobInspectApiClient(BASE_URL, api_key=viewer_api_key)


@pytest.fixture(scope='session')
def api_user_api_key(django_db_blocker):
    """'API User' role: has api.use + scan.create/view/export.json, but NOT
    scan.delete / rbac.* / settings.* — the fixture for per-view 403 tests."""
    with django_db_blocker.unblock():
        return _provision_role_key('API User', 'tests_e2e_api_user')


@pytest.fixture(scope='session')
def api_user_api_client(api_user_api_key):
    return MobInspectApiClient(BASE_URL, api_key=api_user_api_key)
