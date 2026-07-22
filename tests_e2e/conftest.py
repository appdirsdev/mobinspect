"""Shared configuration for the whole tests_e2e suite (UI + API).

Both ``ui/`` and ``api/`` read the same environment variables so a single
target (local dev, a staging box, or a deployed instance) drives the entire
run:

    MOBINSPECT_UI_BASE        base URL of a running server (default 127.0.0.1:8000)
    MOBINSPECT_ADMIN_USERNAME / MOBINSPECT_ADMIN_PASSWORD   admin session creds
    MOBINSPECT_ADMIN_API_KEY  a per-user RBAC API key (mi_... prefix) with the
                              Administrator role — NOT the global sha256 key,
                              which fails every RBAC-gated endpoint.
"""
import os

import pytest

BASE_URL = os.environ.get('MOBINSPECT_UI_BASE', 'http://127.0.0.1:8000').rstrip('/')
ADMIN_USERNAME = os.environ.get('MOBINSPECT_ADMIN_USERNAME', 'admin')
ADMIN_PASSWORD = os.environ.get('MOBINSPECT_ADMIN_PASSWORD', 'admin')
ADMIN_API_KEY = os.environ.get('MOBINSPECT_ADMIN_API_KEY', '')


@pytest.fixture(scope='session', autouse=True)
def _ensure_rbac_roles_synced(django_db_blocker):
    """Run ``create_roles`` once before the suite, exactly as production does.

    The legacy ``@permission_required(Permissions.SUPPRESS/DELETE/SCAN)``
    guards on a few endpoints (delete_scan, suppress_by_rule, ...) resolve
    through each RBAC role's *wrapped Django Group* membership, NOT the RBAC
    catalog directly. That Group only gets its legacy ``auth.Permission``
    rows populated when ``create_roles`` runs its ``_mirror_rbac_role_groups``
    step — the seed migration (0003) sets ``role.permissions`` via historical
    models, so the runtime ``m2m_changed`` sync signal never fires for the
    seeded roles, leaving every role Group with EMPTY Django permissions
    until ``create_roles`` runs.

    ``entrypoint.sh`` runs ``create_roles`` on every container start, so a
    real deployment is always synced. A manually-started dev server used as
    the test target may not be — and an UNSYNCED DB makes non-staff role
    permission tests observe (and mis-assert) a denial that never happens in
    production. Running it here makes the suite deterministic and faithful to
    production regardless of how the target server was booted. Idempotent.
    """
    os.environ.setdefault(
        'DJANGO_SETTINGS_MODULE', 'mobinspect.MobInspect.settings')
    # Playwright keeps an asyncio loop alive for the whole session; Django's
    # sync-ORM guard would otherwise refuse this management command.
    os.environ.setdefault('DJANGO_ALLOW_ASYNC_UNSAFE', 'true')
    import django
    django.setup()
    from django.core.management import call_command
    with django_db_blocker.unblock():
        call_command('create_roles')
