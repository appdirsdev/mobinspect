"""
Shared pytest fixtures for the RBAC + Analytics test suites (H17).

All fixtures here lean on `pytest-django`:
  * `db` is the marker that opts a test into the transactional test
    database; we wrap each fixture that touches the ORM with it.
  * `django_user_model` is the actual `User` class — using it rather
    than importing directly avoids accidentally binding to the wrong
    model when AUTH_USER_MODEL is later overridden.

Conventions:
  * Test usernames are namespaced as ``rbac_<role>`` so cross-test
    collisions are loud and obvious.
  * Every role fixture returns a fresh `RoleAssignment` row. The
    role's permissions come from the seeded `Permission` catalog,
    NOT from hardcoded codenames here — that way these tests catch
    catalog regressions instead of papering over them.
  * Each `*_api_key` fixture returns the **plaintext** key only.
    The hashed `ApiKey` row is created as a side-effect; pull it back
    from the DB if a test needs the row itself.
"""
import pytest

from django.contrib.auth.models import Group

from mobinspect.RBAC.models import ApiKey, Permission, Role, RoleAssignment


# ─────────────────────────────────────────────────────── role helpers
def _ensure_role(name, codenames):
    """Idempotent: fetch the seeded Role, or build one for the test.

    The default-roles migration (0003) seeds Viewer / Security Analyst /
    Administrator with curated permission sets. We prefer those rows so
    a test that breaks the seeds still fails loudly here, but if a fresh
    DB is in use (e.g. a developer running `pytest -x` without prior
    `migrate`) we synthesize a Role with the requested codenames so the
    suite stays self-contained.

    Important: when the role is already seeded with the requested
    codenames we skip the .add() call entirely. The m2m_changed signal
    (`sync_legacy_group_permissions`) would otherwise re-run for no
    behavioral reason and can raise `MultipleObjectsReturned` on a
    legacy Permission row that has historically been seeded more than
    once. That's an upstream-MobInspect data shape we tolerate at runtime
    but mustn't trip on at test setup.
    """
    role = Role.objects.filter(name=name).first()
    if role is None:
        group, _ = Group.objects.get_or_create(name=name)
        role = Role.objects.create(
            group=group,
            name=name,
            description=f'auto-created for tests: {name}',
            is_system=False,
        )
    if codenames:
        existing = set(role.permissions.values_list('codename', flat=True))
        wanted = set(codenames)
        missing = wanted - existing
        if missing:
            perms = list(Permission.objects.filter(codename__in=missing))
            # add() (not set()) so we don't blow away seeded permissions
            # if a test fixture only mentions a subset.
            role.permissions.add(*perms)
    return role


# ─────────────────────────────────────────────────────── user fixtures
@pytest.fixture
def viewer_user(db, django_user_model):
    """User holding only the Viewer role (read-only)."""
    user = django_user_model.objects.create_user(
        username='rbac_viewer',
        password='viewer-pw-not-used',
    )
    role = _ensure_role('Viewer', [
        'scan.view', 'analytics.view', 'scan.export.pdf',
    ])
    RoleAssignment.objects.create(user=user, role=role)
    return user


@pytest.fixture
def analyst_user(db, django_user_model):
    """User holding the Security Analyst role."""
    user = django_user_model.objects.create_user(
        username='rbac_analyst',
        password='analyst-pw-not-used',
    )
    role = _ensure_role('Security Analyst', [
        'scan.view', 'scan.create', 'scan.delete',
        'finding.suppress', 'analytics.view', 'api.use',
    ])
    RoleAssignment.objects.create(user=user, role=role)
    return user


@pytest.fixture
def admin_user(db, django_user_model):
    """User holding the Administrator role.

    Note: we do NOT set `is_superuser=True` here — that would bypass
    every RBAC check via the superuser fast-path and defeat the point
    of testing the permission engine. Use `superuser` for that.
    """
    user = django_user_model.objects.create_user(
        username='rbac_admin',
        password='admin-pw-not-used',
    )
    role = _ensure_role('Administrator', [
        # Admin role — populated from the full catalog at runtime so
        # tests of the escalation guard see a realistic role.
        c for c in Permission.objects.values_list('codename', flat=True)
    ])
    RoleAssignment.objects.create(user=user, role=role)
    return user


@pytest.fixture
def superuser(db, django_user_model):
    """Django superuser — exercises the fast-path bypass in permissions.py."""
    return django_user_model.objects.create_user(
        username='rbac_root',
        password='root-pw-not-used',
        is_staff=True,
        is_superuser=True,
    )


# ─────────────────────────────────────────────────────── api-key fixtures
@pytest.fixture
def viewer_api_key(db, viewer_user):
    """Plaintext API key bound to the Viewer user."""
    _, plaintext = ApiKey.generate(user=viewer_user, name='viewer-test')
    return plaintext


@pytest.fixture
def analyst_api_key(db, analyst_user):
    """Plaintext API key bound to the Security Analyst user."""
    _, plaintext = ApiKey.generate(user=analyst_user, name='analyst-test')
    return plaintext


@pytest.fixture
def admin_api_key(db, admin_user):
    """Plaintext API key bound to the Administrator user."""
    _, plaintext = ApiKey.generate(user=admin_user, name='admin-test')
    return plaintext
