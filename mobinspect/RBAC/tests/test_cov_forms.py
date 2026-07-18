"""Real-execution coverage tests for mobinspect/RBAC/forms.py.

STRICT: no mocks. Instantiates the real Django forms with real POST-shaped
data dicts and real ORM rows (Group/Role/Permission), calling the genuine
`is_valid()` / `clean_*()` validation machinery.
"""
import pytest

from django import forms as django_forms
from django.contrib.auth.models import Group
from django.utils import timezone

from mobinspect.RBAC.forms import ApiKeyForm, RoleForm
from mobinspect.RBAC.models import Permission, Role


pytestmark = pytest.mark.django_db


def _valid_base():
    return {
        'name': 'CovFormRole',
        'description': '',
        'color': '#2563EB',
        'icon': 'shield',
        'permission_codenames': '',
    }


# ─────────────────────────────────────────────────────── clean_color
def test_clean_color_invalid_hex_rejected():
    data = _valid_base()
    # Exactly 7 chars (fits max_length=7) but not '#' + 6 hex digits, so
    # this reaches clean_color()'s own regex check rather than tripping
    # the field's max_length validator first.
    data['color'] = '#GGGGGG'
    form = RoleForm(data=data)
    assert not form.is_valid()
    assert 'color' in form.errors
    assert 'hex' in str(form.errors['color'])


def test_clean_color_valid_hex_accepted():
    form = RoleForm(data=_valid_base())
    assert form.is_valid(), form.errors


# ─────────────────────────────────────────────────────── clean_icon
def test_clean_icon_invalid_name_rejected():
    data = _valid_base()
    data['icon'] = 'Not A Valid Icon!'
    form = RoleForm(data=data)
    assert not form.is_valid()
    assert 'icon' in form.errors
    assert 'Invalid icon name' in str(form.errors['icon'])


# ─────────────────────────────────────────────────────── clean_name
def test_clean_name_system_role_locked_ignores_posted_rename():
    group, _ = Group.objects.get_or_create(name='CovLockedSystemRole')
    role = Role.objects.create(
        group=group, name='CovLockedSystemRole', is_system=True)
    data = _valid_base()
    data['name'] = 'AttemptedNewName'
    form = RoleForm(data=data, instance=role)
    assert form.is_valid(), form.errors
    # clean_name() silently discards the posted rename for a system role.
    assert form.cleaned_data['name'] == 'CovLockedSystemRole'


def test_clean_name_empty_raises_defensive_guard():
    """The model field itself is required (blank=False), so Django's
    field-level required check normally intercepts an empty name before
    clean_name() ever runs. This exercises the defense-in-depth guard
    directly, the same way sibling coverage tests exercise other
    guards that are unreachable through the ordinary validation path."""
    form = RoleForm(data=_valid_base())
    form.instance = Role(pk=None)
    form.cleaned_data = {'name': ''}
    with pytest.raises(django_forms.ValidationError):
        form.clean_name()


def test_clean_name_collides_with_existing_group_rejected():
    Group.objects.get_or_create(name='CovCollisionGroup')
    data = _valid_base()
    data['name'] = 'CovCollisionGroup'
    form = RoleForm(data=data)  # instance.pk is None -> CREATE path
    assert not form.is_valid()
    assert 'name' in form.errors
    assert 'already exists' in str(form.errors['name'])


def test_clean_name_no_collision_on_edit_of_existing_role():
    """The Group-collision guard is CREATE-only (instance.pk is None);
    editing an existing role whose own group already carries that name
    must not trip the guard."""
    group, _ = Group.objects.get_or_create(name='CovEditNoCollide')
    role = Role.objects.create(group=group, name='CovEditNoCollide')
    data = _valid_base()
    data['name'] = 'CovEditNoCollide'
    form = RoleForm(data=data, instance=role)
    assert form.is_valid(), form.errors


# ─────────────────────────────────────────────────────── clean_permission_codenames
def test_clean_permission_codenames_invalid_char_rejected():
    data = _valid_base()
    data['permission_codenames'] = 'scan.view,Bad Codename!'
    form = RoleForm(data=data)
    assert not form.is_valid()
    assert 'permission_codenames' in form.errors
    assert 'Invalid codename' in str(form.errors['permission_codenames'])


def test_clean_permission_codenames_unknown_rejected():
    data = _valid_base()
    data['permission_codenames'] = 'totally.unknown.codename'
    form = RoleForm(data=data)
    assert not form.is_valid()
    assert 'permission_codenames' in form.errors
    assert 'Unknown permission' in str(form.errors['permission_codenames'])


def test_clean_permission_codenames_valid_accepted():
    codename = Permission.objects.first().codename
    data = _valid_base()
    data['permission_codenames'] = codename
    form = RoleForm(data=data)
    assert form.is_valid(), form.errors
    assert form.cleaned_data['permission_codenames'] == [codename]


def test_clean_permission_codenames_actor_escalation_blocked(viewer_user):
    """A non-superuser actor cannot grant a codename they do not hold."""
    dangerous = Permission.objects.filter(is_dangerous=True).first()
    assert dangerous is not None
    data = _valid_base()
    data['permission_codenames'] = dangerous.codename
    form = RoleForm(data=data, actor=viewer_user)
    assert not form.is_valid()
    assert 'cannot grant permissions you do not hold' in str(
        form.errors['permission_codenames'])


def test_clean_permission_codenames_superuser_actor_escapes_cap(superuser):
    dangerous = Permission.objects.filter(is_dangerous=True).first()
    data = _valid_base()
    data['permission_codenames'] = dangerous.codename
    form = RoleForm(data=data, actor=superuser)
    assert form.is_valid(), form.errors


# ─────────────────────────────────────────────────────── ApiKeyForm.expires_at
def test_expires_at_returns_none_when_days_blank():
    form = ApiKeyForm(data={'name': 'cov-key-no-expiry'})
    assert form.is_valid(), form.errors
    assert form.expires_at() is None


def test_expires_at_returns_future_datetime_when_days_given():
    form = ApiKeyForm(data={'name': 'cov-key-expiry', 'expires_in_days': '30'})
    assert form.is_valid(), form.errors
    dt = form.expires_at()
    assert dt is not None
    assert dt > timezone.now()
