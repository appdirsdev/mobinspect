"""MobInspect — RBAC forms."""
import re

from django import forms
from django.utils import timezone

from mobinspect.RBAC.models import (
    ApiKey,
    Permission,
    Role,
)
from mobinspect.RBAC.permissions import get_user_permissions


HEX_COLOR_RE = re.compile(r'^#[0-9A-Fa-f]{6}$')


class RoleForm(forms.ModelForm):
    """Create / edit a Role.

    Pass `actor=request.user` so we can cap the granted permissions to
    permissions the actor already holds (no privilege escalation by
    editing a role whose codename you don't possess).

    System roles disallow editing the name; the view + this form both
    enforce that.
    """

    permission_codenames = forms.CharField(
        required=False, widget=forms.HiddenInput,
        help_text='Comma-separated permission codenames.',
    )

    class Meta:
        model = Role
        fields = ('name', 'description', 'color', 'icon')
        widgets = {
            'description': forms.Textarea(attrs={'rows': 3, 'class': 'input'}),
        }

    def __init__(self, *args, actor=None, **kwargs):
        self.actor = actor
        super().__init__(*args, **kwargs)
        for f in self.fields.values():
            css = f.widget.attrs.get('class', '')
            if 'input' not in css:
                f.widget.attrs['class'] = (css + ' input').strip()

    # ── field cleaners
    def clean_color(self):
        v = self.cleaned_data.get('color') or Role.DEFAULT_COLOR
        if not HEX_COLOR_RE.match(v):
            raise forms.ValidationError('Color must be a hex like #2563EB.')
        return v

    def clean_icon(self):
        v = (self.cleaned_data.get('icon') or Role.DEFAULT_ICON).strip()
        # Restrict to slug-shaped icon names from the curated catalog.
        if not re.match(r'^[a-z0-9-]{1,40}$', v):
            raise forms.ValidationError('Invalid icon name.')
        return v

    def clean_name(self):
        v = (self.cleaned_data.get('name') or '').strip()
        # Block renaming a system role, regardless of what the form posts.
        if self.instance.pk and self.instance.is_system:
            return self.instance.name
        if not v:
            raise forms.ValidationError('Name is required.')
        # On CREATE, refuse a name that collides with an existing Django
        # Group. save() does Group.get_or_create(name=...), which would
        # otherwise silently adopt that group's members and let
        # sync_legacy_group_permissions overwrite its curated permissions
        # (e.g. the legacy 'Maintainer'/'Viewer' groups or a SAML-synced
        # group). Fail closed instead.
        if self.instance.pk is None:
            from django.contrib.auth.models import Group
            if Group.objects.filter(name=v).exists():
                raise forms.ValidationError(
                    f'A group named "{v}" already exists. Choose a different '
                    f'role name so its members and permissions are not adopted.',
                )
        return v

    def clean_permission_codenames(self):
        raw = self.cleaned_data.get('permission_codenames', '') or ''
        codes = [c.strip() for c in raw.split(',') if c.strip()]
        if not codes:
            return []
        # Sanity check: limit to plausible slug-dot characters.
        for c in codes:
            if not re.match(r'^[a-z0-9_.\-]{1,100}$', c):
                raise forms.ValidationError(f'Invalid codename: {c!r}')

        valid = set(
            Permission.objects.filter(codename__in=codes)
            .values_list('codename', flat=True),
        )
        unknown = set(codes) - valid
        if unknown:
            raise forms.ValidationError(
                f'Unknown permission codenames: {", ".join(sorted(unknown))}',
            )

        # Cap to permissions the ACTOR holds — prevents privilege escalation
        # via editing roles. Superusers escape this check.
        if self.actor is not None and not getattr(self.actor, 'is_superuser', False):
            actor_perms = get_user_permissions(self.actor)
            elevated = set(codes) - actor_perms
            if elevated:
                raise forms.ValidationError(
                    f'You cannot grant permissions you do not hold: '
                    f'{", ".join(sorted(elevated))}',
                )

        return codes

    def save(self, commit=True):
        # The wrapped Group is required at create time.
        if self.instance.pk is None:
            from django.contrib.auth.models import Group
            grp, _ = Group.objects.get_or_create(name=self.cleaned_data['name'])
            self.instance.group = grp

        role = super().save(commit=commit)

        if commit:
            codes = self.cleaned_data.get('permission_codenames') or []
            role.permissions.set(
                Permission.objects.filter(codename__in=codes),
            )
        return role


class RoleAssignmentForm(forms.Form):
    """Assign a role to a user."""
    user_id = forms.IntegerField(min_value=1, widget=forms.HiddenInput)
    role_id = forms.IntegerField(min_value=1, widget=forms.HiddenInput)
    expires_at = forms.DateTimeField(
        required=False,
        widget=forms.DateTimeInput(
            attrs={'type': 'datetime-local', 'class': 'input'},
        ),
    )


class ApiKeyForm(forms.Form):
    """Create a new API key."""
    name = forms.CharField(
        max_length=80,
        widget=forms.TextInput(attrs={
            'class': 'input',
            'placeholder': 'e.g. ci-pipeline',
            'autocomplete': 'off',
        }),
    )
    expires_in_days = forms.IntegerField(
        required=False,
        min_value=1, max_value=3650,
        widget=forms.NumberInput(attrs={
            'class': 'input',
            'placeholder': 'leave blank for never',
        }),
    )

    def expires_at(self):
        days = self.cleaned_data.get('expires_in_days')
        if not days:
            return None
        return timezone.now() + timezone.timedelta(days=days)


def all_permissions_grouped():
    """Return permissions ordered & grouped by category for the matrix UI."""
    from collections import OrderedDict
    grouped = OrderedDict()
    for p in Permission.objects.all().order_by('category', 'codename'):
        grouped.setdefault(p.category, []).append(p)
    return grouped
