"""Recolor two default system roles off the severity palette.

The original seed gave 'Administrator' the critical-severity red (#DC2626)
and 'API User' the passed-severity green (#16A34A). Those hexes are reserved
for finding severity elsewhere in the UI, so as role identity accents they
read as "danger" / "good" rather than as a role. Remap them onto the brand
duotone — violet for the all-access Administrator, amber for the programmatic
API User — leaving Security Analyst (blue) and Viewer (slate) untouched.

Only rewrites a role that still holds the old seed color, so an operator who
has since customised a role's color keeps their choice.
"""
from django.db import migrations


RECOLOR = [
    # (role name, old seed color, new brand color)
    ('Administrator', '#DC2626', '#8D5CFC'),  # critical-red → brand violet
    ('API User',      '#16A34A', '#FE4A23'),  # passed-green → brand amber
]


def _apply(apps, forward):
    Role = apps.get_model('rbac', 'Role')
    for name, old, new in RECOLOR:
        frm, to = (old, new) if forward else (new, old)
        Role.objects.filter(name=name, color=frm).update(color=to)


def recolor(apps, schema_editor):
    _apply(apps, forward=True)


def restore(apps, schema_editor):
    _apply(apps, forward=False)


class Migration(migrations.Migration):

    dependencies = [
        ('rbac', '0012_modelintegration_role_and_more'),
    ]

    operations = [
        migrations.RunPython(recolor, restore),
    ]
