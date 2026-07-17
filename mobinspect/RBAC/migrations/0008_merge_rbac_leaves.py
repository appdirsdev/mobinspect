"""Reconcile the two ``rbac`` migration leaves into a single graph head.

Two migrations both descended from ``0004_migrate_existing_users``:

  * ``0005_alter_apikey_id_alter_auditevent_id_and_more`` — the auto-generated
    cosmetic ``id`` field pin (Django 6 ``verbose_name='ID'``).
  * the hand-written audit branch
    ``0005_add_dynamic_adb_shell`` -> ``0006_auditevent_hashchain`` ->
    ``0007_auditevent_immutable_trigger``.

With two leaves, ``manage.py migrate`` aborts with "conflicting migrations".
This empty merge migration joins both leaves so the graph has one head again;
it issues no operations. Databases that already applied either branch advance
straight to this node.
"""
from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('rbac', '0005_alter_apikey_id_alter_auditevent_id_and_more'),
        ('rbac', '0007_auditevent_immutable_trigger'),
    ]

    operations = [
    ]
