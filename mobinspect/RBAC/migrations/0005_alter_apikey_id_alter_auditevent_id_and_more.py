"""Pin the auto-created ``id`` primary keys to ``AutoField`` (no-op SQL).

Django 6.0 began emitting ``verbose_name='ID'`` on the implicit primary-key
field that every model gets from ``DEFAULT_AUTO_FIELD``. The hand-written
``0001_initial`` predates that and omitted the ``verbose_name``, so
``makemigrations`` kept proposing an ``AlterField`` on every ``id`` column on
each run. This migration captures that purely cosmetic state difference once
so the migration graph matches the models again.

It is a metadata-only change: ``AutoField`` -> ``AutoField`` with the same
column type, so no DDL is issued against the database. It exists as a sibling
of ``0005_add_dynamic_adb_shell`` (both descend from ``0004``); the two leaves
are reconciled by the ``0008_merge_*`` migration. Deployed databases that have
already recorded this migration treat it as applied and only run the merge and
the audit hash-chain branch on top.
"""
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('rbac', '0004_migrate_existing_users'),
    ]

    operations = [
        migrations.AlterField(
            model_name='apikey',
            name='id',
            field=models.AutoField(
                auto_created=True, primary_key=True,
                serialize=False, verbose_name='ID',
            ),
        ),
        migrations.AlterField(
            model_name='auditevent',
            name='id',
            field=models.AutoField(
                auto_created=True, primary_key=True,
                serialize=False, verbose_name='ID',
            ),
        ),
        migrations.AlterField(
            model_name='permission',
            name='id',
            field=models.AutoField(
                auto_created=True, primary_key=True,
                serialize=False, verbose_name='ID',
            ),
        ),
        migrations.AlterField(
            model_name='role',
            name='id',
            field=models.AutoField(
                auto_created=True, primary_key=True,
                serialize=False, verbose_name='ID',
            ),
        ),
        migrations.AlterField(
            model_name='roleassignment',
            name='id',
            field=models.AutoField(
                auto_created=True, primary_key=True,
                serialize=False, verbose_name='ID',
            ),
        ),
    ]
