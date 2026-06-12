"""Add tamper-evident hash-chain columns to AuditEvent (H9).

Backfill of ``current_hash`` / ``prev_hash`` for rows that already exist
when the migration runs. New rows produced by Python code go through
``AuditEvent.save()`` which seals the chain; this data migration recreates
the same chain for pre-existing history so ``audit_verify`` does not
flag the entire historical table as broken on the first run.

Also flips ``occurred_at`` from ``auto_now_add=True`` to
``default=timezone.now``. Rationale: ``auto_now_add`` overwrites whatever
value the model has in pre_save, which means our ``save()`` override
cannot reliably fold the final timestamp into the hash. Switching to a
default lets save() seal the value before passing it to the engine.
"""
import hashlib
import json

import django.utils.timezone
from django.db import migrations, models


def _compute_hash(prev_hash, actor_id, action, target_type,
                  target_id, metadata, occurred_at):
    payload = ''.join((
        prev_hash or '',
        '' if actor_id is None else str(actor_id),
        action or '',
        target_type or '',
        target_id or '',
        json.dumps(metadata or {}, sort_keys=True, default=str),
        occurred_at.isoformat() if occurred_at else '',
    ))
    return hashlib.sha256(payload.encode('utf-8')).hexdigest()


def backfill_chain(apps, schema_editor):
    AuditEvent = apps.get_model('rbac', 'AuditEvent')
    prev_hash = ''
    # Walk in insertion order (id ascending == chronological for AutoField).
    qs = AuditEvent.objects.order_by('id').only(
        'id', 'actor_id', 'action', 'target_type', 'target_id',
        'metadata', 'occurred_at',
    )
    for evt in qs.iterator():
        current = _compute_hash(
            prev_hash,
            evt.actor_id,
            evt.action,
            evt.target_type,
            evt.target_id,
            evt.metadata,
            evt.occurred_at,
        )
        AuditEvent.objects.filter(pk=evt.pk).update(
            prev_hash=prev_hash,
            current_hash=current,
        )
        prev_hash = current


def clear_chain(apps, schema_editor):
    # Reverse is a best-effort no-op: drop the values so the columns can
    # be removed cleanly.
    AuditEvent = apps.get_model('rbac', 'AuditEvent')
    AuditEvent.objects.update(prev_hash='', current_hash='')


class Migration(migrations.Migration):

    dependencies = [('rbac', '0005_add_dynamic_adb_shell')]

    operations = [
        migrations.AddField(
            model_name='auditevent',
            name='prev_hash',
            field=models.CharField(blank=True, default='', max_length=64),
        ),
        migrations.AddField(
            model_name='auditevent',
            name='current_hash',
            field=models.CharField(blank=True, default='', max_length=64),
        ),
        migrations.AlterField(
            model_name='auditevent',
            name='occurred_at',
            field=models.DateTimeField(
                db_index=True,
                default=django.utils.timezone.now,
            ),
        ),
        migrations.RunPython(backfill_chain, clear_chain),
    ]
