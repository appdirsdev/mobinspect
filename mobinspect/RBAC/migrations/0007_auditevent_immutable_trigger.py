"""Database-level append-only enforcement for ``rbac_auditevent`` (H9).

The hash chain in :class:`mobinspect.RBAC.models.AuditEvent` is verifiable but
its tamper-evidence is much stronger if the database itself refuses to
mutate or delete rows. We install:

  * SQLite: BEFORE UPDATE / BEFORE DELETE triggers that ``RAISE(ABORT, …)``.
  * PostgreSQL: a trigger that ``RAISE EXCEPTION`` on UPDATE/DELETE.

Operators with direct DB access can still drop the trigger and rewrite
history, but doing so leaves the chain broken and ``manage.py audit_verify``
will report the gap on its next run. That is the security goal: detection,
not impossibility.

Trade-off note (intentional, see AUDIT.md → H9):
  ``actor_id`` is in the trigger's blocked column list. The FK is declared
  ``on_delete=SET_NULL``, so deleting a user that has audit history would
  ordinarily fire an UPDATE ``actor_id = NULL`` on every linked row — and
  the trigger will (correctly) refuse it. Operators that need to delete
  such a user should either:

    (a) re-attribute via a synthetic ``tombstone`` user with a known id, or
    (b) temporarily disable the trigger inside a maintenance transaction.

  Allowing arbitrary ``actor_id`` UPDATE silently would defeat the chain;
  the breakage is the warning that user-deletion needs an explicit policy.
"""
from django.db import migrations


# NOTE: Each entry below is ONE statement passed to cursor.execute().
# SQLite trigger bodies contain ``;`` inside ``BEGIN … END;`` and naive
# split-on-semicolon mangles them, so we keep the SQL as a Python list.
SQLITE_FORWARD_STMTS = [
    """CREATE TRIGGER IF NOT EXISTS no_audit_modify
BEFORE UPDATE OF actor_id, action, target_type, target_id, metadata,
                 occurred_at, prev_hash, current_hash
ON rbac_auditevent
BEGIN
    SELECT RAISE(ABORT, 'audit log is append-only');
END""",
    """CREATE TRIGGER IF NOT EXISTS no_audit_delete
BEFORE DELETE ON rbac_auditevent
BEGIN
    SELECT RAISE(ABORT, 'audit log is append-only');
END""",
]

SQLITE_REVERSE_STMTS = [
    'DROP TRIGGER IF EXISTS no_audit_modify',
    'DROP TRIGGER IF EXISTS no_audit_delete',
]

# Postgres equivalent. Implemented as a trigger because RULE-based DO
# INSTEAD NOTHING silently swallows the statement, which is the opposite
# of what we want (we want loud failure).
POSTGRES_FORWARD_STMTS = [
    """CREATE OR REPLACE FUNCTION rbac_auditevent_no_modify()
RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'audit log is append-only';
END;
$$ LANGUAGE plpgsql""",
    'DROP TRIGGER IF EXISTS no_audit_modify ON rbac_auditevent',
    """CREATE TRIGGER no_audit_modify
BEFORE UPDATE OF actor_id, action, target_type, target_id, metadata,
                 occurred_at, prev_hash, current_hash
ON rbac_auditevent
FOR EACH ROW EXECUTE FUNCTION rbac_auditevent_no_modify()""",
    'DROP TRIGGER IF EXISTS no_audit_delete ON rbac_auditevent',
    """CREATE TRIGGER no_audit_delete
BEFORE DELETE ON rbac_auditevent
FOR EACH ROW EXECUTE FUNCTION rbac_auditevent_no_modify()""",
]

POSTGRES_REVERSE_STMTS = [
    'DROP TRIGGER IF EXISTS no_audit_modify ON rbac_auditevent',
    'DROP TRIGGER IF EXISTS no_audit_delete ON rbac_auditevent',
    'DROP FUNCTION IF EXISTS rbac_auditevent_no_modify()',
]


def _run_stmts(schema_editor, stmts):
    """Run each statement one at a time through the engine cursor."""
    with schema_editor.connection.cursor() as cur:
        for stmt in stmts:
            cur.execute(stmt)


def _install_trigger(apps, schema_editor):
    vendor = schema_editor.connection.vendor
    if vendor == 'sqlite':
        stmts = SQLITE_FORWARD_STMTS
    elif vendor == 'postgresql':
        stmts = POSTGRES_FORWARD_STMTS
    else:
        # MySQL / Oracle: skip rather than silently install a wrong trigger.
        # The Python-level save() override still seals the chain, and
        # audit_verify still detects tampering on those engines.
        return
    _run_stmts(schema_editor, stmts)


def _drop_trigger(apps, schema_editor):
    vendor = schema_editor.connection.vendor
    if vendor == 'sqlite':
        stmts = SQLITE_REVERSE_STMTS
    elif vendor == 'postgresql':
        stmts = POSTGRES_REVERSE_STMTS
    else:
        return
    _run_stmts(schema_editor, stmts)


class Migration(migrations.Migration):

    dependencies = [('rbac', '0006_auditevent_hashchain')]

    operations = [
        migrations.RunPython(_install_trigger, _drop_trigger),
    ]
