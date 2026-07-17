"""
AuditEvent tamper-evidence (H9).

These tests pin four behaviors:

  * ``AuditEvent.save()`` seals each new row into a SHA-256 hash chain.
  * The chain detects in-place tampering — flipping a column on a row
    causes ``audit_verify`` to report a mismatch.
  * The DB-level append-only trigger (SQLite ``RAISE(ABORT, …)``) rejects
    UPDATE and DELETE on the protected columns.
  * The ``audit_verify`` management command exits 0 on a clean chain and
    non-zero on tampered or empty chains.

Why this matters: without the chain, a privileged operator could erase
or rewrite an audit row to hide actions they took. The hash chain makes
any such rewrite detectable on the next verify run.
"""
import hashlib
import io
import json

from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.db import connection, transaction
from django.test import TestCase

from mobinspect.RBAC.models import AuditEvent


class _ChainTestBase(TestCase):
    """Shared setUp: wipe any seeded audit rows via the test-only purge."""

    def setUp(self):
        AuditEvent._raw_purge_for_test()


class HashChainTests(_ChainTestBase):

    def test_first_row_has_empty_prev_hash(self):
        evt = AuditEvent.objects.create(action='test.first')
        self.assertEqual(evt.prev_hash, '')
        self.assertEqual(len(evt.current_hash), 64)

    def test_second_row_prev_hash_equals_first_current_hash(self):
        a = AuditEvent.objects.create(action='test.one')
        b = AuditEvent.objects.create(action='test.two')
        self.assertEqual(b.prev_hash, a.current_hash)
        self.assertNotEqual(a.current_hash, b.current_hash)

    def test_current_hash_is_deterministic_sha256_of_payload(self):
        evt = AuditEvent.objects.create(
            action='test.deterministic',
            target_type='thing',
            target_id='42',
            metadata={'k': 'v', 'a': 1},
        )
        expected = hashlib.sha256(
            ''.join((
                '',  # prev_hash for first row
                '',  # actor_id is None
                'test.deterministic',
                'thing',
                '42',
                json.dumps({'a': 1, 'k': 'v'}, sort_keys=True, default=str),
                evt.occurred_at.isoformat(),
            )).encode('utf-8'),
        ).hexdigest()
        self.assertEqual(evt.current_hash, expected)

    def test_metadata_ordering_does_not_affect_hash(self):
        # Identical payload posted in two different dict orders must
        # produce the same per-row hash (modulo prev_hash + occurred_at,
        # which we hold fixed by recomputing manually).
        a_hash = AuditEvent._compute_hash(
            '', None, 'x', '', '', {'a': 1, 'b': 2},
            __import__('datetime').datetime(2025, 1, 1),
        )
        b_hash = AuditEvent._compute_hash(
            '', None, 'x', '', '', {'b': 2, 'a': 1},
            __import__('datetime').datetime(2025, 1, 1),
        )
        self.assertEqual(a_hash, b_hash)

    def test_actor_id_is_part_of_hash(self):
        User = get_user_model()
        u = User.objects.create_user(username='chain_alice', password='x')
        a = AuditEvent.objects.create(action='same', actor=u)
        AuditEvent._raw_purge_for_test()
        b = AuditEvent.objects.create(action='same')
        # Different actor_id at the same chain position MUST produce a
        # different hash (proves actor is folded into the digest).
        self.assertNotEqual(a.current_hash, b.current_hash)


class AppendOnlyTriggerTests(_ChainTestBase):
    """SQLite RAISE(ABORT) trigger rejects mutation of the protected columns."""

    def test_update_of_protected_column_is_rejected(self):
        evt = AuditEvent.objects.create(action='cannot.change.me')
        # Use raw SQL — Django's QuerySet.update bypasses .save() but
        # still flows through the DB engine, so the trigger fires.
        with self.assertRaises(Exception) as ctx:
            with transaction.atomic():
                AuditEvent.objects.filter(pk=evt.pk).update(
                    action='changed',
                )
        self.assertIn('append-only', str(ctx.exception).lower())

    def test_delete_is_rejected(self):
        evt = AuditEvent.objects.create(action='cannot.delete.me')
        with self.assertRaises(Exception) as ctx:
            with transaction.atomic():
                AuditEvent.objects.filter(pk=evt.pk).delete()
        self.assertIn('append-only', str(ctx.exception).lower())
        # Row is still there.
        self.assertTrue(
            AuditEvent.objects.filter(pk=evt.pk).exists(),
        )

    def test_raw_purge_helper_works_for_tests(self):
        # The escape hatch must be functional, otherwise other test
        # fixtures cannot reset between cases.
        AuditEvent.objects.create(action='x')
        AuditEvent.objects.create(action='y')
        AuditEvent._raw_purge_for_test()
        self.assertEqual(AuditEvent.objects.count(), 0)
        # And the trigger has been reinstalled.
        evt = AuditEvent.objects.create(action='after.purge')
        with self.assertRaises(Exception):
            with transaction.atomic():
                AuditEvent.objects.filter(pk=evt.pk).delete()


class AuditVerifyCommandTests(_ChainTestBase):

    def _run(self, *args):
        out = io.StringIO()
        err = io.StringIO()
        code = 0
        try:
            call_command('audit_verify', *args, stdout=out, stderr=err)
        except SystemExit as e:
            code = e.code
        return code, out.getvalue(), err.getvalue()

    def test_clean_chain_exits_zero(self):
        for i in range(3):
            AuditEvent.objects.create(action=f'evt.{i}')
        code, out, _ = self._run()
        self.assertEqual(code, 0)
        self.assertIn('3 rows OK', out)

    def test_empty_table_exits_two_by_default(self):
        code, _, err = self._run()
        self.assertEqual(code, 2)
        self.assertIn('empty', err.lower())

    def test_empty_table_with_allow_empty_exits_zero(self):
        code, out, _ = self._run('--allow-empty')
        self.assertEqual(code, 0)
        self.assertIn('empty', out.lower())

    def test_tampered_row_is_detected(self):
        AuditEvent.objects.create(action='untouched.1')
        target = AuditEvent.objects.create(action='will.be.tampered')
        AuditEvent.objects.create(action='untouched.2')

        # Bypass the trigger to simulate an attacker with raw DB access.
        with connection.cursor() as cur:
            if connection.vendor == 'postgresql':
                # Postgres refuses ALTER TABLE ... DISABLE TRIGGER while the
                # transaction has pending (deferred FK) trigger events, so
                # flush them first, then disable/re-enable around the write.
                cur.execute('SET CONSTRAINTS ALL IMMEDIATE')
                cur.execute(
                    'ALTER TABLE rbac_auditevent '
                    'DISABLE TRIGGER no_audit_modify')
                cur.execute(
                    'UPDATE rbac_auditevent SET action = %s WHERE id = %s',
                    ['silently.rewritten', target.pk],
                )
                cur.execute(
                    'ALTER TABLE rbac_auditevent '
                    'ENABLE TRIGGER no_audit_modify')
            else:
                cur.execute('DROP TRIGGER IF EXISTS no_audit_modify')
                cur.execute(
                    'UPDATE rbac_auditevent SET action = %s WHERE id = %s',
                    ['silently.rewritten', target.pk],
                )
                # Reinstall so other tests still see the protection.
                cur.execute(
                    'CREATE TRIGGER IF NOT EXISTS no_audit_modify '
                    'BEFORE UPDATE OF actor_id, action, target_type, '
                    'target_id, metadata, occurred_at, prev_hash, '
                    'current_hash ON rbac_auditevent '
                    "BEGIN SELECT RAISE(ABORT, "
                    "'audit log is append-only'); END;",
                )

        code, out, err = self._run()
        self.assertEqual(code, 1)
        combined = out + err
        self.assertIn('current_hash mismatch', combined)
        # The downstream row's prev_hash still matches stored, so the
        # mismatch is localized — verify only ONE row was flagged.
        self.assertIn('1 of 3 rows', err)

    def test_limit_walks_only_recent_window(self):
        for i in range(5):
            AuditEvent.objects.create(action=f'evt.{i}')
        code, out, _ = self._run('--limit', '2')
        self.assertEqual(code, 0)
        self.assertIn('2 rows OK', out)
