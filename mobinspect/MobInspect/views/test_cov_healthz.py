# -*- coding: utf_8 -*-
"""Real-execution coverage tests for mobinspect.MobInspect.views.healthz.

Real DB / real django_q import / real (host-dependent) adb probe are
exercised directly wherever practical. A few branches genuinely require a
live DB outage, a broken django_q install, or specific `adb devices` output
that cannot be induced from application code without real hardware/an
actually-broken environment -- for those we use narrow, single-call
monkeypatches (of `connection.cursor`, `sys.modules['django_q.models']`,
`get_adb`, and `subprocess.check_output`), each documented inline. This
mirrors the existing `RecentScansDB.objects.filter` monkeypatch pattern
already used in test_cov_home.py's `test_never_raises_on_unexpected_error`.

The view-level status-derivation tests (ok/degraded/failed -> the right
HTTP status) patch the three already-unit-tested `_check_*` helpers
directly, since exhaustively exercising every real DB+queue+adb combination
would require actually breaking multiple real subsystems at once; a
genuine, unmocked end-to-end call is included separately.
"""
import subprocess
import sys
from unittest import mock

from django.db import connection
from django.test import Client, TestCase, override_settings

from mobinspect.MobInspect.views import healthz


class CheckDbTests(TestCase):
    """_check_db: real Postgres test-DB probe + a genuine failure branch."""

    def test_real_db_probe_succeeds(self):
        self.assertTrue(healthz._check_db())

    def test_db_probe_exception_is_caught(self):
        # Narrow monkeypatch of a single call (connection.cursor) -- a real
        # DB outage cannot be induced against the live Postgres test DB from
        # application code.
        with mock.patch.object(
                connection, 'cursor', side_effect=RuntimeError('db down')):
            self.assertFalse(healthz._check_db())


class CheckQueueTests(TestCase):
    """_check_queue: real django_q Schedule table probe + import failure."""

    def test_real_queue_probe_succeeds(self):
        self.assertTrue(healthz._check_queue())

    def test_queue_probe_import_failure_is_caught(self):
        # Real fault injection: poison sys.modules so the real `from
        # django_q.models import Schedule` statement inside the function
        # raises ImportError -- not a return-value mock.
        target = 'django_q.models'
        prev = sys.modules.get(target, False)
        sys.modules[target] = None
        try:
            self.assertFalse(healthz._check_queue())
        finally:
            if prev is False:
                sys.modules.pop(target, None)
            else:
                sys.modules[target] = prev


class CheckAdbTests(TestCase):
    """_check_adb: every branch, deterministic regardless of whether THIS
    host happens to have a real adb binary or an attached device (both of
    which vary by CI machine)."""

    def test_no_adb_binary_returns_false(self):
        with mock.patch.object(healthz, 'get_adb', return_value=None):
            self.assertFalse(healthz._check_adb())

    def test_adb_present_no_devices_returns_false(self):
        output = b'List of devices attached\n\n'
        with mock.patch.object(
                healthz, 'get_adb', return_value='/usr/bin/adb'), \
                mock.patch.object(
                    subprocess, 'check_output', return_value=output):
            self.assertFalse(healthz._check_adb())

    def test_adb_present_with_device_returns_true(self):
        output = b'List of devices attached\nemulator-5554\tdevice\n'
        with mock.patch.object(
                healthz, 'get_adb', return_value='/usr/bin/adb'), \
                mock.patch.object(
                    subprocess, 'check_output', return_value=output):
            self.assertTrue(healthz._check_adb())

    def test_adb_present_offline_device_not_counted(self):
        output = b'List of devices attached\nemulator-5554\toffline\n'
        with mock.patch.object(
                healthz, 'get_adb', return_value='/usr/bin/adb'), \
                mock.patch.object(
                    subprocess, 'check_output', return_value=output):
            self.assertFalse(healthz._check_adb())

    def test_adb_command_failure_is_caught(self):
        with mock.patch.object(
                healthz, 'get_adb', return_value='/usr/bin/adb'), \
                mock.patch.object(
                    subprocess, 'check_output',
                    side_effect=subprocess.TimeoutExpired(
                        cmd='adb', timeout=2)):
            self.assertFalse(healthz._check_adb())

    def test_real_adb_probe_never_raises(self):
        # Genuine, unmocked call against whatever this host actually has
        # (adb installed or not, device attached or not) -- must never
        # raise and must return a plain bool.
        self.assertIn(healthz._check_adb(), (True, False))


@override_settings(RATELIMIT_ENABLE=False)
class HealthzViewTests(TestCase):
    """healthz()/readyz(): status derivation, HTTP status mapping, method
    guard. The three `_check_*` probes are unit-tested above in isolation;
    here we patch them directly to exercise every ok/degraded/failed
    combination deterministically, plus one fully real end-to-end call."""

    def setUp(self):
        self.client = Client()

    def _get(self, db, queue, adb):
        with mock.patch.object(healthz, '_check_db', return_value=db), \
                mock.patch.object(
                    healthz, '_check_queue', return_value=queue), \
                mock.patch.object(
                    healthz, '_check_adb', return_value=adb):
            return self.client.get('/healthz')

    def test_all_ok_returns_200(self):
        resp = self._get(True, True, True)
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertEqual(body['status'], 'ok')
        self.assertTrue(body['db'])
        self.assertTrue(body['queue'])
        self.assertTrue(body['adb'])
        self.assertIn('version', body)
        self.assertIn('now', body)

    def test_db_down_returns_503_failed(self):
        resp = self._get(False, True, True)
        self.assertEqual(resp.status_code, 503)
        self.assertEqual(resp.json()['status'], 'failed')

    def test_db_down_beats_queue_and_adb_also_down(self):
        # DB failure must win over queue/adb also being down (still
        # 'failed', not 'degraded').
        resp = self._get(False, False, False)
        self.assertEqual(resp.status_code, 503)
        self.assertEqual(resp.json()['status'], 'failed')

    def test_queue_down_returns_200_degraded(self):
        resp = self._get(True, False, True)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()['status'], 'degraded')

    def test_adb_down_returns_200_degraded(self):
        resp = self._get(True, True, False)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()['status'], 'degraded')

    def test_real_end_to_end_no_mocks(self):
        # A genuinely real call (real DB, real django_q import, real
        # host-dependent adb probe) -- must never 500, and must report a
        # real, well-formed status.
        resp = self.client.get('/healthz')
        self.assertIn(resp.status_code, (200, 503))
        self.assertIn(resp.json()['status'], ('ok', 'degraded', 'failed'))

    def test_post_method_not_allowed(self):
        resp = self.client.post('/healthz')
        self.assertEqual(resp.status_code, 405)

    def test_readyz_returns_ok(self):
        resp = self.client.get('/readyz')
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json(), {'status': 'ok'})

    def test_readyz_post_method_not_allowed(self):
        resp = self.client.post('/readyz')
        self.assertEqual(resp.status_code, 405)
