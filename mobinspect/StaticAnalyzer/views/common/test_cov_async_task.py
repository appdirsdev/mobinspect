# -*- coding: utf_8 -*-
"""Real-execution unit tests for common/async_task.py (STRICT: NO mocks).

Everything drives the real functions with real Django ORM rows
(EnqueuedTask / RecentScansDB), a real superuser, real RequestFactory
requests and the real django_q ORM broker (queue=True enqueues an OrmQ
row in the test DB, it is never executed by a worker).
"""
import json
from datetime import timedelta

from django.test import TestCase, RequestFactory, override_settings
from django.contrib.auth.models import User
from django.utils import timezone
from django.http import HttpResponseRedirect, JsonResponse
from django.conf import settings

from mobinspect.StaticAnalyzer.models import (
    EnqueuedTask,
    RecentScansDB,
)
from mobinspect.StaticAnalyzer.views.common.async_task import (
    async_analysis,
    detect_timeout,
    get_live_status,
    list_tasks,
    mark_task_completed,
    mark_task_started,
)

CHK = 'a' * 32


def _real_scan_func(*args, **kwargs):
    """A real, importable, module-level callable used as the async func."""
    return {'checksum': args[0] if args else None, 'ok': True}


def _raising_scan_func(*args, **kwargs):
    """A real callable that raises when executed."""
    raise ValueError('boom')


class DetectTimeoutTests(TestCase):
    """post_execute signal receiver detect_timeout."""

    def test_timeout_marks_task_failed(self):
        EnqueuedTask.objects.create(
            task_id='t-timeout', checksum=CHK, file_name='a.apk')
        task = {
            'id': 't-timeout',
            'result': 'Task exceeded maximum timeout of 3600 seconds',
        }
        detect_timeout(sender=None, task=task)
        row = EnqueuedTask.objects.get(task_id='t-timeout')
        self.assertEqual(row.app_name, 'Failed')
        self.assertEqual(row.status, 'Scan Timeout')
        self.assertIsNotNone(row.completed_at)

    def test_non_timeout_result_is_ignored(self):
        EnqueuedTask.objects.create(
            task_id='t-ok', checksum=CHK, file_name='a.apk')
        detect_timeout(sender=None, task={'id': 't-ok', 'result': 'all good'})
        row = EnqueuedTask.objects.get(task_id='t-ok')
        self.assertNotEqual(row.app_name, 'Failed')
        self.assertNotEqual(row.status, 'Scan Timeout')

    def test_non_string_result_is_ignored(self):
        detect_timeout(sender=None, task={'id': 'x', 'result': {'k': 'v'}})
        detect_timeout(sender=None, task={'id': 'x', 'result': None})
        self.assertFalse(
            EnqueuedTask.objects.filter(app_name='Failed').exists())


class MarkTaskTests(TestCase):

    def test_mark_task_started(self):
        EnqueuedTask.objects.create(
            task_id='s1', checksum=CHK, file_name='a.apk')
        EnqueuedTask.objects.create(
            task_id='s2', checksum=CHK, file_name='b.apk')
        self.assertIsNone(EnqueuedTask.objects.get(task_id='s1').started_at)
        mark_task_started(CHK)
        # All rows with the checksum get started_at set.
        for tid in ('s1', 's2'):
            self.assertIsNotNone(
                EnqueuedTask.objects.get(task_id=tid).started_at)

    def test_mark_task_completed(self):
        EnqueuedTask.objects.create(
            task_id='c1', checksum=CHK, file_name='a.apk')
        ret = mark_task_completed(CHK, 'MyApp', 'Success')
        self.assertTrue(ret)
        row = EnqueuedTask.objects.get(task_id='c1')
        self.assertEqual(row.app_name, 'MyApp')
        self.assertEqual(row.status, 'Success')
        self.assertIsNotNone(row.completed_at)

    def test_mark_task_completed_truncates_long_values(self):
        EnqueuedTask.objects.create(
            task_id='c2', checksum=CHK, file_name='a.apk')
        mark_task_completed(CHK, 'A' * 300, 'S' * 300)
        row = EnqueuedTask.objects.get(task_id='c2')
        self.assertEqual(len(row.app_name), 254)
        self.assertEqual(len(row.status), 254)


class GetLiveStatusTests(TestCase):

    def test_success_status_returned_directly(self):
        enq = EnqueuedTask.objects.create(
            task_id='g1', checksum=CHK, file_name='a.apk', status='Success')
        self.assertEqual(get_live_status(enq), 'Success')

    def test_failed_app_name_returns_status(self):
        enq = EnqueuedTask.objects.create(
            task_id='g2', checksum=CHK, file_name='a.apk',
            app_name='Failed', status='Some Error')
        self.assertEqual(get_live_status(enq), 'Some Error')

    def test_live_status_from_scan_logs(self):
        # Real RecentScansDB row with real SCAN_LOGS list.
        RecentScansDB.objects.create(
            MD5=CHK,
            APP_NAME='',
            PACKAGE_NAME='',
            SCAN_LOGS=str([
                {'timestamp': '2026-07-04 00:00:00',
                 'status': 'Extracting APK', 'exception': None},
                {'timestamp': '2026-07-04 00:00:01',
                 'status': 'Parsing Manifest', 'exception': None},
            ]),
        )
        enq = EnqueuedTask.objects.create(
            task_id='g3', checksum=CHK, file_name='a.apk', status='Enqueued')
        self.assertEqual(get_live_status(enq), 'Parsing Manifest')

    def test_live_status_falls_back_when_no_logs(self):
        # No RecentScansDB row -> get_scan_logs returns None -> fallback.
        enq = EnqueuedTask.objects.create(
            task_id='g4', checksum='f' * 32, file_name='a.apk',
            status='Enqueued')
        self.assertEqual(get_live_status(enq), 'Enqueued')


class AsyncAnalysisDuplicateTests(TestCase):
    """Early-return / dedup branches (no enqueue happens)."""

    def test_completed_recently_api(self):
        RecentScansDB.objects.create(
            MD5=CHK, APP_NAME='DoneApp', PACKAGE_NAME='com.x')
        EnqueuedTask.objects.create(
            task_id='d1', checksum=CHK, file_name='a.apk',
            completed_at=timezone.now())
        res = async_analysis(CHK, True, 'a.apk', _real_scan_func, CHK)
        self.assertIsInstance(res, dict)
        self.assertIsNone(res['task_id'])
        self.assertIn('already completed', res['message'])

    def test_completed_recently_web_redirect(self):
        RecentScansDB.objects.create(
            MD5=CHK, APP_NAME='DoneApp', PACKAGE_NAME='com.x')
        EnqueuedTask.objects.create(
            task_id='d2', checksum=CHK, file_name='a.apk',
            completed_at=timezone.now())
        res = async_analysis(CHK, False, 'a.apk', _real_scan_func, CHK)
        self.assertIsInstance(res, HttpResponseRedirect)
        self.assertEqual(res.url, '/tasks?q=completed')

    def test_queued_recently_api(self):
        # Enqueued recently but scan not completed -> queued branch.
        EnqueuedTask.objects.create(
            task_id='q1', checksum=CHK, file_name='a.apk',
            created_at=timezone.now())
        res = async_analysis(CHK, True, 'a.apk', _real_scan_func, CHK)
        self.assertIsNone(res['task_id'])
        self.assertIn('already enqueued', res['message'])

    def test_queued_recently_web_redirect(self):
        EnqueuedTask.objects.create(
            task_id='q2', checksum=CHK, file_name='a.apk',
            created_at=timezone.now())
        res = async_analysis(CHK, False, 'a.apk', _real_scan_func, CHK)
        self.assertIsInstance(res, HttpResponseRedirect)
        self.assertEqual(res.url, '/tasks?q=queued')

    def test_started_recently_web_redirect(self):
        # No created_at recent (force it old) but started_at recent.
        old = timezone.now() - timedelta(
            minutes=settings.ASYNC_ANALYSIS_TIMEOUT + 10)
        t = EnqueuedTask.objects.create(
            task_id='s3', checksum=CHK, file_name='a.apk',
            started_at=timezone.now())
        EnqueuedTask.objects.filter(pk=t.pk).update(created_at=old)
        res = async_analysis(CHK, False, 'a.apk', _real_scan_func, CHK)
        self.assertIsInstance(res, HttpResponseRedirect)
        self.assertEqual(res.url, '/tasks?q=queued')


class AsyncAnalysisEnqueueTests(TestCase):
    """The real enqueue path via the django_q ORM broker."""

    def test_enqueue_api_returns_task_id(self):
        res = async_analysis(CHK, True, 'sample.apk', _real_scan_func, CHK)
        self.assertIsInstance(res, dict)
        self.assertIsNotNone(res['task_id'])
        self.assertIn('Scan Queued', res['message'])
        # A real EnqueuedTask row was created for the task.
        row = EnqueuedTask.objects.get(task_id=res['task_id'])
        self.assertEqual(row.checksum, CHK)
        self.assertEqual(row.file_name, 'sample.apk')

    def test_enqueue_web_returns_redirect(self):
        res = async_analysis(
            'b' * 32, False, 'sample2.apk', _real_scan_func, 'b' * 32)
        self.assertIsInstance(res, HttpResponseRedirect)
        self.assertEqual(res.url, '/tasks')
        self.assertTrue(
            EnqueuedTask.objects.filter(checksum='b' * 32).exists())

    def test_enqueue_truncates_long_file_name(self):
        long_name = 'x' * 300 + '.apk'
        res = async_analysis(
            'c' * 32, True, long_name, _real_scan_func, 'c' * 32)
        row = EnqueuedTask.objects.get(task_id=res['task_id'])
        self.assertEqual(len(row.file_name), 254)

    def test_enqueue_with_raising_callable_still_enqueues(self):
        # A real raising callable is only *enqueued* here (never executed),
        # so the enqueue path still succeeds and stores the task.
        res = async_analysis(
            'd' * 32, True, 'r.apk', _raising_scan_func, 'd' * 32)
        self.assertIsNotNone(res['task_id'])
        self.assertTrue(
            EnqueuedTask.objects.filter(task_id=res['task_id']).exists())

    @override_settings(QUEUE_MAX_SIZE=2)
    def test_old_tasks_are_cleared_when_over_queue_max(self):
        # Fill beyond QUEUE_MAX_SIZE with old, unrelated checksums.
        for i in range(5):
            EnqueuedTask.objects.create(
                task_id=f'old-{i}', checksum=f'{i:032d}',
                file_name=f'{i}.apk')
        self.assertEqual(EnqueuedTask.objects.count(), 5)
        res = async_analysis(
            'e' * 32, True, 'new.apk', _real_scan_func, 'e' * 32)
        self.assertIsNotNone(res['task_id'])
        # Oldest tasks pruned down toward the queue size (+ the new one).
        self.assertLessEqual(EnqueuedTask.objects.count(), 3)
        self.assertTrue(
            EnqueuedTask.objects.filter(task_id=res['task_id']).exists())


class ListTasksTests(TestCase):

    def setUp(self):
        self.factory = RequestFactory()
        self.user = User.objects.create_superuser(
            'admin', 'admin@example.com', 'pass1234')

    def test_list_tasks_api_returns_raw_list(self):
        EnqueuedTask.objects.create(
            task_id='l1', checksum=CHK, file_name='a.apk', status='Success')
        req = self.factory.post('/tasks')
        req.user = self.user
        data = list_tasks(req, api=True)
        self.assertIsInstance(data, list)
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]['task_id'], 'l1')
        self.assertEqual(data[0]['status'], 'Success')

    def test_list_tasks_web_post_returns_jsonresponse(self):
        EnqueuedTask.objects.create(
            task_id='l2', checksum=CHK, file_name='a.apk', status='Success')
        req = self.factory.post('/tasks')
        req.user = self.user
        resp = list_tasks(req)
        self.assertIsInstance(resp, JsonResponse)
        payload = json.loads(resp.content)
        self.assertEqual(payload[0]['task_id'], 'l2')

    def test_list_tasks_web_get_renders_template(self):
        req = self.factory.get('/tasks')
        req.user = self.user
        resp = list_tasks(req)
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b'tasks-table', resp.content)
