# -*- coding: utf_8 -*-
"""Real-execution (no-mock) coverage tests for StaticAnalyzer/models.py.

Drives the real model __str__ methods with real (unsaved, in-memory)
model instances -- no DB access needed for either.
"""
from django.test import SimpleTestCase
from django.utils import timezone

from mobinspect.StaticAnalyzer.models import (
    AIEnrichment,
    EnqueuedTask,
    RecentScansDB,
)


class AIEnrichmentStrTests(SimpleTestCase):

    def test_str_formats_md5_and_status(self):
        obj = AIEnrichment(MD5='a' * 32, STATUS='completed')
        self.assertEqual(str(obj), f'{"a" * 32} (completed)')


class RecentScansDBTimestampDefaultTests(SimpleTestCase):
    """Regression test (fixed): TIMESTAMP's default was the naive
    ``datetime.now`` (stdlib), which produced a real
    'RuntimeWarning: naive datetime ... while time zone support is active'
    on every save while ``USE_TZ`` is on, and could silently store a
    wall-clock time in the wrong offset. The default is now
    ``django.utils.timezone.now``, which returns a tz-aware datetime -- no
    DB access needed to observe this, ``get_default()`` runs on
    instantiation.
    """

    def test_default_timestamp_is_timezone_aware(self):
        row = RecentScansDB()
        self.assertTrue(timezone.is_aware(row.TIMESTAMP))


class EnqueuedTaskStrTests(SimpleTestCase):
    """Regression test (fixed): EnqueuedTask.__str__ used to reference
    ``self.name``, but this model defines no ``name`` field at all (only
    task_id, checksum, file_name, status, created_at, started_at,
    completed_at, app_name), so calling str()/repr() on any real
    EnqueuedTask instance -- e.g. from Django admin, a shell, or a log
    statement -- raised a real AttributeError. __str__ now uses the
    existing ``file_name`` field instead.
    """

    def test_str_formats_file_name_and_status(self):
        task = EnqueuedTask(
            task_id='t1', checksum='c1', file_name='f.apk',
            status='Enqueued')
        self.assertEqual(str(task), 'f.apk (Enqueued)')
