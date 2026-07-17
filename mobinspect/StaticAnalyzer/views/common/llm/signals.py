# -*- coding: utf_8 -*-
"""Zero-touch trigger: enqueue AI enrichment after a scan task completes.

Hooks django-q's post_execute signal so the existing scan code is never
modified. The receiver is fully defensive — any error is swallowed, and it
only ever ENQUEUES a separate background job, so it can never affect the scan.
"""
import logging

from django.conf import settings
from django.dispatch import receiver

from django_q.signals import post_execute

logger = logging.getLogger(__name__)

# Scan task functions whose successful completion should trigger enrichment.
_SCAN_TASK_FUNCS = {
    'apk_analysis_task',
    'src_analysis_task',
    'ipa_analysis_task',
    'ios_analysis_task',
    'so_analysis_task',
    'jar_analysis_task',
    'aar_analysis_task',
    'dylib_analysis_task',
    'appx_analysis_task',
    'windows_analysis_task',
}


def _func_name(func):
    if callable(func):
        return getattr(func, '__name__', '')
    if isinstance(func, str):
        return func.rsplit('.', 1)[-1]
    return ''


@receiver(post_execute)
def enqueue_ai_enrichment(sender, task, **kwargs):
    """After a successful scan task, enqueue background enrichment (best-effort)."""
    try:
        if not getattr(settings, 'MOBINSPECT_AI_ENABLED', False):
            return
        if not isinstance(task, dict) or not task.get('success'):
            return
        name = _func_name(task.get('func'))
        if name not in _SCAN_TASK_FUNCS:
            return
        args = task.get('args') or ()
        if not args:
            return
        checksum = args[0]
        if not isinstance(checksum, str) or len(checksum) != 32:
            return
        # Run in a daemon thread, NOT on the scan queue, so enrichment can never
        # occupy a scan worker (scans stay strictly one-at-a-time under a single
        # worker). Local footprint is just HTTP to the remote model box.
        from mobinspect.StaticAnalyzer.views.common.llm.tasks import (
            enrich_in_background)
        enrich_in_background(checksum)
        logger.info('Launched background AI enrichment for %s', checksum)
    except Exception:
        # Must never propagate into the worker's post-execute handling.
        logger.exception('Failed to launch AI enrichment')
