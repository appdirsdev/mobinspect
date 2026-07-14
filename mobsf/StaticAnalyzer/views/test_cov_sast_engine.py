# -*- coding: utf_8 -*-
"""Coverage for sast_engine.get_multiprocessing_strategy().

billiard forks a new pool; forking from inside the already-threaded django-q
worker used by async scanning can deadlock mid SAST scan (fork-inherited
locks never release from the parent's other threads). The async branch must
pick 'thread' on every platform, not just Windows, and an explicit
MOBSF_MULTIPROCESSING/settings.MULTIPROCESSING override must always win.
"""
from django.test import SimpleTestCase, override_settings

from mobsf.StaticAnalyzer.views.sast_engine import get_multiprocessing_strategy


class GetMultiprocessingStrategyTests(SimpleTestCase):

    @override_settings(MULTIPROCESSING='', ASYNC_ANALYSIS=False)
    def test_sync_analysis_defaults_to_default_strategy(self):
        self.assertEqual(get_multiprocessing_strategy(), 'default')

    @override_settings(MULTIPROCESSING='', ASYNC_ANALYSIS=True)
    def test_async_analysis_uses_thread_never_billiard(self):
        self.assertEqual(get_multiprocessing_strategy(), 'thread')

    @override_settings(MULTIPROCESSING='billiard', ASYNC_ANALYSIS=True)
    def test_explicit_setting_overrides_async_default(self):
        self.assertEqual(get_multiprocessing_strategy(), 'billiard')

    @override_settings(MULTIPROCESSING='default', ASYNC_ANALYSIS=False)
    def test_explicit_setting_overrides_sync_default(self):
        self.assertEqual(get_multiprocessing_strategy(), 'default')
