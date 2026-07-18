# -*- coding: utf_8 -*-
"""Coverage for sast_engine.get_multiprocessing_strategy().

billiard forks a new pool; forking from inside the already-threaded django-q
worker used by async scanning can deadlock mid SAST scan (fork-inherited
locks never release from the parent's other threads). The async branch must
pick 'thread' on every platform, not just Windows, and an explicit
MOBINSPECT_MULTIPROCESSING/settings.MULTIPROCESSING override must always win.

ChoiceEngineTests below adds real-execution coverage of ChoiceEngine
(__init__/read_files/run_rules): real libsast Scanner/ChoiceMatcher objects
run against a real extracted Android source tree (the committed
android_src.zip) and the real, shipped android_niap.yaml choice-rule file.
"""
import os
import tempfile
import zipfile
from pathlib import Path

from django.conf import settings as django_settings
from django.test import SimpleTestCase, override_settings

from mobinspect.StaticAnalyzer.views.sast_engine import (
    ChoiceEngine,
    get_multiprocessing_strategy,
)

SAMPLES_DIR = os.path.normpath(
    os.path.join(django_settings.BASE_DIR, '..', 'test_files'))
NIAP_RULES = (
    Path(django_settings.BASE_DIR) / 'StaticAnalyzer' / 'views' / 'android'
    / 'rules' / 'android_niap.yaml')


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


class ChoiceEngineTests(SimpleTestCase):

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.src_dir = tempfile.mkdtemp()
        with zipfile.ZipFile(
                os.path.join(SAMPLES_DIR, 'android_src.zip')) as zf:
            zf.extractall(cls.src_dir)

    def test_init_read_files_and_run_rules_real_scan(self):
        # Real ChoiceEngine construction (lines 102-106): Scanner() +
        # ChoiceMatcher() against a real extracted source tree and the
        # real, shipped android_niap.yaml rule file.
        options = {
            'choice_rules': NIAP_RULES.as_posix(),
            'alternative_path': '',
            'choice_extensions': {'.java', '.xml'},
            'ignore_paths': set(),
        }
        engine = ChoiceEngine(options, self.src_dir + '/')
        self.assertIsNotNone(engine.choice_matcher)
        self.assertTrue(engine.scan_paths)

        # read_files() (lines 110-111): real file reads.
        file_contents = engine.read_files()
        self.assertTrue(file_contents)

        # run_rules() (line 115): real regex_scan via run_with_timeout.
        result = engine.run_rules(file_contents, NIAP_RULES.as_posix())
        self.assertIsInstance(result, dict)
