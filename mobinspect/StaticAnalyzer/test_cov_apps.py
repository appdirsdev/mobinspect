# -*- coding: utf_8 -*-
"""Real-execution (no-mock) coverage tests for StaticAnalyzer/apps.py.

Drives the real StaticAnalyzerConfig.ready() directly. The happy path
(real signals import succeeding) already runs once at Django startup for
every other test in the suite; the failure branch is reached here via a
real, single-target sys.modules poison of the llm.signals dotted path --
the same established pattern used by test_cov_home.py's
test_rollup_import_failure_returns_empty -- so the real
``from ... import signals`` statement genuinely raises ImportError
rather than any mocked return value.
"""
import sys

from django.apps import apps
from django.test import SimpleTestCase

import mobinspect.StaticAnalyzer.views.common.llm as llm_pkg
from mobinspect.StaticAnalyzer.apps import StaticAnalyzerConfig


class StaticAnalyzerConfigReadyTests(SimpleTestCase):

    def test_ready_succeeds_when_signals_import_works(self):
        # Real happy path: the real llm.signals module imports cleanly.
        config = apps.get_app_config('StaticAnalyzer')
        self.assertIsInstance(config, StaticAnalyzerConfig)
        config.ready()  # Should not raise.

    def test_ready_swallows_import_failure(self):
        # Real Django app startup already ran ready() once for real, which
        # (as a side effect of `from ... import signals` succeeding) leaves
        # `signals` bound as a real attribute on the parent llm package.
        # Python's fromlist import machinery checks that attribute BEFORE
        # consulting sys.modules, so poisoning sys.modules alone is not
        # enough to reproduce the failure; the attribute must also be
        # removed for the real import statement to genuinely raise.
        target = 'mobinspect.StaticAnalyzer.views.common.llm.signals'
        prev_mod = sys.modules.get(target, False)
        had_attr = hasattr(llm_pkg, 'signals')
        prev_attr = getattr(llm_pkg, 'signals', None)
        sys.modules[target] = None
        if had_attr:
            delattr(llm_pkg, 'signals')
        try:
            config = apps.get_app_config('StaticAnalyzer')
            # Must not raise -- the broad except Exception swallows it.
            config.ready()
        finally:
            if prev_mod is False:
                sys.modules.pop(target, None)
            else:
                sys.modules[target] = prev_mod
            if had_attr:
                llm_pkg.signals = prev_attr
