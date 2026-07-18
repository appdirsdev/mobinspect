# -*- coding: utf_8 -*-
"""Real-execution coverage tests for the module-level conditional wiring
at the bottom of mobinspect.MobInspect.urls (the AI-route registration
guard and the opt-in exec-tamper-detection hook).

Both branches only run ONCE, at urlconf import time, under whatever
settings were active THEN -- by the time any test runs, urls.py has
already been imported. To exercise them for real we force a genuine
re-import of the module (`importlib.reload`) under a controlled
sys.modules poison (AI import failure) or a real settings override
(EXEC_TAMPER_DETECTION), then restore everything so later tests are
unaffected. No return-value mocks: the AI import genuinely fails (a
poisoned dotted path raises ImportError for real), and the tamper-hook
functions genuinely run.
"""
import importlib
import subprocess
import sys

from django.test import SimpleTestCase

import mobinspect.MobInspect.settings as raw_settings
import mobinspect.MobInspect.urls as urls_module


class AiRouteRegistrationFailureTests(SimpleTestCase):
    """urls.py's AI-route try/except (real import failure -> logged,
    routing continues without it)."""

    def test_ai_import_failure_is_caught_and_routing_still_works(self):
        # Poison the PACKAGE (not the `views` submodule attribute) --
        # `from X.Y.llm import views` resolves via Python's own sys.modules
        # check for every dotted-path level during __import__, but once
        # `views` has been imported at least once it's cached as a plain
        # attribute on the `llm` package object, which `from ... import
        # views` finds WITHOUT re-consulting sys.modules -- so poisoning
        # only the submodule doesn't reproduce a real failure. Poisoning
        # the package itself forces the real ImportError.
        target = 'mobinspect.StaticAnalyzer.views.common.llm'
        prev = sys.modules.get(target, False)
        sys.modules[target] = None  # forces a real ImportError on reload
        try:
            importlib.reload(urls_module)
            # Must not raise, and the AI-only routes are simply absent.
            names = {
                getattr(p, 'name', None) for p in urls_module.urlpatterns}
            self.assertNotIn('ai_dashboard', names)
        finally:
            if prev is False:
                sys.modules.pop(target, None)
            else:
                sys.modules[target] = prev
            # Restore the real urlpatterns (AI import succeeds again) so
            # later tests see the normal, fully-wired urlconf.
            importlib.reload(urls_module)
            names = {
                getattr(p, 'name', None) for p in urls_module.urlpatterns}
            self.assertIn('ai_dashboard', names)


class ExecTamperDetectionWiringTests(SimpleTestCase):
    """urls.py's opt-in EXEC_TAMPER_DETECTION branch: real hook install +
    real hash snapshot, with subprocess.Popen carefully saved/restored
    since init_exec_hooks() wraps it process-globally.

    urls.py reads this flag via `from . import settings; ...
    settings.EXEC_TAMPER_DETECTION` -- the RAW settings module object,
    computed once from `os.getenv(...)` at its own import time. Django's
    `override_settings` only patches attributes on the `django.conf.settings`
    LazySettings singleton, which this code never consults, so it has no
    effect here. The real, direct control point is the raw settings
    module's own attribute -- set and restored here.
    """

    def test_exec_tamper_detection_enabled_wraps_subprocess_popen(self):
        original_popen = subprocess.Popen
        original_flag = raw_settings.EXEC_TAMPER_DETECTION
        try:
            raw_settings.EXEC_TAMPER_DETECTION = True
            importlib.reload(urls_module)
            # init_exec_hooks() really replaced subprocess.Popen with a
            # wrapped version (real side effect, not a mock).
            self.assertIsNot(subprocess.Popen, original_popen)
        finally:
            subprocess.Popen = original_popen
            raw_settings.EXEC_TAMPER_DETECTION = original_flag
            # Reload once more under the real (disabled-by-default)
            # setting so later tests get the normal urlconf back.
            importlib.reload(urls_module)
