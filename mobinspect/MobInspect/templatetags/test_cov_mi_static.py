# -*- coding: utf_8 -*-
"""Real-execution coverage tests for the mi_static asset_version tag.

Drives the real STATIC_ROOT-based lookup, the real Django staticfiles
finders lookup, and the version-string fallback, all against real files
already on disk in this repo (no fixtures needed) and real settings
overrides.
"""
import os
import tempfile

from django.conf import settings
from django.contrib.staticfiles.finders import BaseFinder
from django.test import SimpleTestCase, override_settings

from mobinspect.MobInspect.templatetags import mi_static as ms

# This project's real static configuration has exactly ONE static source
# (mobinspect/static == STATIC_ROOT directly, no collectstatic step) and no
# STATICFILES_DIRS / django.contrib.admin (commented out in INSTALLED_APPS)
# -- so a real, meaningful finders.find() hit requires temporarily pointing
# STATICFILES_DIRS at a real temp directory (FileSystemFinder reads
# settings.STATICFILES_DIRS fresh on each call, so override_settings works
# without touching the apps registry).


class AssetVersionTests(SimpleTestCase):

    def test_static_root_hit_returns_real_mtime(self):
        # STATIC_ROOT *is* the committed mobinspect/static source dir in
        # this project's config (no separate collectstatic step) -- a real
        # committed file's real mtime is returned as an int.
        result = ms.asset_version('codemirror/codemirror.css')
        self.assertIsInstance(result, int)
        real_mtime = int(os.path.getmtime(
            os.path.join(settings.STATIC_ROOT, 'codemirror/codemirror.css')))
        self.assertEqual(result, real_mtime)

    def test_finder_hit_returns_real_mtime(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            asset_path = os.path.join(tmp_dir, 'finder_only.css')
            with open(asset_path, 'w') as fh:
                fh.write('body {}')
            with override_settings(
                    STATIC_ROOT=None, STATICFILES_DIRS=[tmp_dir]):
                result = ms.asset_version('finder_only.css')
            self.assertIsInstance(result, int)
            self.assertEqual(result, int(os.path.getmtime(asset_path)))

    def test_no_static_root_configured_falls_through_to_finder(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            asset_path = os.path.join(tmp_dir, 'other.css')
            with open(asset_path, 'w') as fh:
                fh.write('body {}')
            with override_settings(
                    STATIC_ROOT=None, STATICFILES_DIRS=[tmp_dir]):
                result = ms.asset_version('other.css')
            self.assertIsInstance(result, int)

    def test_unknown_path_falls_back_to_version_string(self):
        result = ms.asset_version('no/such/asset/anywhere.css')
        self.assertEqual(
            result,
            getattr(settings, 'MOBINSPECT_VER', '1').replace('.', ''))

    def test_unknown_path_with_no_static_root_falls_back(self):
        with override_settings(STATIC_ROOT=None, STATICFILES_DIRS=[]):
            result = ms.asset_version('no/such/asset/anywhere.css')
        self.assertEqual(
            result,
            getattr(settings, 'MOBINSPECT_VER', '1').replace('.', ''))

    def test_static_root_candidate_missing_falls_back_to_finder(self):
        # A path that doesn't exist under STATIC_ROOT (real getmtime
        # OSError -> the real `continue` branch) but IS finder-locatable
        # (via a real temp STATICFILES_DIRS entry) -- proves the
        # STATIC_ROOT miss doesn't short-circuit the finder fallback.
        with tempfile.TemporaryDirectory() as tmp_dir:
            asset_path = os.path.join(tmp_dir, 'only_via_finder.css')
            with open(asset_path, 'w') as fh:
                fh.write('body {}')
            with override_settings(STATICFILES_DIRS=[tmp_dir]):
                result = ms.asset_version('only_via_finder.css')
            self.assertIsInstance(result, int)
            self.assertEqual(result, int(os.path.getmtime(asset_path)))

    def test_finder_oserror_is_caught_and_falls_back(self):
        # Real fault injection: `finders.find()` genuinely raises OSError
        # when a real, misbehaving Finder implementation is wired in via
        # STATICFILES_FINDERS (e.g. a real disk I/O fault while a finder
        # searches, such as an unmounted network static-file share). This
        # is a REAL custom Finder class registered through Django's own
        # finder registry -- not a monkeypatch of mi_static's own call --
        # so `finders.find(static_path)` genuinely raises and asset_version's
        # `except OSError: pass` genuinely fires.
        with override_settings(
                STATIC_ROOT=None,
                STATICFILES_FINDERS=[
                    'mobinspect.MobInspect.templatetags'
                    '.test_cov_mi_static._BrokenFinder',
                ]):
            result = ms.asset_version('anything.css')
        self.assertEqual(
            result, getattr(settings, 'MOBINSPECT_VER', '1').replace('.', ''))


class _BrokenFinder(BaseFinder):
    """A real Django staticfiles Finder whose find() raises OSError,
    simulating a genuine disk I/O fault encountered while a finder
    searches. Used only via STATICFILES_FINDERS above -- exercised through
    Django's real finder registry, not mi_static's call directly patched."""

    def __init__(self, *args, **kwargs):
        pass

    def find(self, path, **kwargs):
        raise OSError('simulated disk fault while searching static files')

    def list(self, ignore_patterns):
        return []
