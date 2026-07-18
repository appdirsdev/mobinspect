# -*- coding: utf_8 -*-
"""Real-execution coverage tests for mobinspect.MobInspect.views.playground.

Every branch is exercised by driving the real view with real
`@override_settings(DEBUG=...)` and a real `MOBINSPECT_ENABLE_PLAYGROUND`
environment variable toggle, plus real Django users (superuser vs regular
vs anonymous). No mocks.
"""
import os
from unittest import mock

from django.contrib.auth import get_user_model
from django.contrib.auth.models import AnonymousUser
from django.http import Http404
from django.test import Client, RequestFactory, TestCase, override_settings

from mobinspect.MobInspect.views import playground as pg


@override_settings(DEBUG=False)
class PlaygroundDisabledTests(TestCase):
    """DEBUG off (the real production default) -> always 404, regardless
    of the env var or user."""

    def test_debug_off_raises_404_even_with_env_var_set(self):
        rf = RequestFactory()
        request = rf.get('/_playground/')
        request.user = AnonymousUser()
        with mock.patch.dict(
                os.environ, {'MOBINSPECT_ENABLE_PLAYGROUND': '1'}):
            with self.assertRaises(Http404):
                pg.playground(request)

    def test_client_get_returns_404(self):
        resp = self.client.get('/_playground/')
        self.assertEqual(resp.status_code, 404)


@override_settings(DEBUG=True)
class PlaygroundEnabledTests(TestCase):
    """DEBUG on + the explicit opt-in env var -> reachable, but still
    gated by the superuser check."""

    @classmethod
    def setUpTestData(cls):
        User = get_user_model()
        cls.superuser = User.objects.create_superuser(
            'pg_admin', 'pg_admin@example.com', 'pg_admin')
        cls.regular = User.objects.create_user(
            username='pg_regular', password='x')

    def setUp(self):
        self.factory = RequestFactory()
        self._env_patch = mock.patch.dict(
            os.environ, {'MOBINSPECT_ENABLE_PLAYGROUND': '1'})
        self._env_patch.start()
        self.addCleanup(self._env_patch.stop)

    def test_debug_on_but_env_var_unset_raises_404(self):
        # Explicit opt-in flag missing -> `enabled` is still False even
        # with DEBUG=True (defense in depth against DEBUG being flipped
        # on in production during an incident).
        self._env_patch.stop()
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop('MOBINSPECT_ENABLE_PLAYGROUND', None)
            request = self.factory.get('/_playground/')
            request.user = AnonymousUser()
            with self.assertRaises(Http404):
                pg.playground(request)
        self._env_patch.start()

    def test_authenticated_non_superuser_raises_404(self):
        request = self.factory.get('/_playground/')
        request.user = self.regular
        with self.assertRaises(Http404):
            pg.playground(request)

    def test_anonymous_user_is_allowed(self):
        # Only "authenticated AND not superuser" is denied; an anonymous
        # (not authenticated) request is allowed through.
        request = self.factory.get('/_playground/')
        request.user = AnonymousUser()
        resp = pg.playground(request)
        self.assertEqual(resp.status_code, 200)

    def test_superuser_renders_playground_with_real_context(self):
        request = self.factory.get('/_playground/')
        request.user = self.superuser
        resp = pg.playground(request)
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b'Playground', resp.content)

    def test_client_get_renders_for_superuser(self):
        client = Client()
        client.force_login(self.superuser)
        resp = client.get('/_playground/')
        self.assertEqual(resp.status_code, 200)
        # Real context reaches the template via the test Client's signal
        # capture (unlike a bare RequestFactory call above).
        self.assertEqual(resp.context['title'], 'Playground')
        self.assertEqual(len(resp.context['kpis']), 4)
        self.assertEqual(len(resp.context['findings']), 6)
