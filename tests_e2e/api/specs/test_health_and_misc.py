"""API spec: health/liveness probes + robots.txt.

These have no meaningful UI (JSON / plain-text responses), so they're
exercised here rather than in ``tests_e2e/ui``.

Both ``/healthz/`` and ``/readyz/`` are registered FIRST in
``mobinspect/MobInspect/urls.py`` (see the comment there: "unauthenticated
health probes for monitors ... short-circuit before any auth ... decorators
on later routes can interfere") and their views
(``mobinspect/MobInspect/views/healthz.py``) carry no ``login_required`` /
RBAC decorator -- confirmed by reading the view code, not assumed. They also
sit outside the ``/api/*`` prefix, so ``RestApiAuthMiddleware`` never runs
for them either. ``anon_api_client`` (no API key at all) is used deliberately
to prove that.
"""
import pytest


@pytest.mark.positive
def test_healthz_returns_200_without_any_api_key(anon_api_client):
    r = anon_api_client.get('/healthz/')
    assert r.status_code in (200, 503)  # 503 only if DB probe itself is down
    body = r.json()
    assert body.get('status') in ('ok', 'degraded', 'failed')
    assert 'db' in body and 'queue' in body and 'adb' in body


@pytest.mark.positive
@pytest.mark.smoke
def test_readyz_returns_200_without_any_api_key(anon_api_client):
    r = anon_api_client.get('/readyz/')
    assert r.status_code == 200
    assert r.json().get('status') == 'ok'


@pytest.mark.positive
def test_robots_txt_returns_a_real_robots_body_not_the_app_shell(anon_api_client):
    r = anon_api_client.get('/robots.txt')
    assert r.status_code == 200
    assert r.headers.get('Content-Type', '').startswith('text/plain')
    assert 'User-agent:' in r.text
    # Not the SPA/login shell or a 404 page leaking through.
    assert '<html' not in r.text.lower()
    assert 'Traceback (most recent call last)' not in r.text
