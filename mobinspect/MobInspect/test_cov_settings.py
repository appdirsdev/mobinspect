"""Real-execution coverage tests for mobinspect.MobInspect.settings.

Django settings modules execute their top-level code exactly once, at
process start, driven by whatever real environment/filesystem state existed
at that moment. To exercise the module's conditional module-level branches
(PostgreSQL env validation, ALLOWED_HOSTS/CSRF/TLS/proxy toggles, and the
CONFIG_HOME True/False fork that decides whether the ~150-line default user
config block executes) we do a REAL ``importlib.reload`` of the actual
settings module with real env vars and a real temporary MOBINSPECT_HOME_DIR
— no mocking of the settings logic itself.

Safety: every reload is wrapped by ``reload_with_env()`` below, which:
  * only touches the specific env vars the scenario cares about (restored
    exactly afterward);
  * snapshots the settings module's ``__dict__`` before reloading and
    restores it byte-for-byte in a ``finally``, regardless of whether the
    reload raised partway through — so the live module object is left
    exactly as this test found it once each test ends;
  * never lets a reload take the "very first run ever" path in
    ``first_run()`` (which would spawn a background thread that downloads
    JADX from the network): whenever a fresh MOBINSPECT_HOME_DIR is used, a
    dummy ``secret`` file is pre-created so the fast, side-effect-free
    "read existing secret" branch is taken instead.

Note: ``django.conf.settings`` (the LazySettings object Django itself uses
everywhere else, via ``from django.conf import settings``) copied its
attributes from this module ONCE at process start and holds no live
reference back to it — so none of this touches Django's actual runtime
configuration. Only code that does ``from mobinspect.MobInspect import
settings`` and reads module attributes directly (as this test does, and as
production code like ``utils.py``/``security.py`` does) observes the
temporary reloaded state, and only for the duration of each ``with`` block.
"""
import importlib
import os
from contextlib import contextmanager

import pytest

from django.core.exceptions import ImproperlyConfigured

from mobinspect.MobInspect import settings as settings_mod


@contextmanager
def reload_with_env(**overrides):
    """Reload the real settings module with real env var overrides.

    Only the keys passed in `overrides` are touched; everything else (the
    real POSTGRES_* connection info, MOBINSPECT_JADX_BINARY, etc.) is left
    completely alone so the reload stays connected to the same real
    database. Restores both the environment and the settings module's
    __dict__ exactly, even if the reload raises.
    """
    saved_env = {k: os.environ.get(k) for k in overrides}
    snapshot = dict(vars(settings_mod))
    for k, v in overrides.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v
    try:
        importlib.reload(settings_mod)
        yield settings_mod
    finally:
        for k, v in saved_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        settings_mod.__dict__.clear()
        settings_mod.__dict__.update(snapshot)


# ---------------------------------------------------------------------------
# _mobinspect_ai_url_ok — pure function, no reload needed
# ---------------------------------------------------------------------------
def test_mobinspect_ai_url_ok_valid_url():
    assert settings_mod._mobinspect_ai_url_ok('http://127.0.0.1:11434') is True


def test_mobinspect_ai_url_ok_bad_scheme():
    assert settings_mod._mobinspect_ai_url_ok('ftp://host:21') is False


def test_mobinspect_ai_url_ok_missing_hostname():
    assert settings_mod._mobinspect_ai_url_ok('http://') is False


def test_mobinspect_ai_url_ok_malformed_port_triggers_except():
    # urlparse(...).port raises ValueError for a non-numeric port, caught by
    # the function's own except branch.
    assert settings_mod._mobinspect_ai_url_ok('http://host:notaport') is False


# ---------------------------------------------------------------------------
# ALLOWED_HOSTS / CSRF_TRUSTED_ORIGINS — real reload with real env vars
# ---------------------------------------------------------------------------
def test_allowed_hosts_from_env_csv():
    with reload_with_env(MOBINSPECT_ALLOWED_HOSTS='scan.example.com, 10.0.0.5') as s:
        assert s.ALLOWED_HOSTS == ['scan.example.com', '10.0.0.5']


def test_csrf_origins_skip_wildcard_host():
    with reload_with_env(MOBINSPECT_ALLOWED_HOSTS='*, scan.example.com') as s:
        assert '*' in s.ALLOWED_HOSTS
        assert not any('*' in o for o in s.CSRF_TRUSTED_ORIGINS)
        assert any('scan.example.com' in o for o in s.CSRF_TRUSTED_ORIGINS)


def test_csrf_trusted_origins_extra_from_env():
    with reload_with_env(
            MOBINSPECT_CSRF_TRUSTED_ORIGINS='https://extra.example:9000') as s:
        assert 'https://extra.example:9000' in s.CSRF_TRUSTED_ORIGINS


# ---------------------------------------------------------------------------
# Hardening headers — behind-TLS / behind-proxy toggles
# ---------------------------------------------------------------------------
def test_behind_tls_enables_hsts_and_secure_cookies():
    with reload_with_env(MOBINSPECT_BEHIND_TLS='1') as s:
        assert s.SESSION_COOKIE_SECURE is True
        assert s.CSRF_COOKIE_SECURE is True
        assert s.SECURE_HSTS_SECONDS == 31536000
        assert s.SECURE_HSTS_INCLUDE_SUBDOMAINS is True
        assert s.SECURE_HSTS_PRELOAD is True


def test_behind_proxy_trusts_forwarded_proto_header():
    with reload_with_env(MOBINSPECT_BEHIND_PROXY='1') as s:
        assert s.SECURE_PROXY_SSL_HEADER == ('HTTP_X_FORWARDED_PROTO', 'https')


# ---------------------------------------------------------------------------
# MOBINSPECT_AI_ENABLED fail-closed on malformed endpoint (module-level check)
# ---------------------------------------------------------------------------
def test_ai_enabled_with_malformed_base_url_is_forced_off():
    with reload_with_env(MOBINSPECT_AI_ENABLED='1',
                          MOBINSPECT_AI_BASE_URL='http://host:notaport') as s:
        assert s.MOBINSPECT_AI_ENABLED is False


# ---------------------------------------------------------------------------
# PostgreSQL required — fail-fast ImproperlyConfigured
# ---------------------------------------------------------------------------
def test_missing_postgres_password_raises_improperly_configured():
    with pytest.raises(ImproperlyConfigured):
        with reload_with_env(POSTGRES_PASSWORD=None, POSTGRES_PASSWORD_FILE=None):
            pass


# ---------------------------------------------------------------------------
# CONFIG_HOME=False — the ~150-line default user-config block. Forced by
# pointing MOBINSPECT_HOME_DIR at a fresh temp dir containing a deliberately
# syntactically-broken config.py (so load_source() raises for real and the
# except branch sets CONFIG_HOME=False), with a pre-seeded `secret` file so
# first_run() takes its fast "read existing secret" path instead of ever
# reaching the first-run install/migrate/JADX-download side effects.
# ---------------------------------------------------------------------------
def test_config_home_false_executes_default_config_block(tmp_path):
    broken_home = tmp_path / 'broken_home'
    broken_home.mkdir()
    (broken_home / 'config.py').write_text('this is not ( valid python !!!')
    (broken_home / 'secret').write_text('coverage-test-secret-key')

    with reload_with_env(MOBINSPECT_HOME_DIR=broken_home.as_posix()) as s:
        assert s.CONFIG_HOME is False
        assert 'com/google/' in s.SKIP_CLASS_PATH
        assert isinstance(s.CVSS_SCORE_ENABLED, bool)
        assert s.PERM_MAPPING_ENABLED == '1'
        assert s.DEX2SMALI_ENABLED == '1'
        assert s.SO_ANALYSIS_ENABLED == '1'
        assert s.DYLIB_ANALYSIS_ENABLED == '1'
        assert s.DOMAIN_MALWARE_SCAN == '1'
        assert s.APKID_ENABLED == '1'
        assert s.WINDOWS_VM_PORT == '8000'
        assert s.JAVA_DIRECTORY == ''
        assert s.ANALYZER_IDENTIFIER == ''
        assert s.FRIDA_TIMEOUT == 4
        assert s.PROXY_IP == '127.0.0.1'
        assert s.PROXY_PORT == 1337
        assert s.UPSTREAM_PROXY_TYPE == 'http'
        assert s.UPSTREAM_PROXY_IP == '127.0.0.1'
        assert s.UPSTREAM_PROXY_PORT == 3128
        assert s.VT_ENABLED is False
        assert s.IOS_SSH_USER == 'root'
        assert s.IOS_SSH_PASSWORD == 'alpine'
        assert s.CORELLIUM_API_DOMAIN == ''
