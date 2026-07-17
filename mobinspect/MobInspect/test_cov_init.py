"""Real-execution coverage tests for mobinspect.MobInspect.init.

STRICT: no mocks. Everything runs against real env vars, real temp files,
real settings source, and a real Django superuser via TestCase.
"""
import os
import warnings
from hashlib import sha256
from pathlib import Path

import pytest

from django.test import TestCase

from mobinspect.MobInspect import init as mod
from mobinspect.MobInspect.init import (
    env,
    get_random,
    get_mobinspect_version,
    get_mobinspect_home,
    load_source,
    get_docker_secret_by_file,
    get_secret_from_file_or_env,
    api_key,
    first_run,
    create_user_conf,
    django_operation,
    make_migrations,
    migrate,
    bootstrap_admin,
    VERSION,
    BANNER,
)

# Absolute path to the real repo base dir (mobinspect/ package dir).
BASE_DIR = Path(__file__).resolve().parent.parent  # .../MobInspect/mobinspect

# Env var names touched by the module; snapshot/restore around each test.
_ENV_KEYS = [
    'MOBINSPECT_SECRET_KEY', 'MOBINSPECT_SECRET_KEY',
    'MOBINSPECT_API_KEY', 'MOBINSPECT_API_KEY',
    'MOBINSPECT_API_KEY_FILE', 'MOBINSPECT_API_KEY_FILE',
    'MOBINSPECT_HOME_DIR', 'MOBINSPECT_HOME_DIR',
    'MOBINSPECT_ADMIN_USERNAME', 'MOBINSPECT_ADMIN_PASSWORD',
    'MI_ENV_TEST_NEW', 'MI_ENV_TEST_OLD',
    'MOBINSPECT_ADB_BINARY', 'MOBINSPECT_ADB_BINARY',
]


@pytest.fixture(autouse=True)
def _clean_env():
    saved = {k: os.environ.get(k) for k in _ENV_KEYS}
    for k in _ENV_KEYS:
        os.environ.pop(k, None)
    try:
        yield
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


# --------------------------- env() ---------------------------

def test_env_new_name_wins():
    os.environ['MI_ENV_TEST_NEW'] = 'newval'
    os.environ['MI_ENV_TEST_OLD'] = 'oldval'
    assert env('MI_ENV_TEST_NEW', 'MI_ENV_TEST_OLD') == 'newval'


def test_env_default_when_unset():
    os.environ.pop('MI_ENV_TEST_NEW', None)
    # The LAST positional is the default; an earlier (legacy-alias) positional
    # is accepted but ignored.
    assert env('MI_ENV_TEST_NEW', 'def') == 'def'
    assert env('MI_ENV_TEST_NEW', 'MI_ENV_TEST_OLD', 'def') == 'def'
    assert env('MI_ENV_TEST_NEW') is None


def test_env_legacy_alias_is_ignored():
    # The legacy MOBINSPECT_* alias name is no longer consulted after the rebrand.
    os.environ.pop('MI_ENV_TEST_NEW', None)
    os.environ['MI_ENV_TEST_OLD'] = 'legacy'
    try:
        # 3-arg (new_name, legacy_alias, default): legacy alias is ignored,
        # so the default 'def' is returned rather than the legacy value.
        assert env('MI_ENV_TEST_NEW', 'MI_ENV_TEST_OLD', 'def') == 'def'
        # Only the new name is honored.
        os.environ['MI_ENV_TEST_NEW'] = 'newval'
        assert env('MI_ENV_TEST_NEW', 'MI_ENV_TEST_OLD', 'def') == 'newval'
    finally:
        os.environ.pop('MI_ENV_TEST_OLD', None)
        os.environ.pop('MI_ENV_TEST_NEW', None)


# --------------------------- get_random ---------------------------

def test_get_random_length_and_charset():
    val = get_random()
    assert len(val) == 50
    allowed = set('abcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*(-_=+)')
    assert set(val) <= allowed
    assert get_random() != val  # overwhelmingly likely distinct


# --------------------------- get_mobinspect_version ---------------------------

def test_get_mobinspect_version():
    banner, version, vversion = get_mobinspect_version()
    assert banner == BANNER
    assert version == VERSION
    assert vversion == f'v{VERSION}'


# --------------------------- load_source ---------------------------

def test_load_source_executes_real_file(tmp_path):
    src = tmp_path / 'realmod.py'
    src.write_text('ANSWER = 42\n\ndef greet():\n    return "hi"\n')
    loaded = load_source('realmod_test', src.as_posix())
    assert loaded.ANSWER == 42
    assert loaded.greet() == 'hi'


# --------------------------- docker secret helpers ---------------------------

def test_get_docker_secret_by_file_reads_real_file(tmp_path):
    secret = tmp_path / 'mysecret'
    secret.write_text('  topsecret\n')
    os.environ['MI_ENV_TEST_NEW'] = secret.as_posix()
    assert get_docker_secret_by_file('MI_ENV_TEST_NEW') == 'topsecret'


def test_get_docker_secret_by_file_missing_raises():
    os.environ['MI_ENV_TEST_NEW'] = '/nonexistent/path/xyz'
    with pytest.raises(Exception):
        get_docker_secret_by_file('MI_ENV_TEST_NEW')


def test_get_docker_secret_by_file_env_unset_raises():
    with pytest.raises(Exception):
        get_docker_secret_by_file('MI_ENV_TEST_NEW')


def test_get_secret_from_file_or_env_direct_env():
    os.environ['MOBINSPECT_API_KEY'] = 'plainvalue'
    assert get_secret_from_file_or_env('MOBINSPECT_API_KEY') == 'plainvalue'


def test_get_secret_from_file_or_env_file_variant(tmp_path):
    secret = tmp_path / 's'
    secret.write_text('filevalue\n')
    os.environ['MOBINSPECT_API_KEY_FILE'] = secret.as_posix()
    assert get_secret_from_file_or_env('MOBINSPECT_API_KEY') == 'filevalue'


# --------------------------- api_key ---------------------------

def test_api_key_from_env_variable(tmp_path):
    os.environ['MOBINSPECT_API_KEY'] = 'envapikey'
    assert api_key(tmp_path.as_posix()) == 'envapikey'


def test_api_key_from_legacy_env_variable(tmp_path):
    os.environ['MOBINSPECT_API_KEY'] = 'legacyapikey'
    assert api_key(tmp_path.as_posix()) == 'legacyapikey'


def test_api_key_from_docker_secret_file(tmp_path):
    secret = tmp_path / 'apisecret'
    secret.write_text('dockerapikey\n')
    os.environ['MOBINSPECT_API_KEY_FILE'] = secret.as_posix()
    assert api_key(tmp_path.as_posix()) == 'dockerapikey'


def test_api_key_docker_secret_file_failure_falls_through(tmp_path):
    # File env points at a bad path -> reader raises, caught, falls through.
    os.environ['MOBINSPECT_API_KEY_FILE'] = '/nonexistent/no'
    os.environ['MOBINSPECT_API_KEY'] = 'fallbackkey'
    assert api_key(tmp_path.as_posix()) == 'fallbackkey'


def test_api_key_from_secret_file_sha256(tmp_path):
    secret_file = tmp_path / 'secret'
    secret_file.write_bytes(b'  rawsecret  ')
    expected = sha256(b'rawsecret').hexdigest()
    assert api_key(tmp_path.as_posix()) == expected


def test_api_key_none_when_nothing_available(tmp_path):
    assert api_key(tmp_path.as_posix()) is None


# --------------------------- first_run ---------------------------

def test_first_run_uses_env_secret(tmp_path):
    os.environ['MOBINSPECT_SECRET_KEY'] = 'the-secret-key'
    secret_file = tmp_path / 'secret_key'
    result = first_run(secret_file.as_posix(),
                       BASE_DIR.as_posix(), tmp_path.as_posix())
    assert result == 'the-secret-key'
    assert not secret_file.exists()  # env path does not write a file


def test_first_run_reads_existing_secret_file(tmp_path):
    secret_file = tmp_path / 'secret_key'
    secret_file.write_text('  file-secret\n')
    result = first_run(secret_file.as_posix(),
                       BASE_DIR.as_posix(), tmp_path.as_posix())
    assert result == 'file-secret'


# --------------------------- create_user_conf ---------------------------

def test_create_user_conf_extracts_config_block(tmp_path):
    # Real settings.py contains the ^CONFIG-START^/^CONFIG-END^ markers.
    create_user_conf(tmp_path, BASE_DIR)
    config_path = tmp_path / 'config.py'
    assert config_path.exists()
    content = config_path.read_text()
    assert len(content) > 0
    # Must not include the sentinel line that terminates extraction.
    assert '^CONFIG-END^' not in content


def test_create_user_conf_idempotent_when_exists(tmp_path):
    config_path = tmp_path / 'config.py'
    config_path.write_text('PRE=1\n')
    create_user_conf(tmp_path, BASE_DIR)
    # Existing file is left untouched.
    assert config_path.read_text() == 'PRE=1\n'


def test_create_user_conf_bad_base_dir_is_swallowed(tmp_path):
    # base_dir with no MobInspect/settings.py -> exception caught, no raise.
    create_user_conf(tmp_path, tmp_path)
    assert not (tmp_path / 'config.py').exists()


def test_create_user_conf_extracted_block_loads_and_honors_env_shim(tmp_path):
    # The extracted block is a raw text splice into a standalone file loaded
    # via load_source — it must be syntactically valid on its own (needs its
    # own `env` import) and every MOBINSPECT_* var in it must go through the
    # rebrand shim (MOBINSPECT_* wins, MOBINSPECT_* still works as a fallback).
    create_user_conf(tmp_path, BASE_DIR)
    config_path = tmp_path / 'config.py'

    os.environ['MOBINSPECT_ADB_BINARY'] = '/legacy/adb'
    mod_legacy = load_source('user_settings_legacy', str(config_path))
    assert mod_legacy.ADB_BINARY == '/legacy/adb'

    os.environ['MOBINSPECT_ADB_BINARY'] = '/new/adb'
    mod_new = load_source('user_settings_new', str(config_path))
    assert mod_new.ADB_BINARY == '/new/adb'


# --------------------------- django ops (package bail-out) ---------------------------

def test_django_operation_bails_out_for_package():
    # base_dir.parent (repo root) has a real manage.py -> returns None early
    # without ever invoking subprocess.
    assert django_operation(['makemigrations'], BASE_DIR) is None


def test_make_migrations_and_migrate_bail_out_cleanly():
    # Both wrap django_operation which bails out; must not raise.
    assert make_migrations(BASE_DIR) is None
    assert migrate(BASE_DIR) is None


# --------------------------- get_mobinspect_home ---------------------------

def test_get_mobinspect_home_base_dir_mode_creates_subdirs(tmp_path):
    home = get_mobinspect_home(False, tmp_path.as_posix())
    assert home == tmp_path.as_posix()
    for sub in ('downloads', 'screen', 'uploads', 'tools', 'signatures'):
        assert (tmp_path / sub).is_dir()
    # base_dir mode does not create config.py
    assert not (tmp_path / 'config.py').exists()


def test_get_mobinspect_home_use_home_with_custom_home_dir(tmp_path):
    home_dir = tmp_path / 'customhome'
    home_dir.mkdir()
    os.environ['MOBINSPECT_HOME_DIR'] = home_dir.as_posix()
    # Use a base_dir lacking signatures + MobInspect/settings.py so copytree and
    # create_user_conf hit their swallowed-exception paths (no crash).
    base = tmp_path / 'base'
    base.mkdir()
    home = get_mobinspect_home(True, base.as_posix())
    assert home == home_dir.as_posix()
    for sub in ('downloads', 'screen', 'uploads', 'tools', 'signatures'):
        assert (home_dir / sub).is_dir()


def test_get_mobinspect_home_exception_path_returns_none(tmp_path):
    # base_dir pointing at a real *file* makes the subdir mkdir fail
    # (parent is not a directory) -> outer except -> returns None.
    afile = tmp_path / 'iamafile'
    afile.write_text('x')
    assert get_mobinspect_home(False, afile.as_posix()) is None


# --------------------------- bootstrap_admin (real DB) ---------------------------

class BootstrapAdminTests(TestCase):

    _ENV = [
        'MOBINSPECT_ADMIN_USERNAME', 'MOBINSPECT_ADMIN_PASSWORD',
        'MOBINSPECT_HOME_DIR', 'MOBINSPECT_HOME_DIR',
    ]

    def setUp(self):
        self._saved = {k: os.environ.get(k) for k in self._ENV}
        for k in self._ENV:
            os.environ.pop(k, None)

    def tearDown(self):
        for k, v in self._saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    def test_creates_admin_from_env_password(self):
        from django.contrib.auth import get_user_model
        os.environ['MOBINSPECT_ADMIN_PASSWORD'] = 'S3cretPass!'
        os.environ['MOBINSPECT_ADMIN_USERNAME'] = 'bossadmin'
        assert bootstrap_admin() is True
        User = get_user_model()
        u = User.objects.get(username='bossadmin')
        assert u.is_superuser and u.is_staff and u.is_active
        assert u.check_password('S3cretPass!')

    def test_idempotent_when_superuser_exists(self):
        from django.contrib.auth import get_user_model
        User = get_user_model()
        User.objects.create_superuser(
            username='pre', email='', password='x')
        # A superuser already exists -> returns False, creates nothing new.
        assert bootstrap_admin() is False
        assert User.objects.filter(is_superuser=True).count() == 1

    def test_blank_username_defaults_to_admin(self):
        from django.contrib.auth import get_user_model
        os.environ['MOBINSPECT_ADMIN_PASSWORD'] = 'pw12345'
        os.environ['MOBINSPECT_ADMIN_USERNAME'] = '   '
        assert bootstrap_admin() is True
        User = get_user_model()
        assert User.objects.filter(username='admin').exists()

    def test_generated_password_written_to_custom_home(self):
        from django.contrib.auth import get_user_model
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            os.environ['MOBINSPECT_HOME_DIR'] = d
            # No password env, stdin is not a TTY in test runner ->
            # generated-password branch runs and writes the file.
            assert bootstrap_admin() is True
            pw_file = Path(d) / 'initial-admin-password.txt'
            assert pw_file.is_file()
            assert pw_file.read_text().strip() != ''
            User = get_user_model()
            assert User.objects.filter(
                username='admin', is_superuser=True).exists()
