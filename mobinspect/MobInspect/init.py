"""Initialize on first run."""
import logging
import os
import random
import secrets
import subprocess
import sys
import shutil
import threading
import warnings
from getpass import getpass
from hashlib import sha256
from pathlib import Path
from importlib import (
    machinery,
    util,
)

from mobinspect.MobInspect.tools_download import install_jadx
from mobinspect.install.windows.setup import windows_config_local

logger = logging.getLogger(__name__)


def env(new_name, *args):
    """Read an environment variable, or return the default if unset.

    The LAST positional argument is the default. An earlier positional (a
    legacy ``MOBINSPECT_*`` alias name emitted by an older generated user config)
    is accepted and ignored, so a pre-existing ``config.py`` keeps working
    after the rebrand.
    """
    default = args[-1] if args else None
    return os.environ.get(new_name, default)

VERSION = '5.1.0'
BANNER = r"""
  __  __       _     ___                            _
 |  \/  | ___ | |__ |_ _|_ __  ___ _ __   ___  ___| |_
 | |\/| |/ _ \| '_ \ | || '_ \/ __| '_ \ / _ \/ __| __|
 | |  | | (_) | |_) || || | | \__ \ |_) |  __/ (__| |_
 |_|  |_|\___/|_.__/___|_| |_|___/ .__/ \___|\___|\__|
                                 |_|
"""  # noqa: W291
# ASCII Font: Standard


def first_run(secret_file, base_dir, mobinspect_home):
    # Based on https://gist.github.com/ndarville/3452907#file-secret-key-gen-py
    base_dir = Path(base_dir)
    mobinspect_home = Path(mobinspect_home)
    secret_file = Path(secret_file)
    secret_env = env('MOBINSPECT_SECRET_KEY')
    if secret_env:
        secret_key = secret_env
    elif secret_file.exists() and secret_file.is_file():
        secret_key = secret_file.read_text().strip()
    else:
        try:
            secret_key = get_random()
            secret_file.write_text(secret_key)
        except IOError:
            raise Exception(f'Secret file generation failed: {secret_file}')
        # Run Once
        make_migrations(base_dir)
        migrate(base_dir)
        # Install JADX
        thread = threading.Thread(
            target=install_jadx,
            name='install_jadx',
            args=(mobinspect_home.as_posix(),))
        thread.start()
        # Windows Setup
        windows_config_local(mobinspect_home.as_posix())
    return secret_key


def create_user_conf(mobinspect_home, base_dir):
    try:
        config_path = mobinspect_home / 'config.py'
        if not config_path.exists():
            sample_conf = base_dir / 'MobInspect' / 'settings.py'
            dat = sample_conf.read_text().splitlines()
            config = []
            add = False
            for line in dat:
                if '^CONFIG-START^' in line:
                    add = True
                if '^CONFIG-END^' in line:
                    break
                if add:
                    config.append(line.lstrip())
            config.pop(0)
            conf_str = '\n'.join(config)
            config_path.write_text(conf_str)
    except Exception:
        logger.exception('Cannot create config file')


def django_operation(cmds, base_dir):
    """Generic Function for Djano operations."""
    manage = base_dir.parent / 'manage.py'
    if manage.exists() and manage.is_file():
        # Bail out for package
        return
    print(manage)
    args = [sys.executable, manage.as_posix()]
    args.extend(cmds)
    subprocess.call(args)


def make_migrations(base_dir):
    """Create Database Migrations."""
    try:
        django_operation(['makemigrations'], base_dir)
        django_operation(['makemigrations', 'StaticAnalyzer'], base_dir)
    except Exception:
        logger.exception('Cannot Make Migrations')


def migrate(base_dir):
    """Migrate Database."""
    try:
        django_operation(['migrate'], base_dir)
        django_operation(['migrate', '--run-syncdb'], base_dir)
        django_operation(['create_roles'], base_dir)
    except Exception:
        logger.exception('Cannot Migrate')


def bootstrap_admin():
    """Idempotent first-boot admin bootstrap.

    Replaces the legacy `createsuperuser --noinput` flow that seeded the
    notorious ``mobinspect/mobinspect`` superuser. Refuses to run if any superuser
    already exists (returning False) so it is safe to invoke on every boot
    or from a management command.

    Password resolution order:
      1. ``MOBINSPECT_ADMIN_PASSWORD`` env var (required for non-interactive
         deploys).
      2. Interactive prompt if stdin is a TTY.
      3. A 24-char ``secrets.token_urlsafe`` written to
         ``<MOBINSPECT_HOME>/initial-admin-password.txt`` (mode 0600), with the
         path logged so the operator can retrieve it once.

    Username comes from ``MOBINSPECT_ADMIN_USERNAME`` (default ``admin``).

    Returns ``True`` when a new admin was created, ``False`` if one already
    existed.
    """
    # Imported lazily because Django apps need to be ready before
    # ``django.contrib.auth.models`` can be touched at import time.
    from django.contrib.auth import get_user_model

    User = get_user_model()
    if User.objects.filter(is_superuser=True).exists():
        logger.info(
            'bootstrap_admin: superuser already exists; '
            'skipping initial admin creation.')
        return False

    username = os.environ.get('MOBINSPECT_ADMIN_USERNAME', 'admin').strip()
    if not username:
        username = 'admin'

    password = os.environ.get('MOBINSPECT_ADMIN_PASSWORD')
    password_source = 'env'
    if not password and sys.stdin and sys.stdin.isatty():
        try:
            password = getpass(
                f'Set initial password for admin user {username!r}: ')
            confirm = getpass('Confirm password: ')
            if password != confirm:
                logger.error(
                    'bootstrap_admin: passwords did not match; aborting.')
                return False
            password_source = 'prompt'
        except (EOFError, KeyboardInterrupt):
            password = None

    written_path = None
    if not password:
        password = secrets.token_urlsafe(24)
        password_source = 'generated'
        try:
            # Resolve home lazily so tests can monkey-patch ``Path.home``.
            home_dir = Path.home() / '.MobInspect'
            custom_home = env('MOBINSPECT_HOME_DIR')
            if custom_home:
                p = Path(custom_home)
                if p.is_absolute() and p.is_dir():
                    home_dir = p
            home_dir.mkdir(parents=True, exist_ok=True)
            written_path = home_dir / 'initial-admin-password.txt'
            written_path.write_text(password + '\n')
            try:
                os.chmod(written_path, 0o600)
            except OSError:
                # chmod is best-effort (e.g. Windows / non-POSIX FS).
                logger.warning(
                    'bootstrap_admin: could not chmod 0600 %s',
                    written_path)
        except Exception:
            logger.exception(
                'bootstrap_admin: failed to persist generated password')
            return False

    user = User(username=username)
    user.is_active = True
    user.is_staff = True
    user.is_superuser = True
    user.set_password(password)
    user.save()

    if password_source == 'generated' and written_path is not None:
        logger.info(
            'Initial admin password saved to %s '
            '(read it once, then delete the file). '
            'Username: %s', written_path, username)
    elif password_source == 'prompt':
        logger.info(
            'bootstrap_admin: created superuser %r from interactive prompt.',
            username)
    else:
        logger.info(
            'bootstrap_admin: created superuser %r from '
            'MOBINSPECT_ADMIN_PASSWORD.', username)
    return True


def get_random():
    choice = 'abcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*(-_=+)'
    return ''.join([random.SystemRandom().choice(choice) for i in range(50)])


def get_mobinspect_home(use_home, base_dir):
    try:
        base_dir = Path(base_dir)
        mobinspect_home = ''
        if use_home:
            mobinspect_home = Path.home() / '.MobInspect'
            custom_home = env('MOBINSPECT_HOME_DIR')
            if custom_home:
                p = Path(custom_home)
                if p.exists() and p.is_absolute() and p.is_dir():
                    mobinspect_home = p
            # MobInspect Home Directory
            if not mobinspect_home.exists():
                mobinspect_home.mkdir(parents=True, exist_ok=True)
            create_user_conf(mobinspect_home, base_dir)
        else:
            mobinspect_home = base_dir
        # Download Directory
        dwd_dir = mobinspect_home / 'downloads'
        dwd_dir.mkdir(parents=True, exist_ok=True)
        # Screenshot Directory
        screen_dir = mobinspect_home / 'screen'
        screen_dir.mkdir(parents=True, exist_ok=True)
        # Upload Directory
        upload_dir = mobinspect_home / 'uploads'
        upload_dir.mkdir(parents=True, exist_ok=True)
        # Downloaded tools
        downloaded_tools_dir = mobinspect_home / 'tools'
        downloaded_tools_dir.mkdir(parents=True, exist_ok=True)
        # Signatures Directory
        sig_dir = mobinspect_home / 'signatures'
        sig_dir.mkdir(parents=True, exist_ok=True)
        if use_home:
            src = Path(base_dir) / 'signatures'
            try:
                shutil.copytree(src, sig_dir, dirs_exist_ok=True)
            except Exception:
                pass
        return mobinspect_home.as_posix()
    except Exception:
        logger.exception('Creating MobInspect Home Directory')


def get_mobinspect_version():
    return BANNER, VERSION, f'v{VERSION}'


def load_source(modname, filename):
    loader = machinery.SourceFileLoader(modname, filename)
    spec = util.spec_from_file_location(modname, filename, loader=loader)
    module = util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def get_docker_secret_by_file(secret_key):
    try:
        secret_path = os.environ.get(secret_key)
        path = Path(secret_path)
        if path.exists() and path.is_file():
            return path.read_text().strip()
    except Exception:
        logger.exception('Cannot read secret from %s', secret_path)
    raise Exception('Cannot read secret from file')


def get_secret_from_file_or_env(env_secret_key):
    docker_secret_key = f'{env_secret_key}_FILE'
    if os.environ.get(docker_secret_key):
        return get_docker_secret_by_file(docker_secret_key)
    else:
        return os.environ[env_secret_key]


def api_key(home_dir):
    """Print REST API Key."""
    # Read the API key from a docker secret file if configured.
    new_key_file = env('MOBINSPECT_API_KEY_FILE')
    if new_key_file:
        logger.info('\nAPI Key read from docker secrets')
        try:
            return get_docker_secret_by_file('MOBINSPECT_API_KEY_FILE')
        except Exception:
            logger.exception('Cannot read API Key from docker secrets')
    # From Environment Variable
    new_key = env('MOBINSPECT_API_KEY')
    if new_key:
        logger.info('\nAPI Key read from environment variable')
        return new_key
    home_dir = Path(home_dir)
    secret_file = home_dir / 'secret'
    if secret_file.exists() and secret_file.is_file():
        try:
            _api_key = secret_file.read_bytes().strip()
            return sha256(_api_key).hexdigest()
        except Exception:
            logger.exception('Cannot Read API Key')
    return None
