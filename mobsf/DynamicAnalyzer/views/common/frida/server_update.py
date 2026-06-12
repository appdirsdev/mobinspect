# -*- coding: utf_8 -*-
"""Common Frida Server Update Management for Android and iOS."""

import hashlib
import logging
import shutil
from pathlib import Path
from lzma import LZMAFile
from shutil import copyfileobj

import requests

from django.conf import settings

from mobsf.MobSF.utils import (
    is_internet_available,
    upstream_proxy,
)

logger = logging.getLogger(__name__)


# Expected SHA-256 digests for vetted Frida server binaries, keyed by
# (frida_version, arch_key). The Frida version is NOT pinned here on purpose:
# the runtime version is taken from the installed `frida` Python package
# (`frida.__version__` in the Android/iOS environment modules), so the
# `frida-server` binary that gets downloaded must match that package version.
# Keying the hashes by version means an unpinned/upgraded `frida` package can
# never silently pass verification against a stale digest — it will simply have
# no entry and fall through to the warn/fail-closed path below.
#
# arch_key values:
#   Android: 'arm', 'arm64', 'x86', 'x86_64'  (decompressed ELF binary)
#   iOS:     'ios-arm', 'ios-arm64'           (the .deb archive, as-is)
#
# An empty mapping (or a missing entry) means "no pinned hash":
#   - default (MOBSF_FRIDA_VERIFY=0): a LOUD warning is logged and the binary
#     is used anyway (backwards-compatible behaviour).
#   - fail-closed (MOBSF_FRIDA_VERIFY=1): the binary is refused.
#
# ---------------------------------------------------------------------------
# HOW TO POPULATE / UPDATE A HASH (do this whenever the `frida` package is
# bumped, or to enable verification for the currently installed version):
#
#   1. Determine the installed frida version:
#        poetry run python -c "import frida; print(frida.__version__)"
#      (call it <ver>, e.g. 17.8.2)
#   2. For each Android arch you support, download the matching release asset:
#        https://github.com/frida/frida/releases/tag/<ver>
#      e.g. frida-server-<ver>-android-x86_64.xz
#   3. Decompress it (the runtime stores the *decompressed* ELF):
#        xz -d frida-server-<ver>-android-x86_64.xz
#   4. Compute the digest of the decompressed file:
#        sha256sum frida-server-<ver>-android-x86_64
#   5. Add an entry below: FRIDA_SERVER_SHA256[('<ver>', 'x86_64')] = '<hex>'
#
#   For iOS, download the .deb asset (frida_<ver>_iphoneos-arm64.deb) and hash
#   the .deb file directly (no decompression):
#        sha256sum frida_<ver>_iphoneos-arm64.deb
#   then add: FRIDA_SERVER_SHA256[('<ver>', 'ios-arm64')] = '<hex>'
#
# These digests are sourced from the official Frida GitHub release assets at
# https://github.com/frida/frida/releases ; verify them against that source
# before committing. Once entries exist for the live version, set
# MOBSF_FRIDA_VERIFY=1 to enforce them.
# ---------------------------------------------------------------------------
FRIDA_SERVER_SHA256 = {
    # ('<frida_version>', '<arch_key>'): '<sha256-hex>',
    # No vetted digests are shipped yet — populate using the steps above.
}


def _sha256_of_file(path):
    """Return the SHA-256 hex digest of the given file."""
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(65536), b''):
            h.update(chunk)
    return h.hexdigest()


class FridaServerUpdater:
    """Class for managing Frida server updates and downloads."""

    def __init__(self, platform, version):
        """Initialize the FridaServerUpdater.

        Args:
            platform (str): The platform ('android' or 'ios')
            version (str): The Frida version to manage
        """
        self.download_dir = Path(settings.DWD_DIR)
        self.platform = platform
        self.version = version
        # Optional pre-bundled binaries shipped with the repo.
        self.bundled_dir = (
            Path(__file__).resolve().parents[3]
            / 'tools' / 'onDevice' / 'frida-server'
        )

    def clean_up_old_binaries(self):
        """Delete old Frida server binaries."""
        if self.platform == 'android':
            file_pattern = 'frida-server*'
        else:
            file_pattern = 'frida_*'
        for f in self.download_dir.glob(file_pattern):
            if f.is_file() and self.version not in f.name:
                try:
                    f.unlink()
                except Exception:
                    pass

    def _verify_sha256(self, arch, file_path):
        """Verify the downloaded/copied binary against the pinned SHA-256.

        The expected digest is looked up by (frida_version, arch) so that an
        unpinned/upgraded frida package can never match a stale hash.

        Behaviour when no digest is pinned for the running version+arch:
          - settings.FRIDA_VERIFY is False (default, MOBSF_FRIDA_VERIFY=0):
            log a LOUD warning and continue (backwards-compatible).
          - settings.FRIDA_VERIFY is True (MOBSF_FRIDA_VERIFY=1): delete the
            unverified file and raise RuntimeError (fail-closed).

        Raises RuntimeError on an explicit mismatch regardless of the setting.
        """
        expected = FRIDA_SERVER_SHA256.get((self.version, arch), '')
        if not expected:
            # No vetted digest for this exact version+arch.
            fail_closed = getattr(settings, 'FRIDA_VERIFY', False)
            msg = (
                'SECURITY: no pinned SHA-256 for Frida server '
                f'v{self.version} ({arch}); integrity of {file_path} is '
                'UNVERIFIED. Populate FRIDA_SERVER_SHA256 in '
                'server_update.py (see the inline procedure) to enable '
                'verification.')
            if fail_closed:
                try:
                    Path(file_path).unlink()
                except Exception:
                    pass
                raise RuntimeError(
                    f'{msg} Refusing to use an unverified binary because '
                    'MOBSF_FRIDA_VERIFY=1 (fail-closed).')
            logger.warning(
                '%s Running it anyway because MOBSF_FRIDA_VERIFY is not set; '
                'set MOBSF_FRIDA_VERIFY=1 to fail closed.', msg)
            return
        actual = _sha256_of_file(file_path)
        if actual.lower() != expected.lower():
            try:
                Path(file_path).unlink()
            except Exception:
                pass
            raise RuntimeError(
                f'Frida server SHA-256 mismatch for v{self.version} ({arch}): '
                f'expected {expected}, got {actual}. Refusing to use binary.')
        logger.info(
            'Verified Frida server v%s (%s) SHA-256 OK.',
            self.version, arch)

    def _try_bundled(self, arch, fserver):
        """If a vetted binary is shipped under tools/onDevice/frida-server/,
        copy it into DWD_DIR and verify SHA-256. Returns True on success."""
        if not self.bundled_dir.is_dir():
            return False
        candidate = self.bundled_dir / fserver
        if not candidate.is_file():
            return False
        dest = self.download_dir / fserver
        try:
            shutil.copyfile(candidate, dest)
        except Exception:
            logger.exception(
                '[ERROR] Copying bundled Frida server binary %s', fserver)
            return False
        # Will raise RuntimeError on mismatch — surface to caller.
        self._verify_sha256(arch, dest)
        self.clean_up_old_binaries()
        logger.info(
            'Using pre-bundled Frida server v%s for %s', self.version, arch)
        return True

    def download_frida_server(self, url, fname, proxies, verify):
        """Download Frida server binary.

        Raises on failure so the UI/caller can surface a clear error instead
        of silently returning False.
        """
        dwd_loc = self.download_dir / fname
        try:
            logger.info(
                'Downloading Frida server v%s binary: %s',
                self.version, fname)

            with requests.get(
                    url,
                    timeout=15,
                    proxies=proxies,
                    verify=verify,
                    stream=True) as r:
                r.raise_for_status()

                with open(dwd_loc, 'wb') as f:
                    if fname.endswith('.deb'):
                        copyfileobj(r.raw, f)
                    else:
                        copyfileobj(LZMAFile(r.raw), f)

            self.clean_up_old_binaries()
            return True

        except Exception:
            logger.exception(
                '[ERROR] Downloading Frida Server v%s Binary', self.version)
            # Clean up partial download
            try:
                dwd_loc.unlink()
            except Exception:
                pass
            # Surface the failure to the UI/caller.
            raise

    def update_frida_server(self, arch):
        """Update/download Frida server for the given architecture.

        Returns True on success. Raises RuntimeError (or the underlying
        requests/IO exception) on failure so the UI layer can render a
        meaningful error to the user.
        """
        if self.platform == 'android':
            fserver = f'frida-server-{self.version}-{self.platform}-{arch}'
            sha_key = arch
        else:
            fserver = f'frida_{self.version}_{self.platform}-{arch}.deb'
            sha_key = f'ios-{arch}'
        frida_bin = self.download_dir / fserver
        if frida_bin.is_file():
            # File already present — still verify integrity if pinned.
            try:
                self._verify_sha256(sha_key, frida_bin)
            except RuntimeError:
                logger.exception(
                    'Existing Frida server binary failed SHA-256 check; '
                    'will attempt re-download.')
            else:
                return True
        # Prefer a vetted, repo-bundled binary if one is shipped.
        if self._try_bundled(sha_key, fserver):
            return True
        if not is_internet_available():
            raise RuntimeError(
                'No internet connectivity and no pre-bundled Frida server '
                f'available for {self.platform}-{arch}. Place the binary at '
                f'{self.download_dir / fserver} or under '
                f'{self.bundled_dir}/.')
        try:
            proxies, verify = upstream_proxy('https')
        except Exception:
            logger.exception('[ERROR] Setting upstream proxy')
            proxies, verify = None, True

        try:
            # Get Frida release asset urls
            response = requests.get(
                f'{settings.FRIDA_SERVER}{self.version}',
                timeout=5,
                proxies=proxies,
                verify=verify,
            )
            response.raise_for_status()

            # Find the correct binary
            if self.platform == 'android':
                asset = f'{fserver}.xz'
            else:
                asset = fserver
            for item in response.json()['assets']:
                if item['name'] == asset:
                    self.download_frida_server(
                        item['browser_download_url'],
                        fserver, proxies, verify,
                    )
                    # Verify after download — raises on mismatch.
                    self._verify_sha256(sha_key, frida_bin)
                    return True

            raise RuntimeError(
                f'Frida server v{self.version} binary not found for '
                f'platform: {self.platform}, architecture: {arch}')

        except RuntimeError:
            raise
        except Exception as exc:
            logger.exception(
                '[ERROR] Fetching Frida Server v%s Release', self.version)
            raise RuntimeError(
                f'Failed to fetch Frida server v{self.version} release '
                f'for {self.platform}-{arch}: {exc}') from exc
