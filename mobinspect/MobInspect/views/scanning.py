# -*- coding: utf_8 -*-
import hashlib
import logging
import io
import os
import shutil

from django.conf import settings
from django.utils import timezone

from mobinspect.StaticAnalyzer.models import (
    RecentScansDB,
    StaticAnalyzerAndroid,
)
from mobinspect.MobInspect.security import sanitize_filename

logger = logging.getLogger(__name__)


def add_to_recent_scan(data):
    """Add Entry to Database under Recent Scan."""
    try:
        db_obj = RecentScansDB.objects.filter(MD5=data['hash'])
        if not db_obj.exists():
            new_db_obj = RecentScansDB(
                ANALYZER=data['analyzer'],
                SCAN_TYPE=data['scan_type'],
                FILE_NAME=data['file_name'],
                APP_NAME='',
                PACKAGE_NAME='',
                VERSION_NAME='',
                MD5=data['hash'],
                TIMESTAMP=timezone.now())
            new_db_obj.save()
    except Exception:
        logger.exception('Adding Scan URL to Database')


def handle_uploaded_file(content, extension):
    """Write Uploaded File."""
    md5 = hashlib.md5()
    bfr = isinstance(content, io.BufferedReader)
    if bfr:
        # Not File upload
        while chunk := content.read(8192):
            md5.update(chunk)
    else:
        # File upload
        for chunk in content.chunks():
            md5.update(chunk)
    md5sum = md5.hexdigest()
    anal_dir = os.path.join(settings.UPLD_DIR, md5sum + '/')
    if not os.path.exists(anal_dir):
        os.makedirs(anal_dir)
    with open(f'{anal_dir}{md5sum}{extension}', 'wb+') as destination:
        if bfr:
            content.seek(0, 0)
            while chunk := content.read(8192):
                destination.write(chunk)
        else:
            for chunk in content.chunks():
                destination.write(chunk)
    return md5sum


# ── Duplicate-upload detection ───────────────────────────────────────────────
# A re-upload of an app that was already scanned is rejected with a clear
# "Duplicate APK" error plus a pointer to the existing report, instead of
# silently re-opening the prior scan. Two layers, cheapest first:
#   1. Exact file      — identical bytes (same MD5). Applies to every type.
#   2. Package+version — a re-signed / rebuilt APK carrying the same Android
#      package name and versionName, even though its bytes differ. APK only.
# The version layer never blocks when the manifest can't be parsed, so a
# legitimate first upload is never rejected because of a parsing hiccup.

def scan_report_url(analyzer, md5):
    """Canonical ``/<analyzer>/<md5>/`` report URL, defaulting the analyzer."""
    return f'/{analyzer or "static_analyzer"}/{md5}/'


# Ceiling (bytes) on files we manifest-parse for the version-duplicate layer,
# so a very large or crafted upload can't tie up the request worker with a
# synchronous parse. Above it, only the exact-file (MD5) layer applies.
# androguard's ``APK()`` reads only the manifest/resources (never the DEX), so
# this is a defensive ceiling, not a hot path. Override via settings.
DUP_VERSION_MAX_BYTES_DEFAULT = 300 * 1024 * 1024


def _apk_package_version(file_path):
    """Return ``(package, version_name)`` for an APK, or ``('', '')``.

    Uses the bundled androguard to read the manifest. (``skip_analysis=True``
    would be cheaper, but that code path raises ``KeyError`` in the vendored
    androguard4, so we use the default parse — the same full parse already
    runs later during the scan, so this adds no new capability, only moves
    one parse slightly earlier.) Any failure degrades to ``('', '')`` so the
    caller falls back to the exact-file check rather than blocking the upload.

    NOTE: androguard's ``get_androidversion_name`` is compared against the
    stored ``VERSION_NAME`` (written from the scan-time manifest parse). The
    two agree for the vast majority of apps; a rare parser disagreement only
    causes a *miss* (the app is scanned again), never a wrong block — and the
    exact-bytes (MD5) layer still catches identical re-uploads.
    """
    try:
        from mobinspect.StaticAnalyzer.tools.androguard4 import apk
        a = apk.APK(file_path)
        if not a:
            return '', ''
        return (a.get_package() or '',
                a.get_androidversion_name() or '')
    except Exception:
        logger.warning(
            'Duplicate check: could not parse APK manifest at %s',
            file_path, exc_info=True)
        return '', ''


def _existing_scan_meta(md5):
    """Metadata dict for an existing RecentScansDB row, or ``None``."""
    row = RecentScansDB.objects.filter(MD5=md5).first()
    if not row:
        return None
    return {
        'hash': row.MD5,
        'url': scan_report_url(row.ANALYZER, row.MD5),
        'app_name': row.APP_NAME or row.FILE_NAME,
        'version_name': row.VERSION_NAME,
        'package_name': row.PACKAGE_NAME,
        'timestamp': row.TIMESTAMP,
    }


def find_duplicate_scan(md5, scan_type, file_path):
    """Return metadata for a prior scan of the same app, or ``None``.

    ``md5`` is the just-computed hash of the uploaded file (already written to
    ``file_path``). ``scan_type`` is the short type tag (``apk``, ``ipa``, …).
    """
    # Layer 1 — identical bytes already uploaded (any file type).
    exact = _existing_scan_meta(md5)
    if exact:
        return exact
    # Layer 2 — same Android package name + versionName (plain APK only).
    if scan_type != 'apk':
        return None
    # Bound the synchronous manifest parse (see DUP_VERSION_MAX_BYTES_DEFAULT).
    cap = getattr(settings, 'MOBINSPECT_DUP_VERSION_MAX_BYTES',
                  DUP_VERSION_MAX_BYTES_DEFAULT)
    try:
        if os.path.getsize(file_path) > cap:
            logger.info('Duplicate check: version layer skipped for %s '
                        '(file exceeds %d-byte cap)', md5, cap)
            return None
    except OSError:
        return None
    package, version = _apk_package_version(file_path)
    if not package or not version:
        return None
    dup_md5 = (StaticAnalyzerAndroid.objects
               .filter(PACKAGE_NAME=package, VERSION_NAME=version)
               .exclude(MD5=md5)
               .values_list('MD5', flat=True)
               .first())
    if not dup_md5:
        return None
    return _existing_scan_meta(dup_md5) or {
        'hash': dup_md5,
        'url': scan_report_url('static_analyzer', dup_md5),
        'app_name': '',
        'version_name': version,
        'package_name': package,
        'timestamp': None,
    }


def _remove_orphan_upload(md5):
    """Remove a freshly written upload dir IF nothing in the DB references it.

    Called only for a version-duplicate rejection, where the new bytes are a
    different build than the existing scan. Guard against the rare case where
    the identical file was previously scanned via the API (a StaticAnalyzer
    row with no RecentScansDB row) — never delete an upload backing a real
    scan.
    """
    try:
        # A StaticAnalyzer row (e.g. an API-scanned app with no RecentScansDB
        # row) means these bytes back a real scan — never delete their dir.
        # No RecentScansDB check is needed: this runs only when md5 differs
        # from the existing scan, which Layer 1 already proved has no
        # recent-scan row for md5.
        if StaticAnalyzerAndroid.objects.filter(MD5=md5).exists():
            return
        upload_dir = os.path.join(settings.UPLD_DIR, md5)
        if os.path.isdir(upload_dir):
            shutil.rmtree(upload_dir, ignore_errors=True)
    except Exception:
        logger.warning('Could not clean orphan upload dir for %s', md5)


# Human-readable labels per scan type. Layer 1 (identical bytes) fires for
# every type, so the duplicate message must not assume the upload is an APK.
TYPE_LABELS = {
    'apk': 'APK', 'xapk': 'XAPK', 'apks': 'split APK', 'aab': 'App Bundle',
    'jar': 'JAR', 'aar': 'AAR', 'so': 'shared object',
    'zip': 'source archive', 'ipa': 'IPA', 'dylib': 'dylib',
    'a': 'static library', 'appx': 'APPX',
}


def build_duplicate_response(data, existing, md5):
    """Build the duplicate-error payload and clean up an orphan upload.

    ``existing`` is the metadata dict from :func:`find_duplicate_scan`. When
    the new upload's bytes differ from the existing scan (a same-version
    rebuild), the freshly written upload dir has no DB row backing it — remove
    it so rejected uploads don't accumulate on disk. An exact-file re-upload
    (``md5 == existing['hash']``) shares the existing scan's dir, so it is
    left untouched.
    """
    kind = TYPE_LABELS.get(data.get('scan_type', ''), 'upload')
    name = existing['app_name'] or data['file_name']
    version = existing['version_name']
    when = (existing['timestamp'].strftime('%Y-%m-%d')
            if existing.get('timestamp') else '')
    description = f'Duplicate {kind} — "{name}"'
    if version:
        description += f' v{version}'
    description += ' was already scanned'
    if when:
        description += f' on {when}'
    description += '. Open the existing report instead.'
    if md5 != existing['hash']:
        _remove_orphan_upload(md5)
    # One envelope for both surfaces: the web XHR keys off ``status``, REST
    # clients off the HTTP status (409). ``hash`` points at the EXISTING scan
    # — the one the caller should open — so an ``upload -> scan`` client still
    # has a usable md5; ``error`` mirrors ``description`` for REST convention.
    return {
        'status': 'error',
        'duplicate': True,
        'description': description,
        'error': description,
        'hash': existing['hash'],
        'existing_hash': existing['hash'],
        'existing_url': existing['url'],
        'scan_type': data.get('scan_type', ''),
        'analyzer': data['analyzer'],
        'file_name': data['file_name'],
    }


class Scanning(object):

    def __init__(self, request):
        self.file = request.FILES['file']
        self.file_name = sanitize_filename(
            request.FILES['file'].name)
        self.data = {
            'analyzer': 'static_analyzer',
            'status': 'success',
            'hash': '',
            'scan_type': '',
            'file_name': self.file_name,
        }

    def _finalize(self, extension, scan_type, label,
                  analyzer='static_analyzer'):
        """Persist the upload, reject duplicates, register the recent scan.

        Writes the file, records its hash/type/analyzer, and checks whether
        the same app was already scanned (identical bytes, or — for a plain
        APK — the same package name + versionName). On a match, returns a
        duplicate-error payload; otherwise registers a fresh recent-scan row
        and returns the success payload.
        """
        md5 = handle_uploaded_file(self.file, extension)
        self.data['hash'] = md5
        self.data['scan_type'] = scan_type
        self.data['analyzer'] = analyzer
        file_path = os.path.join(settings.UPLD_DIR, md5, md5 + extension)
        existing = find_duplicate_scan(md5, scan_type, file_path)
        if existing:
            logger.info('%s upload rejected as duplicate of %s',
                        label, existing['hash'])
            return build_duplicate_response(self.data, existing, md5)
        add_to_recent_scan(self.data)
        logger.info('%s uploaded', label)
        return self.data

    def scan_apk(self):
        """Android APK."""
        return self._finalize('.apk', 'apk', 'Android APK')

    def scan_xapk(self):
        """Android XAPK."""
        return self._finalize('.xapk', 'xapk', 'Android XAPK')

    def scan_apks(self):
        """Android Split APK."""
        return self._finalize('.apk', 'apks', 'Android Split APK')

    def scan_aab(self):
        """Android App Bundle."""
        return self._finalize('.aab', 'aab', 'Android App Bundle')

    def scan_jar(self):
        """Java JAR file."""
        return self._finalize('.jar', 'jar', 'Java JAR')

    def scan_aar(self):
        """Android AAR file."""
        return self._finalize('.aar', 'aar', 'Android AAR')

    def scan_so(self):
        """Shared object file."""
        return self._finalize('.so', 'so', 'Shared Object Library')

    def scan_zip(self):
        """Android /iOS Zipped Source."""
        return self._finalize('.zip', 'zip', 'Android/iOS Source code ZIP')

    def scan_ipa(self):
        """IOS Binary."""
        return self._finalize(
            '.ipa', 'ipa', 'iOS IPA', analyzer='static_analyzer_ios')

    def scan_dylib(self):
        """IOS Dylib."""
        return self._finalize(
            '.dylib', 'dylib', 'iOS dylib', analyzer='static_analyzer_ios')

    def scan_a(self):
        """Scan static library."""
        return self._finalize(
            '.a', 'a', 'Static Library', analyzer='static_analyzer_ios')

    def scan_appx(self):
        """Windows appx."""
        return self._finalize(
            '.appx', 'appx', 'Windows APPX',
            analyzer='static_analyzer_windows')
