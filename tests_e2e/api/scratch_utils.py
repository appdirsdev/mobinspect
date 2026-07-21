"""Scratch-file helpers for API specs that must upload/scan/delete/suppress.

Per ``tests_e2e/README.md``'s "never mutate a shared fixture" rule, any spec
that mutates state (uploads a new scan, deletes one, suppresses a finding)
must do so against a private, throwaway copy of a real fixture file, never
against ``fixtures.data.SCANNED[...]`` directly (those hashes are relied on
read-only by many other specs).

A plain APK is unsuitable as the scratch source for anything beyond a
byte-identical duplicate-detection check: ``scanning.find_duplicate_scan``'s
"Layer 2" re-parses any ``.apk``'s manifest for (package, versionName) and
rejects a same-version rebuild as a 409 duplicate even when its MD5 differs
(see ``mobinspect/MobInspect/views/scanning.py``). Appending a random suffix
to ``android.apk`` therefore still collides with the already-scanned Diva
fixture. ``android_src.zip`` (an Android *source* zip, scan_type ``zip``) is
not subject to that layer, produces the same rich report shape (manifest/
permissions/certificate analysis) once scanned, and is the safe default here.
"""
import os
import time
import uuid

from tests_e2e.fixtures.data import TEST_FILES_DIR

SCRATCH_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.scratch')


def make_scratch_copy(source_file_name='android_src.zip', suffix=None):
    """Write a byte-unique copy of a real ``test_files/`` fixture.

    Returns the scratch file's absolute path. Caller is responsible for
    ``os.remove``-ing it (typically in a ``finally`` block).
    """
    os.makedirs(SCRATCH_DIR, exist_ok=True)
    src = os.path.join(TEST_FILES_DIR, source_file_name)
    with open(src, 'rb') as fh:
        payload = fh.read()
    payload += f'e2e-scratch-{suffix or uuid.uuid4().hex}'.encode()
    ext = os.path.splitext(source_file_name)[1]
    scratch_path = os.path.join(SCRATCH_DIR, f'scratch_{uuid.uuid4().hex[:12]}{ext}')
    with open(scratch_path, 'wb') as fh:
        fh.write(payload)
    return scratch_path


def cleanup_scratch_file(path):
    try:
        os.remove(path)
    except OSError:
        pass


def poll_report_json(api_client, file_hash, timeout=180, interval=4):
    """Poll ``report_json`` until ``app_name`` is populated (scan complete).

    Async scans are processed by ``manage.py qcluster`` in the background;
    this bounds how long a spec waits for that worker rather than assuming
    instant completion. Returns the final ``ApiResponse``. Raises
    ``AssertionError`` if the scan never completes within ``timeout``
    seconds.
    """
    deadline = time.time() + timeout
    last_response = None
    while time.time() < deadline:
        last_response = api_client.report_json(file_hash)
        if last_response.status_code == 200:
            body = last_response.json()
            if body.get('app_name'):
                return last_response
        time.sleep(interval)
    raise AssertionError(
        f'Scan for {file_hash} did not complete within {timeout}s '
        f'(last status={last_response.status_code if last_response else None}, '
        f'body={last_response.json() if last_response and last_response.headers.get("content-type", "").startswith("application/json") else None})')
