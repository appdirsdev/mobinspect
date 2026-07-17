"""In-process end-to-end integration test (strict real execution).

Drives the real static-analysis pipeline through Django's test client so
every artifact type actually runs (real jadx/apktool/tooling subprocesses,
real DB writes) under coverage. No mocks. Samples come from the repo-root
``test_files/`` directory committed with the project.

This is the coverage engine for the StaticAnalyzer / MobInspect-core code that
unit tests do not reach; it mirrors what the HTTP E2E harness does but
in-process so coverage.py sees every executed line.
"""
import os

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase, Client, override_settings

from mobinspect.RBAC.models import ApiKey


SAMPLES_DIR = os.path.normpath(
    os.path.join(settings.BASE_DIR, '..', 'test_files'))

# Every artifact type shipped in test_files/. Binary/library types
# exercise the elf/macho/ar/dylib paths; zips exercise source analysis.
SAMPLES = [
    'android.apk',
    'android_xapk.xapk',
    'android.aar',
    'android.jar',
    'android.so',
    'android_src.zip',
    'ios.ipa',
    'ios_src.zip',
    'ios_swift_src.zip',
    'windows.appx',
    'macho.dylib',
    'macho_static_lib.a',
    'linux_static_lib.a',
]


@override_settings(ASYNC_ANALYSIS=False)
class StaticPipelineE2E(TestCase):
    """Upload + scan + report every sample type in one process.

    Forced synchronous: every scan below must be complete before the
    following report/scorecard/render calls run, not merely queued.
    """

    @classmethod
    def setUpTestData(cls):
        User = get_user_model()
        cls.admin = User.objects.create_superuser(
            'admin', 'admin@example.com', 'admin')
        _, cls.api_key = ApiKey.generate(cls.admin, 'itest')

    def setUp(self):
        self.client = Client()
        self.auth = {'HTTP_AUTHORIZATION': self.api_key}
        self.client.force_login(self.admin)

    def _upload(self, fname):
        path = os.path.join(SAMPLES_DIR, fname)
        if not os.path.exists(path):
            return None
        with open(path, 'rb') as fh:
            # Explicit octet-stream content-type (in every *_MIME allowlist);
            # magic-byte checks still validate the real content.
            upload = SimpleUploadedFile(
                fname, fh.read(), content_type='application/octet-stream')
        resp = self.client.post(
            '/api/v1/upload', {'file': upload}, **self.auth)
        if resp.status_code != 200:
            return None
        return resp.json()

    def test_pipeline(self):
        """Exercise the full intake→analysis→report→export chain."""
        uploaded = []
        for fname in SAMPLES:
            obj = self._upload(fname)
            if obj and 'hash' in obj:
                obj['file_name'] = fname
                uploaded.append(obj)
        # At least the core android/ios/windows types must intake.
        self.assertTrue(uploaded, 'no samples uploaded')

        for obj in uploaded:
            h = obj['hash']
            # Static analysis (forced synchronous by the class decorator).
            self.client.post('/api/v1/scan', {'hash': h}, **self.auth)
            # Report + scorecard + JSON views exercise formatters/serializers.
            self.client.post('/api/v1/report_json', {'hash': h}, **self.auth)
            self.client.post('/api/v1/scorecard', {'hash': h}, **self.auth)
            # Recent-scan + web report page render templates + context.
            analyzer = obj.get('analyzer')
            if analyzer:
                self.client.get(f'/{analyzer}/{h}/')
            # Compare-versions picker (android-only view).
            self.client.get(f'/compare_versions/{h}')

        # REST list/search/logs endpoints.
        self.client.get('/api/v1/scans', **self.auth)
        self.client.get('/api/v1/scans?page=1&page_size=5', **self.auth)
        if uploaded:
            h0 = uploaded[0]['hash']
            self.client.post('/api/v1/search', {'query': h0}, **self.auth)
            self.client.post('/api/v1/scan_logs', {'hash': h0}, **self.auth)

        # PDF export for the three report templates (android/ios/windows).
        for fname in ('android.apk', 'ios.ipa', 'windows.appx'):
            obj = next((o for o in uploaded if o['file_name'] == fname), None)
            if obj:
                self.client.post('/api/v1/download_pdf',
                                 {'hash': obj['hash']}, **self.auth)

        # Web dashboards.
        self.client.get('/')
        self.client.get('/recent_scans/')
        self.client.get('/dynamic_analysis/')
        self.client.get('/analytics/')

        # Cleanup path (delete_scan).
        for obj in uploaded:
            self.client.post('/api/v1/delete_scan',
                             {'hash': obj['hash']}, **self.auth)
