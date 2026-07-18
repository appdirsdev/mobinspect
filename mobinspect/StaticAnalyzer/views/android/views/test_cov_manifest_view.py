# -*- coding: utf_8 -*-
"""Real-execution (no-mock) coverage tests for views/manifest_view.py.

Drives the real, login_required-decorated run() view directly via
RequestFactory + a real authenticated user (same convention as the
sibling test_cov_view_source.py / test_cov_find.py), with a real
AndroidManifest.xml written under an isolated (override_settings)
UPLD_DIR.
"""
import tempfile
from pathlib import Path

from django.contrib.auth import get_user_model
from django.test import RequestFactory, TestCase, override_settings

# Importing static_analyzer registers the 'key'/'android_component'/etc.
# template filters used by general/view.html as a module-import side
# effect. Calling manifest_view.run() directly (bypassing the URL
# dispatcher, which would import it as part of urls.py) means those
# filters are otherwise never registered in this test's process.
import mobinspect.StaticAnalyzer.views.android.static_analyzer  # noqa: F401
from mobinspect.StaticAnalyzer.views.android.views.manifest_view import run

TMP_UPLD = tempfile.mkdtemp(prefix='mobinspect_manview_')


@override_settings(UPLD_DIR=TMP_UPLD)
class ManifestViewRunTests(TestCase):

    @classmethod
    def setUpTestData(cls):
        User = get_user_model()
        cls.user = User.objects.create_superuser(
            'cov_manview_user', 'manview@example.com', 'pw')

    def setUp(self):
        self.factory = RequestFactory()

    def _get(self, checksum, typ):
        req = self.factory.get('/manifest_view/x/', {'type': typ})
        req.user = self.user
        return run(req, checksum)

    def test_real_manifest_renders(self):
        # Use typ='aar': get_manifest_file()'s AAR branch reads
        # <app_dir>/AndroidManifest.xml directly (no apktool subprocess
        # needed), so this exercises the real manifest_file.exists()
        # -> read_text() success branch (unlike typ='apk', which looks
        # under apktool_out/ and would require running real apktool on a
        # crafted, real apk to populate it).
        checksum = '1' * 32
        app_dir = Path(TMP_UPLD) / checksum
        app_dir.mkdir(parents=True)
        (app_dir / 'AndroidManifest.xml').write_text(
            '<manifest package="com.example"/>')
        resp = self._get(checksum, 'aar')
        self.assertEqual(resp.status_code, 200)

    def test_missing_manifest_file_uses_empty_string(self):
        checksum = '2' * 32
        (Path(TMP_UPLD) / checksum).mkdir(parents=True)
        resp = self._get(checksum, 'apk')
        self.assertEqual(resp.status_code, 200)

    def test_invalid_checksum_or_type_returns_none(self):
        # Neither is_md5(checksum) nor typ-in-supported holds -> the `if`
        # body never runs and the function implicitly returns None (no
        # explicit else / early error response for this combination).
        self.assertIsNone(self._get('not-an-md5', 'apk'))
        self.assertIsNone(self._get('3' * 32, 'not-a-supported-type'))

    def test_missing_type_param_hits_exception_handler(self):
        req = self.factory.get('/manifest_view/x/')
        req.user = self.user
        resp = run(req, '4' * 32)
        self.assertEqual(resp.status_code, 500)
