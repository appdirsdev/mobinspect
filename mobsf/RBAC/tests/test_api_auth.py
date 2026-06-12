"""
Integration smoke tests for AUDIT C1 — API auth bypass via @permission_required.

History: `permission_required` previously short-circuited when the wrapped
view received `api=True`, which meant any holder of a valid API key
(including a Viewer-role user) could invoke DELETE-scoped endpoints. This
test pins the fix: a Viewer hitting `/api/v1/delete_scan` MUST get 403.

The test is intentionally narrow — full RBAC coverage is tracked
separately. Expand as new endpoints are hardened.
"""
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.test import TestCase, Client, override_settings

from mobsf.MobSF.views.authorization import VIEWER_GROUP
from mobsf.RBAC.models import ApiKey, Role, RoleAssignment


@override_settings(
    # Make sure the kill-switch is OFF so we actually exercise the
    # permission check (default in prod is unset == off, but be explicit
    # so the test is independent of the runner's environment).
    DISABLE_AUTHENTICATION=None,
    # Disable per-IP rate limits — the test client hits endpoints in a
    # tight loop and shouldn't get 429'd.
    RATELIMIT_ENABLE=False,
)
class ApiAuthBypassSmokeTest(TestCase):
    """Pin the C1 fix: Viewer API key cannot call delete_scan."""

    DELETE_URL = '/api/v1/delete_scan'

    def setUp(self):
        User = get_user_model()
        self.viewer = User.objects.create_user(
            username='viewer_smoke',
            password='irrelevant-not-used-by-api',
        )
        # Ensure the legacy Viewer Django group exists and is attached.
        # (RBAC migrations seed this in prod; tests run on a fresh DB.)
        viewer_group, _ = Group.objects.get_or_create(name=VIEWER_GROUP)
        self.viewer.groups.add(viewer_group)
        # Grant the user the MobInspect "Viewer" role plus the standalone
        # `api.use` permission. Without `api.use` the new middleware-level
        # API gate would 403 before per-view authorization runs and the
        # test would conflate two distinct denials; we want to pin that
        # the per-view `scan.delete` check is the one rejecting.
        viewer_role = Role.objects.filter(name='Viewer').first()
        if viewer_role is not None:
            from mobsf.RBAC.models import Permission as MIPerm
            api_use = MIPerm.objects.filter(codename='api.use').first()
            if api_use is not None:
                viewer_role.permissions.add(api_use)
            RoleAssignment.objects.get_or_create(
                user=self.viewer, role=viewer_role,
            )

        # Mint a per-user API key. ApiKey.generate returns
        # (instance, plaintext); we only need the plaintext for headers.
        _api_obj, self.viewer_key = ApiKey.generate(
            user=self.viewer,
            name='smoke-test',
        )
        self.client = Client()

    def test_viewer_cannot_delete_scan(self):
        """Viewer (no DELETE permission) must get 403 from delete_scan."""
        resp = self.client.post(
            self.DELETE_URL,
            data={'hash': '0' * 32},  # well-formed MD5, scan doesn't exist
            HTTP_X_MOBSF_API_KEY=self.viewer_key,
        )
        self.assertEqual(
            resp.status_code, 403,
            msg=(
                f'Expected 403 for Viewer hitting {self.DELETE_URL}; '
                f'got {resp.status_code}. Body: {resp.content!r}. '
                f'Regression of AUDIT C1 — permission_required must '
                f'enforce regardless of the `api` flag.'
            ),
        )
        # JSON shape contract: {'status': 'denied', 'message': '...'}
        # We only assert the status field — the message text is allowed
        # to evolve.
        import json
        payload = json.loads(resp.content.decode('utf-8'))
        self.assertEqual(payload.get('status'), 'denied')

    def test_unauthenticated_request_is_401(self):
        """Sanity check: no API key still 401s at the middleware layer.

        Guards against accidentally weakening the outer auth layer while
        fixing the inner authorization layer.
        """
        resp = self.client.post(
            self.DELETE_URL,
            data={'hash': '0' * 32},
        )
        self.assertEqual(resp.status_code, 401)

    def test_viewer_can_hit_recent_scans(self):
        """Viewer (with scan.view) can GET /api/v1/scans (H17).

        Positive-case pair to test_viewer_cannot_delete_scan — proves
        the per-view permission gate is granular, not a blanket reject
        on every /api/ endpoint for non-admin keys.

        We accept any 2xx as success; the exact body shape is owned by
        RecentScans.recent_scans() and not part of the auth contract.
        """
        resp = self.client.get(
            '/api/v1/scans',
            HTTP_X_MOBSF_API_KEY=self.viewer_key,
        )
        self.assertLess(
            resp.status_code, 400,
            msg=(
                f'Viewer with scan.view must reach /api/v1/scans; '
                f'got {resp.status_code}. Body: {resp.content!r}'
            ),
        )
