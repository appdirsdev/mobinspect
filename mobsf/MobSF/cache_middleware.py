"""
MobInspect — no-store cache-control middleware.

Every dynamically-rendered response carries a CSRF token tied to the
current session. Without an explicit Cache-Control header, browsers are
free to serve a stale cached copy of a page (most commonly via
back-forward-cache after using the Back button) that embeds an outdated
token — the next form submit or JS-driven POST/fetch from that stale page
then fails with "CSRF verification failed. Request aborted.", even though
the user is genuinely logged in and nothing is actually wrong with their
session. This is a well-known Django/CSRF gotcha, not a security bug in
the token check itself.

Static assets are unaffected: whitenoise already sets its own
Cache-Control on those responses, so this middleware only fills in the
header where one isn't already present.
"""


class NoStoreCacheMiddleware:
    """Mark every dynamic response no-store so browsers (and bfcache) never
    serve a stale page carrying an outdated CSRF token."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        if 'Cache-Control' not in response:
            response['Cache-Control'] = 'no-store, no-cache, must-revalidate'
        return response
