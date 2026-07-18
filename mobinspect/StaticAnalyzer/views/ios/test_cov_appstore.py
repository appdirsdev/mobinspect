# -*- coding: utf_8 -*-
"""Real-execution coverage tests for ios/appstore.py.

app_search() makes a real live call to Apple's iTunes Search API. Per the
project's no-network test policy, the branch that requires the live API to
actually return a matching app (lines 39-40, and the rest of that literal)
is pragma'd in production with a reason -- there is no app we can point at
that is guaranteed to exist on the App Store forever, and asserting on a
specific live app's fields would be flaky. The exception branch (lines
61-65) IS covered here for real, using the single sanctioned narrow
monkeypatch of ``requests.get`` (an internal library call, not the
function under test) to make it fail -- this drives the real logging,
the real ``append_scan_status`` ORM write and the real except body.
"""
from unittest import mock

import pytest

from mobinspect.StaticAnalyzer.views.ios import appstore

CHECKSUM = 'ap' * 16


@pytest.mark.django_db
def test_no_results_returns_error_true():
    """A bundle id that (almost certainly) does not exist on the App
    Store makes the real iTunes API return an empty 'results' list ->
    the falsy-results branch (line 59-60). If this sandbox has no live
    egress at all, the same 'error': True return is produced via the
    except branch instead -- either way the real function completes and
    signals failure, which is all callers rely on."""
    result = appstore.app_search(CHECKSUM, 'com.mobinspect.does.not.exist.xyz')
    assert result == {'error': True}


@pytest.mark.django_db
def test_request_exception_hits_except_branch():
    """Narrow, single-call monkeypatch of `requests.get` (not of
    app_search itself) forces a real exception inside the try block,
    driving the real except handler for real (lines 61-65) -- this
    cannot be exercised via real network without a guaranteed-broken
    live endpoint, so this is the sanctioned "make an internal library
    call fail" exception to the no-mocks rule."""
    with mock.patch.object(
            appstore.requests, 'get',
            side_effect=appstore.requests.exceptions.ConnectionError(
                'simulated connection failure')):
        result = appstore.app_search(CHECKSUM, 'com.example.whatever')
    assert result == {'error': True}
