# -*- coding: utf_8 -*-
"""Real-execution coverage tests for suppression logic.

STRICT: no mocks. Drives the real view functions and helpers with a real
SQLite test DB (via pytest-django), real ORM rows, and real
RequestFactory POST requests. Views are invoked with ``api=True`` so
they return plain dicts (the API response shape) and so the
``login_required`` decorator forwards directly; the ``permission_required``
decorator is satisfied with a real staff user attached to the request.
"""
import pytest

from django.test import RequestFactory

from mobinspect.StaticAnalyzer.models import (
    StaticAnalyzerAndroid,
    StaticAnalyzerIOS,
    SuppressFindings,
)
from mobinspect.StaticAnalyzer.views.common.suppression import (
    get_package,
    suppress_by_rule_id,
    suppress_by_files,
    list_suppressions,
    delete_suppression,
    process_suppression,
    process_suppression_manifest,
)

VALID_MD5 = 'a' * 32          # 32 hex chars -> passes is_md5
OTHER_MD5 = 'b' * 32
BAD_MD5 = 'not-a-real-md5'
PKG = 'com.example.app'


def _staff_user(django_user_model):
    # A superuser: represents an authorized admin. Needed because the
    # suppression views are gated by both the legacy permission_required
    # (SUPPRESS/DELETE) and, for list_suppressions, the RBAC
    # require_permission('scan.view') decorator — the latter only bypasses
    # for is_superuser, not is_staff.
    return django_user_model.objects.create_superuser(
        username='sup_staff', password='x')


def _post(user, **params):
    """Build a real POST request with an authenticated staff user."""
    req = RequestFactory().post('/suppress', data=params)
    req.user = user
    return req


def _android(md5=VALID_MD5, pkg=PKG, code_analysis=None):
    return StaticAnalyzerAndroid.objects.create(
        MD5=md5,
        PACKAGE_NAME=pkg,
        CODE_ANALYSIS=code_analysis if code_analysis is not None else {})


def _ios(md5=OTHER_MD5, bundle='com.example.ios', code_analysis=None):
    return StaticAnalyzerIOS.objects.create(
        MD5=md5,
        BUNDLE_ID=bundle,
        CODE_ANALYSIS=code_analysis if code_analysis is not None else {})


# ───────────────────────────────────────────── get_package

@pytest.mark.django_db
def test_get_package_android():
    _android()
    assert get_package(VALID_MD5) == PKG


@pytest.mark.django_db
def test_get_package_ios():
    _ios(md5=OTHER_MD5, bundle='com.example.ios')
    assert get_package(OTHER_MD5) == 'com.example.ios'


@pytest.mark.django_db
def test_get_package_none():
    assert get_package(VALID_MD5) is None


# ───────────────────────────────────────────── suppress_by_rule_id

@pytest.mark.django_db
def test_suppress_rule_invalid_md5(django_user_model):
    u = _staff_user(django_user_model)
    res = suppress_by_rule_id(
        _post(u, hash=BAD_MD5, rule='r1', type='code'), api=True)
    assert res['status'] == 'failed'
    assert res['message'] == 'Invalid Parameters'


@pytest.mark.django_db
def test_suppress_rule_no_package(django_user_model):
    u = _staff_user(django_user_model)
    res = suppress_by_rule_id(
        _post(u, hash=VALID_MD5, rule='r1', type='code'), api=True)
    assert res['message'] == 'Invalid Parameters'


@pytest.mark.django_db
def test_suppress_rule_attack_pattern(django_user_model):
    u = _staff_user(django_user_model)
    _android()
    res = suppress_by_rule_id(
        _post(u, hash=VALID_MD5, rule='r1;rm -rf', type='code'), api=True)
    assert res['message'] == 'Invalid Parameters'


@pytest.mark.django_db
def test_suppress_rule_bad_type(django_user_model):
    u = _staff_user(django_user_model)
    _android()
    res = suppress_by_rule_id(
        _post(u, hash=VALID_MD5, rule='r1', type='bogus'), api=True)
    assert res['message'] == 'Invalid Parameters'


@pytest.mark.django_db
def test_suppress_rule_create_then_update(django_user_model):
    u = _staff_user(django_user_model)
    _android()
    # Create record
    res = suppress_by_rule_id(
        _post(u, hash=VALID_MD5, rule='r1', type='code'), api=True)
    assert res == {'status': 'ok'}
    cfg = SuppressFindings.objects.get(PACKAGE_NAME=PKG, SUPPRESS_TYPE='code')
    from mobinspect.MobInspect.utils import python_list
    assert 'r1' in python_list(cfg.SUPPRESS_RULE_ID)

    # Update record: a new rule gets added
    suppress_by_rule_id(
        _post(u, hash=VALID_MD5, rule='r2', type='code'), api=True)
    cfg.refresh_from_db()
    rules = set(python_list(cfg.SUPPRESS_RULE_ID))
    assert rules == {'r1', 'r2'}

    # Update record: existing rule is a no-op (still ok, no duplicate)
    res = suppress_by_rule_id(
        _post(u, hash=VALID_MD5, rule='r2', type='code'), api=True)
    assert res == {'status': 'ok'}
    cfg.refresh_from_db()
    assert set(python_list(cfg.SUPPRESS_RULE_ID)) == {'r1', 'r2'}


@pytest.mark.django_db
def test_suppress_rule_web_uses_checksum_key(django_user_model):
    """Non-api path reads 'checksum' and returns an HttpResponse."""
    u = _staff_user(django_user_model)
    _android()
    res = suppress_by_rule_id(
        _post(u, checksum=VALID_MD5, rule='rw', type='manifest'), api=False)
    # HttpResponse with JSON body
    assert b'ok' in res.content


# ───────────────────────────────────────────── suppress_by_files

CODE_RES = {
    'ruleA': {'files': {'a/A.java': '1', 'b/B.java': '2'},
              'metadata': {'severity': 'high'}},
}


@pytest.mark.django_db
def test_suppress_files_invalid_md5(django_user_model):
    u = _staff_user(django_user_model)
    res = suppress_by_files(
        _post(u, hash=BAD_MD5, rule='ruleA'), api=True)
    assert res['message'] == 'Invalid Parameters'


@pytest.mark.django_db
def test_suppress_files_no_package(django_user_model):
    u = _staff_user(django_user_model)
    res = suppress_by_files(
        _post(u, hash=VALID_MD5, rule='ruleA'), api=True)
    assert res['message'] == 'Invalid Parameters'


@pytest.mark.django_db
def test_suppress_files_attack(django_user_model):
    u = _staff_user(django_user_model)
    _android(code_analysis=CODE_RES)
    res = suppress_by_files(
        _post(u, hash=VALID_MD5, rule='a && b'), api=True)
    assert res['message'] == 'Invalid Parameters'


@pytest.mark.django_db
def test_suppress_files_android_create_and_update(django_user_model):
    u = _staff_user(django_user_model)
    _android(code_analysis=CODE_RES)
    from mobinspect.MobInspect.utils import python_dict
    # Create
    res = suppress_by_files(
        _post(u, hash=VALID_MD5, rule='ruleA'), api=True)
    assert res == {'status': 'ok'}
    cfg = SuppressFindings.objects.get(PACKAGE_NAME=PKG, SUPPRESS_TYPE='code')
    files = python_dict(cfg.SUPPRESS_FILES)
    assert set(files['ruleA']) == {'a/A.java', 'b/B.java'}

    # Update: same rule already present -> merge old_files branch
    res = suppress_by_files(
        _post(u, hash=VALID_MD5, rule='ruleA'), api=True)
    assert res == {'status': 'ok'}
    cfg.refresh_from_db()
    files = python_dict(cfg.SUPPRESS_FILES)
    assert set(files['ruleA']) == {'a/A.java', 'b/B.java'}


@pytest.mark.django_db
def test_suppress_files_update_new_rule_key(django_user_model):
    u = _staff_user(django_user_model)
    _android(code_analysis={
        'ruleA': {'files': {'a/A.java': '1'}},
        'ruleB': {'files': {'c/C.java': '3'}},
    })
    from mobinspect.MobInspect.utils import python_dict
    suppress_by_files(_post(u, hash=VALID_MD5, rule='ruleA'), api=True)
    # Second, different rule -> 'rule not in old' branch adds a new key
    suppress_by_files(_post(u, hash=VALID_MD5, rule='ruleB'), api=True)
    cfg = SuppressFindings.objects.get(PACKAGE_NAME=PKG, SUPPRESS_TYPE='code')
    files = python_dict(cfg.SUPPRESS_FILES)
    assert files['ruleA'] == ['a/A.java']
    assert files['ruleB'] == ['c/C.java']


@pytest.mark.django_db
def test_suppress_files_ios_path(django_user_model):
    u = _staff_user(django_user_model)
    _ios(md5=VALID_MD5, bundle='com.ios.bundle', code_analysis={
        'iosRule': {'files': {'x/X.swift': '1'}},
    })
    from mobinspect.MobInspect.utils import python_dict
    res = suppress_by_files(
        _post(u, hash=VALID_MD5, rule='iosRule'), api=True)
    assert res == {'status': 'ok'}
    cfg = SuppressFindings.objects.get(
        PACKAGE_NAME='com.ios.bundle', SUPPRESS_TYPE='code')
    assert python_dict(cfg.SUPPRESS_FILES)['iosRule'] == ['x/X.swift']


# ───────────────────────────────────────────── list_suppressions

@pytest.mark.django_db
def test_list_invalid_md5(django_user_model):
    u = _staff_user(django_user_model)
    res = list_suppressions(_post(u, hash=BAD_MD5), api=True)
    assert res['message'] == 'Invalid Parameters'


@pytest.mark.django_db
def test_list_no_package(django_user_model):
    u = _staff_user(django_user_model)
    res = list_suppressions(_post(u, hash=VALID_MD5), api=True)
    assert res['message'] == 'Invalid Parameters'


@pytest.mark.django_db
def test_list_empty_when_no_configs(django_user_model):
    u = _staff_user(django_user_model)
    _android()
    res = list_suppressions(_post(u, hash=VALID_MD5), api=True)
    assert res['status'] == 'ok'
    assert res['message'] == []


@pytest.mark.django_db
def test_list_with_configs(django_user_model):
    u = _staff_user(django_user_model)
    _android()
    SuppressFindings.objects.create(
        PACKAGE_NAME=PKG,
        SUPPRESS_RULE_ID=['r1', 'r2'],
        SUPPRESS_FILES={'r1': ['a.java']},
        SUPPRESS_TYPE='code')
    res = list_suppressions(_post(u, hash=VALID_MD5), api=True)
    assert res['status'] == 'ok'
    assert len(res['message']) == 1
    row = res['message'][0]
    assert set(row['SUPPRESS_RULE_ID']) == {'r1', 'r2'}
    assert row['SUPPRESS_FILES'] == {'r1': ['a.java']}


# ───────────────────────────────────────────── delete_suppression

@pytest.mark.django_db
def test_delete_invalid_md5(django_user_model):
    u = _staff_user(django_user_model)
    res = delete_suppression(
        _post(u, hash=BAD_MD5, rule='r1', type='code'), api=True)
    assert res['message'] == 'Invalid Parameters'


@pytest.mark.django_db
def test_delete_bad_type(django_user_model):
    u = _staff_user(django_user_model)
    _android()
    res = delete_suppression(
        _post(u, hash=VALID_MD5, rule='r1', type='nope'), api=True)
    assert res['message'] == 'Invalid Parameters'


@pytest.mark.django_db
def test_delete_no_config_still_ok(django_user_model):
    u = _staff_user(django_user_model)
    _android()
    res = delete_suppression(
        _post(u, hash=VALID_MD5, rule='r1', type='code'), api=True)
    assert res == {'status': 'ok'}


@pytest.mark.django_db
def test_delete_kind_rule_only(django_user_model):
    u = _staff_user(django_user_model)
    _android()
    from mobinspect.MobInspect.utils import python_list, python_dict
    SuppressFindings.objects.create(
        PACKAGE_NAME=PKG,
        SUPPRESS_RULE_ID=['r1', 'r2'],
        SUPPRESS_FILES={'r1': ['a.java']},
        SUPPRESS_TYPE='code')
    res = delete_suppression(
        _post(u, hash=VALID_MD5, rule='r1', type='code', kind='rule'),
        api=True)
    assert res == {'status': 'ok'}
    cfg = SuppressFindings.objects.get(PACKAGE_NAME=PKG, SUPPRESS_TYPE='code')
    assert set(python_list(cfg.SUPPRESS_RULE_ID)) == {'r2'}
    # File store untouched because kind was scoped to 'rule'
    assert python_dict(cfg.SUPPRESS_FILES) == {'r1': ['a.java']}


@pytest.mark.django_db
def test_delete_kind_file_only(django_user_model):
    u = _staff_user(django_user_model)
    _android()
    from mobinspect.MobInspect.utils import python_list, python_dict
    SuppressFindings.objects.create(
        PACKAGE_NAME=PKG,
        SUPPRESS_RULE_ID=['r1'],
        SUPPRESS_FILES={'r1': ['a.java']},
        SUPPRESS_TYPE='code')
    res = delete_suppression(
        _post(u, hash=VALID_MD5, rule='r1', type='code', kind='file'),
        api=True)
    assert res == {'status': 'ok'}
    cfg = SuppressFindings.objects.get(PACKAGE_NAME=PKG, SUPPRESS_TYPE='code')
    # Rule store untouched, file store cleared for r1
    assert python_list(cfg.SUPPRESS_RULE_ID) == ['r1']
    assert python_dict(cfg.SUPPRESS_FILES) == {}


@pytest.mark.django_db
def test_delete_kind_none_removes_both(django_user_model):
    u = _staff_user(django_user_model)
    _android()
    from mobinspect.MobInspect.utils import python_list, python_dict
    SuppressFindings.objects.create(
        PACKAGE_NAME=PKG,
        SUPPRESS_RULE_ID=['r1', 'r2'],
        SUPPRESS_FILES={'r1': ['a.java'], 'r2': ['b.java']},
        SUPPRESS_TYPE='code')
    res = delete_suppression(
        _post(u, hash=VALID_MD5, rule='r1', type='code'), api=True)
    assert res == {'status': 'ok'}
    cfg = SuppressFindings.objects.get(PACKAGE_NAME=PKG, SUPPRESS_TYPE='code')
    assert set(python_list(cfg.SUPPRESS_RULE_ID)) == {'r2'}
    assert python_dict(cfg.SUPPRESS_FILES) == {'r2': ['b.java']}


@pytest.mark.django_db
def test_delete_web_uses_checksum_key(django_user_model):
    """Non-api delete reads 'checksum' -> HttpResponse."""
    u = _staff_user(django_user_model)
    _android()
    res = delete_suppression(
        _post(u, checksum=VALID_MD5, rule='r1', type='code'), api=False)
    assert b'ok' in res.content


@pytest.mark.django_db
def test_suppress_files_web_uses_checksum_key(django_user_model):
    u = _staff_user(django_user_model)
    _android(code_analysis={'ruleA': {'files': {'a/A.java': '1'}}})
    res = suppress_by_files(
        _post(u, checksum=VALID_MD5, rule='ruleA'), api=False)
    assert b'ok' in res.content


@pytest.mark.django_db
def test_list_web_uses_checksum_key(django_user_model):
    u = _staff_user(django_user_model)
    _android()
    res = list_suppressions(_post(u, checksum=VALID_MD5), api=False)
    assert b'ok' in res.content


# ───────────────────────────────────────────── process_suppression

@pytest.mark.django_db
def test_process_suppression_empty_data():
    out = process_suppression({}, PKG)
    assert out == {'findings': {}, 'summary': {}}


@pytest.mark.django_db
def test_process_suppression_no_filters_severity_counts():
    data = {
        'rh': {'metadata': {'severity': 'high'}, 'files': {'a': '1'}},
        'rw': {'metadata': {'severity': 'warning'}, 'files': {}},
        'ri': {'metadata': {'severity': 'info'}, 'files': {}},
        'rs': {'metadata': {'severity': 'secure'}, 'files': {}},
        'rg': {'metadata': {'severity': 'good'}, 'files': {}},
        'rios': {'severity': 'high', 'files': {}},   # iOS-style severity key
    }
    out = process_suppression(data, 'com.nofilter')
    assert out['findings'] == data
    s = out['summary']
    assert s['high'] == 2
    assert s['warning'] == 1
    assert s['info'] == 1
    assert s['secure'] == 2
    assert s['suppressed'] == 0


@pytest.mark.django_db
def test_process_suppression_filter_rules():
    SuppressFindings.objects.create(
        PACKAGE_NAME=PKG,
        SUPPRESS_RULE_ID=['rh'],
        SUPPRESS_FILES={},
        SUPPRESS_TYPE='code')
    data = {
        'rh': {'metadata': {'severity': 'high'}, 'files': {'a': '1'}},
        'rw': {'metadata': {'severity': 'warning'}, 'files': {'b': '2'}},
    }
    out = process_suppression(data, PKG)
    assert 'rh' not in out['findings']
    assert 'rw' in out['findings']
    assert out['summary']['suppressed'] == 1
    assert out['summary']['warning'] == 1


@pytest.mark.django_db
def test_process_suppression_filter_files_partial():
    SuppressFindings.objects.create(
        PACKAGE_NAME=PKG,
        SUPPRESS_RULE_ID=[],
        SUPPRESS_FILES={'rx': ['a/A.java']},
        SUPPRESS_TYPE='code')
    data = {
        'rx': {'metadata': {'severity': 'high'},
               'files': {'a/A.java': '1', 'b/B.java': '2'}},
    }
    out = process_suppression(data, PKG)
    # a/A.java removed, rule still present because b/B.java remains
    assert 'rx' in out['findings']
    assert 'a/A.java' not in out['findings']['rx']['files']
    assert 'b/B.java' in out['findings']['rx']['files']
    assert out['summary']['suppressed'] == 1
    assert out['summary']['high'] == 1


@pytest.mark.django_db
def test_process_suppression_filter_files_removes_rule():
    SuppressFindings.objects.create(
        PACKAGE_NAME=PKG,
        SUPPRESS_RULE_ID=[],
        SUPPRESS_FILES={'rx': ['a/A.java']},
        SUPPRESS_TYPE='code')
    data = {
        'rx': {'metadata': {'severity': 'high'},
               'files': {'a/A.java': '1'}},
    }
    out = process_suppression(data, PKG)
    # All files removed -> whole rule dropped from cleaned
    assert 'rx' not in out['findings']
    assert out['summary']['suppressed'] == 1
    assert out['summary']['high'] == 0


# ───────────────────────────────────────────── process_suppression_manifest

@pytest.mark.django_db
def test_process_suppression_filter_file_not_present():
    # Suppress list references a file that is NOT in the finding's files ->
    # exercises the 'rem_file not in filtered[k][files]' skip path.
    SuppressFindings.objects.create(
        PACKAGE_NAME=PKG,
        SUPPRESS_RULE_ID=[],
        SUPPRESS_FILES={'rx': ['ghost/Missing.java']},
        SUPPRESS_TYPE='code')
    data = {
        'rx': {'metadata': {'severity': 'warning'},
               'files': {'a/A.java': '1'}},
        # 'ry' has no entry in SUPPRESS_FILES -> exercises the
        # 'k not in filter_files.keys()' continue path.
        'ry': {'metadata': {'severity': 'info'},
               'files': {'z/Z.java': '9'}},
    }
    out = process_suppression(data, PKG)
    # Nothing removed, rule retained, no suppressions counted
    assert 'a/A.java' in out['findings']['rx']['files']
    assert 'ry' in out['findings']
    assert out['summary']['suppressed'] == 0
    assert out['summary']['warning'] == 1


@pytest.mark.django_db
def test_process_manifest_no_filters():
    data = [
        {'rule': 'a', 'title': 'Some Activity', 'severity': 'high'},
        {'rule': 'b', 'title': 'A Service', 'severity': 'warning'},
    ]
    out = process_suppression_manifest(data, 'com.nomanifest')
    assert out['manifest_findings'] == data
    assert out['manifest_summary']['high'] == 1
    assert out['manifest_summary']['warning'] == 1


@pytest.mark.django_db
def test_process_manifest_filter_rules():
    # android_component('Some Activity') -> 'activity_' so dynamic rule is
    # 'activity_a'; suppress exactly that.
    SuppressFindings.objects.create(
        PACKAGE_NAME=PKG,
        SUPPRESS_RULE_ID=['activity_a'],
        SUPPRESS_FILES={},
        SUPPRESS_TYPE='manifest')
    data = [
        {'rule': 'a', 'title': 'Some Activity', 'severity': 'high'},
        {'rule': 'b', 'title': 'A Service', 'severity': 'warning'},
    ]
    out = process_suppression_manifest(data, PKG)
    titles = [f['rule'] for f in out['manifest_findings']]
    assert titles == ['b']
    assert out['manifest_summary']['suppressed'] == 1
    assert out['manifest_summary']['warning'] == 1


@pytest.mark.django_db
def test_process_manifest_empty_filter_rules():
    SuppressFindings.objects.create(
        PACKAGE_NAME=PKG,
        SUPPRESS_RULE_ID=[],
        SUPPRESS_FILES={},
        SUPPRESS_TYPE='manifest')
    data = [{'rule': 'a', 'title': 'Some Activity', 'severity': 'high'}]
    out = process_suppression_manifest(data, PKG)
    assert out['manifest_findings'] == data
    assert out['manifest_summary']['high'] == 1


# ───────────────────────────────────────────── process_suppression_manifest:
# regression test for a fixed production bug. Line 349 of suppression.py
# used to read `elif ['severity'] == INFO:` (a list literal compared to a
# string), which is a typo for `elif i['severity'] == INFO:` (matching the
# HIGH/WARNING arms immediately above it). As originally written the
# comparison was ALWAYS False, so `summary[INFO]` could never be
# incremented by this function no matter what data was passed. This test
# proves the fix (real execution, not a workaround): an INFO-severity
# manifest finding IS now counted.
@pytest.mark.django_db
def test_process_manifest_info_severity_is_counted():
    data = [{'rule': 'a', 'title': 'Some Activity', 'severity': 'info'}]
    out = process_suppression_manifest(data, 'com.infobug')
    assert out['manifest_findings'] == data
    # This is 1 now that the elif compares `i['severity']` like its
    # siblings -- see suppression.py line 350 (formerly unreachable).
    assert out['manifest_summary']['info'] == 1


# ───────────────────────────────────────────── generic except-Exception guards
#
# Each of the four AJAX views below wraps its body in try/except Exception
# as a last-resort safety net. Reaching that arm (as opposed to the
# explicit `invalid_params`/validation returns already covered above)
# requires an unexpected failure from a call the view does not otherwise
# guard against -- `SuppressFindings.objects.create/filter` genuinely
# raising is not producible through any real input (the model has no
# unique/not-null constraints to violate), so a single, narrow patch of
# that ORM call (named per test) stands in for "some unexpected internal
# failure", exactly the scenario the bare `except Exception:` exists for.
@pytest.mark.django_db
def test_suppress_rule_generic_exception_guard(django_user_model, monkeypatch):
    u = _staff_user(django_user_model)
    _android()
    monkeypatch.setattr(
        SuppressFindings.objects, 'create',
        lambda **kw: (_ for _ in ()).throw(RuntimeError('simulated DB failure')))
    res = suppress_by_rule_id(
        _post(u, hash=VALID_MD5, rule='r1', type='code'), api=True)
    assert res == {
        'status': 'failed',
        'message': 'Failed to suppress finding by rule id'}


@pytest.mark.django_db
def test_suppress_files_generic_exception_guard(django_user_model, monkeypatch):
    u = _staff_user(django_user_model)
    _android(code_analysis=CODE_RES)
    monkeypatch.setattr(
        SuppressFindings.objects, 'create',
        lambda **kw: (_ for _ in ()).throw(RuntimeError('simulated DB failure')))
    res = suppress_by_files(
        _post(u, hash=VALID_MD5, rule='ruleA'), api=True)
    assert res == {
        'status': 'failed',
        'message': 'Failed to suppress finding by files'}


@pytest.mark.django_db
def test_list_suppressions_generic_exception_guard(django_user_model, monkeypatch):
    u = _staff_user(django_user_model)
    _android()
    monkeypatch.setattr(
        SuppressFindings.objects, 'filter',
        lambda **kw: (_ for _ in ()).throw(RuntimeError('simulated DB failure')))
    res = list_suppressions(_post(u, hash=VALID_MD5), api=True)
    # NOTE: by the time the patched call raises, list_suppressions() has
    # already reassigned its local `data` from the initial failure dict to
    # `[]` (in preparation for the success path) -- the except block
    # returns whatever `data` currently holds, which is `[]` here, not the
    # original dict. This differs from the other three views (their
    # `data` dict is never reassigned before the point of failure).
    assert res == []


@pytest.mark.django_db
def test_delete_suppression_generic_exception_guard(django_user_model, monkeypatch):
    u = _staff_user(django_user_model)
    _android()
    monkeypatch.setattr(
        SuppressFindings.objects, 'filter',
        lambda **kw: (_ for _ in ()).throw(RuntimeError('simulated DB failure')))
    res = delete_suppression(
        _post(u, hash=VALID_MD5, rule='r1', type='code'), api=True)
    assert res == {
        'status': 'failed',
        'message': 'Failed to delete suppression rule'}


# ───────────────────────────────────────────── suppress_by_files: the
# android/ios-existence "else" branch
#
# get_package(checksum) and this view's own android_static_db/ios_static_db
# lookups query the SAME tables by the SAME checksum, so under normal
# execution a truthy `package` guarantees one of the two `.exists()` checks
# is also true -- the `else: return send_response(data, api)` arm is a
# defensive TOCTOU guard against the row vanishing between those two reads.
# `StaticAnalyzerAndroid.objects.filter` / `StaticAnalyzerIOS.objects.filter`
# (NOT `.get`, which is what get_package() itself calls) are narrowly
# patched to simulate exactly that race, while a real Android row backs
# get_package()'s own (unpatched) lookup.
@pytest.mark.django_db
def test_suppress_files_neither_android_nor_ios_toctou(django_user_model, monkeypatch):
    u = _staff_user(django_user_model)
    _android(code_analysis=CODE_RES)  # backs get_package()'s real .get()

    from mobinspect.StaticAnalyzer.models import StaticAnalyzerAndroid, StaticAnalyzerIOS
    monkeypatch.setattr(
        StaticAnalyzerAndroid.objects, 'filter',
        lambda **kw: StaticAnalyzerAndroid.objects.none())
    monkeypatch.setattr(
        StaticAnalyzerIOS.objects, 'filter',
        lambda **kw: StaticAnalyzerIOS.objects.none())

    res = suppress_by_files(
        _post(u, hash=VALID_MD5, rule='ruleA'), api=True)
    assert res['status'] == 'failed'
    assert res['message'] == 'Failed to suppress finding by files'
