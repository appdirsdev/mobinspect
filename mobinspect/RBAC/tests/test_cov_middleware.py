"""Real-execution coverage tests for mobinspect/RBAC/middleware.py.

STRICT: no mocks. `_LazySet` / `_LazyList` are tiny pure-Python lazy
wrappers; their dunder methods (`__iter__`, `__len__`, `__bool__`,
`__eq__`, `__hash__`, `unwrap`, `__getitem__`) are exercised directly.
`RBACMiddleware.__call__` is exercised through a real request/response
cycle via RequestFactory + a trivial get_response callable.
"""
import pytest

from django.test import RequestFactory

from mobinspect.RBAC.middleware import RBACMiddleware, _LazyList, _LazySet


def test_lazyset_iter_resolves_and_iterates():
    calls = []
    s = _LazySet(lambda: calls.append(1) or {'a', 'b'})
    assert set(iter(s)) == {'a', 'b'}
    # Second access does not re-invoke the resolver function.
    list(iter(s))
    assert calls == [1]


def test_lazyset_len():
    s = _LazySet(lambda: ['a', 'b', 'c'])
    assert len(s) == 3


def test_lazyset_bool_true_and_false():
    assert bool(_LazySet(lambda: {'x'})) is True
    assert bool(_LazySet(lambda: set())) is False


def test_lazyset_repr_resolves_and_formats():
    s = _LazySet(lambda: {'a'})
    assert repr(s) == repr({'a'})


def test_lazyset_eq():
    s = _LazySet(lambda: {'a', 'b'})
    assert s == {'a', 'b'}
    assert s != {'a'}


def test_lazyset_hash():
    s = _LazySet(lambda: frozenset({'a'}))
    assert hash(s) == hash(frozenset({'a'}))


def test_lazyset_unwrap_returns_raw_value():
    s = _LazySet(lambda: {'z'})
    assert s.unwrap() == {'z'}


def test_lazylist_getitem():
    lst = _LazyList(lambda: ['role1', 'role2'])
    assert lst[0] == 'role1'
    assert lst[1] == 'role2'


# ─────────────────────────────────────────────────────── RBACMiddleware.__call__
@pytest.mark.django_db
def test_middleware_attaches_lazy_permissions_and_roles(viewer_user):
    seen = {}

    def get_response(request):
        # Force resolution inside the "view" to prove the attributes work
        # end to end through a real request cycle.
        seen['perms'] = set(request.mi_permissions)
        seen['roles'] = list(request.mi_roles)
        return 'ok-response'

    mw = RBACMiddleware(get_response)
    req = RequestFactory().get('/')
    req.user = viewer_user

    result = mw(req)
    assert result == 'ok-response'
    assert 'scan.view' in seen['perms']
    assert 'Viewer' in seen['roles']
