"""
MobInspect — RBAC middleware.

Populates `request.mi_permissions` (frozenset of codenames) and
`request.mi_roles` (list of role names) once per request, so view
code, decorators, and template tags can check permissions without
re-querying the database.

Resolution is lazy: the first access triggers the DB query.
"""
from mobsf.RBAC.permissions import (
    get_user_permissions,
    get_user_roles,
)


class RBACMiddleware:
    """Attach memoized permission and role accessors to the request."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        request.mi_permissions = _LazySet(lambda: get_user_permissions(request))
        request.mi_roles = _LazyList(lambda: get_user_roles(request))
        return self.get_response(request)


class _LazyBase:
    """Tiny lazy wrapper that resolves once on first access."""

    __slots__ = ('_fn', '_value', '_resolved')

    def __init__(self, fn):
        self._fn = fn
        self._value = None
        self._resolved = False

    def _resolve(self):
        if not self._resolved:
            self._value = self._fn()
            self._resolved = True
        return self._value

    def __contains__(self, item):
        return item in self._resolve()

    def __iter__(self):
        return iter(self._resolve())

    def __len__(self):
        return len(self._resolve())

    def __bool__(self):
        return bool(self._resolve())

    def __repr__(self):
        return repr(self._resolve())

    def __eq__(self, other):
        return self._resolve() == other

    def __hash__(self):
        return hash(self._resolve())

    def unwrap(self):
        return self._resolve()


class _LazySet(_LazyBase):
    pass


class _LazyList(_LazyBase):
    def __getitem__(self, index):
        return self._resolve()[index]
