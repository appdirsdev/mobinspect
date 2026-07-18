"""Real-execution coverage tests for mobinspect/RBAC/templatetags/rbac.py.

STRICT: no mocks. Renders real Django Template strings (`{% load rbac %}`)
through the real template engine, with real request-shaped context objects
carrying `mi_permissions` / `mi_roles` (exactly what RBACMiddleware
attaches). Syntax-error branches are exercised by rendering malformed tag
usage and catching the real `TemplateSyntaxError` the parser raises.
"""
import pytest

from django.template import Context, Template, TemplateSyntaxError

from mobinspect.RBAC.templatetags.rbac import can_filter


class _Req:
    """Minimal duck-typed request carrying only what the tags read."""

    def __init__(self, mi_permissions=None, mi_roles=None):
        if mi_permissions is not None:
            self.mi_permissions = mi_permissions
        if mi_roles is not None:
            self.mi_roles = mi_roles


# ─────────────────────────────────────────────────────── can_filter (function form)
def test_can_filter_returns_false_when_no_mi_permissions_attr():
    req = _Req()  # no mi_permissions attribute at all
    assert can_filter('scan.view', req) is False


def test_can_filter_true_and_false():
    req = _Req(mi_permissions={'scan.view'})
    assert can_filter('scan.view', req) is True
    assert can_filter('scan.delete', req) is False


# ─────────────────────────────────────────────────────── {% can %} block tag
def test_can_tag_wrong_arg_count_raises_syntax_error():
    with pytest.raises(TemplateSyntaxError):
        Template("{% load rbac %}{% can %}x{% endcan %}")
    with pytest.raises(TemplateSyntaxError):
        Template("{% load rbac %}{% can 'a' 'b' %}x{% endcan %}")


def test_can_tag_renders_block_when_permission_present():
    tpl = Template("{% load rbac %}{% can 'scan.view' %}YES{% endcan %}")
    ctx = Context({'request': _Req(mi_permissions={'scan.view'})})
    assert tpl.render(ctx) == 'YES'


def test_can_tag_renders_empty_when_permission_absent():
    tpl = Template("{% load rbac %}{% can 'scan.view' %}YES{% endcan %}")
    ctx = Context({'request': _Req(mi_permissions=set())})
    assert tpl.render(ctx) == ''


def test_can_tag_renders_empty_without_request_in_context():
    """CanNode.render: no `request` in context -> perms stays None -> ''."""
    tpl = Template("{% load rbac %}{% can 'scan.view' %}YES{% endcan %}")
    assert tpl.render(Context({})) == ''


def test_can_tag_renders_empty_when_request_has_no_mi_permissions():
    tpl = Template("{% load rbac %}{% can 'scan.view' %}YES{% endcan %}")
    ctx = Context({'request': _Req()})  # no mi_permissions attr
    assert tpl.render(ctx) == ''


# ─────────────────────────────────────────────────────── {% can_any %}
def test_can_any_tag_wrong_arg_count_raises_syntax_error():
    with pytest.raises(TemplateSyntaxError):
        Template("{% load rbac %}{% can_any %}x{% endcan_any %}")


def test_can_any_tag_renders_when_any_matches():
    tpl = Template(
        "{% load rbac %}{% can_any 'scan.view' 'scan.delete' %}YES{% endcan_any %}")
    ctx = Context({'request': _Req(mi_permissions={'scan.delete'})})
    assert tpl.render(ctx) == 'YES'


def test_can_any_tag_empty_when_none_match():
    tpl = Template(
        "{% load rbac %}{% can_any 'scan.view' 'scan.delete' %}YES{% endcan_any %}")
    ctx = Context({'request': _Req(mi_permissions={'analytics.view'})})
    assert tpl.render(ctx) == ''


# ─────────────────────────────────────────────────────── {% can_all %}
def test_can_all_tag_wrong_arg_count_raises_syntax_error():
    with pytest.raises(TemplateSyntaxError):
        Template("{% load rbac %}{% can_all %}x{% endcan_all %}")


def test_can_all_tag_renders_when_all_match():
    tpl = Template(
        "{% load rbac %}{% can_all 'scan.view' 'scan.delete' %}YES{% endcan_all %}")
    ctx = Context(
        {'request': _Req(mi_permissions={'scan.view', 'scan.delete'})})
    assert tpl.render(ctx) == 'YES'


def test_can_all_tag_empty_when_only_some_match():
    tpl = Template(
        "{% load rbac %}{% can_all 'scan.view' 'scan.delete' %}YES{% endcan_all %}")
    ctx = Context({'request': _Req(mi_permissions={'scan.view'})})
    assert tpl.render(ctx) == ''


# ─────────────────────────────────────────────────────── {% has_role %}
def test_has_role_true_when_role_present():
    tpl = Template(
        "{% load rbac %}{% has_role 'Administrator' as is_admin %}"
        "{% if is_admin %}YES{% else %}NO{% endif %}")
    ctx = Context({'request': _Req(mi_roles=['Administrator', 'Viewer'])})
    assert tpl.render(ctx) == 'YES'


def test_has_role_false_when_role_absent():
    tpl = Template(
        "{% load rbac %}{% has_role 'Administrator' as is_admin %}"
        "{% if is_admin %}YES{% else %}NO{% endif %}")
    ctx = Context({'request': _Req(mi_roles=['Viewer'])})
    assert tpl.render(ctx) == 'NO'


def test_has_role_false_without_request_in_context():
    tpl = Template(
        "{% load rbac %}{% has_role 'Administrator' as is_admin %}"
        "{% if is_admin %}YES{% else %}NO{% endif %}")
    assert tpl.render(Context({})) == 'NO'


def test_has_role_false_when_request_has_no_mi_roles():
    tpl = Template(
        "{% load rbac %}{% has_role 'Administrator' as is_admin %}"
        "{% if is_admin %}YES{% else %}NO{% endif %}")
    ctx = Context({'request': _Req()})  # no mi_roles attr
    assert tpl.render(ctx) == 'NO'
