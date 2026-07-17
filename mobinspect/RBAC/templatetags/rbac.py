"""
MobInspect — RBAC template tags.

Usage:
    {% load rbac %}

    {% can 'scan.create' %}
        <button class="btn btn-primary">New scan</button>
    {% endcan %}

    {% can_any 'scan.view' 'scan.view_own' %}
        <a href="...">Scans</a>
    {% endcan_any %}

    {% has_role 'Administrator' as is_admin %}
    {% if is_admin %} ... {% endif %}

    Inline form:
        {% if 'scan.create'|can:request %}...{% endif %}
"""
from django import template

register = template.Library()


# ─────────────────────────────────────────────────────── filter form
@register.filter(name='can')
def can_filter(codename, request):
    """{% if 'scan.create'|can:request %}"""
    perms = getattr(request, 'mi_permissions', None)
    if perms is None:
        return False
    return codename in perms


# ─────────────────────────────────────────────────────── block tags
@register.tag(name='can')
def do_can(parser, token):
    """{% can 'codename' %}…{% endcan %}"""
    bits = token.split_contents()
    if len(bits) != 2:
        raise template.TemplateSyntaxError(
            "{% can 'codename' %} takes exactly one argument",
        )
    codename = parser.compile_filter(bits[1])
    nodelist = parser.parse(('endcan',))
    parser.delete_first_token()
    return CanNode([codename], nodelist, all_=True)


@register.tag(name='can_any')
def do_can_any(parser, token):
    bits = token.split_contents()
    if len(bits) < 2:
        raise template.TemplateSyntaxError('can_any needs ≥1 codename')
    codenames = [parser.compile_filter(b) for b in bits[1:]]
    nodelist = parser.parse(('endcan_any',))
    parser.delete_first_token()
    return CanNode(codenames, nodelist, all_=False)


@register.tag(name='can_all')
def do_can_all(parser, token):
    bits = token.split_contents()
    if len(bits) < 2:
        raise template.TemplateSyntaxError('can_all needs ≥1 codename')
    codenames = [parser.compile_filter(b) for b in bits[1:]]
    nodelist = parser.parse(('endcan_all',))
    parser.delete_first_token()
    return CanNode(codenames, nodelist, all_=True)


class CanNode(template.Node):
    def __init__(self, codenames, nodelist, all_):
        self.codenames = codenames
        self.nodelist = nodelist
        self.all_ = all_

    def render(self, context):
        request = context.get('request')
        perms = getattr(request, 'mi_permissions', None) if request else None
        if perms is None:
            return ''
        resolved = [c.resolve(context) for c in self.codenames]
        if self.all_:
            ok = all(c in perms for c in resolved)
        else:
            ok = any(c in perms for c in resolved)
        return self.nodelist.render(context) if ok else ''


# ─────────────────────────────────────────────────────── role checks
@register.simple_tag(takes_context=True)
def has_role(context, *role_names):
    """{% has_role 'Administrator' as is_admin %}"""
    request = context.get('request')
    roles = getattr(request, 'mi_roles', None) if request else None
    if roles is None:
        return False
    return any(r in roles for r in role_names)
